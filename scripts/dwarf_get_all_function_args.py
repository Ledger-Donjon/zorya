from elftools.elf.elffile import ELFFile
import json
import sys
import os

# Set up paths for saving results
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
RESULTS_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, "..", "results"))

# Select the ABI register ordering based on the compiler used
def get_abi_registers(compiler):
    compiler = compiler.lower()
    if compiler == "tinygo":
        return ["RCX", "RDX", "RSI", "RDI", "R8", "R9"]
    elif compiler == "gc":
        return ["RDI", "RSI", "RDX", "RCX", "R8", "R9"]
    else:
        print(f"ERROR: Unknown compiler '{compiler}'. Must be 'tinygo' or 'gc'.")
        sys.exit(1)

def safe_decode(attr):
    try:
        return attr.value.decode()
    except Exception:
        return None

# Build index of all DIEs by offset for full resolution
def build_die_index(dwarfinfo):
    die_index = {}
    for cu in dwarfinfo.iter_CUs():
        for die in cu.iter_DIEs():
            die_index[die.offset] = die
    return die_index

# Resolve the type of a DIE recursively
def resolve_type(die, die_index, depth=0):
    if depth > 20:
        return "recursive-type"

    if "DW_AT_type" not in die.attributes:
        return "void"

    type_offset = die.attributes["DW_AT_type"].value
    type_die = die_index.get(type_offset)
    if not type_die:
        return f"unresolved@{hex(type_offset)}"

    tag = type_die.tag
    name_attr = type_die.attributes.get("DW_AT_name")
    name = safe_decode(name_attr) if name_attr else None

    if tag == "DW_TAG_pointer_type":
        pointee = resolve_type(type_die, die_index, depth + 1)
        return f"*{pointee}"

    elif tag == "DW_TAG_array_type":
        base = resolve_type(type_die, die_index, depth + 1)
        return f"[]{base}"

    elif tag == "DW_TAG_typedef":
        if name:
            return name
        return resolve_type(type_die, die_index, depth + 1)

    elif tag == "DW_TAG_structure_type":
        if name:
            return name

        # anonymous struct — could still be meaningful
        member_names = [
            safe_decode(child.attributes.get("DW_AT_name"))
            for child in type_die.iter_children()
            if child.tag == "DW_TAG_member" and "DW_AT_name" in child.attributes
        ]

        if {"buckets", "count", "hash0", "oldbuckets"}.intersection(member_names):
            return "map[?,?]"
        if set(["array", "len", "cap"]).issubset(member_names):
            return "slice"

        return "struct"

    elif tag == "DW_TAG_base_type":
        return name or "base"

    elif tag == "DW_TAG_subrange_type":
        return name or "__ARRAY_SIZE_TYPE__"

    elif tag == "DW_TAG_interface_type":
        return name or "interface"

    # Fallback for unknown or unnamed types
    return name or f"tag:{tag}"

def type_str_to_typedescriptor(ty):
    if ty.startswith("*"):
        return {
            "kind": "Pointer",
            "to": type_str_to_typedescriptor(ty[1:])
        }
    elif ty.startswith("[]"):
        return {
            "kind": "Array",
            "element": type_str_to_typedescriptor(ty[2:]),
            "count": None
        }
    elif ty == "struct":
        return { "kind": "Struct", "members": [] }
    elif ty == "map[?,?]":
        return { "kind": "Unknown", "name": "map[?,?]" }
    elif ty.startswith("unresolved@"):
        return { "kind": "Unknown", "name": ty }
    elif ty == "interface":
        return { "kind": "Unknown", "name": "interface" }
    else:
        return { "kind": "Primitive", "name": ty }

def extract_signatures(dwarfinfo, die_index, abi_registers):
    functions = []
    total = 0
    matched = 0

    for CU in dwarfinfo.iter_CUs():
        for DIE in CU.iter_DIEs():
            if DIE.tag != "DW_TAG_subprogram":
                continue
            total += 1

            name_attr = DIE.attributes.get("DW_AT_name", None)
            func_addr = DIE.attributes.get("DW_AT_low_pc", None)
            if not name_attr or not func_addr:
                continue

            func_name = safe_decode(name_attr)
            if not func_name:
                continue

            args = []

            for child in DIE.iter_children():
                if child.tag == "DW_TAG_formal_parameter":
                    pname = child.attributes.get("DW_AT_name")
                    ptype = child.attributes.get("DW_AT_type")
                    if pname and ptype:
                        arg_name = safe_decode(pname)
                        arg_type = resolve_type(child, die_index)
                        if arg_name:
                            args.append((arg_name, arg_type))

            if args:
                matched += 1

            abi_map = []
            reg_cursor = 0
            for name, ty in args:
                if ty == "string" or ty.startswith("[]") or ty == "interface":
                    if reg_cursor + 1 < len(abi_registers):
                        abi_map.append({
                            "name": name,
                            "type": ty,
                            "registers": [abi_registers[reg_cursor], abi_registers[reg_cursor + 1]]
                        })
                        reg_cursor += 2
                    else:
                        abi_map.append({
                            "name": name,
                            "type": ty,
                            "location": f"Stack[{8 * (reg_cursor - len(abi_registers))}]"
                        })
                        reg_cursor += 2
                else:
                    if reg_cursor < len(abi_registers):
                        abi_map.append({
                            "name": name,
                            "type": ty,
                            "register": abi_registers[reg_cursor]
                        })
                        reg_cursor += 1
                    else:
                        abi_map.append({
                            "name": name,
                            "type": ty,
                            "location": f"Stack[{8 * (reg_cursor - len(abi_registers))}]"
                        })
                        reg_cursor += 1

            functions.append({
                "name": func_name,
                "address": hex(func_addr.value),
                "arguments": abi_map
            })

    print(f"[i] Found {total} functions, {matched} had parameters.")
    return functions

# Main entry point
def main():
    if len(sys.argv) != 3:
        print("Usage: python dwarf_get_all_function_args.py <binary> <compiler>")
        sys.exit(1)

    binary_path = sys.argv[1]
    compiler = sys.argv[2]
    abi_registers = get_abi_registers(compiler)

    with open(binary_path, "rb") as f:
        elf = ELFFile(f)
        if not elf.has_dwarf_info():
            print("No DWARF info found in binary.")
            sys.exit(1)

        dwarfinfo = elf.get_dwarf_info()
        die_index = build_die_index(dwarfinfo)
        funcs = extract_signatures(dwarfinfo, die_index, abi_registers)

        print(f"[✓] Extracted {len(funcs)} functions.")
        os.makedirs(RESULTS_DIR, exist_ok=True)
        output_file = os.path.join(RESULTS_DIR, "function_signature_arg_registers.json")
        with open(output_file, "w") as out_file:
            json.dump({ "functions": funcs }, out_file, indent=2)
            print(f"[✓] Saved output to {output_file}")

if __name__ == "__main__":
    main()
