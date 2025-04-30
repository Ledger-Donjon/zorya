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
        # TinyGo (amd64) calling convention
        return ["RCX", "RDX", "RSI", "RDI", "R8", "R9"]
    elif compiler == "gc":
        # Go standard compiler (gc) uses a slightly different order
        return ["RDI", "RSI", "RDX", "RCX", "R8", "R9"]
    else:
        print(f"ERROR: Unknown compiler '{compiler}'. Must be 'tinygo' or 'gc'.")
        sys.exit(1)

# Collect all known base/struct types from DWARF type table
def extract_types(dwarfinfo):
    types = {}
    for CU in dwarfinfo.iter_CUs():
        for DIE in CU.iter_DIEs():
            if not DIE.tag:
                continue
            if DIE.tag.startswith("DW_TAG_base_type") or DIE.tag.startswith("DW_TAG_structure_type"):
                name_attr = DIE.attributes.get("DW_AT_name", None)
                if name_attr:
                    types[DIE.offset] = name_attr.value.decode()
    return types

# Extract all function names, addresses, and arguments
def extract_signatures(dwarfinfo, types, abi_registers):
    functions = []
    total = 0     # number of functions seen
    matched = 0   # number of functions with parameters

    for CU in dwarfinfo.iter_CUs():
        for DIE in CU.iter_DIEs():
            if DIE.tag != "DW_TAG_subprogram":
                continue
            total += 1

            # Grab function name and starting address
            name_attr = DIE.attributes.get("DW_AT_name", None)
            func_addr = DIE.attributes.get("DW_AT_low_pc", None)
            if not name_attr or not func_addr:
                continue

            func_name = name_attr.value.decode()
            args = []

            # Iterate over children to collect parameter names and types
            for child in DIE.iter_children():
                if child.tag == "DW_TAG_formal_parameter":
                    pname = child.attributes.get("DW_AT_name", None)
                    ptype = child.attributes.get("DW_AT_type", None)
                    if pname and ptype:
                        arg_name = pname.value.decode()
                        type_ref = ptype.value
                        arg_type = types.get(type_ref, f"type@{hex(type_ref)}")
                        args.append((arg_name, arg_type))

            if args:
                matched += 1

            # Map function arguments to ABI registers or fallback to stack
            abi_map = []
            reg_cursor = 0
            for name, ty in args:
                if ty == "string" or ty.startswith("[]") or ty == "interface":
                    # Strings, slices, interfaces take 2 registers
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
                    # Single-register types like int, float, etc.
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

            # Final function signature object
            functions.append({
                "name": func_name,
                "address": hex(func_addr.value),
                "arguments": abi_map
            })

    print(f"[i] Found {total} functions, {matched} had parameters.")
    return functions

# Entry point: parse arguments and orchestrate analysis
def main():
    if len(sys.argv) != 3:
        print("Usage: python sigrecover.py <binary> <compiler>")
        print("Example: python sigrecover.py test tinygo")
        sys.exit(1)

    binary_path = sys.argv[1]
    compiler = sys.argv[2]
    abi_registers = get_abi_registers(compiler)

    # Open ELF and load DWARF info
    with open(binary_path, "rb") as f:
        elf = ELFFile(f)
        if not elf.has_dwarf_info():
            print("No DWARF info found in binary.")
            sys.exit(1)

        dwarfinfo = elf.get_dwarf_info()
        types = extract_types(dwarfinfo)
        funcs = extract_signatures(dwarfinfo, types, abi_registers)

        print(f"[✓] Extracted {len(funcs)} functions.")

        # Ensure results directory exists
        os.makedirs(RESULTS_DIR, exist_ok=True)

        # Save output as JSON in normalized format
        output_file = os.path.join(RESULTS_DIR, "function_signature.json")
        with open(output_file, "w") as out_file:
            json.dump({ "functions": funcs }, out_file, indent=2)
            print(f"[✓] Saved output to {output_file}")

if __name__ == "__main__":
    main()
