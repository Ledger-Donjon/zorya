#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2025 Ledger https://www.ledger.com - INSTITUT MINES TELECOM
#
# SPDX-License-Identifier: Apache-2.0

"""
Extract function signatures AND struct type definitions from Go binaries using llvm-dwarfdump
This script properly handles DWARF5 which has bugs in GNU binutils
"""

import subprocess
import json
import sys
import re
import os

# Global struct type definitions extracted from DWARF
struct_types = {}


def run_llvm_dwarfdump(binary_path):
    """Run llvm-dwarfdump and return the output"""
    try:
        result = subprocess.run(
            ["llvm-dwarfdump-18", "--debug-info", binary_path],
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error running llvm-dwarfdump: {e}", file=sys.stderr)
        sys.exit(1)
    except FileNotFoundError:
        print(
            "Error: llvm-dwarfdump-18 not found. Install with: sudo apt install llvm-18-tools",
            file=sys.stderr,
        )
        sys.exit(1)


def get_symbol_addresses(binary_path):
    """Get function addresses from symbol table as fallback"""
    try:
        result = subprocess.run(
            ["nm", binary_path], capture_output=True, text=True, check=True
        )
        symbol_map = {}
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 3:
                addr, _typ, name = parts[0], parts[1], " ".join(parts[2:])
                symbol_map[name] = addr
        return symbol_map
    except Exception:
        return {}


def parse_struct_types(dwarf_output):
    """Parse llvm-dwarfdump output to extract struct type definitions"""
    global struct_types
    struct_types = {}

    lines = dwarf_output.split("\n")
    i = 0

    while i < len(lines):
        line = lines[i]

        # Detect start of a structure type
        if "DW_TAG_structure_type" in line:
            struct_name = None
            struct_size = 0
            members = []

            # Parse struct details
            j = i + 1
            while j < len(lines):
                detail_line = lines[j]

                # Check if we've reached the end of this struct (NULL terminator or new tag at same level)
                if detail_line.strip() == "NULL" or (
                    detail_line.strip().startswith("0x")
                    and "DW_TAG_structure_type" in detail_line
                ):
                    break

                # New top-level tag means end of struct
                if (
                    re.match(r"^0x[0-9a-fA-F]+:\s+DW_TAG_", detail_line)
                    and "DW_TAG_member" not in detail_line
                ):
                    break

                # Extract struct name
                if "DW_AT_name" in detail_line and struct_name is None:
                    match = re.search(r'DW_AT_name\s*\(\s*"([^"]+)"\s*\)', detail_line)
                    if match:
                        struct_name = match.group(1)

                # Extract struct size
                if "DW_AT_byte_size" in detail_line:
                    match = re.search(r"DW_AT_byte_size\s*\(\s*(\d+)\s*\)", detail_line)
                    if match:
                        struct_size = int(match.group(1))

                # Detect member
                if "DW_TAG_member" in detail_line:
                    member = {"name": "", "offset": 0, "type": "unknown"}

                    # Parse member details
                    k = j + 1
                    while k < len(lines):
                        member_line = lines[k]

                        # End of member
                        if (
                            member_line.strip().startswith("0x")
                            and "DW_TAG" in member_line
                        ):
                            break
                        if member_line.strip() == "NULL":
                            break

                        # Member name
                        if "DW_AT_name" in member_line:
                            match = re.search(
                                r'DW_AT_name\s*\(\s*"([^"]+)"\s*\)', member_line
                            )
                            if match:
                                member["name"] = match.group(1)

                        # Member offset
                        if "DW_AT_data_member_location" in member_line:
                            match = re.search(
                                r"DW_AT_data_member_location\s*\(\s*(\d+)\s*\)",
                                member_line,
                            )
                            if match:
                                member["offset"] = int(match.group(1))

                        # Member type
                        if "DW_AT_type" in member_line:
                            type_match = re.search(
                                r'DW_AT_type\s*\(\s*0x[0-9a-fA-F]+\s+"([^"]+)"\s*\)',
                                member_line,
                            )
                            if type_match:
                                member["type"] = type_match.group(1)

                        k += 1

                    if member["name"]:
                        members.append(member)
                    j = k
                    continue

                j += 1

            # Store struct if it has a name
            if struct_name and members:
                struct_types[struct_name] = {
                    "name": struct_name,
                    "size": struct_size,
                    "members": members,
                }

            i = j
            continue

        i += 1

    return struct_types


def parse_dwarf_output(dwarf_output, symbol_map):
    """Parse llvm-dwarfdump output to extract function signatures"""
    # First, extract struct types
    parse_struct_types(dwarf_output)

    functions = []
    current_function = None
    _current_cu_addr_base = 0

    lines = dwarf_output.split("\n")
    i = 0

    while i < len(lines):
        line = lines[i]

        # Track addr_base for the compilation unit
        if "DW_AT_addr_base" in line:
            match = re.search(r"DW_AT_addr_base\s*\(\s*0x([0-9a-fA-F]+)\s*\)", line)
            if match:
                _current_cu_addr_base = int(match.group(1), 16)

        # Detect start of a subprogram (function)
        if "DW_TAG_subprogram" in line:
            if current_function:
                functions.append(current_function)

            current_function = {"name": "", "address": "0x0", "arguments": []}

            # Parse function details
            j = i + 1
            while (
                j < len(lines)
                and not lines[j].strip().startswith("0x")
                and "DW_TAG" not in lines[j]
            ):
                detail_line = lines[j]

                # Extract function name
                if "DW_AT_name" in detail_line:
                    match = re.search(r'DW_AT_name\s*\(\s*"([^"]+)"\s*\)', detail_line)
                    if match:
                        current_function["name"] = match.group(1)

                # Extract low_pc (function address)
                elif "DW_AT_low_pc" in detail_line:
                    match = re.search(
                        r"DW_AT_low_pc\s*\(\s*0x([0-9a-fA-F]+)\s*\)", detail_line
                    )
                    if match:
                        current_function["address"] = f"0x{match.group(1)}"

                j += 1

            # If DWARF address is 0, try symbol table
            if current_function["address"] == "0x0" and current_function["name"]:
                if current_function["name"] in symbol_map:
                    current_function["address"] = (
                        f"0x{symbol_map[current_function['name']]}"
                    )

            i = j
            continue

        # Detect function parameters
        if "DW_TAG_formal_parameter" in line and current_function:
            param = {
                "name": "",
                "type": "unknown",
                "registers": [],
                "location": "llvm-dwarfdump",
            }

            # Parse parameter details
            j = i + 1
            while (
                j < len(lines)
                and not lines[j].strip().startswith("0x")
                and "DW_TAG" not in lines[j]
            ):
                param_line = lines[j]

                # Extract parameter name
                if "DW_AT_name" in param_line:
                    match = re.search(r'DW_AT_name\s*\(\s*"([^"]+)"\s*\)', param_line)
                    if match:
                        param["name"] = match.group(1)

                # Extract type info
                elif "DW_AT_type" in param_line:
                    # Try to extract the type name from quotes after the hex offset
                    # Format: DW_AT_type (0xHEXADDR "typename")
                    type_match = re.search(
                        r'DW_AT_type\s*\(\s*0x[0-9a-fA-F]+\s+"([^"]+)"\s*\)', param_line
                    )
                    if type_match:
                        param["type"] = type_match.group(1)
                    else:
                        # Fallback if no quoted type name is present
                        param["type"] = "type-ref"

                # Extract location (registers)
                elif "DW_AT_location" in param_line:
                    # The actual location list is on the NEXT line(s)
                    # Look ahead to find the first location entry (at function entry)
                    k = j + 1
                    while k < len(lines) and k < j + 5:  # Look ahead up to 5 lines
                        loc_line = lines[k]
                        # Find the first location list entry: [0xADDR, 0xADDR): ...
                        if re.search(
                            r"\[0x[0-9a-fA-F]+,\s*0x[0-9a-fA-F]+\):", loc_line
                        ):
                            # Extract register names (e.g., "DW_OP_reg0 RAX")
                            # Pattern: DW_OP_reg\d+ REGNAME or just register names
                            reg_matches = re.findall(
                                r"DW_OP_reg\d+\s+([A-Z0-9]+)", loc_line
                            )
                            if reg_matches:
                                param["registers"] = reg_matches
                                param["location"] = loc_line.strip()
                            break
                        k += 1

                j += 1

            # Skip output parameters (~r0, ~r1, etc.) and unnamed params
            if param["name"] and not param["name"].startswith("~r"):
                current_function["arguments"].append(param)

            i = j
            continue

        i += 1

    # Add last function
    if current_function and current_function["name"]:
        functions.append(current_function)

    return functions


def get_register_name(reg_num):
    """Map DWARF register numbers to x86-64 register names.

    The mapping follows the SysV x86-64 ABI register-number table that
    Go's DWARF emitter (and llvm-dwarfdump) use:

      0-15  General-purpose: RAX, RDX, RCX, RBX, RSI, RDI, RBP, RSP,
            R8-R15.
      16    Return-address register (unused for arg locations).
      17-32 XMM0-XMM15 (used for float64 / float32 / vector args under
            Go's regabi from Go 1.17+).
    """
    reg_map = {
        0: "RAX",
        1: "RDX",
        2: "RCX",
        3: "RBX",
        4: "RSI",
        5: "RDI",
        6: "RBP",
        7: "RSP",
        8: "R8",
        9: "R9",
        10: "R10",
        11: "R11",
        12: "R12",
        13: "R13",
        14: "R14",
        15: "R15",
        17: "XMM0",
        18: "XMM1",
        19: "XMM2",
        20: "XMM3",
        21: "XMM4",
        22: "XMM5",
        23: "XMM6",
        24: "XMM7",
        25: "XMM8",
        26: "XMM9",
        27: "XMM10",
        28: "XMM11",
        29: "XMM12",
        30: "XMM13",
        31: "XMM14",
        32: "XMM15",
    }
    return reg_map.get(reg_num)


def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <binary_path> <output_json>", file=sys.stderr)
        sys.exit(1)

    binary_path = sys.argv[1]
    output_path = sys.argv[2]

    if not os.path.exists(binary_path):
        print(f"Error: Binary not found: {binary_path}", file=sys.stderr)
        sys.exit(1)

    print(f"Extracting function signatures from: {binary_path}")
    print("Using llvm-dwarfdump-18 for DWARF5 support...")

    # Get symbol table addresses as fallback
    print("Reading symbol table...")
    symbol_map = get_symbol_addresses(binary_path)
    print(f"Found {len(symbol_map)} symbols")

    # Run llvm-dwarfdump
    print("Running llvm-dwarfdump (this may take a while for large binaries)...")
    dwarf_output = run_llvm_dwarfdump(binary_path)

    # Parse the output (this also extracts struct types)
    print("Parsing DWARF information...")
    functions = parse_dwarf_output(dwarf_output, symbol_map)

    # Save functions to JSON
    print(f"Extracted {len(functions)} functions")
    print(f"Writing functions to: {output_path}")

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(functions, f, indent=2)

    # Save struct types to a separate JSON file
    struct_output_path = output_path.replace(".json", "_structs.json")
    if struct_output_path == output_path:
        struct_output_path = output_path.replace(".json", "") + "_structs.json"

    print(f"Extracted {len(struct_types)} struct types")
    print(f"Writing struct types to: {struct_output_path}")

    with open(struct_output_path, "w") as f:
        json.dump(struct_types, f, indent=2)

    print("Done!")

    # Show a sample of extracted functions
    if functions:
        print("\nSample of extracted functions:")
        for func in functions[:5]:
            print(
                f"  - {func['name']} @ {func['address']} ({len(func['arguments'])} args)"
            )

    # Show a sample of extracted structs
    if struct_types:
        print(f"\nSample of extracted struct types ({len(struct_types)} total):")
        sample_structs = list(struct_types.values())[:5]
        for struct in sample_structs:
            print(
                f"  - {struct['name']} ({struct['size']} bytes, {len(struct['members'])} members)"
            )


if __name__ == "__main__":
    main()
