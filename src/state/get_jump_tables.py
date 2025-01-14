import sys
import json
import pyhidra
from ghidra.program.model.symbol import SymbolType
from ghidra.program.model.address import Address
from ghidra.program.model.listing import Instruction
from ghidra.program.model.data import PointerDataType


def is_code_address(program, addr):
    """
    Checks if the given address points to code by verifying if there is an instruction
    or a function starting at that address.
    """
    listing = program.getListing()
    code_unit = listing.getCodeUnitAt(addr)
    if code_unit and isinstance(code_unit, Instruction):
        return True

    fm = program.getFunctionManager()
    func = fm.getFunctionAt(addr)
    if func is not None:
        return True

    return False


def extract_jump_tables(program):
    """
    Extract jump tables by looking for likely switch data symbols and verifying 
    that they point to code.
    """
    symbol_table = program.getSymbolTable()
    listing = program.getListing()

    jump_tables = []
    visited = set()

    # Adjust these indicators based on Ghidra conventions
    switch_name_indicators = ["switchD_", "switchdata", "switch__"]

    for symbol in symbol_table.getAllSymbols(True):
        if symbol.getSymbolType() == SymbolType.LABEL:
            symbol_name = symbol.getName().lower()
            if any(indicator in symbol_name for indicator in switch_name_indicators):
                base_address = symbol.getAddress()
                
                if base_address in visited:
                    continue
                visited.add(base_address)

                print(f"Processing jump table at {base_address}")

                table_entries = []
                current_addr = base_address
                max_table_entries = 512  # Increased for larger tables
                invalid_entries = 0

                for _ in range(max_table_entries):
                    data = listing.getDataAt(current_addr)
                    if data is None:
                        break

                    if not data.isPointer():
                        # Non-pointer data indicates the end of the jump table
                        invalid_entries += 1
                        if invalid_entries > 3:  # Allow up to 3 invalid entries
                            break
                        current_addr = current_addr.add(8)  # Move to next potential entry
                        continue

                    destination = data.getValue()
                    if not destination or not isinstance(destination, Address):
                        break

                    if is_code_address(program, destination):
                        dest_symbol = symbol_table.getPrimarySymbol(destination)
                        label_name = dest_symbol.getName() if dest_symbol else "Unknown"

                        table_entries.append({
                            "label": label_name,
                            "destination": f"{destination.getOffset():08x}",
                            "input_address": f"{current_addr.getOffset():08x}"
                        })
                        invalid_entries = 0  # Reset invalid entries counter
                    else:
                        invalid_entries += 1
                        if invalid_entries > 3:
                            break

                    current_addr = current_addr.add(data.getLength())

                if len(table_entries) > 1:
                    jump_table = {
                        "switch_id": symbol.getName(),
                        "table_address": f"{base_address.getOffset():08x}",
                        "cases": table_entries
                    }
                    jump_tables.append(jump_table)

    return jump_tables


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 get_jump_tables.py /path/to/binary")
        sys.exit(1)

    binary_path = sys.argv[1]

    try:
        pyhidra.start()
    except Exception as init_error:
        print(f"Pyhidra initialization error: {init_error}")
        sys.exit(1)

    try:
        with pyhidra.open_program(binary_path, analyze=True) as flat_api:
            program = flat_api.getCurrentProgram()
            jump_tables = extract_jump_tables(program)

            output_file = "jump_tables.json"
            with open(output_file, "w") as f:
                json.dump(jump_tables, f, indent=4)

            print(f"Jump tables saved to {output_file}")
            print(f"Total jump tables found: {len(jump_tables)}")

    except Exception as e:
        print(f"Error processing binary: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()

# Example of expected output:
# [
#     {
#         "switch_id": "switchD_00468880::switchdataD_004df620",
#         "table_address": "004df620",
#         "cases": [
#             {
#                 "label": "switchD_00468880::caseD_14",
#                 "destination": "004688d7",
#                 "input_address": "004df658"
#             },
#             {
#                 "label": "switchD_00468880::caseD_12",
#                 "destination": "00468842",
#                 "input_address": "004df660"
#             },
#             {
#                 "label": "switchD_00468880::caseD_12",
#                 "destination": "00468842",
#                 "input_address": "004df668"
#             }
#         ]
#     }
# ]
