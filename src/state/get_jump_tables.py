# Program to get the jump tables in a binary

import sys
import json
import pyhidra

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 get_jump_tables.py /path/to/binary")
        sys.exit(1)

    binary_path = sys.argv[1]

    # Start Pyhidra
    pyhidra.start()

    # Open the binary with Pyhidra
    with pyhidra.open_program(binary_path, analyze=True) as flat_api:
        program = flat_api.getCurrentProgram()
        symbol_table = program.getSymbolTable()
        listing = program.getListing()

        jump_tables = []

        # Analyze switch tables in the binary
        for symbol in symbol_table.getAllSymbols(False):
            if "switchdata" in symbol.getName():
                switch_id = symbol.getName()
                base_address = symbol.getAddress()

                table_entry = {
                    "switch_id": switch_id,
                    "table_address": str(base_address),
                    "cases": []
                }

                # Parse individual entries in the table
                data = listing.getDataAt(base_address)
                while data:
                    destination = data.getValue()
                    if not destination:
                        break  # No more valid entries

                    label = symbol_table.getPrimarySymbol(destination)
                    label_name = label.getName() if label else ""

                    # Check if label still belongs to the current switch table
                    if not label_name.startswith(f"switchD_{switch_id.split('_')[1]}::"):
                        break  # Exit when label doesn't match the expected prefix

                    # Record the input address (current table entry)
                    input_address = data.getAddress()

                    table_entry["cases"].append({
                        "label": label_name if label else "No Label",
                        "destination": str(destination),
                        "input_address": str(input_address) 
                    })

                    data = data.getNext()

                jump_tables.append(table_entry)

        # Output as JSON
        print(json.dumps(jump_tables, indent=4))

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
