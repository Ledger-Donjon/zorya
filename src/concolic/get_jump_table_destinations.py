# Program to get the destinations of a computed jump or indirect branch

import sys
import json
import pyhidra

def main():
    if len(sys.argv) < 3:
        print("Usage: python3 get_jump_table_destinations.py /path/to/binary jump_instruction_address")
        sys.exit(1)
    
    binary_path = sys.argv[1]
    jmp_addr_str = sys.argv[2]

    # Start Pyhidra
    pyhidra.start()

    from ghidra.program.model.symbol import RefType

    # Open the binary with Pyhidra
    with pyhidra.open_program(binary_path, analyze=True) as flat_api:
        # Get the Program object
        program = flat_api.getCurrentProgram()

        # Parse the jump instruction address
        jmp_address = program.getAddressFactory().getAddress(jmp_addr_str)
        if jmp_address is None:
            print(json.dumps({"error": f"Invalid address: {jmp_addr_str}"}))
            sys.exit(1)

        # Get references from the computed jump's address
        references = program.getReferenceManager().getReferencesFrom(jmp_address)

        # Collect all COMPUTED_JUMP references with their labels and addresses
        jump_table_entries = []
        for ref in references:
            if ref.getReferenceType() == RefType.COMPUTED_JUMP:
                destination = ref.getToAddress()
                label = program.getSymbolTable().getPrimarySymbol(destination)
                label_name = label.getName() if label else "No Label"
                jump_table_entries.append({"label": label_name, "destination": str(destination)})

        # Output the entries as JSON
        print(json.dumps(jump_table_entries))

if __name__ == "__main__":
    main()
