# find_panic_xrefs.py
import sys
import pyhidra

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 find_panic_xrefs.py /path/to/binary")
        sys.exit(1)
    binary_path = sys.argv[1]

    # Start Pyhidra
    pyhidra.start()

    from ghidra.program.model.symbol import RefType

    # Open the binary with Pyhidra
    with pyhidra.open_program(binary_path, analyze=True) as flat_api:
        # Get the Program object
        program = flat_api.getCurrentProgram()

        # Get the FunctionManager
        function_manager = program.getFunctionManager()

        # List to store the addresses of xrefs to panic functions
        xref_addresses = []

        # Iterate over all functions in the program
        function_iterator = function_manager.getFunctions(True)
        while function_iterator.hasNext():
            function = function_iterator.next()
            function_name = function.getName()

            # Check if the function name contains "panic"
            if "panic" in function_name:
                # Get references to this function
                references = program.getReferenceManager().getReferencesTo(function.getEntryPoint())

                for ref in references:
                    # We are interested in code references that are calls
                    if ref.getReferenceType().isCall():
                        from_address = ref.getFromAddress()
                        xref_addresses.append(from_address)

        # Output the addresses
        print("Addresses of instructions calling panic functions:")
        for addr in xref_addresses:
            print("0x{}".format(addr.toString()))

        # Write the addresses to a file
        with open("xref_addresses.txt", "w") as file:
            for addr in xref_addresses:
                file.write("0x{}\n".format(addr.toString()))

if __name__ == "__main__":
    main()