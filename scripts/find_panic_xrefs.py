# find_panic_xrefs.py
# Used in main.rs by the get_cross_references function to find cross-references to panic functions.
import sys
import pyhidra
import os
import shutil

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 find_panic_xrefs.py /path/to/binary")
        sys.exit(1)
    
    binary_path = sys.argv[1]
    project_name = os.path.basename(binary_path)  # Use binary name as project name
    project_dir = os.path.join(os.getcwd(), project_name + ".rep")  # Default Ghidra project directory

    # Delete the project if it already exists
    if os.path.exists(project_dir):
        print(f"[INFO] Deleting existing Ghidra project: {project_dir}")
        shutil.rmtree(project_dir, ignore_errors=True)

    print(f"[INFO] Starting Pyhidra for {binary_path}")

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

            # Convert function name to lowercase for case-insensitive comparison
            function_name_lower = function_name.lower()

            # Check if the function name contains "panic" (case-insensitive)
            if "panic" in function_name_lower:
                # Get references to this function
                references = program.getReferenceManager().getReferencesTo(function.getEntryPoint())

                for ref in references:
                    # We are interested in code references that are calls
                    if ref.getReferenceType().isCall():
                        from_address = ref.getFromAddress()
                        xref_addresses.append(from_address)

        # Ensure results directory exists
        results_dir = "results"
        os.makedirs(results_dir, exist_ok=True)

        # Write the addresses to a file in the results directory
        output_file = os.path.join(results_dir, "xref_addresses.txt")
        with open(output_file, "w") as file:
            for addr in xref_addresses:
                file.write("0x{}\n".format(addr.toString()))

        print(f"[INFO] Xref analysis completed. Results saved to {output_file}")

if __name__ == "__main__":
    main()
