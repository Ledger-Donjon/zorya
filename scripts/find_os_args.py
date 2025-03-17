#!/usr/bin/env python3
import sys
import os
import pyhidra

# Pyhidra imports
try:
    from pyhidra import open_program
except ImportError:
    print("Error: pyhidra not installed. Install with pip install pyhidra.")
    sys.exit(1)

def main():
    if len(sys.argv) < 2:
        print("Usage: find_os_args.py <binary_path>")
        sys.exit(1)

    pyhidra.start()

    from ghidra.program.model.symbol import SymbolUtilities

    binary_path = sys.argv[1]
    if not os.path.isfile(binary_path):
        print(f"Error: file {binary_path} does not exist.")
        sys.exit(1)

    with open_program(binary_path, analyze=True) as flat_api:
        # Get the current program object
        program = flat_api.getCurrentProgram()
        
        # Access the symbol table from the program
        symbol_table = program.getSymbolTable()
        found = False

        for symbol in symbol_table.getAllSymbols(True):  # Iterate over all symbols
            name = symbol.getName()
            if 'os.Args' in name:
                address = symbol.getAddress()
                print(f"{name} {address}")
                found = True
                break

        if not found:
            print("ERROR: Could not find 'os.Args' symbol.")
            sys.exit(2)

if __name__ == "__main__":
    main()
