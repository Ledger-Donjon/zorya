#!/usr/bin/env python3
import sys
import os
import pyhidra

try:
    from pyhidra import open_program
except ImportError:
    print("ERROR: Pyhidra not installed. Run: pip install pyhidra")
    sys.exit(1)

def main():
    if len(sys.argv) != 4:
        print("Usage: explore_ast_panic.py <binary_path> <start_address_hex> <max_depth>")
        sys.exit(1)

    binary_path = sys.argv[1]
    start_address_hex = sys.argv[2]
    max_depth = int(sys.argv[3])
    pyhidra.start()

    from ghidra.program.model.block import BasicBlockModel
    from ghidra.program.model.symbol import SymbolType
    from ghidra.util.graph import DirectedGraph
    from ghidra.util.task import ConsoleTaskMonitor

    with open_program(binary_path, analyze=True) as flat_api:
        program = flat_api.getCurrentProgram()
        listing = program.getListing()
        symbol_table = program.getSymbolTable()
        address_factory = program.getAddressFactory()
        panic_addresses = []

        for symbol in symbol_table.getAllSymbols(True):
            if "panic" in symbol.getName().lower():
                panic_addresses.append(symbol.getAddress())

        if not panic_addresses:
            print("WARNING: No panic-related symbols found.")
            return

        start_addr = address_factory.getAddress(start_address_hex)
        monitor = ConsoleTaskMonitor()
        model = BasicBlockModel(program)
        visited = set()

        def dfs(current_addr, depth):
            if depth > max_depth or current_addr in visited:
                return
            visited.add(current_addr)

            for block in model.getCodeBlocksContaining(current_addr, monitor):
                start = block.getFirstStartAddress()
                if start in panic_addresses:
                    print(f"FOUND_PANIC_XREF_AT 0x{start}")
                    return

                refs = flat_api.getReferencesFrom(start)
                for ref in refs:
                    target = ref.getToAddress()
                    dfs(target, depth + 1)

        dfs(start_addr, 0)

if __name__ == "__main__":
    main()
