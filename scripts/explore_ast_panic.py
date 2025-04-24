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
    panic_xref_path = os.path.join("results", "xref_addresses.txt")

    if not os.path.exists(panic_xref_path):
        print(f"ERROR: Expected panic xrefs at {panic_xref_path}")
        sys.exit(2)

    with open(panic_xref_path, "r") as f:
        panic_addresses_hex = [line.strip() for line in f if line.strip()]

    pyhidra.start()

    from ghidra.program.model.block import BasicBlockModel
    from ghidra.util.task import ConsoleTaskMonitor

    with open_program(binary_path, analyze=True) as flat_api:
        program = flat_api.getCurrentProgram()
        address_factory = program.getAddressFactory()
        monitor = ConsoleTaskMonitor()
        model = BasicBlockModel(program)

        # Convert known panic xrefs to address objects
        panic_addresses = set()
        for addr_str in panic_addresses_hex:
            try:
                addr = address_factory.getAddress(addr_str)
                if program.getMemory().contains(addr):
                    panic_addresses.add(addr)
            except:
                continue

        start_addr = address_factory.getAddress(start_address_hex)
        visited = set()
        found = False

        def dfs(block, depth):
            nonlocal found
            if found or depth > max_depth or block in visited:
                return
            visited.add(block)

            block_start = block.getFirstStartAddress()
            block_end = block.getMaxAddress()

            # If any address in this block is a panic address, report it
            for panic_addr in panic_addresses:
                if block_start <= panic_addr <= block_end:
                    print(f"FOUND_PANIC_XREF_AT 0x{panic_addr}")
                    found = True
                    return

            # Recurse on successor blocks
            dest_iter = block.getDestinations(monitor)
            while dest_iter.hasNext():
                ref = dest_iter.next()
                dest_block = model.getCodeBlockAt(ref.getDestinationAddress(), monitor)
                if dest_block is not None:
                    dfs(dest_block, depth + 1)


        # Begin with blocks containing the given address
        blocks = model.getCodeBlocksContaining(start_addr, monitor)
        for block in blocks:
            dfs(block, 0)

        if not found:
            print("NO_PANIC_XREF_FOUND")

if __name__ == "__main__":
    main()
