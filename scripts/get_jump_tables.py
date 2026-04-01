# SPDX-FileCopyrightText: 2025 Ledger https://www.ledger.com - INSTITUT MINES TELECOM
#
# SPDX-License-Identifier: Apache-2.0

import sys
import json
import pyhidra
import os
from pathlib import Path
import shutil
import time


def extract_jump_tables(program):
    """
    Extract jump tables by looking for likely switch data symbols and verifying
    that they point to code.

    Optimizations vs. the original version:
    - Uses getSymbolIterator(pattern, caseSensitive) to search only for
      switch-related symbols instead of iterating ALL symbols (100k+ for Go
      binaries). Each call is a single Java-side pattern scan.
    - Caches listing / function-manager / memory objects so they are fetched
      once instead of per-entry.
    - Builds a set of executable address ranges once for a fast in-Python
      code-address check, falling back to Ghidra only when needed.
    """
    symbol_table = program.getSymbolTable()
    listing = program.getListing()
    fm = program.getFunctionManager()

    # ── Pre-compute executable address ranges for fast code-address test ──
    code_ranges = []
    for block in program.getMemory().getBlocks():
        if block.isExecute():
            start = block.getStart().getOffset()
            end = block.getEnd().getOffset()
            code_ranges.append((start, end))

    def is_code_address_fast(addr):
        """Fast check: is `addr` inside an executable memory block?"""
        off = addr.getOffset()
        for lo, hi in code_ranges:
            if lo <= off <= hi:
                return True
        return False

    def is_code_address(addr):
        """Full check: fast range test, then fall back to Ghidra listing."""
        if is_code_address_fast(addr):
            return True
        code_unit = listing.getCodeUnitAt(addr)
        if code_unit and isinstance(code_unit, Instruction):
            return True
        if fm.getFunctionAt(addr) is not None:
            return True
        return False

    jump_tables = []
    visited = set()

    # ── Targeted symbol search ─────────────────────────────────────────
    # Instead of getAllSymbols(True) which iterates every symbol in the
    # binary, use getSymbolIterator(pattern, caseSensitive) for each
    # switch indicator.  The pattern search is done on the Java side so
    # only matching symbols cross the JNI bridge.
    switch_patterns = ["switchD_*", "*switchdata*", "switch__*"]

    candidate_symbols = []
    for pattern in switch_patterns:
        it = symbol_table.getSymbolIterator(pattern, False)  # case-insensitive
        while it.hasNext():
            sym = it.next()
            if sym.getSymbolType() == SymbolType.LABEL:
                candidate_symbols.append(sym)

    print(f"Found {len(candidate_symbols)} switch-related symbols (filtered search)")

    for symbol in candidate_symbols:
        base_address = symbol.getAddress()

        addr_key = base_address.getOffset()
        if addr_key in visited:
            continue
        visited.add(addr_key)

        table_entries = []
        current_addr = base_address
        max_table_entries = 512
        invalid_entries = 0

        for _ in range(max_table_entries):
            data = listing.getDataAt(current_addr)
            if data is None:
                break

            if not data.isPointer():
                invalid_entries += 1
                if invalid_entries > 3:
                    break
                current_addr = current_addr.add(8)
                continue

            destination = data.getValue()
            if not destination or not isinstance(destination, Address):
                break

            if is_code_address(destination):
                dest_symbol = symbol_table.getPrimarySymbol(destination)
                label_name = dest_symbol.getName() if dest_symbol else "Unknown"

                table_entries.append(
                    {
                        "label": label_name,
                        "destination": f"{destination.getOffset():08x}",
                        "input_address": f"{current_addr.getOffset():08x}",
                    }
                )
                invalid_entries = 0
            else:
                invalid_entries += 1
                if invalid_entries > 3:
                    break

            current_addr = current_addr.add(data.getLength())

        if len(table_entries) > 1:
            jump_tables.append(
                {
                    "switch_id": symbol.getName(),
                    "table_address": f"{base_address.getOffset():08x}",
                    "cases": table_entries,
                }
            )

    return jump_tables


def _project_is_fresh(gpr_path, bin_path):
    """Return True if the Ghidra project exists and is newer than the binary."""
    if not gpr_path.exists():
        return False
    try:
        return gpr_path.stat().st_mtime >= bin_path.stat().st_mtime
    except OSError:
        return False


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 get_jump_tables.py /path/to/binary")
        sys.exit(1)

    total_start = time.time()

    binary_path = sys.argv[1]
    # Normalize paths and expected project layout
    bin_path = Path(os.path.abspath(binary_path))
    bin_parent = bin_path.parent
    bin_name = bin_path.name
    project_name = f"{bin_name}_ghidra"
    project_dir = bin_parent / project_name
    parent_gpr = bin_parent / f"{project_name}.gpr"
    parent_rep = bin_parent / f"{project_name}.rep"
    sub_gpr = project_dir / f"{project_name}.gpr"
    sub_rep = project_dir / f"{project_name}.rep"

    # ── Reuse existing Ghidra project if it is still up-to-date ────────
    # Ghidra analysis (import + auto-analysis) is by far the most expensive
    # step.  If the .gpr is newer than the binary we skip the full rebuild.
    reuse_project = _project_is_fresh(parent_gpr, bin_path) or _project_is_fresh(
        sub_gpr, bin_path
    )

    if reuse_project:
        print("Reusing existing Ghidra project (binary unchanged)")
    else:
        # Clean stale artifacts before fresh import
        try:
            if parent_gpr.exists():
                parent_gpr.unlink()
            if parent_rep.exists():
                shutil.rmtree(parent_rep, ignore_errors=True)
            if sub_gpr.exists():
                sub_gpr.unlink()
            if sub_rep.exists():
                shutil.rmtree(sub_rep, ignore_errors=True)
        except Exception as cleanup_err:
            print(
                f"Warning: could not fully clean existing Ghidra project: {cleanup_err}"
            )

    try:
        pyhidra.start()
    except Exception as init_error:
        print(f"Pyhidra initialization error: {init_error}")
        sys.exit(1)

    # Expose Ghidra classes at module/global scope for helper functions
    global SymbolType, Address, Instruction, PointerDataType
    from ghidra.program.model.symbol import SymbolType
    from ghidra.program.model.address import Address
    from ghidra.program.model.listing import Instruction
    from ghidra.program.model.data import PointerDataType

    # ── Open (and optionally import + analyze) the binary ──────────────
    # pyhidra.open_program handles both import and analysis in a single
    # JVM invocation — no need for a separate analyzeHeadless subprocess.
    # When reusing an existing project, set analyze=False to skip the
    # expensive auto-analysis pass.
    try:
        analysis_start = time.time()
        with pyhidra.open_program(
            str(bin_path),
            project_location=str(bin_parent),
            project_name=project_name,
            analyze=not reuse_project,
        ) as flat_api:
            analysis_elapsed = time.time() - analysis_start
            print(f"Ghidra open/analysis took {analysis_elapsed:.1f}s")

            program = flat_api.getCurrentProgram()

            extract_start = time.time()
            jump_tables = extract_jump_tables(program)
            extract_elapsed = time.time() - extract_start
            print(f"Jump table extraction took {extract_elapsed:.1f}s")

            # Ensure results directory exists
            output_dir = "results"
            os.makedirs(output_dir, exist_ok=True)

            output_file = os.path.join(output_dir, "jump_tables.json")
            with open(output_file, "w") as f:
                json.dump(jump_tables, f, indent=4)

            total_elapsed = time.time() - total_start
            print(f"Jump tables saved to {output_file}")
            print(f"Total jump tables found: {len(jump_tables)}")
            print(f"Total time: {total_elapsed:.1f}s")

    except Exception:
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
