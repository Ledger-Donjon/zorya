# SPDX-FileCopyrightText: 2025 Ledger https://www.ledger.com - INSTITUT MINES TELECOM
#
# SPDX-License-Identifier: Apache-2.0

# find_panic_xrefs.py
# Used in main.rs by the get_cross_references function to find cross-references to panic functions.
import glob
import os
import shutil
import subprocess
import sys

import pyhidra


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 find_panic_xrefs.py /path/to/binary")
        sys.exit(1)

    binary_path = sys.argv[1]
    # Resolve project location: <binary_dir>/<binary_name>_ghidra/<binary_name>_ghidra.gpr
    bin_path = os.path.abspath(binary_path)
    parent = os.path.dirname(bin_path)
    base = os.path.basename(bin_path)
    project_name = f"{base}_ghidra"
    project_dir = os.path.join(parent, project_name)
    gpr_path = os.path.join(project_dir, f"{project_name}.gpr")

    # Locate analyzeHeadless early (needed for both initial creation and retries)
    ghidra_home = os.environ.get("GHIDRA_INSTALL_DIR")
    headless = None
    if ghidra_home:
        candidate = os.path.join(ghidra_home, "support", "analyzeHeadless")
        if os.path.exists(candidate):
            headless = candidate
    if headless is None:
        headless = shutil.which("analyzeHeadless")
    if headless is None:
        raise RuntimeError(
            "Could not find analyzeHeadless. Set GHIDRA_INSTALL_DIR or ensure analyzeHeadless is in PATH."
        )

    # Ensure project directory exists and contains a .gpr; create via headless if missing
    need_create = (not os.path.isdir(project_dir)) or (not os.path.isfile(gpr_path))

    # If directory exists but .gpr is missing, the project is corrupted - remove it entirely
    if os.path.isdir(project_dir) and not os.path.isfile(gpr_path):
        print(
            f"[WARN] Corrupted Ghidra project detected (missing .gpr), removing: {project_dir}"
        )
        try:
            shutil.rmtree(project_dir)
            need_create = True
        except Exception as e:
            print(f"[ERROR] Failed to remove corrupted project: {e}")
            raise

    if need_create:
        os.makedirs(project_dir, exist_ok=True)
        # Clean any stale lock files
        for pattern in ("*.lock", "~*.lock"):
            for lock in glob.glob(os.path.join(project_dir, pattern)):
                try:
                    os.remove(lock)
                    print(f"[INFO] Removed stale lock file: {lock}")
                except Exception as e:
                    print(f"[WARN] Failed to remove lock file {lock}: {e}")

        print(f"[INFO] Creating Ghidra project via headless at {project_dir}")
        try:
            subprocess.run(
                [
                    headless,
                    str(project_dir),  # project_location (actual project directory)
                    project_name,  # project_name
                    "-import",
                    str(bin_path),
                    "-overwrite",
                    "-noanalysis",
                ],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
        except subprocess.CalledProcessError as e:
            print(
                "[ERROR] analyzeHeadless failed:\n" + e.stdout.decode(errors="ignore")
            )
            raise

    print(f"[INFO] Starting Pyhidra for {binary_path}")

    # Start Pyhidra
    pyhidra.start()

    from ghidra.program.model.block import BasicBlockModel
    from ghidra.util.task import ConsoleTaskMonitor

    # Try to open the binary, handle lock errors by recreating the project
    max_retries = 3
    import time

    for attempt in range(max_retries):
        try:
            # Open the binary with Pyhidra using the persistent project we ensured exists
            with pyhidra.open_program(
                binary_path,
                project_location=parent,
                project_name=project_name,
                analyze=True,
            ) as flat_api:
                # Get the Program object
                program = flat_api.getCurrentProgram()

                # Get the FunctionManager
                function_manager = program.getFunctionManager()

                # Addresses (as strings) to seed reverse search: include call sites and containing block starts
                xref_addresses = set()

                # Prepare basic block model to resolve containing block starts
                model = BasicBlockModel(program)
                monitor = ConsoleTaskMonitor()

                # Patterns for panic-like functions (case-insensitive)
                panic_substrings = [
                    "panic",
                    "nilpanic",
                    "panicindex",
                    "panicbounds",
                    "panicmem",
                    "panicdivide",
                    "panicslice",
                    "throw",
                    "fatal",
                    "abort",
                    "trap",
                    "tinygo_longjmp",
                    "lookuppanic",
                    "Panic",
                ]

                # Iterate over all functions in the program
                function_iterator = function_manager.getFunctions(True)
                while function_iterator.hasNext():
                    function = function_iterator.next()
                    function_name = function.getName()

                    # Convert function name to lowercase for case-insensitive comparison
                    function_name_lower = function_name.lower()

                    # Match if any panic-like substring appears in the symbol name
                    if any(pat in function_name_lower for pat in panic_substrings):
                        # Always include the function entry point as a seed (even if no xrefs)
                        entry = function.getEntryPoint()
                        if entry is not None:
                            xref_addresses.add(f"0x{entry.toString()}")

                        # Get references to this function
                        references = program.getReferenceManager().getReferencesTo(
                            function.getEntryPoint()
                        )

                        for ref in references:
                            # We are interested in code references that are calls
                            if ref.getReferenceType().isCall():
                                from_address = ref.getFromAddress()
                                # Add the raw call site
                                xref_addresses.add(f"0x{from_address.toString()}")
                                # Also add the start of the containing basic block
                                blk = model.getCodeBlockAt(from_address, monitor)
                                if blk is None:
                                    # Fallback: blocks containing the address
                                    blocks = model.getCodeBlocksContaining(
                                        from_address, monitor
                                    )
                                    for b in blocks:
                                        if b is not None:
                                            xref_addresses.add(
                                                f"0x{b.getFirstStartAddress().toString()}"
                                            )
                                else:
                                    xref_addresses.add(
                                        f"0x{blk.getFirstStartAddress().toString()}"
                                    )

                # Ensure results directory exists
                results_dir = "results"
                os.makedirs(results_dir, exist_ok=True)

                # Write the addresses to a file in the results directory
                output_file = os.path.join(results_dir, "xref_addresses.txt")
                with open(output_file, "w") as file:
                    file.writelines(f"{addr}\n" for addr in sorted(xref_addresses))

                print(f"[INFO] Xref analysis completed. Results saved to {output_file}")

            # If we get here, success! Break out of retry loop
            break

        except Exception as e:
            error_msg = str(e)
            error_type = type(e).__name__
            error_repr = repr(e)
            # Check if it's a lock error or project not found error
            # Check both the error message and the exception type/repr
            if (
                "LockException" in error_msg
                or "Unable to lock project" in error_msg
                or "NotFoundException" in error_msg
                or "Project marker file not found" in error_msg
                or "LockException" in error_type
                or "NotFoundException" in error_type
                or "LockException" in error_repr
                or "NotFoundException" in error_repr
            ):
                print(
                    f"[WARN] Project issue detected: {error_type} (attempt {attempt + 1}/{max_retries})"
                )
                print(f"[DEBUG] Error details: {error_msg}")
                if attempt < max_retries - 1:
                    print(f"[INFO] Removing project directory: {project_dir}")
                    try:
                        # Force remove the project directory
                        shutil.rmtree(project_dir, ignore_errors=True)
                        # Give filesystem time to release locks
                        time.sleep(2)
                        print("[INFO] Recreating Ghidra project from scratch...")
                        # Recreate the project directory
                        os.makedirs(project_dir, exist_ok=True)
                        # Create project via analyzeHeadless
                        _result = subprocess.run(
                            [
                                headless,
                                str(project_dir),
                                project_name,
                                "-import",
                                str(bin_path),
                                "-overwrite",
                                "-noanalysis",
                            ],
                            check=True,
                            capture_output=True,
                            text=True,
                        )
                        print("[INFO] Project recreated successfully, retrying...")
                        # Small delay before retry
                        time.sleep(1)
                    except subprocess.CalledProcessError as proc_error:
                        print("[ERROR] Failed to recreate project via headless:")
                        print(proc_error.stdout)
                        print(proc_error.stderr)
                        if attempt == max_retries - 1:
                            raise
                    except Exception as cleanup_error:
                        print(f"[ERROR] Failed to recreate project: {cleanup_error}")
                        if attempt == max_retries - 1:
                            raise
                else:
                    print("[ERROR] Failed to open project after all retries")
                    raise
            else:
                # Not a project-related error, re-raise immediately
                raise


if __name__ == "__main__":
    main()
