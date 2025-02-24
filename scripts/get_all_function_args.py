#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Extracts function argument register mappings for all functions in the binary for runtime logging,
and outputs a JSON file.
"""

import os
import sys
import json
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

def main():
    # This version requires one argument: the ZORYA directory.
    script_args = getScriptArgs()
    if len(script_args) < 1:
        print("Usage: <script> <zorya_dir>")
        exit(1)

    zorya_dir = script_args[0]
    if not os.path.exists(zorya_dir):
        print("ERROR: Provided ZORYA_DIR does not exist: {}".format(zorya_dir))
        exit(1)

    results_dir = os.path.join(zorya_dir, "results")
    json_file = os.path.join(results_dir, "function_signature.json")

    # Ensure the results directory exists.
    if not os.path.exists(results_dir):
        os.makedirs(results_dir)
    # (Re)create the output file.
    open(json_file, "w").close()

    print("Function signature JSON will be saved at: {}".format(json_file))

    signatures = []

    if currentProgram is None:
        print("No program loaded!")
        exit(1)

    listing = currentProgram.getListing()
    fm = currentProgram.getFunctionManager()
    functions = fm.getFunctions(True)
    count = 0
    for func in functions:
        entry_point = func.getEntryPoint().toString()  # e.g., "00212710"
        function_name = func.getName()
        params = func.getParameters()
        arguments = []
        for param in params:
            name = param.getName()
            storage = param.getVariableStorage()
            if storage.isRegisterStorage():
                register_name = storage.getRegister().getName()
                arguments.append({"name": name, "register": register_name})
            elif storage.isStackStorage():
                varnode = storage.getFirstVarnode()
                if varnode:
                    offset = varnode.getAddress().getOffset()
                    arguments.append({"name": name, "register": "Stack_0x{:x}".format(offset)})
                else:
                    arguments.append({"name": name, "register": "Stack_Unknown"})
        if len(arguments) == 0:
            arguments.append({"name": "NoArgs", "register": "None"})
        signatures.append({
            "address": entry_point,
            "function_name": function_name,
            "arguments": arguments
        })
        count += 1

    with open(json_file, "w") as f:
        json.dump(signatures, f, indent=2)
    print("Wrote {} function signatures to {}".format(count, json_file))

main()

# #!/usr/bin/env python3
# """
# Usage:
#     python3 get_function_args.py /path/to/binary <function_name_or_address>

# Examples:
#     python3 get_function_args.py ./mybinary "simpleHTTPHead"
#     python3 get_function_args.py ./mybinary 0x595ac0
# """

# import os
# import sys
# import time
# import pyhidra

# def main():
#     if len(sys.argv) < 3:
#         print("Usage: python3 get_function_args.py /path/to/binary <function_name_or_address>")
#         sys.exit(1)

#     # Convert provided binary path to an absolute path.
#     binary_path = os.path.abspath(sys.argv[1])
#     function_id = sys.argv[2]

#     # Start Pyhidra.
#     pyhidra.start()

#     # Import decompiler classes and task monitor.
#     from ghidra.app.decompiler import DecompInterface
#     from ghidra.util.task import ConsoleTaskMonitor

#     # Try to import the auto-analysis command.
#     auto_available = False
#     try:
#         from ghidra.app.cmd.analyze import AutoAnalyzeCommand
#         auto_available = True
#     except ImportError as e:
#         print("AutoAnalyzeCommand not available; skipping additional auto-analysis.")

#     # Open the binary with analysis enabled.
#     with pyhidra.open_program(binary_path, analyze=True) as flat_api:
#         # Get the current program.
#         program = flat_api.getCurrentProgram()
#         monitor = ConsoleTaskMonitor()

#         # --- Optionally force additional auto-analysis if available ---
#         if auto_available:
#             print("Running additional auto-analysis...")
#             autoCmd = AutoAnalyzeCommand()
#             if not autoCmd.applyTo(program, monitor):
#                 print("Warning: Auto-analysis command did not complete as expected.")
#             else:
#                 print("Auto-analysis complete.")
#             # Optionally, sleep briefly to ensure analyzers have finished.
#             time.sleep(2)
#         else:
#             print("Continuing without additional auto-analysis...")

#         # Now look up the function.
#         listing = program.getListing()
#         fm = program.getFunctionManager()
#         function = None

#         if function_id.startswith("0x"):
#             try:
#                 addr_val = int(function_id, 16)
#             except ValueError:
#                 print("Invalid address format: %s" % function_id)
#                 sys.exit(1)
#             addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(addr_val)
#             function = fm.getFunctionContaining(addr)
#             if function is None:
#                 print("No function found at address %s" % function_id)
#                 sys.exit(1)
#         else:
#             # Try an exact lookup first.
#             functions_iter = listing.getGlobalFunctions(function_id)
#             functions = [f for f in functions_iter]
#             if not functions:
#                 # If that fails, do a substring search.
#                 functions = []
#                 func_iter = fm.getFunctions(True)
#                 while func_iter.hasNext():
#                     f = func_iter.next()
#                     if function_id in f.getName():
#                         functions.append(f)
#             if not functions:
#                 print("No function found with name (or containing): %s" % function_id)
#                 sys.exit(1)
#             function = functions[0]

#         # Print basic function info.
#         print("\nFunction: %s" % function.getName())
#         print("Entry point: %s" % function.getEntryPoint().toString())

#         # --- Use the decompiler to get the recovered signature ---
#         decomp = DecompInterface()
#         decomp.openProgram(program)
#         # (Optionally adjust decompiler options here if needed.)
#         result = decomp.decompileFunction(function, 60, monitor)
#         if result.decompileCompleted():
#             recoveredSignature = result.getDecompiledFunction().getSignature()
#             print("\nRecovered Signature from Decompiler:")
#             print("  " + str(recoveredSignature))
#         else:
#             print("\nDecompiler failed to decompile the function.")

#         # --- Also print the raw parameter list from the listing ---
#         print("\nRaw Parameter List (from listing):")
#         params = function.getParameters()
#         for index, param in enumerate(params):
#             name = param.getName()
#             dtype = param.getDataType()
#             storage = param.getVariableStorage()
#             print("Parameter %d: %s, Type: %s, Storage: %s" %
#                   (index, name, dtype, storage))
#             if storage.isStackStorage():
#                 varnode = storage.getFirstVarnode()
#                 if varnode:
#                     addr = varnode.getAddress()
#                     print("  -> Stack offset: 0x%x" % addr.getOffset())

# if __name__ == "__main__":
#     main()


# #!/usr/bin/env python3
# """
# Usage:
#     python3 get_function_args.py /path/to/binary <function_name_or_address>

# Examples:
#     python3 get_function_args.py ./mybinary "simpleHTTPHead"
#     python3 get_function_args.py ./mybinary 0x595ac0
# """

# import os
# import sys
# import pyhidra

# def main():
#     if len(sys.argv) < 3:
#         print("Usage: python3 get_function_args.py /path/to/binary <function_name_or_address>")
#         sys.exit(1)

#     # Convert provided binary path to an absolute path.
#     binary_path = os.path.abspath(sys.argv[1])
#     function_id = sys.argv[2]

#     # Start Pyhidra.
#     pyhidra.start()

#     # Import the decompiler and a task monitor.
#     from ghidra.app.decompiler import DecompInterface
#     from ghidra.util.task import ConsoleTaskMonitor

#     # Open the binary (with analysis enabled) using a context manager.
#     with pyhidra.open_program(binary_path, analyze=True) as flat_api:
#         # Get the current Program.
#         program = flat_api.getCurrentProgram()
#         listing = program.getListing()
#         fm = program.getFunctionManager()

#         # Locate the function by address or name.
#         function = None
#         if function_id.startswith("0x"):
#             try:
#                 addr_val = int(function_id, 16)
#             except ValueError:
#                 print("Invalid address format: %s" % function_id)
#                 sys.exit(1)
#             addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(addr_val)
#             function = fm.getFunctionContaining(addr)
#             if function is None:
#                 print("No function found at address %s" % function_id)
#                 sys.exit(1)
#         else:
#             # Try an exact lookup first.
#             functions_iter = listing.getGlobalFunctions(function_id)
#             functions = [f for f in functions_iter]
#             if not functions:
#                 # If that fails, do a substring search.
#                 functions = []
#                 func_iter = fm.getFunctions(True)
#                 while func_iter.hasNext():
#                     f = func_iter.next()
#                     if function_id in f.getName():
#                         functions.append(f)
#             if not functions:
#                 print("No function found with name (or containing): %s" % function_id)
#                 sys.exit(1)
#             function = functions[0]

#         # Print basic function info.
#         print("Function: %s" % function.getName())
#         print("Entry point: %s" % function.getEntryPoint().toString())

#         # --- Use the decompiler to get the recovered signature ---
#         decomp = DecompInterface()
#         decomp.openProgram(program)
#         monitor = ConsoleTaskMonitor()
#         result = decomp.decompileFunction(function, 60, monitor)
#         if result.decompileCompleted():
#             # Get the decompiler's recovered signature (this returns a string).
#             recoveredSignature = result.getDecompiledFunction().getSignature()
#             print("\nRecovered Signature from Decompiler:")
#             print("  " + str(recoveredSignature))
#             # If you wanted to extract arguments from the signature string, you
#             # would need to parse the string manually.
#         else:
#             print("\nDecompiler failed to decompile the function.")

#         # --- Also print the raw parameter list from the listing ---
#         print("\nRaw Parameter List (from listing):")
#         params = function.getParameters()
#         for index, param in enumerate(params):
#             name = param.getName()
#             dtype = param.getDataType()
#             storage = param.getVariableStorage()
#             print("Parameter %d: %s, Type: %s, Storage: %s" %
#                   (index, name, dtype, storage))
#             # If stored on the stack, print its offset.
#             if storage.isStackStorage():
#                 varnode = storage.getFirstVarnode()
#                 if varnode:
#                     addr = varnode.getAddress()
#                     print("  -> Stack offset: 0x%x" % addr.getOffset())

# if __name__ == "__main__":
#     main()
