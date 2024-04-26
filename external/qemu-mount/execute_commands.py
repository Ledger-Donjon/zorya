# execute_commands.py
# usage: (gdb) exec_cmds /path/to/dump_commands.txt

import os
import gdb  # type: ignore

class ExecuteCommands(gdb.Command):
    "Executes commands from a specified file."

    def __init__(self):
        super(ExecuteCommands, self).__init__("exec_cmds", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        if not arg:
            gdb.write("Usage: exec_cmds <path to command file>\n")
            return
        
        # Ensure the dumps directory exists
        dumps_dir = 'dumps'
        if not os.path.exists(dumps_dir):
            os.makedirs(dumps_dir)

        try:
            with open(arg, 'r') as file:
                for line in file:
                    line = line.strip()
                    if line:  # Ensuring not to execute empty lines
                        try:
                            # Modify the command to point to the dumps directory
                            parts = line.split(' ')
                            if len(parts) > 3:
                                filename = os.path.join(dumps_dir, parts[2])  # Adjust path to include dumps directory
                                modified_command = f"{parts[0]} {parts[1]} {filename} {parts[3]} {parts[4]}"
                                gdb.write(f"Executing: {modified_command}\n")
                                gdb.execute(modified_command)
                            else:
                                gdb.write("Invalid command format: not enough parts to extract filename and addresses.\n")
                        except gdb.error as e:
                            gdb.write(f"Error executing '{line}': {str(e)}\n")
                            if "Cannot access memory" in str(e):
                                # Generate zero file if memory cannot be accessed
                                zero_file_path = filename.replace('.bin', '_zero.bin')
                                with open(zero_file_path, 'wb') as f:
                                    size = int(parts[4], 16) - int(parts[3], 16)  # Calculate size from addresses
                                    f.write(b'\x00' * size)
                                gdb.write(f"Created zero-filled file {zero_file_path} for inaccessible region from {parts[3]} to {parts[4]}.\n")
        except Exception as e:
            gdb.write(f"General error: {str(e)}\n")

ExecuteCommands()
