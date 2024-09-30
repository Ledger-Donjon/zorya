# parse_and_generate.py
def parse_memory_mappings(filename):
    commands = []
    max_dump_size = 1 * 1024 * 1024  # 1 MB in bytes
    start_parsing = False  # We haven't reached the memory mappings section yet.

    try:
        with open(filename, 'r') as file:
            for line in file:
                # Look for the column header line to start parsing immediately after:
                if 'Start Addr' in line and 'End Addr' in line:
                    start_parsing = True
                    continue  # Skip the header line itself

                if start_parsing:
                    if line.strip() == '':
                        break  # Stop parsing if we reach an empty line.

                    parts = line.split()
                    if len(parts) >= 2 and parts[0].startswith('0x'):
                        start_addr = int(parts[0], 16)
                        end_addr = int(parts[1], 16)

                        # Calculate dump size
                        dump_size = end_addr - start_addr

                        # If the dump size is larger than 1MB, split it into sub-dumps
                        if dump_size > max_dump_size:
                            current_addr = start_addr
                            while current_addr < end_addr:
                                next_addr = min(current_addr + max_dump_size, end_addr)
                                sub_filename = f"0x{current_addr:x}-0x{next_addr:x}.bin"
                                command = f"dump memory {sub_filename} 0x{current_addr:x} 0x{next_addr:x}"
                                commands.append(command)
                                current_addr = next_addr
                        else:
                            filename = f"0x{start_addr:x}-0x{end_addr:x}.bin"
                            command = f"dump memory {filename} 0x{start_addr:x} 0x{end_addr:x}"
                            commands.append(command)
    except Exception as e:
        print(f"Error: {str(e)}")

    return commands

def write_commands_to_file(commands, output_file):
    try:
        with open(output_file, 'w') as file:
            for command in commands:
                file.write(command + '\n')
    except Exception as e:
        print(f"Error writing to file: {str(e)}")

# Usage example
input_filename = 'memory_mapping.txt'
output_filename = 'dump_commands.txt'
commands = parse_memory_mappings(input_filename)
write_commands_to_file(commands, output_filename)
if commands:
    print("Command file generated successfully with", len(commands), "commands.")
else:
    print("No commands generated. Check the format of the input file or script conditions.")
