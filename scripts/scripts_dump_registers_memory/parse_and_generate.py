# parse_and_generate.py
def parse_memory_mappings(filename):
    commands = []
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
                        start_addr = parts[0]
                        end_addr = parts[1]
                        if 'warning' not in start_addr.lower() and 'warning' not in end_addr.lower():  # Additional check for the word 'warning'
                            filename = f"{start_addr}-{end_addr}.bin"
                            command = f"dump memory {filename} {start_addr} {end_addr}"
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

# Usage
input_filename = '../../results/initialization_data/memory_mapping.txt'
output_filename = '../../results/initialization_data/dump_commands.txt'
commands = parse_memory_mappings(input_filename)
write_commands_to_file(commands, output_filename)
if commands:
    print("Command file generated successfully with", len(commands), "commands.")
else:
    print("No commands generated. Check the format of the input file or script conditions.")