#!/bin/bash

# Get the absolute path of the Zorya project directory
ZORYA_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
QEMU_MOUNT_DIR="$ZORYA_DIR/external/qemu-mount"

BIN_PATH="$1"
START_POINT="${2:-main}"  # Default to 'main' if not provided

if [ -z "$BIN_PATH" ]; then
    echo "Usage: ./scripts/dump_memory.sh /path/to/bin [start_point]"
    exit 1
fi

# Ensure BIN_PATH is an absolute path
BIN_PATH="$(realpath "$BIN_PATH")"
BIN_NAME="$(basename "$BIN_PATH")"

# Prepare directories
echo "Setting up working directories..."
mkdir -p "$QEMU_MOUNT_DIR"
> "$QEMU_MOUNT_DIR/cpu_mapping.txt"
> "$QEMU_MOUNT_DIR/memory_mapping.txt"

echo "Copying binary to working directory..."
cp "$BIN_PATH" "$QEMU_MOUNT_DIR/$BIN_NAME"

# Locate helper scripts
PARSE_SCRIPT="$QEMU_MOUNT_DIR/parse_and_generate.py"
EXECUTE_SCRIPT="$QEMU_MOUNT_DIR/execute_commands.py"

# Check if helper scripts exist
if [ ! -f "$PARSE_SCRIPT" ] || [ ! -f "$EXECUTE_SCRIPT" ]; then
    echo "Error: Helper scripts not found in $QEMU_MOUNT_DIR"
    exit 1
fi

echo "Running GDB locally to generate CPU and memory mappings..."
cd "$QEMU_MOUNT_DIR"
gdb "$BIN_NAME" -batch \
    -ex "break *$START_POINT" \
    -ex "run < /dev/null" \
    -ex "set logging file cpu_mapping.txt" \
    -ex "set logging on" \
    -ex "info all-registers" \
    -ex "set logging off" \
    -ex "set logging file memory_mapping.txt" \
    -ex "set logging on" \
    -ex "info proc mappings" \
    -ex "set logging off" \
    -ex "quit"

if [ ! -s "cpu_mapping.txt" ] || [ ! -s "memory_mapping.txt" ]; then
    echo "Error: Failed to generate cpu_mapping.txt or memory_mapping.txt."
    exit 1
fi

echo "Generating dump_commands.txt using parse_and_generate.py..."
python3 parse_and_generate.py

echo "Executing dump commands locally in GDB..."
gdb "$BIN_NAME" -batch \
    -ex "break *$START_POINT" \
    -ex "run < /dev/null" \
    -ex "source execute_commands.py" \
    -ex "exec dump_commands.txt" \
    -ex "quit"

echo "Dump commands executed successfully in GDB."

echo "All tasks completed. Output available in $QEMU_MOUNT_DIR."

# SCRIPT IF YOU WANT TO USE QEMU AND ANOTHER 