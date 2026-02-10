#!/bin/bash

# SPDX-FileCopyrightText: 2025 Ledger https://www.ledger.com - INSTITUT MINES TELECOM
#
# SPDX-License-Identifier: Apache-2.0

##############################################################################
# extract_vdso.sh - Extract VDSO from a running process and save as .so
#
# Usage: ./extract_vdso.sh <binary_path> <start_point> [args...]
#
# This script:
# 1. Runs the binary with GDB
# 2. Extracts the VDSO region from memory
# 3. Saves it as a .so file for later analysis
##############################################################################

set -e

ZORYA_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RESULTS_DIR="$ZORYA_DIR/results"
INIT_DATA_DIR="$RESULTS_DIR/initialization_data"
VDSO_DIR="$INIT_DATA_DIR/vdso"

BIN_PATH="$1"
START_POINT="$2"
shift 2
ARGS="$@"

if [ -z "$BIN_PATH" ] || [ -z "$START_POINT" ]; then
    echo "Usage: $0 <binary_path> <start_point> [args...]"
    exit 1
fi

# Ensure BIN_PATH is absolute
BIN_PATH="$(realpath "$BIN_PATH")"

# Create VDSO directory
mkdir -p "$VDSO_DIR"

echo "Extracting VDSO from $BIN_PATH..."

# Create a temporary GDB script
TEMP_GDB_SCRIPT=$(mktemp)
trap "rm -f $TEMP_GDB_SCRIPT" EXIT

cat > "$TEMP_GDB_SCRIPT" << 'EOF'
python
import gdb
import re

class ExtractVDSO(gdb.Command):
    def __init__(self):
        super(ExtractVDSO, self).__init__("extract_vdso", gdb.COMMAND_USER)
    
    def invoke(self, arg, from_tty):
        # Get memory mappings
        mappings = gdb.execute("info proc mappings", to_string=True)
        
        # Find VDSO region
        vdso_match = None
        for line in mappings.split('\n'):
            if '[vdso]' in line:
                parts = line.split()
                if len(parts) >= 2:
                    start_addr = parts[0]
                    end_addr = parts[1]
                    vdso_match = (start_addr, end_addr)
                    break
        
        if not vdso_match:
            print("ERROR: Could not find VDSO mapping")
            return
        
        start_addr, end_addr = vdso_match
        output_file = arg.strip()
        
        print(f"Found VDSO: {start_addr} - {end_addr}")
        print(f"Dumping to: {output_file}")
        
        try:
            gdb.execute(f"dump memory {output_file} {start_addr} {end_addr}")
            print(f"VDSO extracted successfully to {output_file}")
        except Exception as e:
            print(f"ERROR: Failed to dump VDSO: {e}")

ExtractVDSO()
end
EOF

# Run GDB to extract VDSO
VDSO_OUTPUT="$VDSO_DIR/vdso.so"
GDB_LOG="$INIT_DATA_DIR/vdso_extraction.log"

##############################################################################
# If FORCE_PTY is set, wrap GDB in a PTY via `script` so the child process
# sees a real terminal (needed when the binary checks isatty()).
##############################################################################
if [[ "${FORCE_PTY:-false}" == "true" ]]; then
    GDB_CMD="gdb -batch"
    GDB_CMD+=" -ex 'set auto-load safe-path /'"
    GDB_CMD+=" -ex 'set pagination off'"
    GDB_CMD+=" -ex 'set style enabled off'"
    GDB_CMD+=" -ex 'set confirm off'"
    GDB_CMD+=" -ex 'file $BIN_PATH'"
    GDB_CMD+=" -ex 'set args $ARGS'"
    GDB_CMD+=" -ex 'break *$START_POINT'"
    GDB_CMD+=" -ex 'run'"
    GDB_CMD+=" -ex 'source $TEMP_GDB_SCRIPT'"
    GDB_CMD+=" -ex 'extract_vdso $VDSO_OUTPUT'"
    GDB_CMD+=" -ex 'quit'"

    script -qefc "$GDB_CMD" /dev/null &> "$GDB_LOG"
else
    gdb -batch \
        -ex "set auto-load safe-path /" \
        -ex "set pagination off" \
        -ex "set style enabled off" \
        -ex "set confirm off" \
        -ex "file $BIN_PATH" \
        -ex "set args $ARGS" \
        -ex "break *$START_POINT" \
        -ex "run" \
        -ex "source $TEMP_GDB_SCRIPT" \
        -ex "extract_vdso $VDSO_OUTPUT" \
        -ex "quit" &> "$GDB_LOG"
fi

# Check if extraction was successful
if [ -f "$VDSO_OUTPUT" ] && [ -s "$VDSO_OUTPUT" ]; then
    echo "VDSO extracted successfully: $VDSO_OUTPUT"
    
    # Get VDSO base address for later use
    VDSO_BASE=$(grep "Found VDSO:" "$GDB_LOG" | awk '{print $3}')
    echo "$VDSO_BASE" > "$VDSO_DIR/vdso_base_addr.txt"
    echo "VDSO base address: $VDSO_BASE"
else
    echo "[ERROR] Failed to extract VDSO. Check $GDB_LOG for details."
    exit 1
fi

echo "VDSO extraction completed!"

