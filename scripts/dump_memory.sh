#!/bin/bash

# SPDX-FileCopyrightText: 2025 Ledger https://www.ledger.com - INSTITUT MINES TELECOM
#
# SPDX-License-Identifier: Apache-2.0

# Get the absolute path of the Zorya project directory
ZORYA_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPTS_DUMP="$ZORYA_DIR/scripts/scripts_dump_registers_memory"
RESULTS_DIR="$ZORYA_DIR/results"
DUMPS_DIR="$RESULTS_DIR/initialization_data/dumps"
MEMORY_MAP_PATH="$RESULTS_DIR/initialization_data/memory_mapping.txt"
CPU_MAP_PATH="$RESULTS_DIR/initialization_data/cpu_mapping.txt"
DUMP_COMMANDS_PATH="$RESULTS_DIR/initialization_data/dump_commands.txt"

# Ensure the files exist and are empty
mkdir -p "$(dirname "$CPU_MAP_PATH")"
mkdir -p "$(dirname "$MEMORY_MAP_PATH")"
: > "$CPU_MAP_PATH"
: > "$MEMORY_MAP_PATH"

BIN_PATH="$1"
START_POINT="$2" 
ENTRY_POINT="$3"
ARGS=$(printf "%s " "${@:4}" | tr -d '\n')

if [ -z "$BIN_PATH" ] || [ -z "$START_POINT" ]; then
    echo "Usage: ./scripts/dump_memory.sh /path/to/bin <start_point> <arguments>"
    exit 1
fi

# Ensure BIN_PATH is an absolute path
BIN_PATH="$(realpath "$BIN_PATH")"
BIN_NAME="$(basename "$BIN_PATH")"

# Clean up and prepare the dumps directory
if [ -d "$DUMPS_DIR" ]; then
    echo "Cleaning up existing contents in the dumps directory..."
    rm -rf "$DUMPS_DIR"/*
else
    echo "Creating the dumps directory..."
    mkdir -p "$DUMPS_DIR"
fi

# Clean up and prepare the threads directory
THREADS_DIR="$RESULTS_DIR/initialization_data/threads"
if [ -d "$THREADS_DIR" ]; then
    echo "Cleaning up existing thread dumps from previous runs..."
    rm -rf "$THREADS_DIR"/*
else
    echo "Creating the threads directory..."
    mkdir -p "$THREADS_DIR"
fi

# Locate helper scripts
PARSE_SCRIPT="$SCRIPTS_DUMP/parse_and_generate.py"
EXECUTE_SCRIPT="$SCRIPTS_DUMP/execute_commands.py"

# Check if helper scripts exist
if [ ! -f "$PARSE_SCRIPT" ] || [ ! -f "$EXECUTE_SCRIPT" ]; then
    echo "Error: Helper scripts not found in $SCRIPTS_DUMP"
    exit 1
fi

echo "Running GDB locally to generate CPU and memory mappings..."
cd "$SCRIPTS_DUMP"

# Redirect GDB output to log files
GDB_LOG="$RESULTS_DIR/initialization_data/gdb_log.txt"

##############################################################################
# Helper: run_gdb – wraps GDB in a PTY via `script` when FORCE_PTY is set.
# This makes the child process believe stdout/stdin are a real terminal, which
# is required when the target binary (e.g. kubectl) checks isatty().
#
# Usage: run_gdb <redirect_mode> <gdb_args...>
#   redirect_mode: "overwrite" (&>)  or "append" (&>>)
##############################################################################
run_gdb() {
    local redirect_mode="$1"; shift

    if [[ "${FORCE_PTY:-false}" == "true" ]]; then
        # Build the full GDB command as a single string so `script -c` can run it
        local gdb_cmd="gdb"
        for arg in "$@"; do
            gdb_cmd+=" $(printf '%q' "$arg")"
        done

        if [[ "$redirect_mode" == "overwrite" ]]; then
            script -qefc "$gdb_cmd" /dev/null &> "$GDB_LOG"
        else
            script -qefc "$gdb_cmd" /dev/null &>> "$GDB_LOG"
        fi
    else
        if [[ "$redirect_mode" == "overwrite" ]]; then
            gdb "$@" &> "$GDB_LOG"
        else
            gdb "$@" &>> "$GDB_LOG"
        fi
    fi
}

# Single unified GDB session: mapping + registers + memory dumps + thread states.
# All data comes from the SAME process so that dynamically-allocated Go runtime
# regions (goroutine stacks, heap arenas) are captured correctly.
echo "Executing mapping, registers, memory dumps, and thread state capture in a single GDB session..."
run_gdb overwrite -batch \
    -ex "set auto-load safe-path /" \
    -ex "set pagination off" \
    -ex "set style enabled off" \
    -ex "set confirm off" \
    -ex "file $BIN_PATH" \
    -ex "set args ${ARGS}" \
    -ex "show args" \
    -ex "break *$START_POINT" \
    -ex "run" \
    -ex "set logging file $MEMORY_MAP_PATH" \
    -ex "set logging enabled on" \
    -ex "info proc mappings" \
    -ex "set logging enabled off" \
    -ex "shell python3 $PARSE_SCRIPT" \
    -ex "set logging file $CPU_MAP_PATH" \
    -ex "set logging enabled on" \
    -ex "info all-registers" \
    -ex "set logging enabled off" \
    -ex "source execute_commands.py" \
    -ex "exec $DUMP_COMMANDS_PATH" \
    -ex "source $SCRIPTS_DUMP/dump_threads.py" \
    -ex "dump-threads" \
    -ex "quit"

GDB_EXIT=$?

if [ $GDB_EXIT -ne 0 ]; then
    echo ""
    echo "ERROR: GDB exited with code $GDB_EXIT. Check $GDB_LOG for details."
    exit 1
fi

# Detect if the program exited without hitting the breakpoint
if grep -q "exited normally\|exited with code\|No current process" "$GDB_LOG" 2>/dev/null; then
    if ! grep -q "hit Breakpoint\|Breakpoint [0-9].*main\." "$GDB_LOG" 2>/dev/null; then
        echo ""
        echo "==============================================================================="
        echo "ERROR: The program exited BEFORE reaching the breakpoint at $START_POINT."
        echo "==============================================================================="
        echo ""
        echo "  The binary ran to completion without stopping at your target address."
        echo "  This typically happens when:"
        echo ""
        echo "  1. The address is NOT on the execution path for the given arguments."
        echo "     The program may take a different branch (e.g., argument validation"
        echo "     fails and the program exits with a usage message before reaching"
        echo "     your target address)."
        echo ""
        echo "  2. The address falls in the MIDDLE of a multi-byte instruction."
        echo "     GDB's breakpoint corrupts the instruction, causing the program to"
        echo "     behave incorrectly. Verify your address with:"
        echo "       objdump -d --start-address=$START_POINT <binary> | head -5"
        echo ""
        echo "  3. The program crashes or calls os.Exit() before reaching the address."
        echo ""
        # Show what the program printed (if anything) to help diagnose
        PROG_OUTPUT=$(grep -v "^warning:\|^Breakpoint\|^$\|^\[New\|^\[LWP\|^This GDB\|^Enable debug\|^Debuginfod\|^To make\|^Loaded\|^Cleaned\|^Error:\|^The program\|^No current\|^Argument list\|^Use \`info\|set auto-load\|set pagination\|set style\|set confirm\|^$" "$GDB_LOG" 2>/dev/null | head -5)
        if [[ -n "$PROG_OUTPUT" ]]; then
            echo "  The program printed the following before exiting:"
            echo "$PROG_OUTPUT" | while IFS= read -r line; do echo "    > $line"; done
            echo ""
        fi
        echo "  Full GDB log: $GDB_LOG"
        echo ""
        exit 1
    fi
fi

if [ ! -s "$MEMORY_MAP_PATH" ]; then
    echo ""
    echo "ERROR: Failed to generate memory_mapping.txt."
    echo "  The memory mapping dump is empty. Check $GDB_LOG for details."
    exit 1
fi

if [ ! -s "$CPU_MAP_PATH" ]; then
    echo ""
    echo "ERROR: Failed to generate cpu_mapping.txt."
    echo "  The CPU register dump is empty — GDB likely did not stop at the breakpoint."
    echo "  Check $GDB_LOG for details."
    exit 1
fi

if [ ! -s "$DUMP_COMMANDS_PATH" ]; then
    echo ""
    echo "ERROR: Failed to generate dump_commands.txt."
    echo "  The memory dump command file is empty. Check $GDB_LOG for details."
    exit 1
fi

echo "Generating dump_commands.txt using parse_and_generate.py..."
DUMP_CMD_COUNT=$(wc -l < "$DUMP_COMMANDS_PATH")
echo "Command file generated successfully with $DUMP_CMD_COUNT commands."
echo "Dump commands executed successfully in GDB."
echo "Dumping thread states (registers + TLS bases)..."

# Check if thread dumps were created
if [ -d "$THREADS_DIR" ] && [ "$(ls -A $THREADS_DIR 2>/dev/null)" ]; then
    THREAD_COUNT=$(find "$THREADS_DIR" -name "thread_*.json" | wc -l)
    echo "Successfully dumped $THREAD_COUNT thread(s) to $THREADS_DIR"
else
    echo "Warning: No thread dumps found. Single-threaded execution will be assumed."
fi

echo "All dumps completed. Logs available in $GDB_LOG."
echo "Outputs available in $RESULTS_DIR/initialization_data."


# SCRIPT IF YOU WANT TO USE QEMU WITGH ANOTHER CPU MODEL 

#!/bin/bash

# BIN_PATH="$1"
# START_POINT="${2:-main}"  # Default to 'main' if not provided

# if [ -z "$BIN_PATH" ]; then
#     echo "Usage: ./scripts/dump_memory.sh /path/to/bin [start_point]"
#     exit 1
# fi

# # Ensure BIN_PATH is an absolute path
# BIN_PATH="$(realpath "$BIN_PATH")"
# BIN_NAME="$(basename "$BIN_PATH")"

# # Get the absolute paths
# ZORYA_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# SCRIPTS_DIR="$ZORYA_DIR/scripts"
# QEMU_CLOUDIMG_DIR="$ZORYA_DIR/external/qemu-cloudimg"
# QEMU_MOUNT_DIR="$ZORYA_DIR/external/qemu-mount"

# # Reset cpu_mapping.txt and memory_mapping.txt if they already exist
# echo "Resetting cpu_mapping.txt and memory_mapping.txt if they exist..."
# > "$QEMU_MOUNT_DIR/cpu_mapping.txt" 2>/dev/null || true
# > "$QEMU_MOUNT_DIR/memory_mapping.txt" 2>/dev/null || true

# # Check and clear /dumps directory if it exists
# DUMPS_DIR="$QEMU_MOUNT_DIR/dumps"
# if [ -d "$DUMPS_DIR" ]; then
#     echo -e "\rClearing existing contents of /dumps directory..."
#     rm -rf "$DUMPS_DIR"/* > /dev/null 2>&1
# else
#     echo -e "\rCreating /dumps directory..."
#     mkdir "$DUMPS_DIR"
# fi

# # Function to clean up QEMU process
# cleanup() {
#     echo -e "\rShutting down the virtual machine...\r"
#     if ps -p "$QEMU_PID" > /dev/null; then
#         sudo kill "$QEMU_PID" > /dev/null 2>&1
#     fi
# }
# trap cleanup EXIT

# echo "Terminating any existing QEMU instances..."
# sudo killall qemu-system-x86_64 > /dev/null 2>&1 || true

# echo -e "\rPreparing QEMU environment..."
# mkdir -p "$QEMU_CLOUDIMG_DIR" "$QEMU_MOUNT_DIR"

# # Download cloud image if not already downloaded
# if [ ! -f "$QEMU_CLOUDIMG_DIR/jammy-server-cloudimg-amd64.img" ]; then
#     echo -e "\rDownloading Ubuntu cloud image..."
#     cd "$QEMU_CLOUDIMG_DIR"
#     wget -q https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img
#     qemu-img resize jammy-server-cloudimg-amd64.img +10G > /dev/null
# fi

# echo -e "\rCopying binary and helper scripts to shared folder..."
# BIN_DEST="$QEMU_MOUNT_DIR/$BIN_NAME"
# if [ "$(realpath "$BIN_PATH")" != "$(realpath "$BIN_DEST")" ]; then
#     cp -u "$BIN_PATH" "$BIN_DEST" > /dev/null 2>&1
# fi

# for file in "execute_commands.py" "parse_and_generate.py"; do
#     SRC_FILE="$ZORYA_DIR/external/qemu-mount/$file"
#     DEST_FILE="$QEMU_MOUNT_DIR/$file"
#     if [ "$(realpath "$SRC_FILE")" != "$(realpath "$DEST_FILE")" ]; then
#         cp -u "$SRC_FILE" "$DEST_FILE" > /dev/null 2>&1
#     fi
# done

# echo "Starting QEMU virtual machine..."
# sudo qemu-system-x86_64 \
#     -cpu Opteron_G1 \
#     -m 2048 \
#     -drive file="$QEMU_CLOUDIMG_DIR/jammy-server-cloudimg-amd64.img",format=qcow2 \
#     -seed 12345 \
#     -net nic \
#     -net user,hostfwd=tcp::2222-:22 \
#     -fsdev local,id=fsdev0,path="$QEMU_MOUNT_DIR",security_model=mapped \
#     -device virtio-9p-pci,fsdev=fsdev0,mount_tag=hostshare \
#     -virtfs local,path="$QEMU_MOUNT_DIR",security_model=mapped,mount_tag=hostshare \
#     -nographic \
#     > "$ZORYA_DIR/qemu_log.txt" 2>&1 &

# QEMU_PID=$!

# # Function to display an adaptive progress bar
# progress_bar() {
#     local duration=$1
#     local elapsed=0
#     local cols=$(tput cols)
#     local max_bar_width=$((cols - 30))
#     local bar_width=50

#     if [ "$max_bar_width" -lt 20 ]; then
#         bar_width=10
#     elif [ "$max_bar_width" -lt "$bar_width" ]; then
#         bar_width=$max_bar_width
#     fi

#     while [ $elapsed -le $duration ]; do
#         local percent=$(( 100 * elapsed / duration ))
#         local filled=$(( bar_width * elapsed / duration ))
#         local bar=$(printf "%-${bar_width}s" "$(printf "#%.0s" $(seq 1 $filled))")
#         printf "\rStabilizing SSH connection: [%s] %3d%%" "$bar" "$percent"
#         sleep 1
#         elapsed=$((elapsed + 1))
#     done
# }

# echo -e "\rWaiting for SSH to become available..."
# timeout=500
# elapsed=0
# while ! nc -z localhost 2222; do
#     sleep 5
#     elapsed=$((elapsed + 5))
#     if [ "$elapsed" -ge "$timeout" ]; then
#         echo -e "\rTimed out waiting for SSH to become available."
#         exit 1
#     fi
# done
# echo -e "\rSSH is now available."

# progress_bar 70

# echo
# echo -e "\rPreparing to run GDB commands inside the VM..."

# if ! command -v sshpass > /dev/null; then
#     echo "sshpass could not be found. Please install it (e.g., sudo apt install sshpass)."
#     exit 1
# fi

# SSH_PASSWORD="ubuntu"
# SSH_COMMAND="sshpass -p $SSH_PASSWORD ssh -t -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null ubuntu@localhost -p 2222"

# echo -e "\rMounting shared folder inside the VM..."
# $SSH_COMMAND << EOF > /dev/null 2>>"$ZORYA_DIR/qemu_log.txt"
# sudo mkdir -p /mnt/host
# sudo mount -t 9p -o trans=virtio hostshare /mnt/host
# EOF

# echo -e "\rRunning GDB to generate cpu_mapping.txt and memory_mapping.txt..."
# $SSH_COMMAND << EOF > /dev/null 2>>"$ZORYA_DIR/qemu_log.txt"
# cd /mnt/host
# sudo gdb ./$BIN_NAME -batch \
#     -ex "break *$START_POINT" \
#     -ex "run < /dev/null" \
#     -ex "set logging file /mnt/host/cpu_mapping.txt" \
#     -ex "set logging on" \
#     -ex "info all-registers" \
#     -ex "set logging off" \
#     -ex "set logging file /mnt/host/memory_mapping.txt" \
#     -ex "set logging on" \
#     -ex "info proc mappings" \
#     -ex "set logging off" \
#     -ex "quit"
# EOF

# if [ ! -s "$QEMU_MOUNT_DIR/cpu_mapping.txt" ] || [ ! -s "$QEMU_MOUNT_DIR/memory_mapping.txt" ]; then
#     echo "Error: Failed to generate cpu_mapping.txt or memory_mapping.txt."
#     exit 1
# fi
# echo -e "\rMemory and CPU register dumps generated successfully."

# echo -e "\rGenerating dump_commands.txt using parse_and_generate.py..."
# cd "$QEMU_MOUNT_DIR"
# python3 parse_and_generate.py > /dev/null 2>&1
# echo -e "\rdump_commands.txt generated successfully."

# echo -e "\rExecuting dump commands in GDB inside the VM..."
# $SSH_COMMAND << EOF > /dev/null 2>>"$ZORYA_DIR/qemu_log.txt"
# cd /mnt/host
# sudo gdb ./$BIN_NAME -batch \
#     -ex "source execute_commands.py" \
#     -ex "exec dump_commands.txt" \
#     -ex "quit"
# EOF

# echo -e "\rDump commands executed successfully in GDB."