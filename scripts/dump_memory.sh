#!/bin/bash

BIN_PATH="$1"
START_POINT="${2:-main}"  # Default to 'main' if not provided

if [ -z "$BIN_PATH" ]; then
    echo "Usage: ./scripts/dump_memory.sh /path/to/bin [start_point]"
    exit 1
fi

# Ensure BIN_PATH is an absolute path
BIN_PATH="$(realpath "$BIN_PATH")"
BIN_NAME="$(basename "$BIN_PATH")"

# Get the absolute paths
ZORYA_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPTS_DIR="$ZORYA_DIR/scripts"
QEMU_CLOUDIMG_DIR="$ZORYA_DIR/external/qemu-cloudimg"
QEMU_MOUNT_DIR="$ZORYA_DIR/external/qemu-mount"

# Reset cpu_mapping.txt and memory_mapping.txt if they already exist
echo "Resetting cpu_mapping.txt and memory_mapping.txt if they exist..."
> "$QEMU_MOUNT_DIR/cpu_mapping.txt" 2> /dev/null || true
> "$QEMU_MOUNT_DIR/memory_mapping.txt" 2> /dev/null || true

# Check and clear /dumps directory if it exists
DUMPS_DIR="$QEMU_MOUNT_DIR/dumps"
if [ -d "$DUMPS_DIR" ]; then
    echo "Clearing existing contents of /dumps directory..."
    rm -rf "$DUMPS_DIR"/*
else
    echo "Creating /dumps directory..."
    mkdir "$DUMPS_DIR"
fi

# Function to clean up QEMU process
cleanup() {
    echo "Shutting down the virtual machine..."
    if ps -p "$QEMU_PID" > /dev/null; then
        sudo kill "$QEMU_PID"
    fi
}
trap cleanup EXIT

echo "Terminating any existing QEMU instances..."
sudo killall qemu-system-x86_64 2>/dev/null || true

echo "Preparing QEMU environment..."
mkdir -p "$QEMU_CLOUDIMG_DIR" "$QEMU_MOUNT_DIR"

# Download cloud image if not already downloaded
if [ ! -f "$QEMU_CLOUDIMG_DIR/jammy-server-cloudimg-amd64.img" ]; then
    echo "Downloading Ubuntu cloud image..."
    cd "$QEMU_CLOUDIMG_DIR"
    wget https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img
    qemu-img resize jammy-server-cloudimg-amd64.img +10G
fi

echo "Copying binary and helper scripts to shared folder..."
# Copy the binary if it's not already in the destination
BIN_DEST="$QEMU_MOUNT_DIR/$BIN_NAME"
if [ "$(realpath "$BIN_PATH")" != "$(realpath "$BIN_DEST")" ]; then
    cp -u "$BIN_PATH" "$BIN_DEST"
fi

# Copy helper scripts if they are not the same file
for file in "execute_commands.py" "parse_and_generate.py"; do
    SRC_FILE="$ZORYA_DIR/external/qemu-mount/$file"
    DEST_FILE="$QEMU_MOUNT_DIR/$file"
    if [ "$(realpath "$SRC_FILE")" != "$(realpath "$DEST_FILE")" ]; then
        cp -u "$SRC_FILE" "$DEST_FILE"
    fi
done

echo "Starting QEMU virtual machine..."
sudo qemu-system-x86_64 \
    -cpu Opteron_G1 \
    -m 2048 \
    -drive file="$QEMU_CLOUDIMG_DIR/jammy-server-cloudimg-amd64.img",format=qcow2 \
    -seed 12345 \
    -net nic \
    -net user,hostfwd=tcp::2222-:22 \
    -fsdev local,id=fsdev0,path="$QEMU_MOUNT_DIR",security_model=mapped \
    -device virtio-9p-pci,fsdev=fsdev0,mount_tag=hostshare \
    -virtfs local,path="$QEMU_MOUNT_DIR",security_model=mapped,mount_tag=hostshare \
    -nographic \
    > "$ZORYA_DIR/qemu_output.log" 2>&1 &

QEMU_PID=$!

# Function to display an adaptive progress bar
progress_bar() {
    local duration=$1
    local elapsed=0
    local cols=$(tput cols)
    local max_bar_width=$((cols - 30))  # Adjust based on terminal width
    local bar_width=50  # Default bar width

    # Ensure the bar width is within reasonable bounds
    if [ "$max_bar_width" -lt 20 ]; then
        bar_width=10
    elif [ "$max_bar_width" -lt "$bar_width" ]; then
        bar_width=$max_bar_width
    fi

    while [ $elapsed -le $duration ]; do
        # Calculate percentage
        local percent=$(( 100 * elapsed / duration ))
        # Calculate number of '#' characters
        local filled=$(( bar_width * elapsed / duration ))
        # Build the bar
        local bar=$(printf "%-${bar_width}s" "$(printf "#%.0s" $(seq 1 $filled))")
        # Output the progress bar
        printf "\rStabilizing SSH connection: [%s] %3d%%" "$bar" "$percent"
        sleep 1
        elapsed=$((elapsed + 1))
    done
    echo ""
}

echo "Waiting for SSH to become available..."
timeout=500
elapsed=0
while ! nc -z localhost 2222; do
    sleep 5
    elapsed=$((elapsed + 5))
    if [ "$elapsed" -ge "$timeout" ]; then
        echo "Timed out waiting for SSH to become available."
        exit 1
    fi
done
echo "SSH is now available."

progress_bar 70  # Display a progress bar for 70 seconds

echo "Preparing to run GDB commands inside the VM..."

# Check if sshpass is installed
if ! command -v sshpass &> /dev/null; then
    echo "sshpass could not be found. Please install it (e.g., sudo apt install sshpass)."
    exit 1
fi

SSH_PASSWORD="ubuntu"
SSH_COMMAND="sshpass -p $SSH_PASSWORD ssh -t -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null ubuntu@localhost -p 2222"

echo "Mounting shared folder inside the VM..."
$SSH_COMMAND << EOF
echo "$SSH_PASSWORD" | sudo -S mkdir -p /mnt/host
echo "$SSH_PASSWORD" | sudo -S mount -t 9p -o trans=virtio hostshare /mnt/host
EOF

# Run GDB commands to generate cpu_mapping.txt and memory_mapping.txt
echo "Running GDB to generate cpu_mapping.txt and memory_mapping.txt..."
$SSH_COMMAND << EOF
cd /mnt/host
echo "$SSH_PASSWORD" | sudo -S gdb ./$BIN_NAME -batch \
    -ex "break *$START_POINT" \
    -ex "run < /dev/null" \
    -ex "set logging file /mnt/host/cpu_mapping.txt" \
    -ex "set logging on" \
    -ex "info all-registers" \
    -ex "set logging off" \
    -ex "set logging file /mnt/host/memory_mapping.txt" \
    -ex "set logging on" \
    -ex "info proc mappings" \
    -ex "set logging off" \
    -ex "quit"
EOF

if [ ! -s "$QEMU_MOUNT_DIR/cpu_mapping.txt" ] || [ ! -s "$QEMU_MOUNT_DIR/memory_mapping.txt" ]; then
    echo "Error: Failed to generate cpu_mapping.txt or memory_mapping.txt."
    exit 1
fi
echo "Memory and CPU register dumps generated successfully."

# Section 3: Run the parse_and_generate.py script on the local computer to create dump_commands.txt
echo "Generating dump_commands.txt using parse_and_generate.py..."
cd "$QEMU_MOUNT_DIR"
python3 parse_and_generate.py
echo "dump_commands.txt generated successfully."

# Section 4: Load execute_commands.py in QEMU to execute dump commands
echo "Executing dump commands in GDB inside the VM..."
$SSH_COMMAND << EOF
cd /mnt/host
echo "$SSH_PASSWORD" | sudo -S gdb ./$BIN_NAME -batch \
    -ex "source execute_commands.py" \
    -ex "exec dump_commands.txt" \
    -ex "quit"
EOF

echo "Dump commands executed successfully in GDB."
