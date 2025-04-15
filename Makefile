# Makefile for Zorya

# Variables (can be overridden by passing VAR=value)
ZORYA_DIR := $(CURDIR)
PCODE_GENERATOR_DIR ?= $(ZORYA_DIR)/external/pcode-generator
WORKING_FILES_DIR := $(ZORYA_DIR)/src/state/working_files
QEMU_MOUNT_DIR := $(ZORYA_DIR)/external/qemu-mount
QEMU_CLOUDIMG_DIR := $(ZORYA_DIR)/external/qemu-cloudimg
TARGET_INFO_RS := $(ZORYA_DIR)/src/target_info.rs

# System dependencies
SYS_DEPS := qemu-kvm qemu-system-x86 virt-manager virt-viewer libvirt-daemon-system libvirt-clients bridge-utils build-essential libclang-dev clang binutils-dev wget netcat python3 cloud-image-utils

.PHONY: all setup install clean help

all: setup install

help:
	@echo "Available targets:"
	@echo "  setup     - Install dependencies and build the project"
	@echo "  install   - Install the 'zorya' command"
	@echo "  clean     - Clean up build artifacts"
	@echo ""
	@echo "Usage:"
	@echo "  zorya /path/to/bin"
	@echo ""
	@echo "Before running 'zorya', ensure that the 'ZORYA_DIR' environment variable is set to the path of your Zorya project."
	@echo "You can set it by running:"
	@echo "  export ZORYA_DIR=\"/path/to/zorya\""
	@echo ""
	@echo "Alternatively, you can create a configuration file at '/etc/zorya.conf' or '~/.zorya.conf' with the following content:"
	@echo "  ZORYA_DIR=\"/path/to/zorya\""

setup:
	@echo "Installing system dependencies..."
	sudo apt-get update
	sudo apt-get install -y $(SYS_DEPS)
	@echo "Checking for Rust installation..."
	@if ! command -v cargo >/dev/null 2>&1; then \
		echo "Rust is not installed. Installing Rust..."; \
		curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y; \
		source $$HOME/.cargo/env; \
	fi
	@echo "Initializing submodules..."
	git submodule update --init --recursive

	@echo "Building pcode-generator (sleigh_opt + x86-64.sla)..."
	$(MAKE) -C $(PCODE_GENERATOR_DIR) all

	@echo "Building Zorya..."
	cargo build

install:
	@echo "Installing zorya command..."
	@sed 's|^ZORYA_DIR="__ZORYA_DIR__"|ZORYA_DIR="$(CURDIR)"|' scripts/zorya > /tmp/zorya
	@sudo mv /tmp/zorya /usr/local/bin/zorya
	@sudo chmod +x /usr/local/bin/zorya
	@echo "Installation complete. You can now use the "zorya" command."

clean:
	@echo "Cleaning build artifacts..."
	cargo clean
	$(MAKE) -C $(PCODE_GENERATOR_DIR) clean
	@rm -f $(TARGET_INFO_RS).bak
	@echo "Clean complete."
