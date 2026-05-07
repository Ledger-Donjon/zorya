# SPDX-FileCopyrightText: 2025 Ledger https://www.ledger.com - INSTITUT MINES TELECOM
#
# SPDX-License-Identifier: Apache-2.0

# Makefile for Zorya

# Variables (can be overridden by passing VAR=value)
ZORYA_DIR := $(CURDIR)
PCODE_GENERATOR_DIR ?= $(ZORYA_DIR)/external/pcode-generator
WORKING_FILES_DIR := $(ZORYA_DIR)/src/state/working_files
QEMU_MOUNT_DIR := $(ZORYA_DIR)/external/qemu-mount
QEMU_CLOUDIMG_DIR := $(ZORYA_DIR)/external/qemu-cloudimg
TARGET_INFO_RS := $(ZORYA_DIR)/src/target_info.rs

# System dependencies
SYS_DEPS := qemu-kvm qemu-system-x86 virt-manager virt-viewer libvirt-daemon-system libvirt-clients bridge-utils build-essential libclang-dev clang binutils-dev wget netcat-openbsd python3 cloud-image-utils llvm-18-tools
GHIDRA_VERSION ?= 11.3.1
GHIDRA_SNAP_PATH = /snap/ghidra/current/ghidra_$(GHIDRA_VERSION)_PUBLIC

# Allow overriding sudo command (e.g., make SUDO=)
SUDO ?= sudo
JDK_VER ?= 21

.PHONY: all setup ghidra-config install clean help

all: setup install

help:
	@echo "Zorya build targets:"
	@echo "  setup            – Install system deps (Rust, qemu, etc.) and build Zorya"
	@echo "  ghidra-config    – One-time helper: install/refresh Ghidra $(GHIDRA_VERSION) + Pyhidra"
	@echo "  install          – Copy the 'zorya' wrapper into /usr/local/bin"
	@echo "  clean            – Remove all build artifacts (Rust and sleigh)"
	@echo ""
	@echo "Typical first-time workflow:"
	@echo "  make ghidra-config   # install Ghidra + Pyhidra"
	@echo "  make                 # same as 'make setup install'"
	@echo ""
	@echo "Environment overrides:"
	@echo "  SUDO=$(SUDO)         # set to empty to run as root inside a container"
	@echo "  GHIDRA_INSTALL_DIR   # path to an existing Ghidra if not using snap"
	@echo "  ZORYA_DIR            # where your checkout lives (defaults to \$$PWD)"

setup:
	@echo "Installing system dependencies..."
	$(SUDO) apt-get -qq update
	$(SUDO) apt-get -y install $(SYS_DEPS)
	@echo "Checking for Rust installation..."
	@if ! command -v cargo >/dev/null 2>&1; then \
		echo "Rust is not installed. Installing Rust..."; \
		curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y; \
		echo ">>> Rust installed. Open a new shell or '. $$HOME/.cargo/env' before rerunning make if this step fails later."; \
		. $$HOME/.cargo/env; \
	fi
	@echo "Initializing submodules..."
	git submodule update --init --recursive

	@echo "Building pcode-generator (sleigh_opt + x86-64.sla)..."
	$(MAKE) -C $(PCODE_GENERATOR_DIR) -j$$(nproc) all

	@echo "Building Zorya (Rust)..."
	RUSTFLAGS="--cap-lints=allow" cargo build --release -j$$(nproc)

ghidra-config:
	@echo ">>> Ensuring OpenJDK 21, snapd, and pip..."
	sudo apt-get -qq update
	sudo apt-get -y install openjdk-21-jdk snapd python3-pip

	@echo ">>> Checking for an existing Ghidra..."
	@if [ -n "$$GHIDRA_INSTALL_DIR" ] && [ -d "$$GHIDRA_INSTALL_DIR" ]; then \
		echo "Found Ghidra at $$GHIDRA_INSTALL_DIR – skipping snap install."; \
	elif snap list ghidra >/dev/null 2>&1; then \
		echo "Ghidra snap already present – refreshing to latest…"; \
		sudo snap refresh ghidra --classic || true; \
	else \
		echo "No Ghidra found – installing snap package…"; \
		sudo snap install ghidra --classic; \
	fi

	@echo ">>> Exporting GHIDRA_INSTALL_DIR for future shells…"
	@GHIDRA_DIR="$$GHIDRA_INSTALL_DIR"; \
	if [ -z "$$GHIDRA_DIR" ]; then \
		GHIDRA_DIR="$(GHIDRA_SNAP_PATH)"; \
	fi; \
	if ! grep -q "GHIDRA_INSTALL_DIR" $$HOME/.bashrc; then \
		echo "export GHIDRA_INSTALL_DIR=\"$$GHIDRA_DIR\"" >> $$HOME/.bashrc; \
		echo "   (added to ~/.bashrc)"; \
	else \
		echo "   ~/.bashrc already contains GHIDRA_INSTALL_DIR"; \
	fi

	@echo ">>> Installing/Updating Pyhidra…"
	@if ! command -v python3 >/dev/null 2>&1; then \
		echo "ERROR: 'python3' not found. Please install Python 3 and rerun 'make ghidra-config'."; \
		exit 1; \
	fi
	@TMP_ERR=$$(mktemp); \
	if python3 -m pip install --user --upgrade pyhidra > /dev/null 2>$$TMP_ERR; then \
		echo "Pyhidra installed/updated successfully with standard pip."; \
		rm -f $$TMP_ERR; \
	else \
		if grep -q 'externally-managed-environment' $$TMP_ERR; then \
			# PEP 668 case: retry with override, still keeping pip noise hidden unless it truly fails \
			echo "Detected PEP 668 managed environment – retrying with --break-system-packages..."; \
			if python3 -m pip install --user --upgrade pyhidra --break-system-packages > /dev/null 2>>$$TMP_ERR; then \
				echo "Pyhidra installed/updated successfully with PEP 668 override."; \
				rm -f $$TMP_ERR; \
			else \
				echo "ERROR: Failed to install/upgrade Pyhidra even with --break-system-packages."; \
				echo "Details from pip:"; \
				cat $$TMP_ERR; \
				rm -f $$TMP_ERR; \
				exit 1; \
			fi; \
		else \
			echo "ERROR: Failed to install/upgrade Pyhidra with 'python3 -m pip'."; \
			echo "Details from pip:"; \
			cat $$TMP_ERR; \
			rm -f $$TMP_ERR; \
			exit 1; \
		fi; \
	fi

	@echo ">>> Done – open a new shell or 'source ~/.bashrc' before continuing."

install:
	@echo "Installing zorya command..."
	@sed 's|^_ZORYA_EMBED="__ZORYA_DIR__"|_ZORYA_EMBED="$(CURDIR)"|' scripts/zorya > /tmp/zorya
	@sudo mv /tmp/zorya /usr/local/bin/zorya
	@sudo chmod +x /usr/local/bin/zorya
	@echo "Installation complete. You can now use the "zorya" command."

clean:
	@echo "Cleaning build artifacts..."
	cargo clean
	$(MAKE) -C $(PCODE_GENERATOR_DIR) clean
	@rm -f $(TARGET_INFO_RS).bak
	@echo "Clean complete."
