#!/bin/bash

# SPDX-FileCopyrightText: 2025 Ledger https://www.ledger.com - INSTITUT MINES TELECOM
#
# SPDX-License-Identifier: Apache-2.0

##############################################################################
# generate_vdso_pcode.sh - Generate p-code for VDSO and merge with main binary
#
# Usage: ./generate_vdso_pcode.sh <vdso_path> <vdso_base_addr>
#
# This script:
# 1. Uses the pcode-generator to analyze VDSO
# 2. Generates low p-code for VDSO functions
# 3. Adjusts addresses to match runtime VDSO base address
##############################################################################

set -e

ZORYA_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PCODE_GENERATOR_DIR="$ZORYA_DIR/external/pcode-generator"
RESULTS_DIR="$ZORYA_DIR/results"
INIT_DATA_DIR="$RESULTS_DIR/initialization_data"
VDSO_DIR="$INIT_DATA_DIR/vdso"

VDSO_PATH="$1"
VDSO_BASE_ADDR="$2"

if [ -z "$VDSO_PATH" ] || [ -z "$VDSO_BASE_ADDR" ]; then
    echo "Usage: $0 <vdso_path> <vdso_base_addr>"
    exit 1
fi

if [ ! -f "$VDSO_PATH" ]; then
    echo "Error: VDSO file not found: $VDSO_PATH"
    exit 1
fi

echo "Generating P-Code for VDSO..."
echo "VDSO file: $VDSO_PATH"
echo "Base address: $VDSO_BASE_ADDR"

# Generate p-code for VDSO using the pcode-generator
cd "$PCODE_GENERATOR_DIR" || exit 1

# Run pcode generator with the VDSO base address
RUSTFLAGS="--cap-lints=allow" cargo run --release "$VDSO_PATH" --low-pcode --base-addr "$VDSO_BASE_ADDR"

# Check if p-code was generated
VDSO_PCODE="$PCODE_GENERATOR_DIR/results/$(basename "$VDSO_PATH")_low_pcode.txt"

if [ ! -f "$VDSO_PCODE" ]; then
    echo "Error: Failed to generate VDSO p-code"
    exit 1
fi

# Move VDSO p-code to the vdso directory
mv -f "$VDSO_PCODE" "$VDSO_DIR/vdso_low_pcode.txt"

echo "VDSO P-Code generated: $VDSO_DIR/vdso_low_pcode.txt"

