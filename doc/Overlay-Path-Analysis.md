<!--
SPDX-FileCopyrightText: 2025 Ledger https://www.ledger.com - INSTITUT MINES TELECOM

SPDX-License-Identifier: Apache-2.0
-->

# Overlay Path Analysis for Vulnerability Detection

## Overview

Zorya includes **overlay path analysis** to detect vulnerabilities by exploring untaken paths using a copy-on-write overlay mechanism. This technique allows full concolic execution on unexplored paths without modifying the base execution state.

**Note**: The same vulnerability checks (NULL deref, div/0, dangling pointers) run in both concrete and overlay execution. See [Vulnerability-Detection.md](./Vulnerability-Detection.md) for details on detection mechanisms.

## How It Works

For every conditional branch involving symbolic variables, Zorya:

1. **Takes the concrete path** (normal execution continues)
2. **Creates an overlay state** for the untaken path
3. **Executes up to N instructions** in overlay mode (default: 15)
4. **Detects vulnerability patterns**:
   - `LOAD [address]` where address could be 0 → **NULL_DEREF_LOAD**
   - `STORE [address], value` where address could be 0 → **NULL_DEREF_STORE**
   - `DIV/REM` where divisor could be 0 → **DIV_BY_ZERO**
   - Memory access to freed stack frame → **DANGLING_POINTER**
5. **Reports vulnerability** with SMT constraints to trigger it
6. **Notifies plugins** via the `on_overlay_end` hook, passing the clean
   overlay-entry path condition `φ` (the input gate that made the untaken branch
   reachable) so detectors can Z3-solve the inputs that drive events they
   observed during the overlay. The TOCTOU detector uses this to flag a
   credential check reachable only on an input-gated branch — see
   [`src/plugins/builtin/toctou/README.md`](../src/plugins/builtin/toctou/README.md).
7. **Discards overlay** and continues normal execution

## Overlay Mechanism

The overlay uses copy-on-write semantics for efficiency:

- **CPU registers**: Modified registers are stored in overlay, unmodified ones read from base state
- **Memory**: Modified regions are cloned on first write, unmodified regions read from base
- **Stack frames**: Overlay frames are tracked and cleaned up after overlay ends
- **No state pollution**: Base execution state remains unchanged

## Configuration

- **Max depth**: 15 instructions (configurable in `overlay_path_analysis.rs`)
- **Automatic**: Enabled for all conditional branches with symbolic variables
- **Overhead**: Minimal - overlay is discarded after analysis

## When to Use

Overlay path analysis is automatically enabled for:
- **Go GC binaries** - Detects implicit nil dereferences
- **C/C++ binaries** - Detects segfaults and undefined behavior
- **TinyGo binaries** - Works alongside explicit panic detection

## Technical Details

**Implementation**: `src/state/overlay_path_analysis.rs`

The overlay state provides:
- Copy-on-write CPU registers
- Copy-on-write memory regions
- Full concolic execution in isolated environment
- Zero impact on base execution state

**Stack frame cleanup**:
When overlay execution ends, any overlay stack frames (from CALL/RETURN in overlay) are removed from tracking to prevent false positives in dangling pointer detection:

```rust
// Before overlay
let saved_call_stack_depth = executor.state.call_stack.len();
let saved_freed_frames_count = executor.state.freed_stack_frames.len();

// After overlay
executor.state.call_stack.truncate(saved_call_stack_depth);
executor.state.freed_stack_frames.truncate(saved_freed_frames_count);
```

This ensures only frames from concrete execution are used for vulnerability detection.

