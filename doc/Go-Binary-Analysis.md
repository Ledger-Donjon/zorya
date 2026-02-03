<!--
SPDX-FileCopyrightText: 2025 Ledger https://www.ledger.com - INSTITUT MINES TELECOM

SPDX-License-Identifier: Apache-2.0
-->

# Go Binary Analysis

## Overview

Zorya performs low-level concolic execution of Go binaries by extracting runtime internals from DWARF debug information and executing directly from GDB memory dumps. This document describes how Zorya analyzes Go binaries and known limitations when dealing with Go runtime state.

---

## Runtime Internals Extraction

Zorya automatically extracts Go runtime structures and function signatures during initialization using `scripts/get-funct-arg-types/main.go`.

### Runtime G Offsets

The `runtime_g_offsets.json` file contains **byte offsets** for fields in Go's internal `runtime.g` struct, which represents a goroutine.

**Format:**

```json
{
  "go_version": "go1.25.1",
  "runtime_g_offsets": {
    "goid": 152,      // goroutine ID is at byte offset 152
    "stack": 0,       // stack bounds at byte offset 0
    "m": 48,          // pointer to M (OS thread) at byte offset 48
    "racectx": 304,   // race detector context at byte offset 304
    ...
  }
}
```

**Purpose:**
- Read goroutine state directly from process memory
- Navigate Go runtime internals without runtime API calls
- Track goroutine scheduling and execution
- Access thread and stack information

**Important:**
- Offsets are **version-specific** (Go runtime struct layouts change between versions)
- Values are **byte positions**, not actual runtime values
- Critical fields: `goid`, `stack`, `stackguard0`, `m`, `atomicstatus`

### Function Signatures

Function signatures map Go function arguments to their **physical locations** (CPU registers or stack offsets).

**Format:**

```json
{
  "name": "main.ProcessData",
  "address": "0x4a2c00",
  "arguments": [
    {
      "name": "data",
      "type": "[]uint8",
      "registers": ["RDI", "RSI", "RDX"]  // ptr, len, cap
    },
    {
      "name": "flags",
      "type": "int64",
      "registers": ["RCX"]
    }
  ]
}
```

**Extraction Process:**

1. **DWARF-first approach**: Reads `DW_AT_location` attributes to determine register/stack assignments
2. **Location expressions**: Parses DWARF opcodes (`DW_OP_reg*`, `DW_OP_breg*`, `DW_OP_fbreg`)
3. **ABI fallback**: If DWARF lacks location info, infers from Go's register calling convention (RAX, RBX, RCX, RDI, RSI, R8, R9)
4. **Multi-register types**: Handles compound types automatically

**Register Mapping:**
- **Slices** (`[]T`): 3 registers (pointer, length, capacity)
- **Strings**: 2 registers (pointer, length)
- **Interfaces**: 2 registers (type pointer, data pointer)
- **Scalars**: 1 register
- **Stack args**: Notation `STACK+0x<offset>` when registers exhausted

**Important:**
- Result parameters (`~r0`, `~r1`) are filtered out
- Used to initialize symbolic values for concolic execution

---

## Known Current Limitations and Issues

### Go Runtime State Dependencies

**Problem:** Certain Go runtime functions maintain complex internal state tied to the scheduler, goroutines, and processor (P) state. When Zorya executes from a **GDB memory dump**, this state may be inconsistent, causing panics or incorrect behavior.

### Affected Functions

| Function | Reason | Typical Symptom |
|----------|--------|-----------------|
| `sync.(*Pool).Get` | Accesses per-P local pools via `runtime_procPin()` | Panic in `sync.(*Pool).pinSlow` |
| `sync.(*Pool).Put` | Same per-P state dependency | Panic or incorrect pool writes |
| `sync.(*Pool).pin` | Calls `runtime_procPin()` which needs P state | Panic when accessing invalid P |
| `sync.(*Pool).pinSlow` | Iterates per-P local structures | Panic or segfault |
| `runtime.(*mcache).nextFree` | Per-P memory allocator cache | Memory corruption or panic |
| `runtime.(*mcentral).cacheSpan` | Central span cache with runtime locks | Deadlock or panic |
| `runtime.deferprocStack` | Manipulates goroutine defer stack | Panic during unwinding |

