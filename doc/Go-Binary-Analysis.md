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

---

## Struct Pointer Arguments and NULL-Check Handling

### Non-Null Constraint for Go Struct Pointers

When Zorya analyzes a Go function in `--mode function`, it makes each argument symbolic so the Z3 solver can reason about possible inputs.  For struct-pointer arguments (e.g. a method receiver `p *BlobPool`), Zorya adds a **non-null constraint** (`ptr ≠ 0`) to the solver.

**Rationale:**

- In Go, method receivers and struct-pointer arguments are virtually always non-nil at the call site.  A nil receiver is a bug in the *caller*, not inside the function itself.
- Without the constraint, the solver trivially reports that `p` could be `NULL` at the first `LOAD` through `p`, producing a low-value finding that shadows deeper, more interesting bugs inside the function body (e.g. index-out-of-bounds panics, nil map dereferences).
- This mirrors the existing non-null constraint already applied to Go string pointers in `initialize_string_argument`.

**What is still checked:**

| Pointer kind | NULL-check behavior |
|---|---|
| Struct-pointer args (method receivers) | Non-null constrained; NULL-check cache pre-seeded → solver never invoked |
| Map / interface / slice pointers | Unconstrained; solver checks normally at each LOAD/STORE |
| Derived expressions (`ptr + offset`) | Filtered out by `is_direct_tracked_symbolic_bv_internal` → skipped |
| Concrete NULL (`ptr == 0` at runtime) | Always caught immediately (`process::exit(1)`) regardless of constraints |

### NULL-Check Caching

The symbolic NULL-dereference check uses a per-variable cache (`null_check_cache`) to avoid redundant solver calls:

- **SAT (nullable):** Cached permanently — the vulnerability is already reported.
- **UNSAT (non-nullable):** Cached at the current constraint level — re-checked only when new path constraints are added.
- **Pre-seeded:** For Go struct pointers with non-null constraints, the cache is pre-seeded with `(false, 0)` at initialization time, so the check is a hash-map lookup with zero solver overhead.

---

## TTY-Dependent Code Paths and `--force-pty`

### Problem

Many Go CLI tools check whether their I/O streams are connected to a real terminal using calls like `term.IsTerminal()`, `term.GetFdInfo()`, or the underlying `isatty()` syscall. These checks gate entire code paths: interactive prompts, terminal size monitoring, colored output, progress bars, etc.

When Zorya runs a binary under GDB to capture memory dumps, GDB connects the child process's stdin/stdout to **pipes**, not a terminal. As a result, `isatty()` returns `false`, and all terminal-dependent code paths are **skipped**. Fields that would normally be initialized in those paths remain at their zero values (nil pointers, empty structs) in the GDB dump.

This means that any bug living inside a TTY-gated code path is invisible to Zorya by default — the dump never reaches a state where the relevant data structures are populated.

### Concrete Example: `kubectl exec -it`

In Kubernetes `kubectl`, the `exec` command with `-it` (interactive + TTY) initializes terminal size monitoring:

```go
// staging/src/k8s.io/kubectl/pkg/cmd/exec/exec.go
var sizeQueue remotecommand.TerminalSizeQueue
if t.Raw {
    sizeQueue = &terminalSizeQueueAdapter{
        delegate: t.MonitorSize(t.GetSize()),  // ← delegate set here
    }
}
```

The `MonitorSize` function (in `pkg/util/term/resize.go`) checks whether stdout is a terminal:

```go
func (t *TTY) MonitorSize(initialSizes ...*TerminalSize) TerminalSizeQueue {
    outFd, isTerminal := term.GetFdInfo(t.Out)
    if !isTerminal {
        return nil  // ← returns nil when not a TTY
    }
    // ... sets up real size monitoring ...
    return t.sizeQueue
}
```

When GDB runs `kubectl` with pipes, `isTerminal` is `false`, so `MonitorSize()` returns `nil`, and `delegate` is **always nil** in the dump. The nil pointer dereference bug in `terminalSizeQueueAdapter.Next()` (fixed in commit `5f67574`) can only manifest when `delegate` is nil — but since the concrete dump already has `delegate == nil`, Zorya needs symbolic exploration to find the alternative path. With `--force-pty`, `delegate` is non-nil in the concrete dump, allowing Zorya to also exercise the happy path and use path negation to explore the nil case.

### Solution: `--force-pty`

The `--force-pty` flag wraps every GDB session inside the Linux `script` command:

```bash
script -qefc "gdb -batch -ex '...' ..." /dev/null
```

This allocates a real pseudo-terminal (`/dev/pts/N`) for the child process. When `kubectl` (or any binary) calls `isatty()`, it returns `true`, and terminal-dependent initialization proceeds normally. The GDB dump then captures the **fully initialized** state of TTY-related data structures.

### When to Use

| Scenario | `--force-pty` needed? |
|----------|----------------------|
| Binary calls `isatty()` / `term.IsTerminal()` to gate code paths | **Yes** |
| Binary uses interactive prompts only when on a TTY | **Yes** |
| Binary has different buffering behavior on TTY vs pipe | Maybe (if relevant state differs) |
| Binary does not check terminal status | No |
| Simple CLI tools, libraries, web servers | No |

### Usage

```bash
zorya /path/to/binary --lang go --compiler gc --mode function 0x<addr> \
  --arg "exec -it pod -- cmd" --negate-path-exploration --force-pty
```

### How It Works Internally

1. The `scripts/zorya` wrapper parses `--force-pty` and exports `FORCE_PTY=true`.
2. `scripts/dump_memory.sh` wraps both GDB phases (memory mapping + full dump) using:
   ```bash
   script -qefc "gdb -batch ..." /dev/null
   ```
3. `scripts/extract_vdso.sh` does the same for the VDSO extraction GDB session.
4. The `script` command (from `util-linux`, pre-installed on virtually all Linux systems) creates a PTY pair and runs the given command with its stdin/stdout connected to the slave side.
5. The child process (`kubectl`, etc.) sees a real `/dev/pts/N` device, so all `isatty()` checks return `true`.

### Notes

- The `script` command is part of `util-linux` and is available on all standard Linux distributions.
- The `-q` flag suppresses "Script started"/"Script done" messages, `-e` preserves exit codes, `-f` flushes output, and `-c` specifies the command to run.
- The PTY output is discarded to `/dev/null` since Zorya only needs the GDB log files and memory dumps.
- This flag has no effect on the Zorya concolic engine itself — it only affects the GDB dump capture phase.