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

## Nil Receivers and Method Calls in Go

### Go Allows Method Calls on Nil Pointers

Unlike C/C++, Go **does not panic** when you call a method on a nil pointer — the nil pointer is simply passed as the receiver argument. The program only panics if the method body dereferences that nil pointer. This is well-documented behavior, not a bug:

- [Go Language Spec — Method Sets](https://go.dev/ref/spec#Method_sets): The method set of a pointer type `*T` includes all methods with receiver `*T` or `T`. There is no restriction that the pointer be non-nil.
- [Go Language Spec — Calls](https://go.dev/ref/spec#Calls): A method call `x.m()` is valid if `x` is addressable and `x`'s method set contains `m`. The spec makes no mention of nil checks.
- [Go FAQ — Why is my nil error value not equal to nil?](https://go.dev/doc/faq#nil_error): Illustrates how nil interface values interact with the type system, reinforcing that nil is a first-class value in Go.

**Practical consequence:** Some Go code intentionally calls methods on nil receivers:

```go
// Linked list — nil signals end-of-list
func (n *Node) Value() int {
    if n == nil {
        return 0  // sentinel — no dereference, no panic
    }
    return n.val
}
```

Whether a nil receiver is a bug or intentional depends on the function contract. If nil is not an expected value, the panic on dereference **is** the correct behavior. If nil is expected (linked lists, tree nodes, optional config structs), the method should guard against it explicitly.

**References:**
- [golang-nuts: "Do pointer receiver methods need to be checked for nil?"](https://groups.google.com/g/golang-nuts/c/HgmSxF85MyU)
- [Go issue #22729 — nil receiver discussion](https://github.com/golang/go/issues/22729)
- [Claudiu Constantin Bogdan — Nil Value vs Nil Receiver in Go (2024)](https://claudiuconstantinbogdan.me/articles/nil-value-vs-nil-receiver-go)

### Implications for Zorya

When Zorya reports a "Symbolic NULL pointer dereference" on a method receiver or parameter, it means the function **will panic if called with a nil pointer**. This is a true positive — the crash is real — but the severity depends on context:

| Scenario | Severity | Example |
|----------|----------|---------|
| Public API method, receiver/parameter not checked | **High** — any caller can trigger | `func (t *Tracer) OnTxEnd(receipt *Receipt) { receipt.GasUsed }` |
| Internal method, all callers guarantee non-nil | **Low** — nil is caller's fault | `func (b *block) hash() { return b.header.Hash() }` |
| Method intentionally handles nil | **Expected** — nil is part of the contract | `func (n *Node) Next() *Node { if n == nil { return nil } }` |

Zorya leaves **all struct pointers nullable** (receivers AND parameters) to catch missing nil checks, which are a common source of bugs in Go code.

---

## Struct Pointer Arguments and NULL-Check Handling

### Nullable Struct Pointers in Go

When Zorya analyzes a Go function in `--mode function`, it makes each argument symbolic so the Z3 solver can reason about possible inputs. For struct-pointer arguments (both method receivers like `t *callTracer` and regular parameters like `receipt *types.Receipt`), Zorya leaves them **nullable** — no constraints are added.

**Rationale:**

- In Go, calling a method on a nil pointer is **valid** — the nil pointer is passed as the receiver or parameter. The function only panics when it **dereferences** the nil pointer. This means missing nil checks are real bugs that Zorya should detect.
- Leaving pointers nullable allows Zorya to find cases where the code assumes a pointer is always non-nil without checking (e.g., `receipt.GasUsed` without `if receipt != nil`).
- This applies to **both receivers and regular parameters** — Go makes no distinction in its nil-handling semantics.

**What is checked:**

| Pointer kind | NULL-check behavior |
|---|---|
| Struct-pointer args (receivers and parameters) | Left nullable; solver checks at each LOAD/STORE unless cached |
| Struct pointer **fields** (e.g., `t.config`, `receipt.Logs.ptr`) | Left nullable; solver checks normally |
| Map / interface / slice pointers | Unconstrained; solver checks normally at each LOAD/STORE |
| Any expression involving a tracked variable (ptr+offset) | Base tracked variable checked for NULL |
| Concrete NULL (`ptr == 0` at runtime) | Always caught immediately (`process::exit(1)`) |

### NULL-Check Caching

The symbolic NULL-dereference check uses a per-variable cache (`null_check_cache`) to avoid redundant solver calls:

- **SAT (nullable):** Cached permanently — the vulnerability is already reported.
- **UNSAT (non-nullable):** Cached at the current constraint level — re-checked only when new path constraints are added.

This means for nullable struct pointers, the first dereference will call the solver, and subsequent dereferences of the same pointer reuse the cached result (UNSAT if the pointer cannot be nil under current constraints, SAT if a nil-dereference vulnerability was found).

### NULL-Check Performance: No simplify(), Precise Matching

The NULL-check function (`check_symbolic_null_dereference`) is designed for minimal Z3 overhead:

1. **Fast reject**: If the BV is a Z3 numeral constant (`as_u64()` succeeds), skip immediately — no formatting.
2. **One format, no simplify**: The raw expression is formatted once to find which tracked variable appears in it. Z3 `simplify()` is **never** called — it can be extremely expensive for large expression trees.
3. **Precise Z3 name matching**: Instead of substring matching on the HashMap key (e.g., `"t"`), the function matches on the **formatted Z3 BV name** (e.g., `"t_ptr!141"`). This eliminates spurious matches and handles struct field names correctly (keys use dots like `"t.config"`, Z3 names use underscores like `"t_config!145"`).
4. **Check the base variable, not the expression**: Instead of checking "can this derived address be zero?", we check "can the base tracked variable be NULL?". If `t_ptr` is nil, then any derived address (`t_ptr + offset`, `t.field`, etc.) is an invalid memory access.
5. **One check per variable per constraint level**: The per-variable cache means the solver is invoked at most once per tracked variable per new path constraint.
6. **Ghost variable elimination**: When `initialize_struct_pointer_fields` creates a symbolic pointer (e.g., `t_ptr`), it removes any ghost variable from a prior `initialize_register_argument` call (e.g., `t_RAX` tracked as `"t"`). This prevents the solver from finding false SAT results on unreferenced variables.

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