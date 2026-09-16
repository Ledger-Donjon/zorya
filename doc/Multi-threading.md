<!--
SPDX-FileCopyrightText: 2025 Ledger https://www.ledger.com - INSTITUT MINES TELECOM

SPDX-License-Identifier: Apache-2.0
-->

# Multi-Thread Support in Zorya

Zorya supports multi-threaded Go binaries by automatically dumping and restoring all OS thread states (registers + FS/GS bases) from GDB.

## Overview

When analyzing Go binaries compiled with the `gc` compiler (standard Go compiler), the runtime creates multiple OS threads. Starting execution at `main.main` or `runtime.main` requires all threads to be properly initialized with their TLS (Thread-Local Storage) bases.

## How It Works

### 1. Automatic Thread Dumping (GDB)

The `dump_memory.sh` script now automatically:
- Dumps all OS thread states to `results/initialization_data/threads/thread_<TID>.json`
- Captures general-purpose registers (RAX, RBX, RCX, RDX, RSI, RDI, RBP, RSP, R8-R15, RIP, EFLAGS)
- Captures TLS bases (FS_BASE and GS_BASE)
- **Captures full backtraces using `thread apply all bt`** for context
- Automatically identifies the main thread (the one at `main.main`)
- Classifies thread states (at_main, waiting, sysmon, background)
- Creates a thread index file (`threads_index.json`) with thread states
- Saves full backtrace output to `thread_backtraces.txt` for debugging

### 2. Automatic Thread Restoration (Zorya)

During initialization, Zorya:
- Scans `results/initialization_data/threads/` for thread dumps
- Creates an `OSThread` for each dump with full register state
- Sets FS base (offset 0x110) and GS base (offset 0x118) for each thread
- Marks the main thread as "Running" and others as "Ready"

### 3. ThreadManager Integration

The `ThreadManager`:
- Tracks `fs_base` and `gs_base` separately for each thread
- Supports creating threads from dumps via `create_thread_from_dump()`
- Maintains thread status (Running, Ready, Blocked, Exited)


## Files Created

After running Zorya, you'll find:

```
results/initialization_data/
├── threads/
│   ├── thread_<TID1>.json    # Thread 1 state
│   ├── thread_<TID2>.json    # Thread 2 state
│   └── threads_index.json    # Index with main_tid
├── dumps/                     # Memory region dumps
├── cpu_mapping.txt           # Primary CPU state
└── memory_mapping.txt        # Memory regions
```

## Thread Dump Format

Each `thread_<TID>.json` contains:

```json
{
  "tid": 164698,
  "regs": {
    "rax": 0,
    "rbx": 140737353945088,
    "rcx": 0,
    "rip": 4595152,
    ...
  },
  "fs_base": 140737353946880,
  "gs_base": 0,
  "backtrace": "#0  main.main () at main.go:16",
  "is_at_main": true
}
```

The `threads_index.json` contains:

```json
{
  "main_tid": 164698,
  "thread_count": 5,
  "threads": [164698, 164701, 164702, 164703, 164704],
  "thread_states": [
    {"tid": 164698, "state": "at_main"},
    {"tid": 164701, "state": "sysmon"},
    {"tid": 164702, "state": "waiting"},
    {"tid": 164703, "state": "waiting"},
    {"tid": 164704, "state": "waiting"}
  ]
}
```

This makes it trivial to identify:
- **Main thread**: The one with `"is_at_main": true` or at `main.main` in backtrace
- **System monitor**: Thread running `runtime.sysmon` (background GC/scheduling)
- **Waiting threads**: Blocked on futex/sleep (worker threads waiting for work)
- **Background threads**: Other runtime threads


## Goroutine-Aware Scheduling (Go)

The thread dumping above restores the OS threads (Go `M`s) that exist **at the dump point**.
Go, however, multiplexes many **goroutines** onto those few OS threads with a user-space
scheduler (`gopark → schedule → findRunnable → gogo`). A goroutine created *after* the dump
(e.g. by `go f()` or `sync.WaitGroup.Go`) only starts running once the runtime performs that
stack switch, which is far too instruction-dense for per-instruction concolic execution to
traverse in budget. Without help, freshly-created goroutine bodies never execute, and the
concurrency plugins (volos / chancheck / toctou) only ever observe the main goroutine.

Zorya closes this gap with a **goroutine-spawn hook** on `runtime.newproc`, the single
fan-out primitive behind every `go` / `sync.WaitGroup.Go`. Instead of stepping the (stubbed)
runtime scheduler, the engine reconstructs the new goroutine's initial context directly, the
way `runtime.gogo` would after `gostartcallfn`, and registers it as a first-class schedulable
thread in the `ThreadManager`.

### How the hook works

`runtime.newproc(fn *funcval)` is routed to `SummaryEffect::SpawnGoroutine` and intercepted by
`ConcolicExecutor::spawn_goroutine_and_switch` (`src/concolic/executor.rs`), which:

1. Reads the goroutine entry PC from the funcval (`fn` in RAX under Go's internal register ABI).
2. Simulates `newproc`'s void return so the **parent** resumes right after the `go` / `wg.Go`
   call site.
3. Allocates a private goroutine stack seeded with the thread-exit sentinel, so the body's
   final `ret` lands on the scheduler's yield-back path.
4. Fabricates a minimal `runtime.g` (distinct synthetic `goid`; `stackguard0 = 0` so the
   prologue never spuriously calls `morestack`) plus a private TLS block linking `[FS-8] → g`,
   so the plugins can attribute each access to its goroutine via the usual TLS → `g` → `g.goid`
   walk. It also links `g.m` to the host `M`'s real `runtime.m` (see the two-level model below),
   so `getg().m` reads resolve to a live `m` instead of nil.
5. Clones the parent register file and sets the goroutine-start registers (`RIP` = entry,
   `RSP`/`RBP` = fresh stack, `RDX` = closure context, `R14` = g, `FS` = TLS base).
6. Registers the goroutine as a schedulable thread (`ContextKind::Goroutine`, carrying its
   synthetic `goid` and host-`M` tid), switches into it, and dispatches `Event::ThreadSpawn` so
   vector-clock-aware detectors fork the parent's clock (the happens-before "fork" rule).

`sync.(*WaitGroup).Wait` is modelled as a no-op *plus a join edge* under this scheme: the
spawned workers already ran to completion at their creation point, so the parent has nothing
left to block on (the real park path would otherwise dive into `runtime.semacquire1` / `gopark`
and burn the whole budget), but the hook still emits a `HappensBefore` edge from each of the
waiter's child goroutines so the parent's post-`Wait` accesses are correctly ordered after the
workers (see the happens-before section below).

### Two-level M↔G model

`ThreadManager` schedules a single flat list of execution contexts, so Go's M:N model (many
goroutines multiplexed over few OS threads via `P`s) is flattened to 1:1: each goroutine
becomes its own schedulable context with its **own** private `g` and TLS. That flattening left
one visible divergence: a fabricated goroutine's `g.m` was nil, so any real code reading
`getg().m` (or a field off it) misbehaved.

The hook closes that with a pragmatic **two-level M↔G link**. Each context records whether it
is an OS thread (`ContextKind::OsThread`, i.e. an `m`) or a goroutine (`ContextKind::Goroutine`,
hosted by an `m`). On spawn, the engine reads the host `M`'s real `runtime.m` from the parent's
live `g` (`[FS-8] → g`, then `g.m` at the DWARF-derived offset, default 48) and writes it into
the fabricated `g.m`. A goroutine spawned by another goroutine (nested `go`) inherits its
parent's host `m`. This keeps `getg().m` coherent without emulating `P`s, `m.curg`, or a shared
per-`m` TLS; those remain future work.

### Happens-before edges (release / acquire)

Beyond the fork and join edges above, the executor emits object-keyed release/acquire edges for
Go synchronization primitives (`Event::SyncRelease` / `Event::SyncAcquire`, API v3). At each
sync call site it reads the object pointer (the receiver / first argument in `RAX` under Go's
internal ABI) and classifies it:

- **Release:** channel send / close, `WaitGroup.Done` (including the inlined `Add(-1)` form),
  mutex / rwmutex unlock.
- **Acquire:** channel receive, `WaitGroup.Wait`, mutex / rwmutex lock.

The volos detector keeps a per-object vector clock: a release folds the releaser's clock into
it, and a matching acquire merges it back into the acquirer, so accesses ordered by the
primitive stop being reported as races. Go mutexes are additionally object-keyed into the
lockset via these events (the earlier call-target keying collapsed every `*Mutex` into one
lock). C / pthread synchronization stays on the `Call` / `RDI` path and is unchanged.

### Enabling it

The hook is active whenever the **round-robin** policy is selected (`--thread-scheduling
all-threads`), i.e. when concurrency analysis was explicitly requested, and is a no-op under
`main-only`, so single-threaded analyses are byte-for-byte unaffected. Set
`ZORYA_GOROUTINE_SCHED=0` to force it off even under round-robin (it then falls back to the
historical `newproc` stub, a plain caller-return).

```bash
zorya <binary> --lang go --compiler gc \
  --thread-scheduling all-threads \
  --mode main "$ADDR" --plugin "volos toctou chancheck"
```

With the hook active, each `go` / `wg.Go` fan-out spawns a worker the detectors can watch:
Volos observes real cross-goroutine interleavings (a distinct `go=<goid>` per worker) and
reports genuine Go data races, while safe patterns (shared-lock, disjoint memory) are correctly
suppressed. See the volos [README](../src/plugins/builtin/volos/README.md) for the
`race-counter` control.

## Future Work

- ~~Support for thread scheduling/switching during execution~~: **done** via round-robin
  OS-thread scheduling plus the goroutine-spawn hook above.
- Goroutine-level state tracking: goroutines now schedule as first-class contexts with a
  synthetic `goid`; deeper `runtime.g` state tracking (real scheduler status, per-`g` stacks)
  remains partial.
- ~~Channel-recv / `WaitGroup` happens-before edges~~: **done** via object-keyed release/acquire
  (`SyncRelease` / `SyncAcquire`) plus the `WaitGroup.Wait` join edge. Remaining: per-item
  precision for buffered channels (v1 uses one clock per channel, a sound-leaning
  approximation), and a faithful shared-`M` TLS / `m.curg` / `P` model.
- Stack memory regions per thread
- Thread-specific breakpoints and watchpoints

## References

- Go Runtime: https://github.com/golang/go/tree/master/src/runtime
- x86-64 ABI: https://refspecs.linuxbase.org/elf/x86_64-abi-0.99.pdf
- GDB Python API: https://sourceware.org/gdb/onlinedocs/gdb/Python-API.html

