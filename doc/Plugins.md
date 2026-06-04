<!--
SPDX-FileCopyrightText: 2026 Ledger https://www.ledger.com - INSTITUT MINES TELECOM

SPDX-License-Identifier: Apache-2.0
-->

# Zorya Plugins

Zorya exposes a small plugin layer so contributors can react to events fired
by the concolic executor — memory accesses, branches, calls, syscalls,
thread events, panics — without modifying core data structures or the
existing memory / executor APIs.

This document is the contract between the engine and plugin authors. When
the contract changes, `EVENT_API_VERSION` in `src/plugins/event.rs` is
bumped and this document is updated in lockstep.

## Why a plugin layer

Domain-specific analyses — race detectors, taint trackers, coverage
profilers, custom invariant checkers, sandbox policies — share a common
shape: they need to observe what the executor does (memory accesses,
branches, calls, syscalls, thread events) and react. Without a plugin
layer, every such analysis ends up implemented as inline edits to
`src/state/memory_x86_64.rs`, `src/state/state_manager.rs`,
`src/concolic/executor.rs`, and `src/main.rs`. That has three concrete
costs:

- **Merge conflicts.** Out-of-tree forks accumulate dozens of edits to the
  same hot files; every upstream change becomes a manual merge.
- **Coupled signatures.** Adding analysis-specific parameters to memory or
  executor APIs (a record handle, an `internal: bool` to skip recursive
  bookkeeping, a thread context) forces every caller to be updated and
  blocks unrelated refactors.
- **Tangled output.** Detector log lines, state machines, and ad-hoc data
  structures end up living in core types, making them impossible to
  upstream as-is and impossible to disable cleanly.

The plugin layer fixes this by inverting the dependency. Core fires events.
Plugins observe them and decide what to do. Each plugin lives in a single
directory (`src/plugins/builtin/<name>/` or its own crate), holds its own
private state, owns its own log channel, and never touches `MemoryX86_64`,
`State`, or the executor.

## Architecture

```
                                  ┌──────────────────────────┐
                                  │    ConcolicExecutor      │
                                  │   (handle_load, etc.)    │
                                  └─────────────┬────────────┘
                                                │ bus.dispatch(Event::…)
                                                ▼
                                       ┌──────────────────┐
                                       │    EventBus      │
                                       │ (re-entrancy,    │
                                       │  subscriber-set  │
                                       │  gating)         │
                                       └────┬────────┬────┘
                                            │        │
                          ┌─────────────────┘        └─────────────────┐
                          ▼                                            ▼
                   ┌────────────┐                              ┌──────────────┐
                   │ Plugin A   │       …                      │ Plugin Z     │
                   └────────────┘                              └──────────────┘
```

Two invariants make this safe and cheap:

- **Events fire only from binary-originated execution sites.** They are
  dispatched from the executor handlers (`handle_load`, `handle_store`,
  `handle_cbranch`, `handle_call`, `handle_return`, `handle_syscall`, the
  thread manager) — not from the memory layer. Engine-internal reads
  performed by Zorya for its own bookkeeping (sigaction reads,
  `runtime.g` extraction, jump-table lookups, dump loading) bypass the
  bus by going directly through `state.memory.read_*`. The
  binary/engine boundary is enforced by construction.

- **Re-entrancy guard.** A depth counter on `EventBus` short-circuits
  dispatch while a plugin is running. Plugins that read engine state from
  inside a handler — e.g. dereferencing a runtime struct to extract a
  thread or goroutine identifier — cannot recursively re-fire events.
  This single primitive replaces the per-call `internal: bool` parameter
  that ad-hoc, in-tree analyses tend to plumb through the memory API.

## Surface area

### `Plugin` trait

```rust
pub trait Plugin<'ctx>: 'ctx {
    fn name(&self) -> &'static str;
    fn version(&self) -> &'static str { "0.0.0" }
    fn wants(&self) -> HashSet<EventKind> { /* default: all but InstrPre/Post */ }
    fn symbol_hooks(&self) -> &'static [&'static str] { &[] }
    fn on_init(&mut self, ctx: &EventCtx<'ctx, '_>) {}
    fn on_event(&mut self, ev: &Event<'ctx, '_>, ctx: &EventCtx<'ctx, '_>) -> Verdict {
        Verdict::Continue
    }
    fn on_finish(&mut self, ctx: &EventCtx<'ctx, '_>) {}
}
```

Default implementations on every method mean a new plugin only writes
the methods it cares about.

### `Event` enum

| Variant         | Fired from                                 | Example consumer                |
|-----------------|--------------------------------------------|---------------------------------|
| `MemRead`       | `executor::handle_load`                    | race / taint / shape analyses   |
| `MemWrite`      | `executor::handle_store`                   | race / taint / shape analyses   |
| `Branch`        | `executor::handle_cbranch`                 | path-sensitive analyses         |
| `Call`          | `executor::handle_call` / `handle_callind` | symbol-hook dispatch            |
| `Return`        | `executor::handle_return`                  | scope cleanup                   |
| `Syscall`       | `handle_syscall` entry                     | sandbox / policy                |
| `SyscallRet`    | `handle_syscall` exit                      | sandbox / policy                |
| `ThreadSpawn`   | `sys_clone` handler                        | concurrency state init          |
| `ThreadSwitch`  | `thread_manager::switch_to_thread`         | concurrency state update        |
| `ThreadExit`    | thread teardown                            | resource bookkeeping            |
| `Panic`         | runtime-panic detector                     | finding aggregator              |
| `InstrPre/Post` | `executor::execute_instruction`            | profilers, coverage             |

`InstrPre` / `InstrPost` are gated by the subscriber bitmap so they are
zero-cost when no profiler is loaded.

### `Verdict`

What a plugin asks the engine to do after an event.

| Variant               | Effect                                                        |
|-----------------------|---------------------------------------------------------------|
| `Continue`            | Default; plugin had nothing to say.                           |
| `StopPath(reason)`    | Prune the current exploration branch.                         |
| `ReportAndContinue(f)`| Record a `Finding`; carry on.                                 |
| `AbortAnalysis(why)`  | Halt the engine. Reserved for unrecoverable invariant breaks. |

When several plugins fire on the same event their verdicts are folded by
severity (`AbortAnalysis > StopPath > ReportAndContinue > Continue`).
Multiple `ReportAndContinue` findings are all kept.

### `EventCtx`

Read-only handle every plugin receives alongside an event. Holds `&State`,
the Z3 `Context` and `Optimize` solver, the current PC / TID / instruction
counter, and the analysis start time. It does **not** expose `&mut State`
— plugins mutate their own state through `&mut self` on their own struct.

### `Finding`

Uniform shape for plugin-emitted reports: `plugin` id + `rule` id + `Severity`
+ `pc` + `title` + free-form `details`. The report writer, MCP server, and
CI baselines all consume this.

## Adding a built-in plugin

```bash
mkdir -p src/plugins/builtin/myplugin
cp src/plugins/builtin/example/* src/plugins/builtin/myplugin/
# edit mod.rs and manifest.yaml
```

Then:

1. Add `pub mod myplugin;` to `src/plugins/builtin/mod.rs`.
2. Add a Cargo feature `plugin-myplugin` in the workspace `Cargo.toml`.
3. Add a feature-gated `myplugin::register(bus)` call inside
   `src/plugins/registry.rs::register_default`.

A future revision will replace steps 1 and 3 with a build-script sweep
over `src/plugins/builtin/*/manifest.yaml`. The trait surface is
unchanged by that work, so plugins written today will keep working.

## Porting an existing in-tree analysis

When migrating an analysis that currently lives as inline edits across
core files, the standard refactor is:

1. **Identify the analysis state.** Anything the analysis writes
   (records, regions, counters, vector clocks, taint maps) becomes a
   private field on the plugin struct. Anything it reads from the engine
   (current PC, TID, register values, memory contents) becomes an
   `EventCtx` query inside the handler.
2. **Map each in-tree edit to an event.**

   | In-tree pattern                                                              | Plugin handler                                       |
   |------------------------------------------------------------------------------|------------------------------------------------------|
   | Bookkeeping added to `read_value` / `read_u32` / etc.                        | `on_event(MemRead { addr, size, pc, tid, .. })`      |
   | Bookkeeping added to `write_value` / `write_u32` / etc.                      | `on_event(MemWrite { addr, size, pc, tid, .. })`     |
   | Hooking a specific function symbol (locks, allocators, runtime calls)        | `on_event(Call { symbol: Some(name), .. })`          |
   | Reaction to thread creation                                                  | `on_event(ThreadSpawn { .. })`                       |
   | Reaction to scheduling                                                       | `on_event(ThreadSwitch { .. })`                      |
   | End-of-trace summary / cross-check pass                                      | `on_finish(...)`                                     |
   | Inline `println!` / `[TAG]` log lines in core                                | per-plugin sub-logger owned by the plugin            |
   | Extra parameters threaded through memory APIs (`extra: ExtraCtx`, `internal: bool`) | not needed — re-entrancy guard handles recursion |

3. **Drop the inline core edits.** Replace them with `bus.dispatch(...)`
   calls already provided at the dispatch sites. The analysis no longer
   touches `MemoryX86_64`, `State`, or the executor; upstream merges
   become trivial.

A worked example for one such migration (a Go data-race detector) lives
in [the volos fork notes][volos]. Any other in-tree analysis follows the
same pattern.

[volos]: https://github.com/kmsec137/zorya-volos

## Status

The directory tree, trait, and event vocabulary defined here are the
**Phase A** scaffold. The dispatch sites in `src/concolic/executor.rs` and
`src/state/thread_manager.rs` are not yet wired; that lands in a follow-up
PR alongside the `panic_reach` migration as the first real plugin.

## Conventions

- Plugin names are kebab-case stable identifiers.
- Stable rule ids inside a plugin are also kebab-case.
- Plugins write to `results/<plugin-name>.log` for per-plugin tracing.
- Findings use `Severity::Critical` only for confirmed vulnerabilities;
  use `Error` for definite invariant violations and `Warning` for
  heuristic signals.
- Plugins must not stash event payload references (`&[u8]`, `&Bool<'ctx>`)
  beyond the lifetime of the dispatch call. Copy what you need into your
  own state.
