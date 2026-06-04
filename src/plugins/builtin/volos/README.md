<!--
SPDX-FileCopyrightText: 2026 KMSEC (PTY) LTD - https://kmsecurity.co.za
SPDX-FileCopyrightText: 2026 Ledger https://www.ledger.com - INSTITUT MINES TELECOM

SPDX-License-Identifier: Apache-2.0
-->

# `Volos` : Data-race detector plugin

Plugin-layer port of the [`zorya-volos`](https://github.com/kmsec137/zorya-volos) fork by Keith Makan / KMSEC. The detector observes binary-originated memory accesses and lock-primitive calls dispatched by the concolic executor, classifies each cell with a small finite-state automaton, and emits one `Finding` per witness pair at end-of-trace.

The original fork plumbed `Volos` records through every memory API and embedded race state inside `MemoryRegion`. This port keeps **all of the upstream semantics** but moves the bookkeeping into a self-contained plugin so the core executor and memory layer stay unmodified.

## What's in this directory

| File | Purpose |
| --- | --- |
| `mod.rs` | `VolosPlugin` — implements the `Plugin` trait, owns per-thread state, builds records on each event, and emits findings at `on_finish`. Also contains the unit tests. |
| `record.rs` | `Volos` — one access record (tid, op, addr/size, locks held, vector clock, synthetic go_id, pc, timestamp) and the `AccessType` enum. |
| `region.rs` | `VolosRegion` — per-byte access history, the `VolosState` FSA classifier, and `race_pairs`: the end-of-trace pass that produces witness pairs. |
| `vector_clock.rs` | `VolosVC` — Lamport-style vector clock with `tick`, `tick_at`, `merge`, and a partial-order `partial_cmp` used to filter happens-before-related access pairs. |
| `manifest.yaml` | Plugin descriptor consumed by the build-time discovery sweep (Cargo feature `plugin-volos`). Lists subscriptions, hooked symbols, and env vars. |

## Event subscriptions

Declared in `VolosPlugin::wants()` and mirrored in `manifest.yaml`:

| Event | What the plugin does |
| --- | --- |
| `MemRead`  | Build a `Read` record, tick the thread's vector clock, append to `VolosRegion`. |
| `MemWrite` | Same as `MemRead` but with `AccessType::Write`. |
| `Call` | If `symbol` matches a known lock primitive, push (acquire) or pop (release) the target address from the per-thread lockset. |
| `ThreadSpawn` | Fork the parent's vector clock to seed the child's, tick both sides so subsequent accesses on either thread are concurrent, and assign the child a synthetic goroutine id. |
| `ThreadExit` | Drop the thread's lockset. |

Symbols hooked for `Call` events:

```
runtime.lock              runtime.unlock
runtime.lock2             runtime.unlock2
sync.(*Mutex).Lock        sync.(*Mutex).Unlock
sync.(*RWMutex).Lock      sync.(*RWMutex).Unlock
sync.(*RWMutex).RLock     sync.(*RWMutex).RUnlock
pthread_mutex_lock        pthread_mutex_unlock
pthread_rwlock_rdlock     pthread_rwlock_wrlock      pthread_rwlock_unlock
pthread_spin_lock         pthread_spin_unlock
```

The list is data, not code: extending it to cover more lock APIs is a one-line append in `LOCK_ACQUIRE_SYMBOLS` / `LOCK_RELEASE_SYMBOLS`. For C binaries, lock identity is keyed by the mutex *pointer* (the value of `RDI` at the call site) so distinct mutex objects are always distinguishable.

## Race-detection algorithm

For every cell with two or more recorded accesses, `VolosRegion::race_pairs` considers each ordered pair `(v1, v2)` and applies these filters in order:

1. **Same-thread skip.** Only cross-thread pairs can race.
2. **Either-write skip.** Read-read pairs are never races.
3. **Happens-before filter.** Compute `v1.vector_clock.partial_cmp(&v2.vector_clock)`. If it returns `Some(Less)` or `Some(Greater)` the pair is causally ordered and cannot race. Only `None` (truly concurrent) and `Some(Equal)` (clocks coincide — possible at trace start) survive.
4. **Lockset analysis.** Either lockset empty → `RaceReason::Unprotected`. Both locksets non-empty but disjoint → `RaceReason::InconsistentLocking`. Locksets share at least one lock → no race (finding suppressed).

Each surviving pair becomes a `Finding` of severity `High` carrying both accesses' tid, synthetic goroutine id, pc, lockset, and full vector clock for forensics.

## Vector-clock semantics

Pre-tick, then snapshot. `build_record` increments the live thread clock **before** cloning it into the record. Without the pre-tick, a thread's first event would carry `{tid: 0}`, and the partial-order compare against another thread's `{other: 1}` would spuriously report `Some(Less)` because missing components default to 0. Pre-ticking guarantees every record's local component is at least 1, so two unrelated threads' first events compare as concurrent.

`ThreadSpawn` ticks **both** parent and child: `child_clock = parent_clock.clone()` (child inherits the parent's world view), then `child_clock.tick_at(child_tid)` (child's first event strictly happens after the spawn), then `parent_clock.tick()` (parent's post-spawn events are concurrent with the child's, not spuriously ordered before them). This matches the FastTrack / DJIT⁺ fork rule. A future `ThreadJoin` / channel-recv event would `merge` into the receiver's clock to close the back edge; the data structure already supports it.

## Synthetic goroutine ids

The plugin assigns a monotonic `go_id` (0, 1, 2, …) on first sight of each tid. The first thread to issue any event — typically the main thread, which has no `ThreadSpawn` — gets `go = 0`; each subsequent spawn or first-seen tid increments. The id is **not** the real Go `g.goid`; extracting that requires reading the runtime `g` struct from engine memory, which is gated on `EventCtx` exposing engine-state accessors. Until then this is a stable, deterministic, human-readable label that ships in every finding.

## Logging

`VOLOS_VERBOSE=1` enables one stderr line per dispatched event. This mirrors the upstream fork's behaviour. When the per-plugin `Logger` lands on `EventCtx`, `vlog` will route through `ctx.sub_logger("volos")` and write to `results/volos.log` instead.

## Tests

`mod.rs` contains 9 unit tests exercising the plugin end-to-end through the bus (no executor needed):

| Test | What it proves |
| --- | --- |
| `volos_subscriptions` | The right `EventKind`s are declared in `wants()`. |
| `volos_records_reads_and_writes_via_bus` | `MemRead` / `MemWrite` events round-trip through the bus into the plugin. |
| `volos_detects_unprotected_race_at_finish` | Two cross-thread writes with empty locksets produce a `data-race-unprotected` finding. |
| `volos_no_race_when_protected_by_shared_lock` | A common lock around both writes suppresses the finding. |
| `volos_detects_inconsistent_locking` | Disjoint non-empty locksets produce a `data-race-inconsistent-locking` finding. |
| `volos_hb_filter_suppresses_fork_ordered_accesses` | Parent-write → spawn → child-write is *not* flagged (causally ordered). |
| `volos_post_spawn_parent_access_still_races` | Parent's *post-spawn* write vs child's write *is* flagged (concurrent thanks to the parent tick). |
| `volos_assigns_go_ids_in_first_seen_order` | Synthetic goroutine ids appear in finding details in observation order. |
| `region_race_pairs_skips_strictly_ordered_clocks` | Direct unit test on `VolosRegion`: forged records with strictly ordered clocks produce no pairs even with empty locksets. |

Run them with:

```bash
cargo test --lib plugins::builtin::volos
```

## Integration test programs

All fixture binaries live under `tests/programs/`. Build flags are identical for every C binary:

```bash
gcc -O0 -g -no-pie -pthread -fcf-protection=none main.c -o <name>
```

`-no-pie` keeps calls going through the classic `.plt` so the symbol hook can match `plt_pthread_mutex_lock` etc. `-fcf-protection=none` avoids the `.plt.sec` indirection from CET/`endbr` so the call target is the named PLT entry.

The zorya invocation pattern is also the same for every C binary. Replace `<binary>` with the program path:

```bash
ADDR=$(nm <binary> | awk '/T main$/{print "0x"$1}')
zorya <binary> \
  --lang c \
  --thread-scheduling all-threads \
  --mode function "$ADDR" \
  --arg none \
  --no-negate-path-exploration
```

### `race-counter-c-simple` — positive control (C, no lock)

Two threads write an unprotected global `counter`. volos **must** report a `Write vs Write` data race.

```bash
ADDR=$(nm tests/programs/race-counter-c-simple/race-counter-c-simple | awk '/T main$/{print "0x"$1}')
zorya tests/programs/race-counter-c-simple/race-counter-c-simple \
  --lang c --thread-scheduling all-threads \
  --mode function "$ADDR" --arg none --no-negate-path-exploration
# Expected: 4 findings on counter (one per byte)
```

### `race-counter-c-mutex` — negative control (C, fully locked)

Same program as `race-counter-c-simple` but every write is wrapped in a `pthread_mutex_t`. volos **must** report nothing.

```bash
ADDR=$(nm tests/programs/race-counter-c-mutex/race-counter-c-mutex | awk '/T main$/{print "0x"$1}')
zorya tests/programs/race-counter-c-mutex/race-counter-c-mutex \
  --lang c --thread-scheduling all-threads \
  --mode function "$ADDR" --arg none --no-negate-path-exploration
# Expected: 0 findings
```

### `race-counter-c-mixed` — combined control (C, one locked / one naked)

Two globals: `safe_counter` protected by a mutex and `unsafe_counter` left naked. volos **must** report a race on `unsafe_counter` and stay silent on `safe_counter`. This is the primary regression fixture.

```bash
ADDR=$(nm tests/programs/race-counter-c-mixed/race-counter-c-mixed | awk '/T main$/{print "0x"$1}')
zorya tests/programs/race-counter-c-mixed/race-counter-c-mixed \
  --lang c --thread-scheduling all-threads \
  --mode function "$ADDR" --arg none --no-negate-path-exploration
# Expected: 4 findings on unsafe_counter, 0 findings on safe_counter
```

### `race-counter` — Go positive control

Two goroutines write an unprotected `counter` global. Requires `runtime.newproc` hook support (work in progress); currently exercises the Go runtime boot path.

```bash
ADDR=$(go tool nm tests/programs/race-counter/race-counter | awk '/ T main\.main$/{print "0x"$1}')
zorya tests/programs/race-counter/race-counter \
  --lang go --compiler gc \
  --thread-scheduling all-threads \
  --mode main "$ADDR" \
  --negate-path-exploration
```

Verify the race natively with the Go race detector:

```bash
cd tests/programs/race-counter && go run -race .
```

## Integration status

| Concern | Status |
| --- | --- |
| Plugin code (record / region / clock / dispatch / finish) | Complete. |
| `Plugin` trait conformance | Complete. |
| Lock-primitive bookkeeping for Go (`runtime.lock` family) | Complete. |
| Lock-primitive bookkeeping for C (`pthread_mutex_*`, identified by RDI mutex pointer) | Complete. |
| Vector-clock-aware race detection | Complete. |
| Real Go `g.goid` in findings (via `EventCtx::current_goid`) | Complete. |
| Synthetic goroutine ids (fallback when `current_goid` is unresolved) | Complete. |
| `VOLOS_VERBOSE` stderr tracing | Functional (per-plugin file logger deferred). |
| Executor dispatch — Pass A: `MemRead`, `MemWrite`, `Call`, `CallInd`, `ThreadSpawn`, `ThreadExit`, `run_finish` | Complete. |
| Executor dispatch — Pass B: `Branch`, `Return`, `Syscall`, `SyscallRet`, `Panic`, `ThreadSwitch` | Deferred — not needed by volos, useful for future plugins. |
| Per-region sharding (one `VolosRegion` per `MemoryRegion`) | Won't do — design artefact of the upstream fork; `HashMap<u64, CellHistory>` is correct without sharding. |
| Go `runtime.newproc` goroutine-spawn hook (to skip runtime allocator during Go analysis) | Planned. |

## Attribution

Original Volos design and implementation: **Keith Makan** (KMSEC PTY LTD), Apache-2.0 licensed in [`kmsec137/zorya-volos`](https://github.com/kmsec137/zorya-volos). This directory is a plugin-layer port that preserves the FSA, the unprotected / inconsistent-locking race rules, and the per-cell access history. Mechanical changes (event-driven dispatch, vector-clock-aware filtering, synthetic goroutine ids) are documented inline in the source files.
