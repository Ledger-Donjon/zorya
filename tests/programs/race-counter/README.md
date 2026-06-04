<!--
SPDX-FileCopyrightText: 2026 Ledger https://www.ledger.com - INSTITUT MINES TELECOM

SPDX-License-Identifier: Apache-2.0
-->

# `race-counter` — minimal data-race witness for volos

A two-goroutine Go program that writes to a shared global with no
synchronisation. Used to smoke-test the
[`volos`](../../../src/plugins/builtin/volos/) plugin's end-to-end wiring:
the executor's `MemWrite` dispatch site, the volos plugin's race
detector, and `main.rs`'s findings sink.

## Build

```bash
cd tests/programs/race-counter
go build -gcflags="all=-N -l" -o race-counter main.go
```

`-N -l` disables optimisation and inlining so DWARF debug info stays
intact (volos uses it via `runtime_g_offsets.json` to extract
`g.goid`).

## Confirm with the official Go race detector

```bash
go run -race ./tests/programs/race-counter
```

Expect a `WARNING: DATA RACE` block with stack traces pointing at
`main.go:XX` (the two `counter = …` lines).

## Run under Zorya

```bash
SOURCE_LANG=go ./target/debug/zorya tests/programs/race-counter/race-counter
```

(or whatever the project's standard invocation is — see
`tests/programs/panic-index/` for a worked example).

## Expected volos finding

After the run, `results/plugin_findings.txt` should contain something
like:

```
[volos::data-race-unprotected] Data race at 0x<addr>: Unprotected access (Write vs Write) (pc=0x<pc>, severity=High)
    Access 1 (tid=N, go=M): Write at 0x<pc1>, locks=[], vc=VolosVC { node_id: "N", clocks:[ … ] }
    Access 2 (tid=N', go=M'): Write at 0x<pc2>, locks=[], vc=VolosVC { node_id: "N'", clocks:[ … ] }
    Reason: Unprotected access
```

Set `VOLOS_VERBOSE=1` to see one stderr line per memory access volos
records, useful for confirming both goroutines are being scheduled.

## What's actually being tested

| Layer | Validates |
| --- | --- |
| `handle_store` dispatch | Both `counter = 1` and `counter = 2` produce `Event::MemWrite` |
| `sys_clone` dispatch | Each goroutine spawn produces `Event::ThreadSpawn` |
| `EventCtx::current_goid` | Real Go `g.goid` shows up in finding details |
| `VolosRegion::race_pairs` | Cross-thread, either-write, no shared lock → finding |
| HB filter | Vector clocks remain concurrent (`None`) → not suppressed |
| `finalize_plugin_analysis` | `run_finish` runs and `results/plugin_findings.txt` appears |

## What this program is *not*

- Not a property test: the order of the two writes is non-deterministic
  but irrelevant — both fire under the round-robin scheduler.
- Not a benchmark: it's deliberately tiny (one race, no loops) so
  concolic execution finishes in seconds.
- Not a test of channel-based or atomic-based synchronisation —
  volos's vector-clock merge currently triggers only on
  `runtime.lock` / `sync.Mutex.Lock` symbols. A future test program
  with `chan bool` synchronisation will validate the HB filter
  *suppressing* a falsely-reported race.
