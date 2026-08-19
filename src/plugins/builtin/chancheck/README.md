<!--
SPDX-FileCopyrightText: 2026 Ledger https://www.ledger.com - INSTITUT MINES TELECOM

SPDX-License-Identifier: Apache-2.0
-->

# `chancheck` : Send-on-Closed-Channel detector plugin

Detects Go channel invariant violations where a goroutine sends on a channel
that has already been closed. In standard Go, this causes an unrecoverable
`panic("send on closed channel")` at runtime.

## What's in this directory

| File | Purpose |
| --- | --- |
| `mod.rs` | `ChanCheckPlugin` — implements the `Plugin` trait, tracks channel lifecycle (create, close, send), and uses Z3 to verify that the close-then-send path is feasible. |
| `manifest.yaml` | Plugin descriptor listing subscriptions, patterns, and environment variables. |

## Target pattern

```text
runtime.makechan(chantype, size)  <- channel creation (tracked via summary)
  ... application logic ...
runtime.closechan(hchan)          <- channel is closed
  ... race window (or logic error) ...
runtime.chansend1(hchan, elem)    <- send on already-closed channel (BUG)
```

This can happen in two scenarios:

1. **Same-goroutine logic error**: the program unconditionally closes a channel
   and then attempts to send on it (reachable via a specific input path).

2. **Cross-goroutine race**: one goroutine closes the channel while another
   concurrently sends on it, without proper synchronization.

## Event subscriptions

| Event | What the plugin does |
| --- | --- |
| `Call(runtime.makechan)` | Records channel creation intent. The actual `*hchan` pointer is registered via `register_channel()` from the summary engine. |
| `Call(runtime.closechan)` | Marks the channel as closed, records the closer TID and Z3 path constraints. |
| `Call(runtime.chansend1)` | Records send attempts with their path constraints. |
| `Call(runtime.chanrecv1)` | Tracks receives for completeness (recv on closed is not a bug in Go). |

## Detection algorithm

1. Track channel creation via the `MakeChan` summary (registers ptr + creator TID).

2. On `closechan`, mark the channel as closed and store the path constraints (phi).

3. On `chansend1`, record the send attempt with its path constraints.

4. At analysis end (`on_finish`), for each send on a closed channel:
   - If same-goroutine: always a bug.
   - If cross-goroutine: compute Z3 feasibility of `close_phi AND send_phi`.
     Only emit a finding if the conjunction is satisfiable.

5. Emit findings with severity based on whether the violation is same-goroutine
   (deterministic) or cross-goroutine (scheduling-dependent).

## Usage

Enable the plugin via `--plugin chancheck` (or `--plugin all`).

### Test 1: unconditional send-on-closed (no input gate)

The bug is always reachable regardless of input:

```bash
zorya tests/programs/chancheck-test1-no-inputs/chancheck-test1-no-inputs \
  --lang go \
  --compiler gc \
  --mode main \
  --negate-path-exploration \
  --plugin chancheck
```

### Test 2: input-gated send-on-closed

The vulnerable path only triggers when `input[0] == 'X'` (0x58). Zorya must
solve this constraint symbolically to discover the bug:

```bash
zorya tests/programs/chancheck-test2-with-input/chancheck-test2-with-input \
  --lang go \
  --compiler gc \
  --mode main \
  --negate-path-exploration \
  --plugin chancheck
```

The plugin produces output like:

```
[CHANCHECK] MAKECHAN call observed tid=1 chantype_ptr=0x4a1200
[CHANCHECK] CLOSECHAN hchan=0x7f0000 tid=1 |phi|=0
[CHANCHECK] CHANSEND hchan=0x7f0000 tid=1 |phi|=0
[CHANCHECK] *** BUG / VULNERABILITY DETECTED: 1 send-on-closed-channel violation(s) ***
```

Full details are written to `results/plugin_findings.txt`.

## Environment variables

| Variable | Default | Description |
| --- | --- | --- |
| `CHANCHECK_VERBOSE` | `1` (verbose on) | Set to `0` to suppress per-event log messages. Only the final summary will be shown. |

## Output

Findings are written to `results/plugin_findings.txt` with details including:
- The channel pointer and creator thread
- The close operation (TID, PC, path constraints)
- The send operation (TID, PC, path constraints)
- Whether it's a same-goroutine or cross-goroutine violation
- Z3 satisfiability result for cross-goroutine cases
