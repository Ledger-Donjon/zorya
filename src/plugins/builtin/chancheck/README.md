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

1. **Same-goroutine logic error**: the program closes a channel and then (later
   in program order) attempts to send on it, reachable via a specific input
   path. Detection requires that the send occurs *after* the close.

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

2. On `closechan`, mark the channel as closed and store the path constraints (phi)
   and the Go goroutine id (`goid`).

3. On `chansend1`, record the send attempt with its path constraints and `goid`.

4. At analysis end (`on_finish`), for each send on a closed channel:
   - Compare `goid` (falls back to OS `tid` if goid unavailable).
   - If same-goroutine: only a bug if the send happened **after** the close.
     Ordering is established by a plugin-internal monotonic sequence counter
     (incremented on every close/send event), so it holds even when function
     summaries skip the body of `runtime.closechan`/`runtime.chansend`. A send
     that *precedes* the close (the safe send-then-close idiom) is not flagged.
   - If cross-goroutine: compute Z3 feasibility of `close_phi AND send_phi`.
     Only emit a finding if the conjunction is satisfiable.

5. Emit findings with severity based on whether the violation is same-goroutine
   (deterministic) or cross-goroutine (scheduling-dependent).

### Temporal ordering (avoiding false positives / negatives)

Within a single goroutine, execution is sequential, so the close/send order is
decisive:

| Order (same goroutine) | Verdict |
| --- | --- |
| `send` then `close` | Safe (idiomatic: producer sends, then closes) |
| `close` then `send`  | Bug (`panic: send on closed channel`) |

The plugin records a monotonic sequence number at each close and send. A
same-goroutine violation is reported only when `send_seq > close_seq`. This is
independent of the executor's instruction counter, which does not advance
through summarized runtime functions.

## Goroutine identification

The plugin uses the Go runtime's `goid` (goroutine id) extracted from the `g`
struct via TLS at each event dispatch. This allows accurate classification even
when the Go scheduler multiplexes multiple goroutines onto the same OS thread:

| Scenario | Classification |
| --- | --- |
| Same `goid` for close and send | `same-goroutine` (deterministic crash) |
| Different `goid` | `cross-goroutine` (schedule-dependent race) |
| `goid` unavailable (early runtime) | Falls back to OS `tid` comparison |

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

### Test 3: same-goroutine deterministic close→send

The close and send are in the same goroutine but separated by a `//go:noinline`
function call boundary. This is a deterministic bug (always panics), not a race:

```bash
zorya tests/programs/chancheck-test3-racy-close-send/chancheck-test3-racy-close-send \
  --lang go \
  --compiler gc \
  --mode main \
  --thread-scheduling all-threads \
  --negate-path-exploration \
  --plugin chancheck
```

Output in `results/plugin_findings.txt`:

```
[chancheck::send-on-closed-channel] Send on closed channel at 0x49c3b2 [same-goroutine]: hchan=0x700000000000, close at 0x49c453
    Close: tid=430620, goid=1, pc=0x49c453, |φ_close|=0
    Send: tid=430620, goid=1, pc=0x49c3b2, |φ_send|=0
    Path condition: unconditional (no symbolic guards on either close or send)
    Interleaving: close (tid=430620) scheduled before send (tid=430620) by round-robin
```

Both operations have `goid=1` (the `main` goroutine), confirming this is a
deterministic logic error, not a scheduling race.

### Test 4: realistic shutdown/cancellation race (CVE-inspired)

Modeled on graceful-shutdown / cancellation races found in real Go services
(worker-pool "result" channels closed on a cancel/shutdown signal while a
producer path still writes a final status — the shape behind DoS panics in
production servers). A request dispatcher reads a 1-byte opcode:

- `opPing` (0x01) / `opData` (0x02): safe (send result, then close).
- `opCancel` (0x03): teardown closes the channel to release any waiter, but the
  cleanup path then reports a final status on the now-closed channel — bug.

The bug is gated on `opcode == 0x03`, so Zorya must solve the opcode
symbolically. Run the buggy path directly with the cancel opcode:

```bash
zorya tests/programs/chancheck-test4-shutdown-race/chancheck-test4-shutdown-race \
  --lang go \
  --compiler gc \
  --mode main \
  --thread-scheduling all-threads \
  --arg $'\x03' \
  --negate-path-exploration \
  --plugin chancheck
```

Output in `results/plugin_findings.txt`:

```
[chancheck::send-on-closed-channel] Send on closed channel at 0x49c320 [same-goroutine]: hchan=0x700000000000, close at 0x49c2d3
    Close: tid=653475, goid=1, pc=0x49c2d3, |φ_close|=3
    Send: tid=653475, goid=1, pc=0x49c320, |φ_send|=3
    Triggering input (satisfies φ_close ∧ φ_send): arg1_byte_0!251 -> #x03
    Interleaving: close (tid=653475) scheduled before send (tid=653475) by round-robin
```

Running the same harness with a safe opcode (e.g. `--arg $'\x01'`, opPing) sends
before closing and correctly produces **no findings**, demonstrating the
temporal-ordering check.

## Environment variables

| Variable | Default | Description |
| --- | --- | --- |
| `CHANCHECK_VERBOSE` | `1` (verbose on) | Set to `0` to suppress per-event log messages. Only the final summary will be shown. |

## Output

Findings are written to `results/plugin_findings.txt` with details including:
- The channel pointer and creator thread
- The close operation (TID, goid, PC, path constraints)
- The send operation (TID, goid, PC, path constraints)
- Whether it's a same-goroutine or cross-goroutine violation (based on goid)
- Z3 satisfiability result for cross-goroutine cases
