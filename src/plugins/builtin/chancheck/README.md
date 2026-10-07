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
| `Call(runtime.closechan)`, `Call(runtime.chansend1)` inside an overlay (`overlay_call_hooks`) | Kept aside until the overlay ends, then recorded with the overlay-entry path condition handed to `on_overlay_end`. |

## Detection algorithm

1. Track channel creation via the `MakeChan` summary (registers ptr + creator TID).

2. On `closechan`, mark the channel as closed and store the path constraints (phi)
   and the Go goroutine id (`goid`).

3. On `chansend1`, record the send attempt with its path constraints and `goid`.

   With `--negate-path-exploration`, a close or a send that the run itself does not execute, because it sits on a branch the input did not take, is still recorded when the overlay exploration of that branch reaches it. Its path condition is the overlay-entry condition (the path up to the branch plus the condition selecting the untaken side), so it describes the inputs that reach it. This is what lets the plugin start from a harmless input.

4. At analysis end (`on_finish`), for each send on a closed channel:
   - Compare `goid` (falls back to OS `tid` if goid unavailable).
   - If same-goroutine: only a bug if the send happened **after** the close.
     Ordering is established by a plugin-internal monotonic sequence counter
     (incremented on every close/send event), so it holds even when function
     summaries skip the body of `runtime.closechan`/`runtime.chansend`. A send
     that *precedes* the close (the safe send-then-close idiom) is not flagged.
     When the close or the send was reached on an untaken branch, `close_phi AND send_phi` must also be satisfiable.
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
solve this constraint symbolically to discover the bug, starting from an input that does not trigger it:

```bash
zorya tests/programs/chancheck-test2-with-input/chancheck-test2-with-input \
  --lang go \
  --compiler gc \
  --mode main \
  --arg a \
  --negate-path-exploration \
  --plugin chancheck
```

With `a`, `dispatch` returns early; the close and the send are both reached by the overlay exploration of the untaken branch. Output in `results/plugin_findings.txt`:

```
[chancheck::send-on-closed-channel] Send on closed channel at 0x49c271 [same-goroutine]: hchan=0x700000000000, close at 0x49c2d3 (close and send on a branch not taken by this run) (pc=0x49c271, severity=Critical)
    Triggering input (satisfies φ_close ∧ φ_send): arg1_byte_0!245 -> #x58
```

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

### Test 5: a malicious input that races a channel close

`dispatch(data)` starts a producer goroutine that sends every input byte on the unbuffered channel `ch`, and a control goroutine that closes `ch` when `data[0] == 0xCA`. The panic needs both the sentinel byte and an interleaving where the close comes before a send: natively, `\xcaAB` panics in only about 1% of runs. Zorya starts from an input that does not trigger the bug:

```bash
zorya tests/programs/chancheck-test5-input-close-race/chancheck-test5-input-close-race \
  --lang go \
  --compiler gc \
  --mode main \
  --thread-scheduling all-threads \
  --arg $'\x01\x02' \
  --negate-path-exploration \
  --plugin chancheck
```

The run never closes the channel: the producer sends both bytes and the control goroutine skips the close. The overlay exploration of the control goroutine's branch reaches `runtime.closechan` under `data[0] == 0xCA`, and the end-of-run check finds that condition compatible with the producer's sends, which nothing orders after the close. Output in `results/plugin_findings.txt` (one finding per producer send, about 25 s):

```
[chancheck::send-on-closed-channel] Send on closed channel at 0x49c632 [cross-goroutine]: hchan=0x700000000010, close at 0x49c577 (close on a branch not taken by this run) (pc=0x49c632, severity=Critical)
    Close: tid=3, goid=1002, pc=0x49c577, |φ_close|=1
    Send: tid=2, goid=1001, pc=0x49c632, |φ_send|=0
    Triggering input (satisfies φ_close ∧ φ_send): arg1_byte_0!257 -> #xca
    Path condition φ = φ_close ∧ φ_send: (= (ite (= (ite (= arg1_byte_0!257 #xca) #x01 #x00) #x00) #x01 #x00) #x00)
    Interleaving: close (tid=3) ordered before send (tid=2); this run did not schedule it, but nothing orders the two goroutines
```

The cross-goroutine check does not model happens-before: if the program synchronised the close after the sends (for example by waiting for the producer before closing), the plugin would still report it.

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
