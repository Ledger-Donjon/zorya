<!--
SPDX-FileCopyrightText: 2026 Ledger https://www.ledger.com - INSTITUT MINES TELECOM

SPDX-License-Identifier: Apache-2.0
-->

# `toctou` : Time-of-Check-Time-of-Use detector plugin

Detects race conditions where a program checks an external property (file
attributes, process identity, permissions) and then uses the result in a
security-sensitive operation, with an exploitable race window between the two.

## What's in this directory

| File | Purpose |
| --- | --- |
| `mod.rs` | `ToctouPlugin` — implements the `Plugin` trait, classifies syscalls as Check or Use, pairs them, checks Z3 feasibility of the path between them, and emits findings immediately upon detection. Also implements `on_overlay_end` to flag checks that are only reachable on an untaken (input-gated) branch (see [Detection modes](#detection-modes)). |
| `manifest.yaml` | Plugin descriptor listing subscriptions, patterns, and environment variables. |

## Target patterns

### Pattern 1: `SO_PEERCRED` + `/proc/<pid>/exe`

```text
getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred)  <- CHECK: get peer PID
  ... race window (PID could be recycled) ...
readlinkat(AT_FDCWD, "/proc/<pid>/exe", buf)     <- USE: verify binary
```

Attack: PID recycling. The original process exits, a malicious process forks
rapidly to reclaim the same PID, and the `readlink` verifies the wrong binary.

### Pattern 2: `stat` + `open`

```text
stat("/path/to/file", &st)     <- CHECK: file exists / permissions OK
  ... race window ...
open("/path/to/file", O_RDWR)  <- USE: open the (now different) file
```

Attack: symlink swap or rename between check and use.

### Pattern 3: `access` + `open`

```text
access("/path", R_OK)          <- CHECK
open("/path", O_RDONLY)        <- USE
```

Attack: permission bypass via file replacement.

## Event subscriptions

| Event | What the plugin does |
| --- | --- |
| `Syscall` | Classify the syscall (by number and arguments) as Check, Use, or irrelevant. Record check/use events with their path constraints. On Use, immediately try to pair with prior Checks and emit findings. |
| `SyscallRet` | Capture return values for recorded syscalls. |
| `Call` | Detect Go wrapper functions (`syscall.Getsockopt`, `os.Readlink`, etc.) for additional context. |
| `ThreadSwitch` | Record context switches to flag cross-thread check-use pairs (higher severity). |

In addition, the plugin implements the `on_overlay_end` lifecycle hook (not an
event) to reason about checks reached only during overlay concolic execution —
see [Detection modes](#detection-modes).

## Detection modes

The plugin reports through two complementary rules.

### Mode A — confirmed `check-use-race`

Both the check and the use execute on the analyzed path (the classic case).
The plugin pairs them, verifies feasibility with Z3, and reports.

1. Record each "check" syscall with its arguments, thread ID, instruction
   counter, and Z3 path constraints.
2. Record each "use" syscall similarly.
3. On each "use" event, immediately pair it with every prior "check" event on
   a related resource (matched by path, PID, or file descriptor).
4. For each pair, compute the instruction window and check whether a thread
   switch occurred in between (escalates severity to Critical).
5. Verify feasibility via Z3: the conjunction of both path constraints must be
   satisfiable for the pair to be a real vulnerability.
6. Emit findings immediately (written to `results/plugin_findings.txt` and
   displayed in the terminal).

### Mode B — overlay `overlay-check-reachable`

The vulnerable check lives on a branch the concrete run never takes (e.g.
gated on `input[0] == 0x02`, the `opVerifyPeer` opcode in the test harness). Zorya reaches it via **overlay concolic execution** of the untaken branch. In that setting the engine keeps theoriginal concrete input, so it typically cannot drive execution all the way to the paired use — but the check being reachable under attacker-influenced input is itself the signal.

This mode requires `--negate-path-exploration` (env `NEGATE_PATH_FLAG=true`),
which enables overlay exploration of untaken branches.

1. During overlay exploration, `Syscall` events carry the executor's path
   condition `φ`, so a check recorded on the untaken branch remembers the input
   gate that reached it.
2. When the overlay is torn down, the engine calls `on_overlay_end` with the
   *clean* overlay-entry `φ` = (main path up to the branch) ∧ (the gate
   selecting the untaken branch). This is deliberately **not** conjoined with
   the branch constraints the overlay accumulated afterwards: the overlay runs
   on the original concrete input, so those later constraints would contradict
   the gate.
3. For each `SO_PEERCRED` check recorded on that branch, the plugin solves `φ`
   with Z3. If satisfiable, it records the triggering input and keeps the
   candidate; if unsatisfiable, the check is not actually reachable and is
   dropped.
4. At `on_finish`, each remaining candidate not already covered by a confirmed
   `check-use-race` pairing is reported as a **potential** TOCTOU
   (`overlay-check-reachable`, severity High) with the Z3-solved triggering
   input and the full attack narrative.

Only `SO_PEERCRED` is reported from a lone check: the peer PID it retrieves is
meaningless unless later used to verify identity (the `/proc/<pid>/exe`
readlink), so a reachable check on an attacker-influenced path is sufficient to
flag the vulnerable code path. Other check kinds (`stat`/`access`) still
require their paired use (Mode A) to avoid flagging every benign `stat`.

## Usage

Enable the plugin via `--plugin toctou` (or `--plugin all`).

### Test 1: unconditional TOCTOU (no input gate)

The vulnerability is always reachable regardless of input:

```bash
zorya tests/programs/toctou-test1-no-inputs/toctou-test1-no-inputs \
  --lang go \
  --compiler gc \
  --thread-scheduling all-threads \
  --mode main \
  --negate-path-exploration \
  --plugin toctou
```

### Test 2: input-gated TOCTOU (overlay Mode B)

The harness models a tiny request protocol: the first input byte is an opcode,
and only the privileged "verify peer" opcode (`opVerifyPeer == 0x02`) runs the
SO_PEERCRED identity check. The concrete run sends a non-privileged request and
takes the safe branch, so Zorya must explore the untaken branch via overlay
concolic execution and solve the opcode gate symbolically. This **requires**
`--negate-path-exploration`; without it, no overlay runs and nothing is found:

> The gate is a single symbolic-byte comparison on purpose: overlay concolic
> execution flips exactly one untaken branch and keeps the original concrete
> input for everything else, so a chained multi-byte compare
> (`input[0]=='A' && input[1]=='U' && …`) would bail on the second concrete
> byte. A one-byte opcode dispatch is both realistic and reliably explorable.

```bash
zorya tests/programs/toctou-test2-with-input/toctou-test2-with-input \
  --lang go \
  --compiler gc \
  --thread-scheduling all-threads \
  --mode main \
  --negate-path-exploration \
  --plugin toctou
```

The plugin produces output like:

```
[TOCTOU] Recorded Check(SO_PEERCRED(fd=<runtime-assigned>)) at pc=0x408660 tid=187937 ic=1
[TOCTOU] Overlay-only check Check(SO_PEERCRED(fd=<runtime-assigned>)) at pc=0x408660 (ic=1) recorded as potential TOCTOU; input solved=true
[TOCTOU] *** BUG / VULNERABILITY DETECTED: Potential TOCTOU: SO_PEERCRED(fd=<runtime-assigned>) reachable on input-gated path (use not reached in overlay) ***
[TOCTOU] 1 TOCTOU violation(s) detected
```

The finding includes the Z3-solved triggering input, e.g. `arg1_byte_0 -> #x02`
(the `opVerifyPeer` opcode gate). Full details are written to
`results/plugin_findings.txt`.

> Note on `fd=<runtime-assigned>`: in overlay concolic execution the concrete
> file descriptor carried into the syscall is a simulated/stale value, so it is
> not surfaced as a real number. The attacker-relevant value (the input gate)
> is reported precisely. When a syscall genuinely carries a small descriptor
> (as in Test 1), it is shown as `fd=N`.

## Environment variables

| Variable | Default | Description |
| --- | --- | --- |
| `TOCTOU_VERBOSE` | `1` (verbose on) | Set to `0` to suppress per-event log messages. Only the final vulnerability detection line will be shown. |

## Thread scheduling requirement

TOCTOU detection benefits from `--thread-scheduling all-threads` because:
- Cross-thread check-use pairs (where a context switch occurs in the race
  window) are classified as **Critical** severity.
- Single-thread pairs are still detected but classified as **Error** severity,
  since exploitation requires external scheduling influence.

## Output

Findings are written to `results/plugin_findings.txt` with full details
including:
- The check and use syscalls with their addresses and arguments
- The instruction window size
- Whether a thread switch occurred in the window
- An attack narrative explaining how to exploit the race
- Mitigation guidance
