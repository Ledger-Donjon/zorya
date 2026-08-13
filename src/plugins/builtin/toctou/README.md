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
| `mod.rs` | `ToctouPlugin` — implements the `Plugin` trait, classifies syscalls as Check or Use, pairs them, checks Z3 feasibility of the path between them, and emits findings immediately upon detection. |
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

## Detection algorithm

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

### Test 2: input-gated TOCTOU

The vulnerable path only triggers when `input[0] == 'V'` (0x56). Zorya must
solve this constraint symbolically to discover the bug:

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
[TOCTOU] Recorded Check(PeerCred { fd: 1 }) at pc=0x408660 tid=209219 ic=824
[TOCTOU] Recorded Use(ReadlinkExe { path: "/proc/1234/exe", pid: Some(1234) }) at pc=0x408660 tid=209219 ic=925
[TOCTOU] *** VULNERABILITY DETECTED: TOCTOU: PeerCred { fd: 1 } -> ReadlinkExe { ... } (window=101 insns, switch=false) ***
```

Full details are written to `results/plugin_findings.txt`.

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
