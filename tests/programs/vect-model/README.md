<!--
SPDX-FileCopyrightText: 2026 Ledger https://www.ledger.com - INSTITUT MINES TELECOM

SPDX-License-Identifier: Apache-2.0
-->

# `vect-model` — the two VECT 2.0 bugs in one program

A small Go model of the bug structure of the VECT 2.0 ransomware, built from the public analyses (Check Point, Morphisec, JUMPSEC, 2026). VECT's source was never released and the live sample is not run here; the model does no file I/O, encryption or networking. It keeps two defects:

1. **A shared-buffer data race.** VECT uses one process-global I/O buffer for all encryptor workers instead of a per-thread one, so concurrent workers overwrite each other's data.
2. **An input-gated out-of-bounds write.** The only size comparison in VECT is the 128 KB large-file branch. On the single-pass path the read length is used as an offset into the 32 KB buffer with no bound against it, so any file between 33 KB and 128 KB writes past the buffer. There is no "32 KB < size ≤ 128 KB" test anywhere in the code; the window comes from the buffer size meeting the 128 KB threshold.

The race depends on the schedule, and the overflow depends on the input. This program shows that Zorya reports both in one run, classifies the race correctly, and solves for a file size that triggers the overflow.

## The model

Sizes are in KB to keep the model small (VECT uses bytes: `0x8000` and `0x20000`). `ioBuf` is the 32-byte global buffer. `os.Args[1]` is the file size as three decimal digits, parsed without `strconv` so the solver sees one expression over the input bytes. `main` starts two `worker` goroutines with the same size and waits for both on a buffered channel. Each worker writes `ioBuf[0]` unconditionally, then calls `encryptInPlace`, which writes `ioBuf[sizeKB-1]` when `sizeKB ≤ 128` and `ioBuf[31]` otherwise. `worker` and `encryptInPlace` are marked `//go:noinline` so their branches stay real branches in the binary.

## Build

```bash
cd tests/programs/vect-model
CGO_ENABLED=0 go build -gcflags=all='-N -l' -o vect-model .
go tool nm vect-model | grep -E 'main\.(ioBuf|encryptInPlace|worker)$'
```

## Run under Zorya

```bash
ZORYA_FORCE_PANIC_XREF=1 ZORYA_AST_PANIC_STRICT=1 zorya "$PWD/vect-model" --lang go --compiler gc \
  --mode main --thread-scheduling all-threads --arg "016" --negate-path-exploration --plugin "volos"
```

`--thread-scheduling all-threads` enables the `runtime.newproc` goroutine-spawn hook, so both worker bodies run (see [Multi-threading.md](../../../doc/Multi-threading.md#goroutine-aware-scheduling-go)). The seed `"016"` is a 16 KB file, in bounds, so the concrete run completes and Volos sees both workers' writes. The three symbolic bytes let the solver reach both sides of the 128 KB branch and the out-of-bounds write. `ZORYA_FORCE_PANIC_XREF=1` recomputes the panic cross-references; Zorya also recomputes them on its own whenever the binary's sha256 changes. `ZORYA_AST_PANIC_STRICT=1` makes the AST panic walk stop at the next conditional branch, so a negated branch is only reported when it leads to a panic without any further decision. Without it, a branch such as `if n > 0 { sizeKB = n }` is reported because some later branch reaches the bounds check. The run takes about a minute and ends with `main.main returned, analysis complete`.

## Expected findings

Addresses below are from a Go 1.26.5 build of this directory (`main.ioBuf` at `0x577660`). The host thread id in the vector clocks (`396128`) changes on every run.

`results/plugin_findings.txt` contains exactly two findings, with the path condition shortened here:

```
[volos::data-race-unprotected] Data race at 0x577660 [input-independent]: Unprotected access (Write vs Write) (pc=0x49c424, severity=High)
    Access 1 (tid=2, go=1001): Write at 0x49c1d8, locks_held=[], vc=VolosVC { node_id: "2", clocks:[ "2":"14", "396128":"37" ] }
    Access 2 (tid=3, go=1002): Write at 0x49c1d8, locks_held=[], vc=VolosVC { node_id: "3", clocks:[ "3":"14", "396128":"52" ] }
    Reason: Unprotected access
    Input class: input-independent (no symbolic branch gates either access)

[volos::input-gated-data-race-unprotected] Data race at 0x57766f [input-dependent]: Unprotected access (Write vs Write) (pc=0x49c424, severity=High)
    Access 1 (tid=2, go=1001): Write at 0x49c177, locks_held=[], vc=VolosVC { node_id: "2", clocks:[ "2":"48", "396128":"37" ] }
    Access 2 (tid=3, go=1002): Write at 0x49c177, locks_held=[], vc=VolosVC { node_id: "3", clocks:[ "3":"19", "396128":"52" ] }
    Reason: Unprotected access
    Path condition φ = φ₁ ∧ φ₂: (sizeKB ≤ 128) ∧ (sizeKB - 1 < 32) ∧ ...   [over arg1_byte_0..2]
    Input class: input-dependent — race occurs iff input ⊨ φ; triggering input: arg1_byte_2!215 -> #x50; arg1_byte_1!214 -> #x30; arg1_byte_0!213 -> #x30
    Escape input (⊨ ¬φ, takes a different path, no race): arg1_byte_2!215 -> #x37; arg1_byte_1!214 -> #x1d; arg1_byte_0!213 -> #x16
```

`results/FOUND_SAT_STATE.txt` contains one satisfiable panic, at the `ioBuf[sizeKB-1]` bounds check in `main.encryptInPlace` (`CMPQ CX, $0x20; JB` at `main.go:60`):

```
Instruction Address: 0x49c164
Panic Address: 0x49c168
Opcode: CBRANCH
Detection method: Exploring the not taken path with Overlay Execution
The program can panic if its inputs are the following:
  - The input 'arg1_byte_0' must be 48 (unsigned: 48; signed: 48; ASCII: '0')
  - The input 'arg1_byte_1' must be 48 (unsigned: 48; signed: 48; ASCII: '0')
  - The input 'arg1_byte_2' must be 48 (unsigned: 48; signed: 48; ASCII: '0')
```

There is no report at the parse and none inside the Go runtime.

## Reading the findings

Both races are Write vs Write between the two workers (`go=1001` and `go=1002`), with no lock held and concurrent vector clocks.

The race on `ioBuf[0]` (`0x577660`, the store at `0x49c1d8` in `worker`) is **input-independent**: no symbolic branch decides whether a worker reaches that write, so it races for every input. Each goroutine's path condition holds only its own branches plus what its parent had decided when it spawned it. The second worker therefore does not inherit the first worker's `encryptInPlace` branches.

The race on `ioBuf[15]` (`0x57766f`, the store at `0x49c177` in `encryptInPlace`) is **input-dependent**: that write only happens on the `sizeKB ≤ 128` path, and its address depends on the size. The seed's 16 KB puts it at `ioBuf + 15`. The triggering input `"00P"` decodes to 0·100 + 0·10 + (0x50 − 0x30) = 32 KB, the largest in-bounds size on that path. The escape input decodes to a size above 128 KB, which takes the four-chunk path instead.

The SAT state is the negated bounds check: any size outside 1..32 on the single-pass path indexes out of the 32-byte buffer. The solver is free to pick which one. On this build it returns `000`, so `sizeKB = 0` writes `ioBuf[-1]`. That is a real bug, but it is not VECT's window. Other builds have returned sizes inside the window, such as `'0' '3' 'q'` (0·100 + 3·10 + (0x71 − 0x30) = 95 KB, so `ioBuf[94]`). To force the 33 KB..128 KB window, guard the parse as described below.

## Replayable digit inputs

The parse does not check that the bytes are digits, so the solver may pick any byte. To get all-digit inputs in both the SAT state and the Volos witnesses, set `ARG_ASCII_PROFILE=digits`. To exclude the `000` witness, guard the parse with `if n > 0 { sizeKB = n }`. The solver then returns sizes such as `089` or `106`. Keep `ZORYA_AST_PANIC_STRICT=1` with that guard: the default AST walk reports the `n > 0` branch itself as a path to panic.

## Confirm with the Go race detector

```bash
cd tests/programs/vect-model
CGO_ENABLED=1 go build -race -o vect-model-race .
./vect-model-race 016        # race, no panic
./vect-model-race 033        # race + index out of range [32] with length 32
./vect-model-race 128        # index out of range [127] with length 32
./vect-model-race $'03q'     # Zorya's solved input: index out of range [94]
./vect-model-race 129        # race, no panic (four-chunk path)
```

The race detector sometimes misses the race when the panic kills the process first; re-run. It confirms the bugs only for sizes you already know to try. Zorya derives the overflow window and the race classification from the binary itself.
