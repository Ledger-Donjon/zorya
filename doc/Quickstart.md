# Quickstart and Expected Results

## Run on bundled test binary

```bash
zorya /absolute/path/to/zorya/tests/programs/crashme-go/crashme
```

Without flags, Zorya asks for the language, compiler, scheduling, mode and arguments. The same run without prompts, with a seed argument that does not crash:

```bash
zorya /absolute/path/to/zorya/tests/programs/crashme-go/crashme --lang go --compiler gc \
  --thread-scheduling all-threads --mode main --arg a --negate-path-exploration
```

## Expected behavior

- Zorya initializes CPU and memory from dumps.
- Execution runs from selected mode/address.
- Symbolic exploration can produce satisfiable panic-triggering inputs.

`crashme` (`tests/programs/crashme-go/main.go`) dereferences a nil pointer when the first byte of its argument is `'K'` (`crash(arg byte)`). The concrete run with `a` takes the safe side. On the branch `arg == 'K'`, Zorya explores the untaken side in an overlay, finds the nil write, and solves the path constraint. The run takes under a minute and ends with `main.main returned, analysis complete`.

`results/FOUND_SAT_STATE.txt` holds two reports. The first is the crash found on the overlay path:

```
[*] BUG DETECTED (overlay concolic path, not the concrete execution)
Mode: main
Crash Address: 0x4b721c              ← Go's nil check (test %al,(%rax)) before *p = 0
------------------------------------------------------------
Bug: NULL pointer dereference
Opcode: LOAD
```

The second is the input that reaches it:

```
[*] SATISFIABLE STATE FOUND
Mode: main
Instruction Address: 0x4b720e        ← cmp $0x4b,%al ; je   (arg == 'K')
Panic Address: 0x4b7212              ← je target: the p = nil; *p = 0 block
Opcode: CBRANCH
Detection method: Exploring the not taken path with Overlay Execution
------------------------------------------------------------
RESULTS
The program can panic if its inputs are the following:
  - The input 'arg1_byte_0' must be 75 (unsigned: 75; signed: 75; ASCII: 'K')
```

Addresses come from the bundled build and change if you rebuild `crashme`. `arg1_byte_0` is the first byte of `os.Args[1]`. Each report is followed by the full Z3 model, and the `Running command:` line at the top of each report shows how to replay the run.

## Output files

Primary outputs are written under `results/`:

- `execution_log.txt`: detailed instruction-level trace (unless `LOG_MODE=trace_only`)
- `execution_trace.txt`: executed function trace with runtime argument context
- `FOUND_SAT_STATE.txt`: concrete satisfying input/state when found

Depending on enabled analyses, additional outputs may include:

- `panic_reachable.txt`
- `panic_coverage.json`
- `unreachable_summary.txt`
- `unreachable_summary.json`
- `jump_tables.json`

## Interpreting SAT output

If Zorya reports a satisfiable state, it means the symbolic engine found concrete constraints
that can reach a panic/vulnerable path from the chosen start context.
