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
- `FOUND_SAT_STATE.json`: the same reports in JSON
- `plugin_findings.txt` and `plugin_findings.json`: plugin findings, when plugins are enabled

Depending on enabled analyses, additional outputs may include:

- `panic_reachable.txt`
- `panic_coverage.json`
- `unreachable_summary.txt`
- `unreachable_summary.json`
- `jump_tables.json`

### JSON reports

`FOUND_SAT_STATE.json` and `plugin_findings.json` carry the content of the two text reports in a form scripts can parse. Both are rewritten after each new entry, so they stay valid JSON if the run is interrupted. Addresses are hex strings such as `"0x4b720e"`. Both files start with the same header: `schema_version` (currently `1`), `zorya_version`, `command` (the `Running command:` line), `binary` and `mode`.

`FOUND_SAT_STATE.json` lists its reports in `results`, in the order they were found. Each entry has a `kind`:

- `"bug"`: a crash found on an overlay path, with `crash_address`, `bug`, `opcode`, `description` and `pointer`.
- `"satisfiable_state"`: a satisfiable path to a panic, with `instruction_address`, `panic_address`, `opcode`, `detection_method`, `panic_gating`, `constrained_inputs` (the input bytes the path condition constrains) and `variables` (the model value of every symbolic argument).

All entries also carry `timestamp`, `elapsed_seconds` and `mode`. An integer value is given as `value` (unsigned), `signed`, `hex` and `char` (the printable ASCII character, or `null`); values wider than 64 bits are given as decimal strings. For the Quickstart run above, the `crashme` report reads:

```json
{
  "kind": "satisfiable_state",
  "instruction_address": "0x4b720e",
  "panic_address": "0x4b7212",
  "opcode": "CBRANCH",
  "constrained_inputs": [
    { "name": "arg1_byte_0", "type": "int", "value": 75, "signed": 75, "hex": "0x4b", "char": "K" }
  ],
  "...": "..."
}
```

`plugin_findings.json` holds `finding_count` and a `findings` array. Each finding has `plugin`, `rule`, `severity` (`Info`, `Warning`, `High` or `Critical`), `pc`, `title` and `details`, the same fields as in `plugin_findings.txt`. The file is written even when there are no findings.

Keys are written in alphabetical order. The `.txt` reports are unchanged.

## Interpreting SAT output

If Zorya reports a satisfiable state, it means the symbolic engine found concrete constraints
that can reach a panic/vulnerable path from the chosen start context.
