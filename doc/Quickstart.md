# Quickstart and Expected Results

## Run on bundled test binary

```bash
zorya /absolute/path/to/zorya/tests/programs/crashme/crashme
```

## Expected behavior

- Zorya initializes CPU and memory from dumps.
- Execution runs from selected mode/address.
- Symbolic exploration can produce satisfiable panic-triggering inputs.

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
