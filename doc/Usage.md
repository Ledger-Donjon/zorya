# Usage Reference

This page contains the complete usage details intentionally kept out of the main README.

## Interactive mode

Run:

```bash
zorya <absolute-path-to-binary>
```

Interactive prompts cover:
1. Source language: `go`, `c`, or `c++`
2. Go compiler (for Go): `tinygo` or `gc`
3. Thread scheduling (for Go gc): `all-threads` or `main-only`
4. Analysis mode: `start`, `main`, `function`, or `advanced`
5. Function address when required
6. Advanced symbolic selections (registers/memory)
7. Optional binary arguments
8. Negated-path exploration toggle

## Command-line mode

```bash
zorya <path> --lang <go|c|c++> [--compiler <tinygo|gc>] \
  --mode <start|main|function|advanced> <addr> \
  [--thread-scheduling <all-threads|main-only>] \
  [--arg "<arg1> <arg2>"] \
  [--negate-path-exploration|--no-negate-path-exploration] \
  [--force-pty] \
  [--symbolic-registers "REG1 REG2|all"] \
  [--symbolic-memory "0xADDR1:SIZE1 0xADDR2:SIZE2"] \
  [--no-symbolic-registers] [--no-symbolic-memory]
```

### Flags

- `--lang`: Source language (`go`, `c`, `c++`)
- `--compiler`: Go compiler (`tinygo`, `gc`) when `--lang go`
- `--mode`:
  - `start`: Use binary entry point
  - `main`: Analyze main function (`main.main` preferred in Go)
  - `function`: Analyze from a provided function address
  - `advanced`: Analyze from arbitrary address with explicit symbolic control
- `--thread-scheduling` (Go gc):
  - `all-threads`: load and schedule all dumped OS threads
  - `main-only`: execute only main thread
- `--negate-path-exploration`: enable symbolic negated branch exploration
- `--no-negate-path-exploration`: disable negated branch exploration
- `--force-pty`: run GDB sessions inside a PTY to preserve TTY-gated behavior
- `--arg`: pass runtime arguments to the analyzed binary
- `--symbolic-registers` (advanced): space-separated registers (or `all`)
- `--symbolic-memory` (advanced): ranges `0xADDR:SIZE`
- `--no-symbolic-registers` (advanced): explicit no-register symbolic selection
- `--no-symbolic-memory` (advanced): explicit no-memory symbolic selection

### Environment

- `LOG_MODE=trace_only`: disables `results/execution_log.txt` creation, while preserving `results/execution_trace.txt`

### Notes

- Missing options can be completed interactively.
- `<addr>` is required for `function` and `advanced` modes.
- `--arg` is optional.
- `--negate-path-exploration` is enabled by default unless disabled.

## PTY behavior (`--force-pty`)

Some binaries gate initialization with `isatty()` (or Go `term.IsTerminal()`).
Without PTY, GDB typically launches targets with pipes, so terminal-dependent code can be skipped.
`--force-pty` wraps GDB via `script`, allocates `/dev/pts/*`, and preserves terminal-gated paths.

See also: [Go-Binary-Analysis.md](Go-Binary-Analysis.md)
