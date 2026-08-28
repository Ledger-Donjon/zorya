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
9. Plugin selection: `none`, `volos`, `toctou`, `chancheck`, `all` (or combinations)

## Command-line mode

```bash
zorya <path> --lang <go|c|c++> [--compiler <tinygo|gc>] \
  --mode <start|main|function|advanced> <addr> \
  [--thread-scheduling <all-threads|main-only>] \
  [--arg "<arg1> <arg2>"] \
  [--negate-path-exploration|--no-negate-path-exploration] \
  [--plugin "<plugin1> <plugin2>"|all|none] \
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
- `--plugin`: plugins to activate at runtime
  - `all` (default): enable all compiled-in plugins
  - `none`: disable all plugins (pure concolic execution)
  - `"volos toctou"`: space-separated list of specific plugins
  - Available plugins: `volos` (data-race), `toctou` (TOCTOU), `chancheck` (send-on-closed-channel)
- `--force-pty`: run GDB sessions inside a PTY to preserve TTY-gated behavior
- `--arg`: pass runtime arguments to the analyzed binary
- `--symbolic-registers` (advanced): space-separated registers (or `all`)
- `--symbolic-memory` (advanced): ranges `0xADDR:SIZE`
- `--no-symbolic-registers` (advanced): explicit no-register symbolic selection
- `--no-symbolic-memory` (advanced): explicit no-memory symbolic selection

> **Automatic symbolic inputs:** Program arguments (`os.Args` for Go, `argv`
> for C/C++) are automatically made symbolic in `main` and `start` modes.
> Most analyses do NOT need `--symbolic-registers` or `--symbolic-memory`.
> These flags exist only for `advanced` mode when you want to inject symbolic
> values at arbitrary registers or memory locations (e.g. analyzing a function
> in isolation).

### Environment

- `LOG_MODE=trace_only`: disables `results/execution_log.txt` creation, while preserving `results/execution_trace.txt`
- `ZORYA_DUMP_REGS_EACH_INST=1`: enables per-instruction full register dumps (RAX..R15/flags/YMM) in the executor logs. Disabled by default because it can severely slow long runs.
- `ZORYA_INT_ARITH_ORACLES=1`: enables expensive integer arithmetic solver oracles (`INT_ADD`/`INT_SUB`/`INT_MULT` overflow/underflow SAT checks). Disabled by default to keep concolic instruction throughput high during race-focused runs.
- `ZORYA_MEM_SAFETY_ORACLES=1`: enables symbolic NULL / dangling-pointer memory safety checks in `LOAD`/`STORE`. By default, these checks are auto-disabled for multithreaded C/C++ runs (`--thread-scheduling all-threads`) to avoid stalls in race-analysis workflows.

### Analysis profiles

Use one of these profiles depending on your goal:

- **Fast race profile** (recommended for volos race discovery):
  - Keep defaults for `ZORYA_INT_ARITH_ORACLES` and `ZORYA_MEM_SAFETY_ORACLES` (both effectively off in this workflow).
  - Prefer `LOG_MODE=trace_only` unless you need full instruction logs.
- **Full vulnerability profile** (max checks, slower):
  - Set `ZORYA_INT_ARITH_ORACLES=1`
  - Set `ZORYA_MEM_SAFETY_ORACLES=1`
  - Optionally keep `LOG_MODE=trace_only` to reduce I/O overhead.

## Apple Silicon / ARM hosts (x86-64 targets)

Zorya's initial-state capture (`scripts/dump_memory.sh`) drives GDB to read the
target's registers, memory mappings and memory at a breakpoint. On a real
x86-64 Linux host this uses `ptrace` directly (the "native" path).

Inside a `linux/amd64` Docker image on Apple Silicon (or any ARM host), the
x86-64 target actually runs under **qemu user-mode emulation** (`qemu-x86_64`
via binfmt_misc). qemu-user emulates the CPU but does **not** implement
`PTRACE_GETREGS` or `info proc mappings`, so GDB attaches and hits the
breakpoint yet fails with `Couldn't get registers: Input/output error` and
produces an empty register dump. (This is a qemu-user limitation, not a Rosetta
or security-policy issue; `--cap-add=SYS_PTRACE` does not help.)

### Capture modes (`ZORYA_CAPTURE`)

`scripts/dump_memory.sh` supports two capture backends, selected with the
`ZORYA_CAPTURE` environment variable:

- `ZORYA_CAPTURE=native` — the original ptrace/GDB path. Use on real x86-64
  Linux.
- `ZORYA_CAPTURE=qemu-user` — launches the target under qemu-user's built-in
  **gdbstub** (`qemu-x86_64 -g <port>`) and captures state over the GDB remote
  protocol instead of `ptrace`. This works on ARM hosts because it never issues
  `PTRACE_GETREGS`. Memory mappings (including the `objfile` column needed to
  locate `libc.so.6` / `ld-linux`) are recovered from the guest's emulated
  `/proc/self/maps`, fetched over the stub. Static, dynamically-linked, and
  multithreaded Go binaries are all supported.
- `ZORYA_CAPTURE=auto` (default) — uses `native` on real x86-64 Linux, and
  automatically switches to `qemu-user` when it detects binfmt_misc emulation
  (`/proc/sys/fs/binfmt_misc/qemu-x86_64`). As a safety net, if a native
  capture yields a register-less dump it retries via `qemu-user`.

Requirements for the `qemu-user` path: `qemu-user-static` (provides
`qemu-x86_64-static`) and `iproute2` (`ss`) inside the container. Override the
stub port with `ZORYA_GDBSTUB_PORT` (default `12345`).

The rest of the Zorya pipeline (P-code generation, execution, plugins) is
unchanged and runs the same on ARM hosts once the state has been captured.

### Fallbacks

If for any reason you cannot use the `qemu-user` capture path, you can still:

1. Run Zorya on a native x86-64 Linux runner (see below), or
2. Use a **full-system** x86-64 VM (`qemu-system-x86_64` / the
   [`qemu-cloudimg`](../external/qemu-cloudimg/README.md) setup, UTM, or Colima
   in x86-64 VM mode), where the guest has a real x86-64 kernel and `ptrace`
   works end-to-end.

## Linux runner workflow (manual, remote x86-64 host)

The recommended fallback is to run Zorya on a Linux x86_64 runner (remote host
or Linux VM), while driving it from your macOS machine.

### A) One-time setup on Linux runner

```bash
git clone --recursive https://github.com/Ledger-Donjon/zorya
cd zorya
make ghidra-config
make all
```

### B) Copy target binary from macOS to Linux

From your macOS machine:

```bash
scp /absolute/path/to/your-binary user@linux-host:/tmp/your-binary
```

### C) Run analysis on Linux

On the Linux runner:

```bash
cd ~/zorya
zorya /tmp/your-binary \
  --lang go \
  --compiler gc \
  --thread-scheduling all-threads \
  --mode main \
  --arg "a" \
  --negate-path-exploration \
  --plugin "volos toctou"
```

### D) Retrieve results back to macOS

From your macOS machine:

```bash
scp -r user@linux-host:~/zorya/results ./zorya-results
```

Main artifacts:
- `results/plugin_findings.txt`
- `results/vulnerability_log.txt`
- `results/execution_trace.txt`
- `results/execution_log.txt` (unless `LOG_MODE=trace_only`)

### Optional helper script

You can automate steps B/C/D with:

```bash
scripts/zorya-remote-run.sh \
  --host user@linux-host \
  --binary /absolute/path/to/local/binary \
  -- --mode main --lang go --compiler gc \
     --thread-scheduling all-threads \
     --arg "a" \
     --negate-path-exploration \
     --plugin all
```

The script uploads the binary, runs Zorya on the Linux host, and downloads
`results/` into a local timestamped directory under `./zorya-remote-results`.

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
