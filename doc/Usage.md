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
  [--arg <arg1> [<arg2> ...]] \
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
  - `all-threads`: load and schedule all dumped OS threads (round-robin). For Go this also
    enables the **goroutine-spawn hook**, so goroutines created by `go` / `sync.WaitGroup.Go`
    are scheduled as first-class threads and their bodies execute under the concurrency plugins
    (see [Multi-threading.md](Multi-threading.md#goroutine-aware-scheduling-go)).
  - `main-only`: execute only main thread (goroutine hook disabled; single-threaded analysis)
- `--negate-path-exploration`: enable symbolic negated branch exploration
- `--no-negate-path-exploration`: disable negated branch exploration
- `--plugin`: plugins to activate at runtime
  - `all` (default): enable all compiled-in plugins
  - `none`: disable all plugins (pure concolic execution)
  - `"volos toctou"`: space-separated list of specific plugins
  - Available plugins: `volos` (data-race), `toctou` (TOCTOU), `chancheck` (send-on-closed-channel)
- `--force-pty`: run GDB sessions inside a PTY to preserve TTY-gated behavior
- `--arg`: pass runtime arguments to the analyzed binary. Every token after `--arg` is one argument, up to the next Zorya flag, so arguments that start with `-` or `--` go through. Shell quoting decides the boundaries: `--arg 1 + 2` passes three arguments, while `--arg "a b"` passes the single argument `a b`. An empty argument (`--arg ""`) is passed as an empty string. `--arg none`, or leaving `--arg` out, runs the binary with no arguments. At the interactive prompt, arguments are split on whitespace.
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

### Static analysis modes

Some passes are pure static analyses that need neither pcode generation, memory
dumps, nor a concolic run. They short-circuit straight to the pass and exit.

- `--recursion-scan`: static unbounded-recursion (stack-exhaustion DoS) scan. Builds the
  function call graph (Ghidra), extracts recursive strongly-connected components and
  self-recursive functions, and ranks those reachable from an untrusted-input entry as
  candidate stack-overflow DoS sites. Requires `GHIDRA_INSTALL_DIR` (and a headless
  `JAVA_HOME` / `_JAVA_OPTIONS`) as for the other Ghidra passes.
  - `--entry <symbol-substring>`: entry seed (repeatable) overriding the default seeds
    (`main.main` and any `parsesourcefile`). Reachability is computed forward from the union.
  - Output: `results/recursion_cycles.txt` plus a ranked report on stdout.

  ```bash
  zorya ./parseharness --recursion-scan --entry parseSourceFile
  ```

  See [Go-Binary-Analysis.md](Go-Binary-Analysis.md#static-unbounded-recursion-scan-stack-exhaustion-dos).

### Environment

- `LOG_MODE=trace_only`: disables `results/execution_log.txt` creation, while preserving `results/execution_trace.txt`
- `ZORYA_DUMP_REGS_EACH_INST=1`: enables per-instruction full register dumps (RAX..R15/flags/YMM) in the executor logs. Disabled by default because it can severely slow long runs.
- `ZORYA_INT_ARITH_ORACLES=1`: enables expensive integer arithmetic solver oracles (`INT_ADD`/`INT_SUB`/`INT_MULT` overflow/underflow SAT checks). Disabled by default to keep concolic instruction throughput high during race-focused runs.
- `ZORYA_MEM_SAFETY_ORACLES=1`: enables symbolic NULL / dangling-pointer memory safety checks in `LOAD`/`STORE`. By default, these checks are auto-disabled for multithreaded C/C++ runs (`--thread-scheduling all-threads`) to avoid stalls in race-analysis workflows.
- `ZORYA_GOROUTINE_SCHED=0`: force-disables the Go goroutine-spawn hook even under `--thread-scheduling all-threads` (falls back to the historical `runtime.newproc` stub, a plain caller-return). The hook is enabled by default whenever round-robin scheduling is active; see [Multi-threading.md](Multi-threading.md#goroutine-aware-scheduling-go).
- `ARG_ASCII_PROFILE=digits|printable`: restricts every symbolic argument byte to `0`..`9` or to printable ASCII when Zorya solves for an input. It applies to the SAT reports in `FOUND_SAT_STATE.txt` and to the Volos triggering and escape inputs, so the reported inputs can be typed back on a command line.
- `ZORYA_TIMEOUT_SECS=<n>`: wall-clock budget for the concolic run. When it is reached, Zorya stops like on Ctrl+C and still writes the plugin findings.
- `ZORYA_SHUTDOWN_GRACE_SECS=<n>` (default 60): how long Zorya waits, after a signal, for the engine to reach a point where it can stop cleanly. If the engine is stuck in a long solve, the process exits without findings once this delay has passed.
- `ZORYA_FORCE_PANIC_XREF=1`: recomputes the panic cross-references (`results/xref_addresses.txt`) even if a cached table exists. The table is stored with the sha256 of the binary it was computed for (`results/xref_addresses.sha256`) and is only reused for that same binary, so this is rarely needed.
- `ZORYA_AST_PANIC_STRICT=1`: makes the AST panic walk report a negated branch only when it leads to a panic without any further branch decision. By default the walk follows every edge up to its depth limit, which can report a harmless branch because a later, independent branch reaches a panic. See [Overlay-Path-Analysis.md](Overlay-Path-Analysis.md#which-branches-are-explored).

### Stopping a run

Ctrl+C (SIGINT), `timeout` (SIGTERM) and a closed terminal (SIGHUP) all stop the run gracefully. Zorya leaves the execution loop, runs the plugins' final analysis and writes `results/plugin_findings.txt`, so findings collected until then are kept. A second Ctrl+C exits immediately without findings. If the engine cannot reach a clean stopping point within `ZORYA_SHUTDOWN_GRACE_SECS`, it exits on its own, so `timeout` always ends the process.

### Analysis profiles

Use one of these profiles depending on your goal:

- **Fast race profile** (recommended for volos race discovery):
  - Keep defaults for `ZORYA_INT_ARITH_ORACLES` and `ZORYA_MEM_SAFETY_ORACLES` (both effectively off in this workflow).
  - Prefer `LOG_MODE=trace_only` unless you need full instruction logs.
- **Full vulnerability profile** (max checks, slower):
  - Set `ZORYA_INT_ARITH_ORACLES=1`
  - Set `ZORYA_MEM_SAFETY_ORACLES=1`
  - Optionally keep `LOG_MODE=trace_only` to reduce I/O overhead.

## C and C++ binaries

`--lang c` and `--lang c++` run the same analysis: Zorya explores the input-dependent branches with the overlay path analysis and reports NULL dereferences and divisions by zero, and the concurrency plugins follow the pthread threads. The AST panic walk only runs for Go. There is no C++-specific support, so C++ works only as far as it behaves like C, and in practice that is rarely the case for real C++ code.

### Building the target

Build the target without PIE, the way the bundled C test programs are built (`tests/programs/race-counter-c*`): `gcc -O0 -g -no-pie -fcf-protection=none -Wl,-z,now main.c -o prog`, adding `-pthread` for threaded programs (use `g++` with the same flags for C++). Zorya does not relocate position-independent executables and does not set up the FS base register, so a PIE build, which is the `gcc`/`g++` default on most distributions, stops on the first stack-canary read (`mov %fs:0x28, %rax`) with `Failed to read memory at address 0x28: ReadOutOfBounds`.

### Library calls are not executed

Zorya does not execute shared-library code. A call through the PLT to a library function is skipped and returns 0 (`[EXTERNAL] skipping unresolved call ... returning 0` in `results/execution_log.txt`, see `handle_external_boundary` in `src/concolic/executor.rs`). Only `pthread_create` and `pthread_join` are modelled; lock and unlock calls such as `pthread_mutex_lock` are reported to the Volos plugin as lock events and then skipped the same way. This works when the input reaches the branches of the program's own code directly, as in `if (argv[1][0] == 'K')`, which is the case for the bundled C test programs. It does not work when the input or a pointer goes through a library call such as `strlen`, `memcpy` or `malloc`, since the call returns 0 instead of its real result. Linking statically (`-static`) does not solve this: glibc reaches `strlen`, `memcpy` and similar functions through IFUNC PLT stubs, and those are skipped the same way.

### C++ limitations

In C++ almost every operation goes through libstdc++, so the limitation above hits nearly all programs:

- `operator new` returns 0 in a dynamically linked build, and the first write to the new object is reported as a false NULL dereference.
- `std::string s(argv[1])` copies nothing, because the `strlen` it relies on returns 0. The symbolic argument bytes are lost, and a later `if (s[0] == 'K')` is a concrete branch that is never explored.
- `std::cout` stops the run with `Unhandled syscall number: 5`, because `fstat` is not implemented.
- Exceptions and stack unwinding (`__cxa_throw`, `_Unwind_Resume`) are not modelled, and C++ names are not demangled in the reports.
- There is no C++ program in `tests/programs`.

C++ support would need calls resolved through the GOT of the memory dump (including IFUNC stubs) instead of being skipped, function summaries for `strlen`, `memcpy`, `malloc`, `operator new` and `operator delete`, the `fstat` syscall, and a C++ test program.

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
