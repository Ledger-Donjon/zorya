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

With `--analysis`, nothing is asked: the answers follow from the analysis, as described below.

## Choosing what to look for (`--analysis`)

`--analysis` names what Zorya should look for. Zorya then picks the plugins, the thread scheduling and the path exploration the analysis needs, reads the language and the Go compiler from the binary, and starts at `main`, so a run needs nothing else:

```bash
zorya ./myprog --analysis data-race --arg 0 0
```

| Profile | Looks for |
|---|---|
| `data-race` | Data races between goroutines or pthreads |
| `channel-safety` | Close of a closed channel, send on a closed channel (Go) |
| `toctou` | Time-of-check to time-of-use races on files |
| `concurrency` | `data-race`, `channel-safety` and `toctou` together |
| `panic` | Inputs that reach a panic |
| `memory-safety` | NULL and dangling pointer dereferences |
| `arithmetic` | Integer overflows and divisions by zero |
| `recursion` | Unbounded recursion |
| `full` | Every profile above except `recursion` |

### What each profile stands for

A profile is a shorthand for flags and environment variables. Every profile except `recursion` sets these, unless the flag is given:

- `--lang` and `--compiler`, read from the binary: `go` with `--compiler tinygo` when it has `tinygo_` symbols, `go` with `--compiler gc` when it has a `.go.buildinfo` section or a `runtime.goexit` symbol, `c++` when it links libstdc++ or has `_ZNSt` symbols, and `c` otherwise.
- `--mode main`, starting at the address of the program's `main` function.
- `--negate-path-exploration`.
- `--thread-scheduling all-threads` when `data-race`, `channel-safety` or `toctou` is selected, or when the binary is a Go `gc` binary. Otherwise the flag is not set, and the engine runs only the main thread (`main-only`).
- The arguments of `--arg`; without `--arg`, the binary runs without arguments and nothing is asked.

On top of these, each profile sets:

| Profile | Flags | Environment | Input rounds |
|---|---|---|---|
| `data-race` | `--plugin volos`, `--thread-scheduling all-threads` | `ZORYA_MEM_SAFETY_ORACLES=0` | up to 4 |
| `channel-safety` | `--plugin chancheck`, `--thread-scheduling all-threads` | `ZORYA_MEM_SAFETY_ORACLES=0` | up to 4 |
| `toctou` | `--plugin toctou`, `--thread-scheduling all-threads` | `ZORYA_MEM_SAFETY_ORACLES=0` | up to 4 |
| `concurrency` | `--plugin "volos chancheck toctou"`, `--thread-scheduling all-threads` | `ZORYA_MEM_SAFETY_ORACLES=0` | up to 4 |
| `panic` | `--plugin none` | none: the memory safety checks keep their default (on, except for C and C++ with `all-threads`), and the arithmetic checks stay off | none |
| `memory-safety` | `--plugin none` | `ZORYA_MEM_SAFETY_ORACLES=1` | none |
| `arithmetic` | `--plugin none` | `ZORYA_INT_ARITH_ORACLES=1` | none |
| `full` | `--plugin "volos chancheck toctou"`, `--thread-scheduling all-threads` | `ZORYA_MEM_SAFETY_ORACLES=1`, `ZORYA_INT_ARITH_ORACLES=1` | up to 4 |
| `recursion` | runs `zorya --recursion-scan <binary>` and nothing else | | |

An environment variable set before the run wins over the value of the profile. "Up to 4" is the default of `--max-input-rounds`.

The selected analyses also change what the engine does, which no other flag controls: the panic prepass and the AST panic exploration only run for `panic` and `full`, and bugs reached in a negated branch (panics, NULL dereferences, divisions by zero) are only reported for `panic`, `memory-safety`, `arithmetic` and `full`. For example, on a Go `gc` binary,

```bash
zorya ./myprog --analysis data-race --arg 0 0
```

has the settings of

```bash
ZORYA_MEM_SAFETY_ORACLES=0 zorya ./myprog --lang go --compiler gc --mode main \
  --thread-scheduling all-threads --negate-path-exploration --plugin volos --arg 0 0
```

but the second command also runs the panic prepass, also reports bugs reached in negated branches, and runs once, without input rounds. `--dry-run` prints what the profiles expand to for a given binary.

Profiles combine. `--analysis data-race --analysis channel-safety`, `--analysis data-race channel-safety` and `--analysis data-race,channel-safety` are the same run, with the plugins of both profiles, `all-threads` if either needs it, and the environment variables of both. Skipping the panic prepass outside `panic` and `full` lets a concurrency analysis spend its time on the goroutines; without `--analysis` the prepass runs as before. `recursion` is a static pass and runs on its own.

Flags given explicitly win over the profiles. `--plugin` adds plugins to those of the profiles, and `--plugin none` removes them. `--no-negate-path-exploration` and `--thread-scheduling main-only` are applied, with a warning when they turn off something a selected analysis needs. `--lang`, `--compiler` and `--mode` replace what Zorya would detect or default to. `--dry-run` prints the command and the settings the profiles resolve to, without running anything.

`data-race`, `channel-safety` and `toctou` need the goroutines, or the file checks, to exist, and the given arguments may not create them. While one of these analyses has found nothing, the run writes an input solved from a negated branch that creates goroutines (`next_seed`), and the launcher reruns the binary with it, up to `--max-input-rounds` more times (default 4). The rounds stop as soon as every selected analysis has found something, or when no new input is left to try. Each round's reports are kept as `results/<report>.round<N>.<ext>` (for example `results/plugin_findings.round1.json`), `results/analysis_rounds.json` gathers the summaries of all rounds, and the launcher prints the round in which each analysis found something. [Input-gated data races](#input-gated-data-races-go) walks through an example.

When solving for an input, these analyses prefer printable argument bytes, so the inputs can be typed on a command line. When only a non-printable byte satisfies a condition, that byte is used, and it is written `\xHH` in the reports.

Every run with `--analysis` writes `results/analysis_summary.json`:

- `analyses`: the selected analyses, after expanding `concurrency` and `full`.
- `seed`: the arguments of this run. `seeds_tried`: those of the earlier rounds.
- `results`: one object per analysis, with `found`, `done` (no further round can add to it) and a count: `findings` for the plugin analyses, `sat_states` for `panic`, `memory-safety` and `arithmetic`. `data-race` also has the `status` of `results/race_summary.json` and `races`, the number of distinct races, and is done when its status is `stdlib_fixed`.
- `found` (some analysis found something), `complete` (every analysis is done), `candidate_seeds` (how many inputs were solved from negated branches), `next_seed` and `run` (the `termination` object of `run_status.json`).

`--race-only` is a deprecated alias of `--analysis data-race`. `ZORYA_RACE_RESEED` is still read as the default of `--max-input-rounds`. The `race_only` field of `results/race_summary.json` and `results/run_status.json` is replaced by `analyses`.

`LOG_MODE=trace_only` speeds up long runs when the instruction-level log is not needed.

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
  [--no-symbolic-registers] [--no-symbolic-memory] \
  [--analysis <profile> [<profile> ...]] [--max-input-rounds <n>] [--dry-run] \
  [--no-panic-prepass] \
  [--max-goroutine-switches <n>] [--max-loop-iterations <n>] \
  [--max-goroutines-per-site <n>] [--max-goroutine-instructions <n>] \
  [--schedule <rr|random>] [--schedule-seed <n>]
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
- `--analysis <profile>`: what to look for, see [Choosing what to look for](#choosing-what-to-look-for---analysis). Repeatable; several profiles can also follow one flag, separated by spaces or commas.
- `--max-input-rounds <n>` (default 4): with `data-race`, `channel-safety` or `toctou`, how many more runs the launcher makes with the inputs Zorya solves (`next_seed`). `0` runs once.
- `--dry-run`: print the resolved command and settings, and exit.
- `--race-only`: deprecated alias of `--analysis data-race`.
- `--no-panic-prepass`: skip the panic cross-reference prepass (the Ghidra pass that writes `results/xref_addresses.txt`). Panic reachability gating is then off.
- `--max-goroutine-switches <n>` (default 512): goroutine context-switch budget.
- `--max-loop-iterations <n>` (default 3): loop iterations a goroutine may run, counted at back-edges to the same loop head in application code, before it is retired. `0` disables the limit.
- `--max-goroutines-per-site <n>` (default 2): goroutines created by one `go` statement. Further executions of the statement return without creating a goroutine.
- `--max-goroutine-instructions <n>` (default 2000000): instruction budget per goroutine.
- `--schedule rr|random` (default `rr`): deterministic round-robin, or a seeded random schedule.
- `--schedule-seed <n>`: seed of the random schedule. The seed of every random run is recorded in `results/race_summary.json`, so the run can be replayed.

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
- `ZORYA_INT_ARITH_ORACLES=1`: enables expensive integer arithmetic solver oracles (`INT_ADD`/`INT_SUB`/`INT_MULT` overflow/underflow SAT checks). Disabled by default to keep concolic instruction throughput high during race-focused runs. `--analysis arithmetic` sets it.
- `ZORYA_MEM_SAFETY_ORACLES=1`: enables symbolic NULL / dangling-pointer memory safety checks in `LOAD`/`STORE`. By default, these checks are auto-disabled for multithreaded C/C++ runs (`--thread-scheduling all-threads`) to avoid stalls in race-analysis workflows. `--analysis memory-safety` sets it to `1`, and an analysis made only of `data-race`, `channel-safety` and `toctou` sets it to `0`; a value set in the environment wins.
- `ZORYA_GOROUTINE_SCHED=0`: force-disables the Go goroutine-spawn hook even under `--thread-scheduling all-threads` (falls back to the historical `runtime.newproc` stub, a plain caller-return). The hook is enabled by default whenever round-robin scheduling is active; see [Multi-threading.md](Multi-threading.md#goroutine-aware-scheduling-go).
- `ARG_ASCII_PROFILE=digits|printable`: restricts every symbolic argument byte to `0`..`9` or to printable ASCII when Zorya solves for an input. It applies to the SAT reports in `FOUND_SAT_STATE.txt`, to the Volos triggering and escape inputs and to the candidate seeds, so the reported inputs can be typed back on a command line. Unlike the printable preference of the concurrency analyses, it is a hard limit.
- `ZORYA_TIMEOUT_SECS=<n>`: wall-clock budget for the concolic run. When it is reached, Zorya stops like on Ctrl+C and still writes the plugin findings.
- `ZORYA_SHUTDOWN_GRACE_SECS=<n>` (default 60): how long Zorya waits, after a signal, for the engine to reach a point where it can stop cleanly. If the engine is stuck in a long solve, the process exits without findings once this delay has passed.
- `ZORYA_FORCE_PANIC_XREF=1`: recomputes the panic cross-references (`results/xref_addresses.txt`) even if a cached table exists. The table is stored with the sha256 of the binary it was computed for (`results/xref_addresses.sha256`) and is only reused for that same binary, so this is rarely needed.
- `ZORYA_RACE_RESEED=<n>`: default of `--max-input-rounds`, kept for scripts written for `--race-only`.
- `ZORYA_VOLOS_MAP_INTERNALS=1`: also report raw accesses inside the Go map implementation, besides the map-level accesses of the application.
- `ZORYA_VOLOS_RUNTIME_RACES=1`: keep race pairs whose two sides both execute Go runtime internals. They are dropped by default.
- `ZORYA_VENDORED_STDLIB=<pkg>[,<pkg>...]`: standard-library packages (for example `net/http`) that the binary links as a vendored or modelled copy, so known advisories on them are not decided by the toolchain version.
- `ZORYA_AST_PANIC_STRICT=1`: makes the AST panic walk report a negated branch only when it leads to a panic without any further branch decision. By default the walk follows every edge up to its depth limit, which can report a harmless branch because a later, independent branch reaches a panic. See [Overlay-Path-Analysis.md](Overlay-Path-Analysis.md#which-branches-are-explored).

### Stopping a run

Ctrl+C (SIGINT), `timeout` (SIGTERM) and a closed terminal (SIGHUP) all stop the run gracefully. Zorya leaves the execution loop, runs the plugins' final analysis and writes `results/plugin_findings.txt`, so findings collected until then are kept. A second Ctrl+C exits immediately without findings. If the engine cannot reach a clean stopping point within `ZORYA_SHUTDOWN_GRACE_SECS`, it exits on its own, so `timeout` always ends the process.

Every run writes `results/run_status.json`. It lists the phases with their durations (p-code generation, memory dump, binary setup, panic prepass, symbolic argument setup, execution, goroutine scheduler exploration, SMT solving, report generation) and is rewritten at each phase change, so after a run killed by `timeout` it still names the phase that was running. Its `termination` object gives the outcome (`completed`, `timeout`, `signal` or `error`) and a reason such as `timeout during SMT solving: SIGTERM received`.

### Input-gated data races (Go)

Some data races only happen for some inputs: the goroutines that race are only created when a flag is set, or when a count is at least two. `--analysis data-race` finds those. Run it with a seed that does not trigger the race; Zorya finds the input itself:

```bash
zorya ./mailpit-proxy-assets --analysis data-race --arg 0 0
```

Two arguments are written `--arg 0 0`. `--arg "0 0"` passes a single argument containing a space, and the launcher prints a note when it sees one.

A run goes as follows:

1. The seed runs under the goroutine scheduler described in [Multi-threading.md](Multi-threading.md#goroutine-scheduling-model). Goroutines block on channels and `WaitGroup`s, run their defers, and are retired after a few loop iterations, and the run continues after `main.main` returns until the goroutines are done.
2. Volos records reads, writes, lock operations, happens-before edges and map operations. A race between two accesses is reported with the path condition of each access; their conjunction is the input gate of the race. The gate is solved for a triggering input, and its negation for an escaping input when one exists.
3. When the seed creates no goroutine, each negated branch is checked for a `go` statement. A branch counts when its overlay reaches `runtime.newproc`, or when a `go` statement is reachable in the control-flow graph from the negated side but not from the side the run took. The branch's condition is solved into a candidate seed. An earlier branch that contradicts it, such as the first half of a short-circuit `a || b`, is dropped from the condition. The engine does this for every concurrency analysis, so `channel-safety` and `toctou` get candidate seeds without Volos.
4. The launcher re-runs the binary with the best candidate (`next_seed`), up to `--max-input-rounds` times. Each round's reports are kept as `results/race_summary.round<N>.json`, `results/analysis_summary.round<N>.json` and so on.

For the Mailpit harness above, the seed `0 0` gives `1 " "`, then `1 1`, which reaches the race:

```text
[RACE] status: race_found (10 distinct race(s) reported)
[RACE] seed: ["1","1"]
[RACE] gate: argv[1][0] == '1' && argv[2][0] == '1'
[RACE] trigger: ["1","1"]
[RACE] escape: [" "," "]
[RACE]   read by goroutine 1001: main.rewriteCSS(): asset := assets[id] // BUG: missing assetsMutex.
[RACE]   write by goroutine 1003: main.cacheAsset(): delete(assets, id)
[RACE] schedule: g1 -> g1001 -> g1 -> g1002 -> g1 -> g1003 -> g1 -> g1001 -> g1002 -> g1003 -> g1
```

The gate is shown one constraint per argument byte when the bytes are constrained independently (`argv[2][0] in '2'..'9'` for "a digit of at least 2"), which Z3 checks to be equivalent to the full condition. Otherwise it is printed as the conjunction of the branch conditions. `gate_smt` always holds the raw SMT-LIB form.

`results/race_summary.json` holds the same answer in a parsable form:

- `status`: `race_found`; `gate_not_reached` (the seed did not create the goroutines, and `next_seed` does); `gate_reached_schedule_not_explored` (goroutines ran, but some were still blocked, or the budget or the timeout ended the run); `race_reached_not_reported` (application accesses conflicted, but were discarded as ordered or protected while the run relied on forced wake-ups or goroutines that failed in unmodelled code); `stdlib_fixed` (the racy code is in a standard-library package and the toolchain contains the fix); `no_concurrency`; `no_race`.
- `race_found`, `seed`, `gate`, `gate_smt`, `trigger`, `escape`, `schedule` (for example `"g1 -> g1001 -> g1"`), `next_seed`, `candidate_seeds`, `seeds_tried`. Each candidate seed has its gate, the branch it negates and `reached_by`: `overlay` when the overlay executed up to `runtime.newproc`, `static_cfg` when the `go` statement was only found in the control-flow graph. Executed candidates are preferred for `next_seed`.
- `accesses`: the two accesses of the main race, each with `kind`, `operation` (`main.rewriteCSS(): asset := assets[id]`), `function`, `goroutine`, `os_thread`, `pc`, `source`, `map_variable`, `key`, `locks_held` and `stack`. `races` lists up to 32 distinct races in the same form.
- `scheduler`: policy, seed, budgets, switches, forced wake-ups and the contexts still blocked at the end. `goroutines`: every goroutine with its entry function, its `go` statement and how it ended.
- `toolchain`: the Go version from the binary's build information and the standard-library advisories checked against it. `detector`: Volos counters. `run`: the `termination` object of `run_status.json`.

Zorya reads the Go version from the binary's build information and prints it. Some races are in the standard library (`net/http` for CVE-2020-15586): when the binary's toolchain already contains the fix, Zorya says so and the status is `stdlib_fixed`. To analyse such a race, build with a vulnerable toolchain, or vendor or model the vulnerable package so it is compiled as application code. A copy of the package under a module path is recognised as such; a copy under another name can be declared with `ZORYA_VENDORED_STDLIB=net/http` (comma-separated). Either way the toolchain version no longer decides the status.

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
- `results/plugin_findings.txt` and `results/plugin_findings.json`
- `results/FOUND_SAT_STATE.txt` and `results/FOUND_SAT_STATE.json`
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
