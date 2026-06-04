# race-counter-c

Minimal C data race for end-to-end testing of the **volos** plugin.

## Design

Three problems had to be solved to make a C binary work with Zorya + volos.

### Problem 1 — only one thread in the GDB dump

Zorya's dump script runs the binary under GDB and stops at the `START_POINT`
address.  With `--mode main` that is `main()`, before any `pthread_create` call.
Only one thread (main) exists at that point.

**Fix:** `zorya_entry()` is a named symbol called by `main` **after** both
writer threads have been created and are spinning at a barrier.  Pass its address
as `--mode function 0x<zorya_entry_addr>`.  When GDB breaks there, all three
thread states (main + writer\_a + writer\_b) are in the dump.

### Problem 2 — PLT lazy binding blocks execution

At program entry, GOT entries for `pthread_create`, `pthread_join`, etc. are
unresolved (lazy binding).  Zorya's first call to `pthread_create@plt` follows
the PLT stub into the dynamic linker's resolver, which it cannot handle.

**Fix:** compile with `-Wl,-z,now` (eager binding).  All GOT entries are
resolved by the dynamic linker at startup before `main` is entered.  By the
time GDB breaks at `zorya_entry()`, every PLT entry is already filled in.

### Problem 3 — time slice too large to switch threads

The cooperative scheduler only switches at function-call checkpoints **after**
the time slice has expired.  `zorya_entry()` is ~8 instructions; with the
default Go slice of 10 000, the slice never expires before `main` calls
`pthread_join` (libc), and the writer threads never get scheduled.

**Fix:** the time slice is hardcoded to **10 instructions** for C/C++ binaries
in `src/main.rs`.  This guarantees the scheduler switches to a writer thread
at the first function-call checkpoint after `zorya_entry()` returns.  To
change the value, search for `"10"` in the `// C / C++ — 10 instructions`
block in `src/main.rs`.

### Thread exit without libc

After the racy write each writer exits via inline assembly `SYS_exit` (syscall
60), bypassing all libc pthread-cleanup paths.  Zorya handles syscall 60 as
`ThreadExit`, fires the event, and removes the thread from the scheduler.

## Expected execution flow in Zorya

```
1. Zorya starts at zorya_entry() — 3 threads loaded from dump.
2. zorya_entry() sets go_flag = 1, returns (~8 pcode ops).
3. main reaches pthread_join call — time-slice (10) expired → switch to writer_a.
4. writer_a: go_flag == 1 → exits spin → counter = 1  (MemWrite A, addr 0x404014)
            → direct_exit() → SYS_exit → ThreadExit.
5. Scheduler switches to writer_b → counter = 2  (MemWrite B) → ThreadExit.
6. on_finish: volos sees two concurrent writes at 0x404014 → race reported.
```

## Key addresses (recompile to refresh)

| Symbol        | Address      |
|---------------|--------------|
| `zorya_entry` | `0x4011a2`   |
| `zorya_spin`  | `0x40118b`   |
| `writer_a`    | `0x4011b7`   |
| `writer_b`    | `0x4011e8`   |
| `counter`     | `0x404014`   |

Re-run `nm race-counter-c | grep -E 'zorya_entry|counter'` after any recompile.

## Build

```bash
gcc -O0 -g -no-pie -pthread -Wl,-z,now main.c -o race-counter-c
```

## Run with Zorya

```bash
zorya tests/programs/race-counter-c/race-counter-c \
    --lang c \
    --thread-scheduling all-threads \
    --mode function 0x4011a2 \
    --arg none \
    --no-negate-path-exploration
```

Or derive the address automatically:

```bash
ADDR=$(nm tests/programs/race-counter-c/race-counter-c | awk '/T zorya_entry/{print "0x"$1}')
zorya tests/programs/race-counter-c/race-counter-c \
    --lang c \
    --thread-scheduling all-threads \
    --mode function "$ADDR" \
    --arg none \
    --no-negate-path-exploration
```

## Expected finding in `results/plugin_findings.txt`

```
[volos::data-race-unprotected] Data race at 0x404014
  Write (tid=<T1>, go=<G1>) vs Write (tid=<T2>, go=<G2>) — unprotected, clocks concurrent
```
