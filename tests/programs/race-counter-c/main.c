// SPDX-FileCopyrightText: 2026 Ledger https://www.ledger.com - INSTITUT MINES TELECOM
//
// SPDX-License-Identifier: Apache-2.0

/*
 * race-counter-c — minimal C data race for the volos plugin.
 *
 * Three-problem solution
 * ─────────────────────
 * Problem 1 – only one thread in GDB dump
 *   GDB normally captures at `main` entry before pthread_create runs.
 *   Fix: zorya_entry() is a named function called by main AFTER both
 *   threads are alive and spinning.  Use --mode function <zorya_entry_addr>
 *   so GDB breaks there.  At that moment all 3 thread states are in the dump.
 *
 * Problem 2 – PLT lazy binding blocks execution
 *   At program entry the GOT entries for libc symbols are unresolved.
 *   Fix: compile with -Wl,-z,now (eager binding).  By the time GDB reaches
 *   zorya_entry(), all PLT entries including pthread_create and pthread_join
 *   have been resolved.
 *
 * Problem 3 – main terminates on pthread_join@plt
 *   pthread_join is a libc PLT stub that Zorya has no lifted pcode for.
 *   When main reaches it the instruction loop exits and the simulation
 *   terminates before the writer threads have run.
 *   Fix: main exits via direct_exit(0) right after zorya_entry().  Zorya's
 *   sys_exit handler marks main as exited and switches to the writers.
 *
 * Thread exit without libc
 * ────────────────────────
 * After the racy write, each writer exits via a direct SYS_exit (60) inline
 * asm.  This avoids any libc pthread cleanup path that Zorya might not handle.
 *
 * Expected Zorya flow
 * ───────────────────
 *   1. Zorya starts at zorya_entry() with 3 threads loaded.
 *   2. zorya_entry() sets go_flag = 1, returns (≈10 instructions).
 *   3. Main calls direct_exit(0) — sys_exit handler exits main and
 *      switches to writer_a.
 *   4. writer_a: go_flag==1 → exits spin → counter=1 (MemWrite A) → SYS_exit.
 *   5. Scheduler switches to writer_b → counter=2 (MemWrite B) → SYS_exit.
 *   6. on_finish: volos sees two concurrent writes at counter → race reported.
 *
 * Build
 * ─────
 *   gcc -O0 -g -no-pie -pthread -Wl,-z,now main.c -o race-counter-c
 *
 * Run
 * ───
 *   ADDR=$(nm race-counter-c | awk '/T zorya_entry/{print "0x"$1}')
 *   zorya tests/programs/race-counter-c/race-counter-c \
 *     --lang c \
 *     --thread-scheduling all-threads \
 *     --mode function "$ADDR" \
 *     --arg none \
 *     --no-negate-path-exploration
 *
 * Note: the C thread time-slice (50 pcode instructions) is hardcoded in
 * src/main.rs under THREAD_TIME_SLICE defaults — do not pass it on the
 * command line.
 */

#define _GNU_SOURCE
#include <pthread.h>
#include <stdatomic.h>

/* Shared global — deliberately unprotected. */
volatile int counter = 0;

/*
 * go_flag == 0: writers spin-wait before the race.
 * go_flag == 1: set by zorya_entry() — writers proceed to the racy write.
 */
static volatile int go_flag = 0;

/* Both writers increment this before entering their spin.
 * main waits until it reaches 2 before calling zorya_entry(). */
static atomic_int ready_count = ATOMIC_VAR_INIT(0);

/*
 * Direct SYS_exit (syscall 60) — exits the current thread without
 * going through any libc cleanup path.  Zorya handles syscall 60
 * as ThreadExit, fires the event, and removes the thread from the
 * scheduler.
 */
static inline void __attribute__((noreturn)) direct_exit(int code)
{
    __asm__ volatile(
        "mov %0, %%edi\n"
        "mov $60, %%rax\n"   /* SYS_exit */
        "syscall\n"
        :: "r"(code) : "rax", "rdi"
    );
    __builtin_unreachable();
}

/*
 * zorya_spin() — tight spin until go_flag is set.
 *
 * Compiled as a separate non-inline function so it appears as a real
 * stack frame in the GDB thread backtraces — making it easy to confirm
 * both writers are waiting here when the dump is taken.
 */
__attribute__((noinline)) static void zorya_spin(void)
{
    while (!go_flag)
        ; /* busy wait */
}

/*
 * zorya_entry() — THE GDB BREAKPOINT AND ZORYA START POINT.
 *
 * When GDB stops here:
 *   - writer_a is in zorya_spin() (go_flag == 0)
 *   - writer_b is in zorya_spin() (go_flag == 0)
 *   - all three thread states are captured in the dump
 *
 * When Zorya simulates from here:
 *   - sets go_flag = 1 → both writers exit their spin
 *   - writers execute their racy stores
 *   - writers exit via SYS_exit (Zorya syscall 60 handler)
 */
__attribute__((noinline)) void zorya_entry(void)
{
    go_flag = 1; /* release both writers */
}

void *writer_a(void *arg)
{
    (void)arg;
    atomic_fetch_add(&ready_count, 1); /* signal: I'm ready */
    zorya_spin();
    counter = 1;       /* RACE: Write A — volos target */
    direct_exit(0);
}

void *writer_b(void *arg)
{
    (void)arg;
    atomic_fetch_add(&ready_count, 1); /* signal: I'm ready */
    zorya_spin();
    counter = 2;       /* RACE: Write B — volos target */
    direct_exit(0);
}

int main(void)
{
    pthread_t t1, t2;
    pthread_create(&t1, NULL, writer_a, NULL);
    pthread_create(&t2, NULL, writer_b, NULL);

    /* Wait until both writers are inside zorya_spin(). */
    while (atomic_load(&ready_count) < 2)
        ;

    zorya_entry(); /* ← GDB breakpoint here */

    /*
     * WHY direct_exit instead of pthread_join:
     *
     * Zorya only lifts pcode for the binary's own functions.  pthread_join
     * lives in libc and is reached through the PLT — a stub that has no
     * lifted pcode.  When the simulation's instruction loop encounters an
     * address outside its map it terminates immediately, killing all threads
     * before the writers have a chance to run.
     *
     * direct_exit(0) issues SYS_exit (syscall 60) directly.  Zorya's
     * sys_exit handler catches it, marks this thread as exited, and hands
     * control to the next ready writer thread via the scheduler.
     *
     * TODO(zorya): teach the instruction loop to yield to other ready
     * threads — rather than terminating the whole simulation — when the
     * current thread reaches an address outside the lifted pcode map.
     * That would let binaries keep their real pthread_join calls here.
     */
    direct_exit(0);
}
