// SPDX-FileCopyrightText: 2026 Ledger https://www.ledger.com - INSTITUT MINES TELECOM
//
// SPDX-License-Identifier: Apache-2.0

/*
 * race-counter-c-simple — idiomatic C data race for the volos plugin.
 *
 * Unlike tests/programs/race-counter-c/main.c, this program needs NO
 * adaptation to Zorya's execution model. It is a textbook pthreads data race:
 * two threads write the same unprotected global. There is no zorya_entry()
 * breakpoint helper, no spin barrier, no direct SYS_exit, and no eager-binding
 * link flag.
 *
 * It works because Zorya now hooks the library boundary directly:
 *
 *   pthread_create  — intercepted at the PLT. Zorya allocates a stack for the
 *                     child, seeds its registers (entry = start_routine,
 *                     RDI = arg), and registers it with the scheduler. No
 *                     worker threads need to exist in the GDB dump, so we can
 *                     break at `main` itself.
 *
 *   pthread_join    — intercepted at the PLT. Zorya blocks the caller and
 *                     yields to the joinee, then resumes the caller once the
 *                     joinee has exited. This is the PLT fallback: an address
 *                     with no lifted pcode no longer terminates the run.
 *
 *   thread return   — when a start_routine executes its final `ret`, it pops
 *                     a sentinel return address that Zorya planted on the
 *                     child stack; the engine treats it as thread exit.
 *
 * Build
 * ─────
 *   gcc -O0 -g -no-pie -pthread -fcf-protection=none main.c -o race-counter-c-simple
 *
 *   -no-pie            keeps calls going through the classic .plt so the
 *                      symbol hook can match `plt_pthread_create` etc.
 *   -fcf-protection=none avoids .plt.sec indirection from endbr/CET so the
 *                      call target is the named .plt entry.
 *
 * Run (break at main; the worker threads are created at runtime)
 * ───
 *   ADDR=$(nm race-counter-c-simple | awk '/T main$/{print "0x"$1}')
 *   zorya tests/programs/race-counter-c-simple/race-counter-c-simple \
 *     --lang c \
 *     --thread-scheduling all-threads \
 *     --mode function "$ADDR" \
 *     --arg none \
 *     --no-negate-path-exploration
 *
 * Expected: volos reports a Write vs Write data race on `counter`.
 */

#include <pthread.h>

/* Shared global — deliberately unprotected. */
int counter = 0;

void *writer(void *arg)
{
    counter = *(int *)arg; /* RACE: unsynchronised write to the shared global */
    return NULL;
}

int main(void)
{
    pthread_t t1, t2;
    int a = 1, b = 2;

    pthread_create(&t1, NULL, writer, &a);
    pthread_create(&t2, NULL, writer, &b);

    pthread_join(t1, NULL);
    pthread_join(t2, NULL);

    return 0;
}
