// SPDX-FileCopyrightText: 2026 Ledger https://www.ledger.com - INSTITUT MINES TELECOM
//
// SPDX-License-Identifier: Apache-2.0

/*
 * race-counter-c-mutex — the *negative* control for the volos race detector.
 *
 * This is byte-for-byte the same program as race-counter-c-simple EXCEPT the
 * shared write is wrapped in a single global mutex. Both worker threads take
 * the SAME `pthread_mutex_t` before touching `counter`, so every access to the
 * shared cell holds a common lock.
 *
 * Purpose: prove that volos's lockset tracking actually suppresses a race.
 *   - race-counter-c-simple  → volos MUST report a Write-vs-Write data race.
 *   - race-counter-c-mutex   → volos MUST report NOTHING (the common lock makes
 *                              the accesses "protected").
 *
 * For this to work, Zorya must observe the pthread_mutex_lock/unlock calls and
 * attribute the mutex object (the pointer in RDI) to each thread's lockset:
 *
 *   pthread_mutex_lock  — intercepted at the PLT. The Call event carries the
 *                         mutex pointer in arg0 (RDI); volos pushes it onto the
 *                         calling thread's lockset (keyed by the mutex object,
 *                         not the PLT stub address).
 *   pthread_mutex_unlock— pops the matching lock from the lockset.
 *
 * When volos compares the two writes at end-of-trace, the lockset intersection
 * is non-empty ({&lock}), so the unprotected-race rule does not fire.
 *
 * Build
 * ─────
 *   gcc -O0 -g -no-pie -pthread -fcf-protection=none main.c -o race-counter-c-mutex
 *
 *   -no-pie              keeps calls going through the classic .plt so the
 *                        symbol hook can match `plt_pthread_mutex_lock` etc.
 *   -fcf-protection=none avoids .plt.sec indirection from endbr/CET so the
 *                        call target is the named .plt entry.
 *
 * Run (break at main; the worker threads are created at runtime)
 * ───
 *   ADDR=$(nm race-counter-c-mutex | awk '/T main$/{print "0x"$1}')
 *   zorya tests/programs/race-counter-c-mutex/race-counter-c-mutex \
 *     --lang c \
 *     --thread-scheduling all-threads \
 *     --mode function "$ADDR" \
 *     --arg none \
 *     --no-negate-path-exploration
 *
 * Expected: zero volos findings (the shared mutex protects every access).
 */

#include <pthread.h>

/* Shared global — protected by `lock` below. */
int counter = 0;

/* Single mutex shared by both writers. */
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

void *writer(void *arg)
{
    pthread_mutex_lock(&lock);
    counter = *(int *)arg; /* protected write — both threads hold `lock` */
    pthread_mutex_unlock(&lock);
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
