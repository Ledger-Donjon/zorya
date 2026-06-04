// SPDX-FileCopyrightText: 2026 Ledger https://www.ledger.com - INSTITUT MINES TELECOM
//
// SPDX-License-Identifier: Apache-2.0

/*
 * race-counter-c-mixed — combined positive/negative control for volos.
 *
 * Two globals. Two worker threads. One mutex.
 *
 *   safe_counter   — written under `lock`. No race; volos must be silent.
 *   unsafe_counter — written with NO lock.  Data race; volos must report it.
 *
 * This lets a single run exercise both halves of the detector at once:
 *   - lock tracking correctly populates the lockset for `safe_counter`.
 *   - the unprotected-race rule fires for `unsafe_counter`.
 *
 * Expected volos output
 * ─────────────────────
 *   # 4 finding(s)    ← 4 bytes of unsafe_counter raced across 2 threads
 *   [volos::data-race-unprotected] Data race at 0x<addr_of_unsafe_counter+N>
 *   ...
 *   (no finding for safe_counter)
 *
 * Build
 * ─────
 *   gcc -O0 -g -no-pie -pthread -fcf-protection=none main.c -o race-counter-c-mixed
 *
 * Run
 * ───
 *   ADDR=$(nm race-counter-c-mixed | awk '/T main$/{print "0x"$1}')
 *   zorya tests/programs/race-counter-c-mixed/race-counter-c-mixed \
 *     --lang c \
 *     --thread-scheduling all-threads \
 *     --mode function "$ADDR" \
 *     --arg none \
 *     --no-negate-path-exploration
 */

#include <pthread.h>

int safe_counter   = 0;   /* protected by `lock`  */
int unsafe_counter = 0;   /* deliberately naked   */

pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

void *worker(void *arg)
{
    int val = *(int *)arg;

    /* protected write — both threads hold the same lock */
    pthread_mutex_lock(&lock);
    safe_counter = val;
    pthread_mutex_unlock(&lock);

    /* unprotected write — intentional race */
    unsafe_counter = val;

    return NULL;
}

int main(void)
{
    pthread_t t1, t2;
    int a = 1, b = 2;

    pthread_create(&t1, NULL, worker, &a);
    pthread_create(&t2, NULL, worker, &b);

    pthread_join(t1, NULL);
    pthread_join(t2, NULL);

    return 0;
}
