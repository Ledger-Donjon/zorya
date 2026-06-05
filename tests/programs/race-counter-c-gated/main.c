// SPDX-FileCopyrightText: 2026 Ledger https://www.ledger.com - INSTITUT MINES TELECOM
//
// SPDX-License-Identifier: Apache-2.0

/*
 * race-counter-c-gated — input × concurrency coupling for the volos plugin.
 *
 * This is the end-to-end companion to tests/tests_volos_input_gated.rs. Where
 * that integration test drives the EventBus directly, this binary is meant to
 * be run through the FULL Zorya pipeline (Ghidra p-code + GDB dump + concolic
 * execution + round-robin scheduling) so the input-gated race is discovered
 * from real symbolic argv, not synthetic events.
 *
 * Scenario S1 — InputDependent race
 * ─────────────────────────────────
 * Two threads write the same unprotected global `counter`:
 *
 *   writer_gated : writes counter ONLY when the first byte of argv[1] is 'K'.
 *                  The write therefore sits behind a branch on symbolic input,
 *                  so its path condition is  φ = (arg1_byte0 == 'K').
 *
 *   writer_plain : writes counter unconditionally — path condition is empty.
 *
 * When both writes are observed under round-robin scheduling, volos sees a
 * Write/Write race on `counter`. Because one racing access carries φ and the
 * negation ¬φ does NOT witness the gated write, volos classifies it as
 * InputDependent and attaches the witness model (arg1_byte0 = 'K').
 *
 * Compare with:
 *   race-counter-c-simple  — S2, Unconditional / InputIndependent (no gate)
 *   race-counter-c-mutex   — S4, mutex-protected, no race (negative control)
 *
 * Build
 * ─────
 *   gcc -O0 -g -no-pie -pthread -fcf-protection=none main.c -o race-counter-c-gated
 *
 *   -no-pie               keeps calls on the classic .plt so the pthread_create
 *                         / pthread_join symbol hooks match.
 *   -fcf-protection=none  avoids .plt.sec endbr/CET indirection.
 *
 * Run (symbolic argv + all-threads scheduling)
 * ───
 *   zorya tests/programs/race-counter-c-gated/race-counter-c-gated \
 *     --lang c \
 *     --thread-scheduling all-threads \
 *     --mode main \
 *     --arg "K" \
 *     --negate-path-exploration
 *
 * Expected: volos reports a Write vs Write data race on `counter`, classified
 * as InputDependent, with a witness assignment for arg1_byte0.
 */

#include <pthread.h>

/* Shared global — deliberately unprotected. */
int counter = 0;

/* Gated writer: the racing write is reachable only when the input gate is 'K'. */
void *writer_gated(void *arg)
{
    const char *s = (const char *)arg; /* points at argv[1] */
    if (s != 0 && s[0] == 'K') {
        counter = 1; /* RACE — only on the input class {arg1_byte0 == 'K'} */
    }
    return 0;
}

/* Plain writer: always races, no input dependence. */
void *writer_plain(void *arg)
{
    (void)arg;
    counter = 2; /* RACE — unconditional */
    return 0;
}

int main(int argc, char **argv)
{
    pthread_t t1, t2;

    /* argv[1] is symbolized by Zorya; argc is fixed by --arg. */
    char *gate = (argc > 1) ? argv[1] : 0;

    pthread_create(&t1, NULL, writer_gated, gate);
    pthread_create(&t2, NULL, writer_plain, NULL);

    pthread_join(t1, NULL);
    pthread_join(t2, NULL);

    return 0;
}
