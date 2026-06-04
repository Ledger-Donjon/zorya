// SPDX-FileCopyrightText: 2026 Ledger https://www.ledger.com - INSTITUT MINES TELECOM
//
// SPDX-License-Identifier: Apache-2.0

// race-counter — minimal Go data race for the volos plugin.
//
// Two goroutines write to the same global `counter` with no
// synchronisation. Under volos this is the simplest possible witness:
// two `MemWrite` events at the same address from different tids, with
// disjoint (empty) locksets, vector clocks that compare to `None`
// (concurrent). Expected finding:
//
//   [volos::data-race-unprotected] Data race at 0x<addr_of_counter>:
//       Unprotected access (Write vs Write)
//
// Confirm under the standard Go race detector with:
//
//   go run -race ./tests/programs/race-counter
//
// which prints "DATA RACE" with stack traces from both goroutines.
//
// `sync.WaitGroup` is used purely so both goroutines reliably run
// before main exits. WaitGroup's internal atomic ops do *not* create a
// happens-before edge between the two goroutine writes — they only
// order each Done() before the corresponding Wait() return — so the
// writes themselves remain concurrent and volos will flag them.

package main

import (
	"fmt"
	"sync"
)

// Shared global, deliberately unprotected.
var counter int

func main() {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		counter = 1 // race: write from goroutine A
	}()

	go func() {
		defer wg.Done()
		counter = 2 // race: write from goroutine B
	}()

	wg.Wait()
	fmt.Println("counter =", counter)
}
