// SPDX-FileCopyrightText: 2026 Ledger https://www.ledger.com - INSTITUT MINES TELECOM
//
// SPDX-License-Identifier: Apache-2.0

// panic-send-closed-channel — input-triggered send-on-closed-channel panic.
//
// The control goroutine closes `ch` only when data[0] == 0xCA.
// If that close happens before the producer send, Go panics:
// "send on closed channel".
package main

import "os"

func dispatch(data []byte) {
	ch := make(chan int)

	go func() { // producer
		v := 0
		if len(data) > 0 {
			v = int(data[0])
		}
		ch <- v // panics if ch was already closed
	}()

	go func() { // control
		if len(data) > 0 && data[0] == 0xCA {
			close(ch) // early close on crafted first byte
		}
	}()

	<-ch // consume one value when no panic path is taken
}

func main() {
	var data []byte
	if len(os.Args) > 1 {
		data = []byte(os.Args[1])
	} else {
		// Keep at least one byte by default for deterministic progress.
		data = []byte{'a'}
	}
	dispatch(data)
}
