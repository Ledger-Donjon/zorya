// Chancheck harness: close/send race using thread-cooperative scheduling.
//
// Both close and send are in the same goroutine but separated by a function
// call boundary (where Zorya's thread scheduler can interleave). The close
// happens inside a helper; the send happens in the caller. Zorya's scheduler
// can switch threads between function calls, simulating the race.
//
// Build: CGO_ENABLED=0 go build -gcflags=all='-N -l' -o chancheck-test3-racy-close-send .
package main

import "os"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "__skip__" {
		return
	}

	ch := make(chan int, 1)

	// The close and send are separated by a function call boundary.
	// Zorya's round-robin scheduler can interleave another thread between
	// closeChannel returning and the send below, testing whether chancheck
	// correctly identifies the close-before-send invariant violation.
	closeChannel(ch)
	ch <- 42
}

//go:noinline
func closeChannel(ch chan int) {
	close(ch)
}
