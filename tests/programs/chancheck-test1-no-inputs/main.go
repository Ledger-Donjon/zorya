// Zorya ChanCheck harness: exercises the send-on-closed-channel pattern.
//
// This program creates a channel, closes it, then sends on it. In normal Go
// execution this panics ("send on closed channel"). Zorya's chancheck plugin
// should detect the invariant violation by observing:
//   1. runtime.makechan (channel creation)
//   2. runtime.closechan (channel close)
//   3. runtime.chansend1 (send attempt on the closed channel)
//
// This version unconditionally triggers the bug (no input gating).
//
// Build: CGO_ENABLED=0 go build -o chancheck-test1-no-inputs .
package main

import (
	"fmt"
	"os"
)

func main() {
	ch := make(chan int, 1)

	fmt.Fprintln(os.Stderr, "Closing channel...")
	close(ch)

	fmt.Fprintln(os.Stderr, "Sending on closed channel (BUG)...")
	ch <- 42
	// In normal Go execution, the line above panics.
	// Zorya's chancheck plugin should flag it before the panic.

	fmt.Println("Unreachable")
}
