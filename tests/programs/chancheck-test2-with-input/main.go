// Zorya ChanCheck harness (input-gated variant): the send-on-closed-channel
// pattern only triggers when the input argument satisfies a condition.
//
// The vulnerable path is gated on: input[0] == 'X' (0x58)
// - If the condition is NOT met, the program returns safely.
// - If the condition IS met, the channel is closed then sent on (panic).
//
// Build: CGO_ENABLED=0 go build -gcflags=all='-N -l' -o chancheck-test2-with-input .
package main

import "os"

func main() {
	if len(os.Args) < 2 {
		return
	}
	input := []byte(os.Args[1])
	dispatch(input)
}

//go:noinline
func dispatch(input []byte) {
	ch := make(chan int, 1)

	if len(input) == 0 || input[0] != 'X' {
		return
	}

	// Vulnerable path: close then send (panics in real Go)
	closeChannel(ch)
	ch <- 42
}

//go:noinline
func closeChannel(ch chan int) {
	close(ch)
}
