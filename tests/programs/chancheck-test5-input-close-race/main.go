// Chancheck harness: a malicious input that races a channel close.
//
// A producer goroutine forwards each input byte over the unbuffered channel
// ch; a control goroutine closes ch early when the first input byte is the
// sentinel 0xCA. If the close is ordered before one of the producer's sends,
// Go panics with "send on closed channel". The crash needs both the right
// input (len(data) > 0 && data[0] == 0xCA) and the right interleaving
// (close before send).
//
// Build: CGO_ENABLED=0 go build -gcflags=all='-N -l' -o chancheck-test5-input-close-race .
package main

import "os"

func main() {
	if len(os.Args) < 2 {
		return
	}
	dispatch([]byte(os.Args[1]))
}

//go:noinline
func dispatch(data []byte) {
	ch := make(chan int)

	go func() { // producer
		for _, b := range data {
			ch <- int(b) // send, panics if ch is already closed
		}
	}()
	go func() { // control
		if len(data) > 0 && data[0] == 0xCA {
			close(ch) // early close on a crafted first byte
		}
	}()

	<-ch // consume one result
}
