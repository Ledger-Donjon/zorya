// Zorya ChanCheck harness (test4): realistic send-on-closed-channel bug
// inspired by graceful-shutdown / cancellation races found in real Go
// services (worker-pool "result" channels closed on a cancel/shutdown
// signal while a producer path still writes a final status). This class
// of bug has caused DoS panics in production Go servers (NATS, go-ethereum,
// Docker/moby-style dispatchers) where a channel is closed to release a
// blocked waiter but a mis-ordered cleanup still sends on it.
//
// Real-world shape: a request dispatcher reads a 1-byte opcode.
//   - opPing / opData: normal usage (send result, then close).
//   - opCancel:        teardown closes the result channel to unblock any
//                      waiter, but the status-reporting cleanup then
//                      publishes a final code on the already-closed
//                      channel -> panic("send on closed channel").
//
// The bug is gated on: opcode == opCancel (0x03).
//
// Build: CGO_ENABLED=0 go build -gcflags=all='-N -l' -o chancheck-test4-shutdown-race .
package main

import "os"

const (
	opPing   = 0x01
	opData   = 0x02
	opCancel = 0x03
)

func main() {
	if len(os.Args) < 2 {
		return
	}
	req := []byte(os.Args[1])
	if len(req) == 0 {
		return
	}
	handleRequest(req[0])
}

//go:noinline
func handleRequest(opcode byte) {
	results := make(chan int, 1)

	switch opcode {
	case opPing:
		results <- 0
		close(results)
	case opData:
		results <- 42
		close(results)
	case opCancel:
		// Teardown: close the channel to release any blocked waiter...
		shutdown(results)
		// ...but the cleanup path still reports a final status code on the
		// now-closed channel. This is the invariant violation.
		reportStatus(results, -1)
	}
}

//go:noinline
func shutdown(results chan int) {
	close(results)
}

//go:noinline
func reportStatus(results chan int, code int) {
	results <- code
}
