// Zorya TOCTOU harness (input-gated variant): the SO_PEERCRED -> readlink
// pattern only executes when the client sends a specific request type.
//
// This tests that Zorya's concolic engine can symbolically explore the branch
// and discover the TOCTOU bug is reachable for specific input values.
//
// The agent speaks a tiny request protocol: the first byte of the client
// message is an opcode. Only the privileged "verify peer" opcode performs the
// SO_PEERCRED-based identity check; every other opcode is served without ever
// touching peer credentials. This mirrors how a real credential agent gates
// expensive/privileged verification behind a specific request type. Zorya must
// symbolically solve which opcode reaches the vulnerable check-then-use.
//
// Build: CGO_ENABLED=0 go build -o toctou-test2-with-input .
package main

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

// Request opcodes understood by the agent. Only opVerifyPeer is privileged and
// performs peer-identity verification (the vulnerable check-then-use path).
const (
	opPing       = 0x01 // liveness probe, no credentials needed
	opVerifyPeer = 0x02 // privileged: authenticate the connecting peer
	opEcho       = 0x03 // echo payload back, no credentials needed
)

func main() {
	data := os.Args
	if len(data) < 2 {
		data = []string{"harness", "\x00"}
	}
	dispatch([]byte(data[1]))
}

func dispatch(input []byte) {
	socketPath := "/tmp/zorya-toctou-test2.sock"
	os.Remove(socketPath)

	serverFD, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "socket: %v\n", err)
		return
	}
	defer syscall.Close(serverFD)

	addr := &syscall.SockaddrUnix{Name: socketPath}
	if err := syscall.Bind(serverFD, addr); err != nil {
		fmt.Fprintf(os.Stderr, "bind: %v\n", err)
		return
	}
	defer os.Remove(socketPath)

	if err := syscall.Listen(serverFD, 1); err != nil {
		fmt.Fprintf(os.Stderr, "listen: %v\n", err)
		return
	}

	connFD, _, err := syscall.Accept(serverFD)
	if err != nil {
		fmt.Fprintf(os.Stderr, "accept: %v\n", err)
		return
	}
	defer syscall.Close(connFD)

	// ─── REQUEST DISPATCH (INPUT GATE) ──────────────────────────────────
	// The first byte of the client message is the request opcode. Only the
	// privileged "verify peer" opcode triggers the SO_PEERCRED identity
	// check; all other opcodes are served without touching peer credentials.
	// Zorya must solve this constraint symbolically to reach the vulnerable
	// path (opcode == opVerifyPeer).
	if len(input) == 0 || input[0] != opVerifyPeer {
		fmt.Println("Safe path: non-privileged request, skipping identity verification")
		return
	}

	// ─── CHECK: get peer credentials (PID) via SO_PEERCRED ──────────────
	cred, err := getsockoptUcred(connFD)
	if err != nil {
		fmt.Fprintf(os.Stderr, "getsockopt SO_PEERCRED: %v\n", err)
		return
	}
	pid := cred.Pid

	// ─── RACE WINDOW ────────────────────────────────────────────────────
	// Between here and the readlink below, the PID could be recycled.

	// ─── USE: verify process executable via /proc/<pid>/exe ─────────────
	exePath := fmt.Sprintf("/proc/%d/exe", pid)
	target, err := os.Readlink(exePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "readlink %s: %v\n", exePath, err)
		return
	}
	fmt.Printf("Peer PID=%d executable: %s\n", pid, target)
}

func getsockoptUcred(fd int) (*syscall.Ucred, error) {
	var cred syscall.Ucred
	credLen := uint32(unsafe.Sizeof(cred))
	_, _, errno := syscall.Syscall6(
		syscall.SYS_GETSOCKOPT,
		uintptr(fd),
		uintptr(syscall.SOL_SOCKET),
		uintptr(syscall.SO_PEERCRED),
		uintptr(unsafe.Pointer(&cred)),
		uintptr(unsafe.Pointer(&credLen)),
		0,
	)
	if errno != 0 {
		return nil, errno
	}
	return &cred, nil
}
