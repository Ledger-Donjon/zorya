// Zorya TOCTOU harness: exercises the SO_PEERCRED → readlink(/proc/pid/exe)
// pattern from ordain's credential agent in an isolated, analysable binary.
//
// The TOCTOU window is between getsockopt and readlink: the PID obtained from
// SO_PEERCRED could be recycled if the original process exits before readlink
// executes. Zorya's toctou plugin should flag this pair.
//
// This version uses a LINEAR execution flow (no goroutines) so the concolic
// executor can trace the full path without needing goroutine scheduling.
// The accept() syscall in Zorya returns a virtual fd immediately.
//
// Build: CGO_ENABLED=0 go build -o toctou-test1-no-inputs .
package main

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

func main() {
	data := os.Args
	if len(data) < 2 {
		data = []string{"harness", "\x00"}
	}
	dispatch([]byte(data[1]))
}

func dispatch(input []byte) {
	socketPath := "/tmp/zorya-toctou-test.sock"
	os.Remove(socketPath)

	// Create server socket
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

	// Accept a connection (Zorya's accept returns a virtual fd immediately).
	connFD, _, err := syscall.Accept(serverFD)
	if err != nil {
		fmt.Fprintf(os.Stderr, "accept: %v\n", err)
		return
	}
	defer syscall.Close(connFD)

	// ─── CHECK: get peer credentials (PID) via SO_PEERCRED ───────────────
	cred, err := getsockoptUcred(connFD)
	if err != nil {
		fmt.Fprintf(os.Stderr, "getsockopt SO_PEERCRED: %v\n", err)
		return
	}
	pid := cred.Pid

	// ─── RACE WINDOW ─────────────────────────────────────────────────────
	// Between here and the readlink below, the PID could be recycled if the
	// peer process exits. An attacker who can cause PID reuse in this window
	// bypasses the identity check.

	// ─── USE: verify process executable via /proc/<pid>/exe ──────────────
	exePath := fmt.Sprintf("/proc/%d/exe", pid)
	target, err := os.Readlink(exePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "readlink %s: %v\n", exePath, err)
		return
	}
	fmt.Printf("Peer PID=%d executable: %s\n", pid, target)
}

// getsockoptUcred wraps the SO_PEERCRED getsockopt call.
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
