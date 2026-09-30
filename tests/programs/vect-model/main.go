// SPDX-FileCopyrightText: 2026 Ledger https://www.ledger.com - INSTITUT MINES TELECOM
//
// SPDX-License-Identifier: Apache-2.0
//
// vect-model — a model of the VECT 2.0 bug *structure*, for Zorya.
//
// Built only from the public analyses (Check Point, Morphisec, JUMPSEC, 2026);
// VECT's C++ source was never released and the live sample is not run here.
// The model does no file I/O, no encryption, no network: it keeps the defects
// and drops the capability, like the benchmark corpora in the talk.
//
// What is faithful to VECT:
//   - ONE process-global I/O buffer, reused across all encryptor workers
//     (Morphisec: the per-file buffers are not thread-local).
//   - The ONLY size comparison in the code is the 128 KB large-file branch
//     (Check Point). There is no "32 KB < size <= 128 KB" test anywhere.
//   - On the single-pass path (size <= 128 KB) the read length is written into
//     the fixed-size buffer with no bound against it (JUMPSEC). Writing the
//     last byte of the read therefore overflows the 32 KB buffer as soon as
//     the file is larger than that buffer. The 32 here is the buffer's size,
//     not a hand-written gate.
//
// Sizes are in KB units to keep the model small (VECT uses bytes: 0x8000 and
// 0x20000). os.Args[1] is the file size in KB, as three decimal digits, parsed
// without strconv so the solver sees one expression over the input bytes.
//
// Build: CGO_ENABLED=0 go build -gcflags=all='-N -l' -o vect-model .
//
// Run (symbolic os.Args, all-threads scheduling, Volos):
//
//	ZORYA_FORCE_PANIC_XREF=1 zorya "$PWD/vect-model" --lang go --compiler gc \
//	  --mode main --thread-scheduling all-threads --arg "016" \
//	  --negate-path-exploration --plugin "volos"
//
// --arg "016" seeds a 16 KB file, in bounds, so the concrete seed run completes
// and Volos observes the shared-buffer race; three digits let the solver reach
// both sides of the 128 KB branch and the out-of-bounds write.
package main

import (
	"os"
)

// VECT sizes, in KB units (real: 0x8000 and 0x20000 bytes).
const (
	bufKB   = 32  // 32 KB I/O buffer (VirtualAlloc), reused across workers
	largeKB = 128 // 128 KB single-pass vs four-chunk threshold
)

// ioBuf is VECT's process-global I/O buffer, shared by every worker.
var ioBuf [bufKB]byte

// encryptInPlace mirrors VECT's per-file routine. The only size test is the
// 128 KB large-file branch; the 32 KB buffer is never compared against size.
//
//go:noinline
func encryptInPlace(sizeKB int) {
	if sizeKB <= largeKB {
		// Single-pass: the read length is used as the buffer offset with no
		// bound against bufKB, so the last written byte lands out of the
		// 32 KB buffer whenever the file is larger than it.
		ioBuf[sizeKB-1] = 0x41
	} else {
		// Four-chunk path: each read is capped at the 32 KB buffer (in bounds).
		for c := 0; c < 4; c++ {
			ioBuf[bufKB-1] = 0x42
		}
	}
}

// worker models one EncWorker goroutine handling one file.
//
//go:noinline
func worker(sizeKB int, done chan<- bool) {
	ioBuf[0] = byte(sizeKB) // shared-buffer write: races across workers
	encryptInPlace(sizeKB)
	done <- true
}

func main() {
	sizeKB := bufKB // default: a 32 KB file, in bounds
	if len(os.Args) > 1 && len(os.Args[1]) == 3 {
		d := os.Args[1] // symbolic: file size in KB, three decimal digits
		sizeKB = int(d[0]-'0')*100 + int(d[1]-'0')*10 + int(d[2]-'0')
	}

	done := make(chan bool, 2)
	go worker(sizeKB, done)
	go worker(sizeKB, done)
	<-done
	<-done
}
