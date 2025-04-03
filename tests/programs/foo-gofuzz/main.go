// Exploit variants for go-fuzz/test.go functions

package main

import (
	"fmt"
	"math"
)

func main() {
	fooExploit()

}

func fooExploit() {
	x := math.Inf(-1)
	if foo(x) {
		fmt.Println("Passed foo")
	}
}

// Test for issue #35.
const X = 1 << 129

func foo(x float64) bool {
	return x < X
}