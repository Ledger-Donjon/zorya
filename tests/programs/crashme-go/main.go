// SPDX-FileCopyrightText: 2025 Ledger https://www.ledger.com - INSTITUT MINES TELECOM
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
)

func crash(arg byte) {
	if arg == 'K' {
		var p *int
		*p = 0
	}
}

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage: ./crashme [char]")
		return
	}
	arg := os.Args[1][0]
	crash(arg)
	fmt.Println("OK")
}
