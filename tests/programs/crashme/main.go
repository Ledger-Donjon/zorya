package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage: ./crashme [char]")
		return
	}
	if os.Args[1][0] == 'C' {
		var p *int
		*p = 0
	}
	fmt.Println("OK")
}
