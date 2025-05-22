package main

import (
	"fmt"
	"os"
	"strconv"
)

// coreEngine performs integer calculations and returns the result.
func coreEngine(num1 int, operator string, num2 int) (int, error) {
	var result int

	switch operator {
	case "+":
		result = num1 + num2
	case "-":
		result = num1 - num2
	case "*":
		result = num1 * num2
	case "/":
		if num2 == 0 {
			return 0, fmt.Errorf("error: division by zero is not allowed")
		}
		result = num1 / num2
	default:
		return 0, fmt.Errorf("error: unsupported operator. Use one of +, -, *, /")
	}

	// Intentional panic trigger
	if num1 == 5 && num2 == 5 {
		var p *int
		*p = 0
	}

	return result, nil
}

func main() {
	if len(os.Args) != 4 {
		fmt.Println("Usage: ./broken-calculator-tinygo [num1] [operator] [num2]")
		return
	}

	num1, err1 := strconv.Atoi(os.Args[1])
	operator := os.Args[2]
	num2, err2 := strconv.Atoi(os.Args[3])

	if err1 != nil || err2 != nil {
		fmt.Println("Error: Both arguments must be valid integers.")
		return
	}

	result, err := coreEngine(num1, operator, num2)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Printf("Result: %d\n", result)
}
