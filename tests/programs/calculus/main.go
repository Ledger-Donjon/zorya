package main

import (
	"fmt"
)

func main() {
	var x, y int
	fmt.Print("Enter two numbers (separated by space): ")
	fmt.Scanf("%d %d", &x, &y)

	sum := x + y
	fmt.Println("Sum:", sum)

	if sum > 10 {
		fmt.Println("Sum is greater than 10.")
	} else {
		fmt.Println("Sum is less than or equal to 10.")
	}

	for i := 0; i < 5; i++ {
		fmt.Println("Iteration:", i)
	}

	product := multiply(x, y)
	fmt.Println("Product:", product)
}

func multiply(a, b int) int {
	return a * b
}