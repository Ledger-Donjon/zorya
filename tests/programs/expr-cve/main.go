package main

import (
    "fmt"
    "os"

    // vulnerable release:
    // go get github.com/expr-lang/expr@v1.16.0
    "github.com/expr-lang/expr/conf"
    "github.com/expr-lang/expr/parser"
)

func main() {
    if len(os.Args) < 2 {
        fmt.Printf("Usage: %s <expr>\n", os.Args[0])
        os.Exit(1)
    }

    maliciousExpr := os.Args[1]

    // If 'maliciousExpr' is huge or deeply nested, it can explode memory usage.
    _, err := parser.ParseWithConfig(maliciousExpr, conf.CreateNew())

    if err != nil {
        fmt.Printf("Parse error: %v\n", err)
    } else {
        fmt.Println("Parse succeeded (may have created a massive AST).")
    }
}
