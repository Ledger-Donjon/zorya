package main

import (
    "fmt"
    "os"
    "strings"

    "github.com/golang-jwt/jwt/v4"
)

func main() {
    if len(os.Args) < 2 {
        fmt.Printf("Usage: %s <token-file>\n", os.Args[0])
        os.Exit(1)
    }

    tokenFile := os.Args[1]
    tokenBytes, err := os.ReadFile(tokenFile)
    if err != nil {
        panic(err)
    }

    maliciousToken := strings.TrimSpace(string(tokenBytes))

    parser := jwt.Parser{}
    _, parts, err := parser.ParseUnverified(maliciousToken, jwt.MapClaims{})

    fmt.Printf("Parts split length: %d\n", len(parts))
    if err != nil {
        fmt.Printf("Parse error: %v\n", err)
    }
}
