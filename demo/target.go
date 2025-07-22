// Author: KleaSCM
// Email: KleaSCM@gmail.com
// File: target.go
// Description: Simple Go target for fuzzing demo. Contains a function with multiple code paths and a possible crash for coverage-guided fuzzing.

package main

import (
	"fmt"
	"os"
)

// FuzzMe is the function under test. It panics on a magic input.
func FuzzMe(data []byte) {
	if len(data) < 4 {
		return
	}
	if string(data) == "CRSH" {
		panic("demo crash: magic input detected!")
	}
	if data[0] == 'A' && data[1] == 'B' && data[2] == 'C' {
		fmt.Println("ABC path reached!")
	}
	if data[0] == 0xFF && data[1] == 0x00 {
		fmt.Println("FF00 path reached!")
	}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: target <inputfile>")
		os.Exit(1)
	}
	input, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Println("Failed to read input:", err)
		os.Exit(1)
	}
	FuzzMe(input)
}
