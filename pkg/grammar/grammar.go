/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: grammar.go
Description: Grammar interface and JSONGrammar implementation for grammar-based fuzzing in the Akaylee Fuzzer. Enables structure-aware input generation and mutation.
*/

package grammar

import (
	"encoding/json"
	"math/rand"
	"time"
)

// Grammar defines the interface for grammar-based input generation and mutation.
type Grammar interface {
	// Generate returns a new valid input as a byte slice.
	Generate() ([]byte, error)
	// Mutate takes a valid input and returns a mutated, still-valid input.
	Mutate(input []byte) ([]byte, error)
	// Name returns the name of the grammar.
	Name() string
}

// JSONGrammar implements Grammar for JSON data.
type JSONGrammar struct{}

// NewJSONGrammar creates a new JSONGrammar instance.
func NewJSONGrammar() *JSONGrammar {
	return &JSONGrammar{}
}

// Generate returns a random valid JSON object as bytes.
func (g *JSONGrammar) Generate() ([]byte, error) {
	rand.Seed(time.Now().UnixNano())
	obj := map[string]interface{}{
		"key":  rand.Intn(1000),
		"flag": rand.Intn(2) == 1,
		"data": []interface{}{rand.Float64(), rand.Intn(100)},
	}
	return json.Marshal(obj)
}

// Mutate takes a valid JSON input and returns a mutated, still-valid JSON input.
func (g *JSONGrammar) Mutate(input []byte) ([]byte, error) {
	var obj map[string]interface{}
	if err := json.Unmarshal(input, &obj); err != nil {
		return g.Generate() // fallback to new
	}
	// Mutate a random key
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	if len(keys) > 0 {
		k := keys[rand.Intn(len(keys))]
		obj[k] = rand.Intn(1000)
	}
	return json.Marshal(obj)
}

// Name returns the name of the grammar.
func (g *JSONGrammar) Name() string {
	return "JSONGrammar"
}
