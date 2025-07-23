/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: grammar_demo.go
Description: Beautiful demo showcasing the enhanced grammar features including
seed keys, deep fuzzing, advanced mutation variability, and array/object support.
Demonstrates the  grammar implementation with real examples.
*/

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/kleascm/akaylee-fuzzer/pkg/grammar"
	"github.com/kleascm/akaylee-fuzzer/pkg/interfaces"
	"github.com/kleascm/akaylee-fuzzer/pkg/strategies"
)

func runGrammarDemo() {
	fmt.Println("🌸 Akaylee Fuzzer - Enhanced Grammar Demo 🌸")
	fmt.Println("=============================================")
	fmt.Println()

	// Demo 1: Basic JSON Generation
	demoBasicGeneration()

	// Demo 2: Seed Keys for Target-Aware Generation
	demoSeedKeys()

	// Demo 3: Deep Fuzzing with Nested Structures
	demoDeepFuzzing()

	// Demo 4: Advanced Mutation Variability
	demoMutationVariability()

	// Demo 5: Array and Object Mutation
	demoArrayObjectMutation()

	// Demo 6: Grammar Mutator with Configuration
	demoGrammarMutator()

	fmt.Println("🎉 Grammar Demo Complete! 🎉")
}

func demoBasicGeneration() {
	fmt.Println("✨ Demo 1: Basic JSON Generation")
	fmt.Println("--------------------------------")

	g := grammar.NewJSONGrammar()

	for i := 0; i < 3; i++ {
		data, err := g.Generate()
		if err != nil {
			log.Printf("Error generating JSON: %v", err)
			continue
		}

		// Pretty print the JSON
		var pretty interface{}
		json.Unmarshal(data, &pretty)
		prettyJSON, _ := json.MarshalIndent(pretty, "", "  ")

		fmt.Printf("Generated JSON %d:\n%s\n\n", i+1, string(prettyJSON))
	}
}

func demoSeedKeys() {
	fmt.Println("🌱 Demo 2: Seed Keys for Target-Aware Generation")
	fmt.Println("------------------------------------------------")

	// Define seed keys for a user profile API
	seedKeys := []string{"user_id", "username", "email", "age", "is_active", "created_at"}

	g := grammar.NewJSONGrammarWithSeeds(seedKeys)

	for i := 0; i < 3; i++ {
		data, err := g.Generate()
		if err != nil {
			log.Printf("Error generating JSON with seeds: %v", err)
			continue
		}

		// Pretty print the JSON
		var pretty interface{}
		json.Unmarshal(data, &pretty)
		prettyJSON, _ := json.MarshalIndent(pretty, "", "  ")

		fmt.Printf("Generated JSON with seed keys %d:\n%s\n\n", i+1, string(prettyJSON))
	}
}

func demoDeepFuzzing() {
	fmt.Println("🌳 Demo 3: Deep Fuzzing with Nested Structures")
	fmt.Println("-----------------------------------------------")

	g := grammar.NewJSONGrammar()
	g.SetMaxDepth(4) // Allow deeper nesting

	for i := 0; i < 3; i++ {
		data, err := g.Generate()
		if err != nil {
			log.Printf("Error generating deep JSON: %v", err)
			continue
		}

		// Pretty print the JSON
		var pretty interface{}
		json.Unmarshal(data, &pretty)
		prettyJSON, _ := json.MarshalIndent(pretty, "", "  ")

		fmt.Printf("Generated deep JSON %d:\n%s\n\n", i+1, string(prettyJSON))
	}
}

func demoMutationVariability() {
	fmt.Println("🎭 Demo 4: Advanced Mutation Variability")
	fmt.Println("----------------------------------------")

	g := grammar.NewJSONGrammar()

	// Create a test JSON with various types
	originalJSON := `{
		"string_field": "hello world",
		"number_field": 42.5,
		"integer_field": 100,
		"boolean_field": true,
		"array_field": [1, 2, 3],
		"object_field": {"nested": "value"}
	}`

	originalData := []byte(originalJSON)

	fmt.Println("Original JSON:")
	var original interface{}
	json.Unmarshal(originalData, &original)
	originalPretty, _ := json.MarshalIndent(original, "", "  ")
	fmt.Println(string(originalPretty))
	fmt.Println()

	// Show multiple mutations
	for i := 0; i < 3; i++ {
		mutatedData, err := g.Mutate(originalData)
		if err != nil {
			log.Printf("Error mutating JSON: %v", err)
			continue
		}

		fmt.Printf("Mutation %d:\n", i+1)
		var mutated interface{}
		json.Unmarshal(mutatedData, &mutated)
		mutatedPretty, _ := json.MarshalIndent(mutated, "", "  ")
		fmt.Println(string(mutatedPretty))
		fmt.Println()
	}
}

func demoArrayObjectMutation() {
	fmt.Println("🔗 Demo 5: Array and Object Mutation")
	fmt.Println("------------------------------------")

	g := grammar.NewJSONGrammar()

	// Test array mutation
	fmt.Println("Array Mutation:")
	originalArray := `[1, "hello", true, {"key": "value"}]`
	arrayData := []byte(originalArray)

	fmt.Printf("Original array: %s\n", originalArray)

	for i := 0; i < 2; i++ {
		mutatedArray, err := g.Mutate(arrayData)
		if err != nil {
			log.Printf("Error mutating array: %v", err)
			continue
		}

		fmt.Printf("Mutated array %d: %s\n", i+1, string(mutatedArray))
	}
	fmt.Println()

	// Test object mutation
	fmt.Println("Object Mutation:")
	originalObject := `{"name": "test", "value": 42, "active": true}`
	objectData := []byte(originalObject)

	fmt.Printf("Original object: %s\n", originalObject)

	for i := 0; i < 2; i++ {
		mutatedObject, err := g.Mutate(objectData)
		if err != nil {
			log.Printf("Error mutating object: %v", err)
			continue
		}

		fmt.Printf("Mutated object %d: %s\n", i+1, string(mutatedObject))
	}
	fmt.Println()
}

func demoGrammarMutator() {
	fmt.Println("🎪 Demo 6: Grammar Mutator with Configuration")
	fmt.Println("---------------------------------------------")

	// Create grammar with configuration
	seedKeys := []string{"id", "name", "status", "priority"}
	maxDepth := 3

	jsonGrammar := grammar.NewJSONGrammar()
	jsonGrammar.SetSeedKeys(seedKeys)
	jsonGrammar.SetMaxDepth(maxDepth)

	// Create grammar mutator with advanced configuration
	mutator := strategies.NewGrammarMutatorWithConfig(jsonGrammar, seedKeys, maxDepth)

	// Create a test case
	testCase := &interfaces.TestCase{
		ID:         "demo-test",
		Data:       []byte(`{"id": 1, "name": "demo"}`),
		Generation: 0,
		CreatedAt:  time.Now(),
		Priority:   100,
	}

	fmt.Printf("Configuration:\n")
	fmt.Printf("  Seed Keys: %v\n", mutator.GetSeedKeys())
	fmt.Printf("  Max Depth: %d\n", mutator.GetMaxDepth())
	fmt.Printf("  Mutation Count: %d\n", mutator.GetMutationCount())
	fmt.Println()

	// Perform mutations
	for i := 0; i < 3; i++ {
		mutated, err := mutator.Mutate(testCase)
		if err != nil {
			log.Printf("Error in grammar mutation: %v", err)
			continue
		}

		fmt.Printf("Mutation %d:\n", i+1)
		fmt.Printf("  ID: %s\n", mutated.ID)
		fmt.Printf("  Parent ID: %s\n", mutated.ParentID)
		fmt.Printf("  Generation: %d\n", mutated.Generation)
		fmt.Printf("  Priority: %d\n", mutated.Priority)
		fmt.Printf("  Data: %s\n", string(mutated.Data))
		fmt.Printf("  Metadata: %+v\n", mutated.Metadata)
		fmt.Println()
	}

	fmt.Printf("Final mutation count: %d\n", mutator.GetMutationCount())
	fmt.Println()
}
