/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: inference.go
Description: Grammar inference command implementation for the Akaylee Fuzzer. Provides
advanced input structure inference from sample corpora with automatic format detection
and grammar generation for structure-aware fuzzing.
*/

package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kleascm/akaylee-fuzzer/pkg/inference"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// PerformGrammarInference analyzes a corpus and infers a grammar
func PerformGrammarInference(cmd *cobra.Command, args []string) error {
	fmt.Println("🧬 Akaylee Fuzzer - Grammar Inference")
	fmt.Println("=====================================")
	fmt.Println()

	// Load configuration first
	if err := LoadConfig(); err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	// Setup logging for inference
	if err := SetupLogging(); err != nil {
		return fmt.Errorf("failed to setup logging: %w", err)
	}

	// Get corpus directory from config or default
	corpusDir := viper.GetString("corpus_dir")
	if corpusDir == "" {
		corpusDir = "./corpus"
	}

	// Get format from flags or auto-detect
	format := viper.GetString("format")
	if format == "" {
		format = "auto"
	}

	fmt.Printf("📁 Analyzing corpus in: %s\n", corpusDir)
	fmt.Printf("🎯 Format: %s\n", format)
	fmt.Println()

	// Check if corpus directory exists
	if _, err := os.Stat(corpusDir); os.IsNotExist(err) {
		fmt.Printf("❌ Corpus directory not found: %s\n", corpusDir)
		fmt.Println("   Create a corpus directory with sample files first.")
		return nil
	}

	// Find sample files
	files, err := filepath.Glob(filepath.Join(corpusDir, "*"))
	if err != nil {
		return fmt.Errorf("failed to read corpus directory: %w", err)
	}

	sampleFiles := make([]string, 0)
	for _, file := range files {
		if info, err := os.Stat(file); err == nil && !info.IsDir() {
			sampleFiles = append(sampleFiles, file)
		}
	}

	if len(sampleFiles) == 0 {
		fmt.Println("📭 No sample files found.")
		fmt.Println("   Add sample files to the corpus directory first.")
		return nil
	}

	fmt.Printf("📊 Found %d sample files\n", len(sampleFiles))
	fmt.Println()

	// Auto-detect format if needed
	if format == "auto" {
		format = autoDetectFormat(sampleFiles)
		fmt.Printf("🔍 Auto-detected format: %s\n", format)
		fmt.Println()
	}

	// Create inference engine
	engine := inference.NewEngine(format)
	if engine == nil {
		return fmt.Errorf("unsupported format: %s", format)
	}

	// Load samples
	samples := make([][]byte, 0, len(sampleFiles))
	for i, sampleFile := range sampleFiles {
		fmt.Printf("📖 Loading sample %d/%d: %s\n", i+1, len(sampleFiles), filepath.Base(sampleFile))

		data, err := os.ReadFile(sampleFile)
		if err != nil {
			fmt.Printf("  ❌ Failed to read sample file: %v\n", err)
			continue
		}
		samples = append(samples, data)
	}

	if len(samples) == 0 {
		fmt.Println("❌ No valid samples loaded.")
		return nil
	}

	fmt.Printf("✅ Loaded %d valid samples\n", len(samples))
	fmt.Println()

	// Perform inference
	fmt.Println("🧠 Performing structure inference...")
	startTime := time.Now()

	grammar, err := engine.InferStructure(samples)
	if err != nil {
		return fmt.Errorf("inference failed: %w", err)
	}

	inferenceTime := time.Since(startTime)
	fmt.Printf("✅ Inference completed in %v\n", inferenceTime)
	fmt.Println()

	// Display results
	fmt.Println("📋 Inferred Grammar")
	fmt.Println("===================")
	fmt.Printf("Format: %s\n", grammar.Format)
	fmt.Printf("Root Rule: %s\n", grammar.RootRule)
	fmt.Printf("Samples Analyzed: %v\n", grammar.Metadata["samples"])
	fmt.Println()

	// Pretty print the grammar
	fmt.Println("📝 Grammar Rules:")
	prettyPrintGrammar(grammar)

	// Save grammar to file
	outputFile := fmt.Sprintf("inferred_grammar_%s.json", format)
	if err := saveGrammar(grammar, outputFile); err != nil {
		fmt.Printf("⚠️  Failed to save grammar: %v\n", err)
	} else {
		fmt.Printf("💾 Grammar saved to: %s\n", outputFile)
	}

	fmt.Println("\n✨ Grammar inference completed!")
	fmt.Println("   Use the inferred grammar with --grammar-type and --grammar-file flags.")

	return nil
}

// autoDetectFormat attempts to detect the format of sample files
func autoDetectFormat(files []string) string {
	if len(files) == 0 {
		return "json" // Default
	}

	// Check first few files for format indicators
	for _, file := range files[:min(3, len(files))] {
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}

		// Try to parse as JSON
		var v interface{}
		if json.Unmarshal(data, &v) == nil {
			return "json"
		}

		// Check for binary indicators (non-printable characters)
		if len(data) > 0 {
			binaryCount := 0
			for _, b := range data {
				if b < 32 && b != 9 && b != 10 && b != 13 { // Not tab, newline, carriage return
					binaryCount++
				}
			}
			if float64(binaryCount)/float64(len(data)) > 0.1 {
				return "binary"
			}
		}
	}

	return "json" // Default to JSON
}

// prettyPrintGrammar displays the grammar in a readable format
func prettyPrintGrammar(grammar *inference.Grammar) {
	rootRule := grammar.Rules["root"]
	if rootRule == nil {
		fmt.Println("  No root rule found")
		return
	}

	if rule, ok := rootRule.(map[string]interface{}); ok {
		printRule("root", rule, 2)
	}
}

// printRule recursively prints a grammar rule
func printRule(name string, rule map[string]interface{}, indent int) {
	indentStr := strings.Repeat("  ", indent)

	if types, ok := rule["types"].([]string); ok {
		fmt.Printf("%s%s: %s\n", indentStr, name, strings.Join(types, "|"))
	}

	if fields, ok := rule["fields"].(map[string]interface{}); ok {
		fmt.Printf("%s  fields:\n", indentStr)
		for fieldName, fieldRule := range fields {
			if fr, ok := fieldRule.(map[string]interface{}); ok {
				printRule(fieldName, fr, indent+2)
			}
		}
	}

	if required, ok := rule["required"].([]string); ok && len(required) > 0 {
		fmt.Printf("%s  required: %s\n", indentStr, strings.Join(required, ", "))
	}

	if optional, ok := rule["optional"].([]string); ok && len(optional) > 0 {
		fmt.Printf("%s  optional: %s\n", indentStr, strings.Join(optional, ", "))
	}

	if enum, ok := rule["enum"].([]string); ok && len(enum) > 0 {
		fmt.Printf("%s  enum: %s\n", indentStr, strings.Join(enum, ", "))
	}

	if min, ok := rule["min"].(float64); ok {
		fmt.Printf("%s  min: %v\n", indentStr, min)
	}

	if max, ok := rule["max"].(float64); ok {
		fmt.Printf("%s  max: %v\n", indentStr, max)
	}
}

// saveGrammar saves the grammar to a JSON file
func saveGrammar(grammar *inference.Grammar, filename string) error {
	data, err := json.MarshalIndent(grammar, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filename, data, 0644)
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
