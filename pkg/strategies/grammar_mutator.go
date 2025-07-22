/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: grammar_mutator.go
Description: GrammarMutator for structure-aware fuzzing in the Akaylee Fuzzer. Uses a Grammar to generate and mutate valid inputs with advanced configuration options. Implements interfaces.Mutator.
*/

package strategies

import (
	"time"

	"github.com/kleascm/akaylee-fuzzer/pkg/grammar"
	"github.com/kleascm/akaylee-fuzzer/pkg/interfaces"
)

// GrammarMutator uses a Grammar to generate and mutate structure-aware inputs.
type GrammarMutator struct {
	grammar       grammar.Grammar
	seedKeys      []string // Optional seed keys for target-aware generation
	maxDepth      int      // Maximum recursion depth for deep fuzzing
	mutationCount int64    // Track number of mutations performed
}

// NewGrammarMutator creates a new GrammarMutator with the given Grammar.
func NewGrammarMutator(g grammar.Grammar) *GrammarMutator {
	return &GrammarMutator{
		grammar:  g,
		maxDepth: 5, // Default max depth
	}
}

// NewGrammarMutatorWithConfig creates a new GrammarMutator with advanced configuration.
func NewGrammarMutatorWithConfig(g grammar.Grammar, seedKeys []string, maxDepth int) *GrammarMutator {
	return &GrammarMutator{
		grammar:  g,
		seedKeys: seedKeys,
		maxDepth: maxDepth,
	}
}

// SetSeedKeys sets the seed keys for target-aware generation.
func (m *GrammarMutator) SetSeedKeys(keys []string) {
	m.seedKeys = keys
	// If the grammar supports seed keys, configure it
	if jsonGrammar, ok := m.grammar.(*grammar.JSONGrammar); ok {
		jsonGrammar.SetSeedKeys(keys)
	}
}

// SetMaxDepth sets the maximum recursion depth for deep fuzzing.
func (m *GrammarMutator) SetMaxDepth(depth int) {
	m.maxDepth = depth
	// If the grammar supports max depth, configure it
	if jsonGrammar, ok := m.grammar.(*grammar.JSONGrammar); ok {
		jsonGrammar.SetMaxDepth(depth)
	}
}

// GetSeedKeys returns the current seed keys.
func (m *GrammarMutator) GetSeedKeys() []string {
	return m.seedKeys
}

// GetMaxDepth returns the current max depth.
func (m *GrammarMutator) GetMaxDepth() int {
	return m.maxDepth
}

// GetMutationCount returns the number of mutations performed.
func (m *GrammarMutator) GetMutationCount() int64 {
	return m.mutationCount
}

// Mutate creates a new test case by mutating the input using the grammar.
func (m *GrammarMutator) Mutate(testCase *interfaces.TestCase) (*interfaces.TestCase, error) {
	// Increment mutation counter
	m.mutationCount++

	// Try to mutate existing data first
	var mutatedData []byte
	var err error

	if len(testCase.Data) > 0 {
		mutatedData, err = m.grammar.Mutate(testCase.Data)
		if err != nil {
			// If mutation fails, generate new data
			mutatedData, err = m.grammar.Generate()
			if err != nil {
				return nil, err
			}
		}
	} else {
		// If no data, generate new data
		mutatedData, err = m.grammar.Generate()
		if err != nil {
			return nil, err
		}
	}

	// Create enhanced metadata
	metadata := map[string]interface{}{
		"mutator":        m.Name(),
		"grammar":        m.grammar.Name(),
		"mutation_count": m.mutationCount,
		"max_depth":      m.maxDepth,
		"has_seed_keys":  len(m.seedKeys) > 0,
	}

	// Add seed keys info if available
	if len(m.seedKeys) > 0 {
		metadata["seed_keys"] = m.seedKeys
	}

	// Add data size info
	metadata["original_size"] = len(testCase.Data)
	metadata["mutated_size"] = len(mutatedData)

	return &interfaces.TestCase{
		ID:         generateTestCaseID(),
		Data:       mutatedData,
		ParentID:   testCase.ID,
		Generation: testCase.Generation + 1,
		CreatedAt:  time.Now(),
		Priority:   testCase.Priority,
		Metadata:   metadata,
	}, nil
}

// Name returns the name of this mutator.
func (m *GrammarMutator) Name() string {
	return "GrammarMutator"
}

// Description returns a description of this mutator.
func (m *GrammarMutator) Description() string {
	desc := "Mutates inputs using a structure-aware grammar for valid, deep fuzzing."
	if len(m.seedKeys) > 0 {
		desc += " Uses seed keys for target-aware generation."
	}
	if m.maxDepth > 5 {
		desc += " Supports deep recursive mutation."
	}
	return desc
}

// Init initializes the grammar mutator with configuration.
func (m *GrammarMutator) Init() error {
	// Configure grammar with current settings
	if jsonGrammar, ok := m.grammar.(*grammar.JSONGrammar); ok {
		if len(m.seedKeys) > 0 {
			jsonGrammar.SetSeedKeys(m.seedKeys)
		}
		jsonGrammar.SetMaxDepth(m.maxDepth)
	}
	return nil
}
