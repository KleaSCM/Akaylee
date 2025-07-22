/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: grammar_mutator.go
Description: GrammarMutator for structure-aware fuzzing in the Akaylee Fuzzer. Uses a Grammar to generate and mutate valid inputs. Implements interfaces.Mutator.
*/

package strategies

import (
	"time"

	"github.com/kleascm/akaylee-fuzzer/pkg/grammar"
	"github.com/kleascm/akaylee-fuzzer/pkg/interfaces"
)

// GrammarMutator uses a Grammar to generate and mutate structure-aware inputs.
type GrammarMutator struct {
	grammar grammar.Grammar
}

// NewGrammarMutator creates a new GrammarMutator with the given Grammar.
func NewGrammarMutator(g grammar.Grammar) *GrammarMutator {
	return &GrammarMutator{grammar: g}
}

// Mutate creates a new test case by mutating the input using the grammar.
func (m *GrammarMutator) Mutate(testCase *interfaces.TestCase) (*interfaces.TestCase, error) {
	mutatedData, err := m.grammar.Mutate(testCase.Data)
	if err != nil {
		return nil, err
	}
	return &interfaces.TestCase{
		ID:         testCase.ID + "_grammar",
		Data:       mutatedData,
		ParentID:   testCase.ID,
		Generation: testCase.Generation + 1,
		CreatedAt:  time.Now(),
		Priority:   testCase.Priority,
		Metadata:   map[string]interface{}{"mutator": m.Name(), "grammar": m.grammar.Name()},
	}, nil
}

// Name returns the name of this mutator.
func (m *GrammarMutator) Name() string {
	return "GrammarMutator"
}

// Description returns a description of this mutator.
func (m *GrammarMutator) Description() string {
	return "Mutates inputs using a structure-aware grammar for valid, deep fuzzing."
}

// Init is a no-op for GrammarMutator.
func (m *GrammarMutator) Init() error { return nil }
