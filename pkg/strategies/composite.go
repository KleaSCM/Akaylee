/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: composite.go
Description: Composite mutator for the Akaylee Fuzzer. Allows chaining and composition of multiple mutation strategies for maximum test case diversity.
Supports both sequential and random chaining of mutators.
*/

package strategies

import (
	"math/rand"
	"time"

	"github.com/kleascm/akaylee-fuzzer/pkg/interfaces"
)

// CompositeMutator composes multiple Mutator instances for chained mutation.
// Supports both sequential and random chaining of mutators.
type CompositeMutator struct {
	mutators    []interfaces.Mutator // List of mutators to chain
	chainLength int                  // Number of mutators to apply per mutation
	randomOrder bool                 // If true, apply mutators in random order
}

// NewCompositeMutator creates a new CompositeMutator.
// mutators: list of mutators to chain
// chainLength: number of mutators to apply per mutation (default: len(mutators) if 0)
// randomOrder: if true, apply mutators in random order
func NewCompositeMutator(mutators []interfaces.Mutator, chainLength int, randomOrder bool) *CompositeMutator {
	if chainLength <= 0 || chainLength > len(mutators) {
		chainLength = len(mutators)
	}
	return &CompositeMutator{
		mutators:    mutators,
		chainLength: chainLength,
		randomOrder: randomOrder,
	}
}

// Mutate applies a chain of mutators to the test case.
// The chain can be sequential or random, based on configuration.
func (c *CompositeMutator) Mutate(testCase *interfaces.TestCase) (*interfaces.TestCase, error) {
	if len(c.mutators) == 0 {
		return nil, nil
	}

	mutated := testCase
	order := make([]int, len(c.mutators))
	for i := range order {
		order[i] = i
	}

	if c.randomOrder {
		rand.Seed(time.Now().UnixNano())
		rand.Shuffle(len(order), func(i, j int) { order[i], order[j] = order[j], order[i] })
	}

	for i := 0; i < c.chainLength; i++ {
		idx := order[i]
		mutator := c.mutators[idx]
		var err error
		mutated, err = mutator.Mutate(mutated)
		if err != nil {
			return nil, err
		}
		// Optionally, merge metadata
		if mutated.Metadata == nil {
			mutated.Metadata = make(map[string]interface{})
		}
		mutated.Metadata["composite_chain"] = c.Name()
	}

	return mutated, nil
}

// Name returns the name of this mutator.
func (c *CompositeMutator) Name() string {
	return "CompositeMutator"
}

// Description returns a description of this mutator.
func (c *CompositeMutator) Description() string {
	return "Chains multiple mutators for diverse, powerful mutations (sequential or random order)"
}
