/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: mutators.go
Description: Advanced mutation strategies for the Akaylee Fuzzer. Implements multiple
mutation algorithms including bit flipping, byte substitution, arithmetic mutations,
structure-aware mutations, and crossover operations. Provides maximum test case diversity
for comprehensive fuzzing coverage.
*/

package strategies

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/kleascm/akaylee-fuzzer/pkg/interfaces"
)

// BitFlipMutator implements bit-level mutation strategy
// Flips individual bits in the test case data for fine-grained mutations
type BitFlipMutator struct {
	mutationRate float64 // Probability of mutation per bit
}

// NewBitFlipMutator creates a new bit flip mutator
func NewBitFlipMutator(mutationRate float64) *BitFlipMutator {
	return &BitFlipMutator{
		mutationRate: mutationRate,
	}
}

// Mutate creates a new test case by flipping bits in the original
func (m *BitFlipMutator) Mutate(testCase *interfaces.TestCase) (*interfaces.TestCase, error) {
	// Create copy of original data
	mutatedData := make([]byte, len(testCase.Data))
	copy(mutatedData, testCase.Data)

	// Flip bits based on mutation rate
	for i := 0; i < len(mutatedData)*8; i++ {
		if rand.Float64() < m.mutationRate {
			byteIndex := i / 8
			bitIndex := i % 8
			mutatedData[byteIndex] ^= 1 << bitIndex
		}
	}

	// Create new test case
	mutated := &interfaces.TestCase{
		ID:         generateTestCaseID(),
		Data:       mutatedData,
		ParentID:   testCase.ID,
		Generation: testCase.Generation + 1,
		CreatedAt:  time.Now(),
		Priority:   testCase.Priority,
		Metadata:   make(map[string]interface{}),
	}

	mutated.Metadata["mutator"] = m.Name()
	mutated.Metadata["mutation_rate"] = m.mutationRate

	return mutated, nil
}

// Name returns the name of this mutator
func (m *BitFlipMutator) Name() string {
	return "BitFlipMutator"
}

// Description returns a description of this mutator
func (m *BitFlipMutator) Description() string {
	return "Flips individual bits in test case data for fine-grained mutations"
}

// Add Init() to all mutators for stateful setup
func (m *BitFlipMutator) Init() error { return nil }

// ByteSubstitutionMutator implements byte-level substitution strategy
// Replaces bytes with random values or predefined patterns
type ByteSubstitutionMutator struct {
	mutationRate float64 // Probability of mutation per byte
}

// NewByteSubstitutionMutator creates a new byte substitution mutator
func NewByteSubstitutionMutator(mutationRate float64) *ByteSubstitutionMutator {
	return &ByteSubstitutionMutator{
		mutationRate: mutationRate,
	}
}

// Mutate creates a new test case by substituting bytes in the original
func (m *ByteSubstitutionMutator) Mutate(testCase *interfaces.TestCase) (*interfaces.TestCase, error) {
	// Create copy of original data
	mutatedData := make([]byte, len(testCase.Data))
	copy(mutatedData, testCase.Data)

	// Substitute bytes based on mutation rate
	for i := 0; i < len(mutatedData); i++ {
		if rand.Float64() < m.mutationRate {
			mutatedData[i] = byte(rand.Intn(256))
		}
	}

	// Create new test case
	mutated := &interfaces.TestCase{
		ID:         generateTestCaseID(),
		Data:       mutatedData,
		ParentID:   testCase.ID,
		Generation: testCase.Generation + 1,
		CreatedAt:  time.Now(),
		Priority:   testCase.Priority,
		Metadata:   make(map[string]interface{}),
	}

	mutated.Metadata["mutator"] = m.Name()
	mutated.Metadata["mutation_rate"] = m.mutationRate

	return mutated, nil
}

// Name returns the name of this mutator
func (m *ByteSubstitutionMutator) Name() string {
	return "ByteSubstitutionMutator"
}

// Description returns a description of this mutator
func (m *ByteSubstitutionMutator) Description() string {
	return "Substitutes bytes with random values for coarse-grained mutations"
}

// Add Init() to all mutators for stateful setup
func (m *ByteSubstitutionMutator) Init() error { return nil }

// ArithmeticMutator implements arithmetic mutation strategy
// Performs arithmetic operations on numeric values in the test case
type ArithmeticMutator struct {
	mutationRate float64 // Probability of mutation per potential numeric value
}

// NewArithmeticMutator creates a new arithmetic mutator
func NewArithmeticMutator(mutationRate float64) *ArithmeticMutator {
	return &ArithmeticMutator{
		mutationRate: mutationRate,
	}
}

// Mutate creates a new test case by performing arithmetic operations
func (m *ArithmeticMutator) Mutate(testCase *interfaces.TestCase) (*interfaces.TestCase, error) {
	// Create copy of original data
	mutatedData := make([]byte, len(testCase.Data))
	copy(mutatedData, testCase.Data)

	// Perform arithmetic mutations on potential numeric values
	for i := 0; i < len(mutatedData)-3; i++ {
		if rand.Float64() < m.mutationRate {
			// Try to interpret as 32-bit integer
			value := int32(mutatedData[i]) | int32(mutatedData[i+1])<<8 |
				int32(mutatedData[i+2])<<16 | int32(mutatedData[i+3])<<24

			// Apply arithmetic operations
			operations := []func(int32) int32{
				func(x int32) int32 { return x + 1 },
				func(x int32) int32 { return x - 1 },
				func(x int32) int32 { return x * 2 },
				func(x int32) int32 { return x / 2 },
				func(x int32) int32 { return x ^ 0x7FFFFFFF },
				func(x int32) int32 { return x + 0x1000 },
				func(x int32) int32 { return x - 0x1000 },
			}

			operation := operations[rand.Intn(len(operations))]
			newValue := operation(value)

			// Write back to data
			mutatedData[i] = byte(newValue & 0xFF)
			mutatedData[i+1] = byte((newValue >> 8) & 0xFF)
			mutatedData[i+2] = byte((newValue >> 16) & 0xFF)
			mutatedData[i+3] = byte((newValue >> 24) & 0xFF)
		}
	}

	// Create new test case
	mutated := &interfaces.TestCase{
		ID:         generateTestCaseID(),
		Data:       mutatedData,
		ParentID:   testCase.ID,
		Generation: testCase.Generation + 1,
		CreatedAt:  time.Now(),
		Priority:   testCase.Priority,
		Metadata:   make(map[string]interface{}),
	}

	mutated.Metadata["mutator"] = m.Name()
	mutated.Metadata["mutation_rate"] = m.mutationRate

	return mutated, nil
}

// Name returns the name of this mutator
func (m *ArithmeticMutator) Name() string {
	return "ArithmeticMutator"
}

// Description returns a description of this mutator
func (m *ArithmeticMutator) Description() string {
	return "Performs arithmetic operations on numeric values in test cases"
}

// Add Init() to all mutators for stateful setup
func (m *ArithmeticMutator) Init() error { return nil }

// StructureAwareMutator implements structure-aware mutation strategy
// Maintains data structure integrity while performing mutations
type StructureAwareMutator struct {
	mutationRate float64 // Probability of mutation per structural element
}

// NewStructureAwareMutator creates a new structure-aware mutator
func NewStructureAwareMutator(mutationRate float64) *StructureAwareMutator {
	return &StructureAwareMutator{
		mutationRate: mutationRate,
	}
}

// Mutate creates a new test case with structure-aware mutations
func (m *StructureAwareMutator) Mutate(testCase *interfaces.TestCase) (*interfaces.TestCase, error) {
	// Create copy of original data
	mutatedData := make([]byte, len(testCase.Data))
	copy(mutatedData, testCase.Data)

	// Apply structure-aware mutations
	mutatedData = m.applyStructureMutations(mutatedData)

	// Create new test case
	mutated := &interfaces.TestCase{
		ID:         generateTestCaseID(),
		Data:       mutatedData,
		ParentID:   testCase.ID,
		Generation: testCase.Generation + 1,
		CreatedAt:  time.Now(),
		Priority:   testCase.Priority,
		Metadata:   make(map[string]interface{}),
	}

	mutated.Metadata["mutator"] = m.Name()
	mutated.Metadata["mutation_rate"] = m.mutationRate

	return mutated, nil
}

// applyStructureMutations applies structure-aware mutations to data
func (m *StructureAwareMutator) applyStructureMutations(data []byte) []byte {
	if len(data) < 4 {
		return data
	}

	// Try to identify and preserve common data structures
	for i := 0; i < len(data)-3; i++ {
		if rand.Float64() < m.mutationRate {
			// Preserve potential length fields
			if i > 0 && data[i-1] == 0x00 && data[i] > 0 {
				// This might be a length field, mutate carefully
				data[i] = byte(rand.Intn(int(data[i]) + 10))
			} else {
				// Regular mutation
				data[i] = byte(rand.Intn(256))
			}
		}
	}

	return data
}

// Name returns the name of this mutator
func (m *StructureAwareMutator) Name() string {
	return "StructureAwareMutator"
}

// Description returns a description of this mutator
func (m *StructureAwareMutator) Description() string {
	return "Performs mutations while preserving data structure integrity"
}

// Add Init() to all mutators for stateful setup
func (m *StructureAwareMutator) Init() error { return nil }

// CrossOverMutator implements crossover mutation strategy
// Combines parts of multiple test cases to create new ones
type CrossOverMutator struct {
	mutationRate float64 // Probability of crossover operation
}

// NewCrossOverMutator creates a new crossover mutator
func NewCrossOverMutator(mutationRate float64) *CrossOverMutator {
	return &CrossOverMutator{
		mutationRate: mutationRate,
	}
}

// Mutate creates a new test case by combining parts of multiple test cases
func (m *CrossOverMutator) Mutate(testCase *interfaces.TestCase) (*interfaces.TestCase, error) {
	// For crossover, we need multiple test cases
	// This is a simplified implementation that creates variations
	mutatedData := make([]byte, len(testCase.Data))
	copy(mutatedData, testCase.Data)

	// Apply crossover-like operations
	if rand.Float64() < m.mutationRate {
		// Split and recombine data
		splitPoint := rand.Intn(len(mutatedData))
		firstPart := mutatedData[:splitPoint]
		secondPart := mutatedData[splitPoint:]

		// Create new data by recombining parts
		newData := make([]byte, 0, len(mutatedData))
		newData = append(newData, secondPart...)
		newData = append(newData, firstPart...)

		// Ensure we don't exceed original length
		if len(newData) > len(mutatedData) {
			newData = newData[:len(mutatedData)]
		} else if len(newData) < len(mutatedData) {
			// Pad with random data
			padding := make([]byte, len(mutatedData)-len(newData))
			rand.Read(padding)
			newData = append(newData, padding...)
		}

		mutatedData = newData
	}

	// Create new test case
	mutated := &interfaces.TestCase{
		ID:         generateTestCaseID(),
		Data:       mutatedData,
		ParentID:   testCase.ID,
		Generation: testCase.Generation + 1,
		CreatedAt:  time.Now(),
		Priority:   testCase.Priority,
		Metadata:   make(map[string]interface{}),
	}

	mutated.Metadata["mutator"] = m.Name()
	mutated.Metadata["mutation_rate"] = m.mutationRate

	return mutated, nil
}

// Name returns the name of this mutator
func (m *CrossOverMutator) Name() string {
	return "CrossOverMutator"
}

// Description returns a description of this mutator
func (m *CrossOverMutator) Description() string {
	return "Combines parts of multiple test cases to create new ones"
}

// Add Init() to all mutators for stateful setup
func (m *CrossOverMutator) Init() error { return nil }

// generateTestCaseID generates a unique test case ID
func generateTestCaseID() string {
	// Generate random bytes
	bytes := make([]byte, 16)
	rand.Read(bytes)

	// Convert to hex string
	id := ""
	for _, b := range bytes {
		id += fmt.Sprintf("%02x", b)
	}

	return id
}
