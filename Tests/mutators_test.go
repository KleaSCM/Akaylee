/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: mutators_test.go
Description: Comprehensive tests for the mutation strategies. Tests bit flipping,
byte substitution, arithmetic mutations, structure-aware mutations, and crossover
operations with proper validation and edge case handling.
*/

package Tests

import (
	"bytes"
	"testing"
	"time"

	"github.com/kleascm/akaylee-fuzzer/pkg/core"
	"github.com/kleascm/akaylee-fuzzer/pkg/strategies"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBitFlipMutator tests the bit flip mutation strategy
func TestBitFlipMutator(t *testing.T) {
	mutator := strategies.NewBitFlipMutator(0.5) // 50% mutation rate

	originalData := []byte{0x00, 0xFF, 0x55, 0xAA}
	testCase := &core.TestCase{
		ID:         "test1",
		Data:       originalData,
		Generation: 0,
		CreatedAt:  time.Now(),
		Priority:   100,
	}

	// Test mutation
	mutated, err := mutator.Mutate(testCase)
	require.NoError(t, err)
	assert.NotNil(t, mutated)

	// Verify basic properties
	assert.NotEqual(t, testCase.ID, mutated.ID)
	assert.Equal(t, testCase.ID, mutated.ParentID)
	assert.Equal(t, testCase.Generation+1, mutated.Generation)
	assert.Equal(t, len(originalData), len(mutated.Data))

	// Verify metadata
	assert.Equal(t, "BitFlipMutator", mutated.Metadata["mutator"])
	assert.Equal(t, 0.5, mutated.Metadata["mutation_rate"])

	// Test mutator interface
	assert.Equal(t, "BitFlipMutator", mutator.Name())
	assert.Contains(t, mutator.Description(), "bit")
}

// TestByteSubstitutionMutator tests the byte substitution mutation strategy
func TestByteSubstitutionMutator(t *testing.T) {
	mutator := strategies.NewByteSubstitutionMutator(0.3) // 30% mutation rate

	originalData := []byte("hello world")
	testCase := &core.TestCase{
		ID:         "test2",
		Data:       originalData,
		Generation: 1,
		CreatedAt:  time.Now(),
		Priority:   50,
	}

	// Test mutation
	mutated, err := mutator.Mutate(testCase)
	require.NoError(t, err)
	assert.NotNil(t, mutated)

	// Verify basic properties
	assert.NotEqual(t, testCase.ID, mutated.ID)
	assert.Equal(t, testCase.ID, mutated.ParentID)
	assert.Equal(t, testCase.Generation+1, mutated.Generation)
	assert.Equal(t, len(originalData), len(mutated.Data))

	// Verify metadata
	assert.Equal(t, "ByteSubstitutionMutator", mutated.Metadata["mutator"])
	assert.Equal(t, 0.3, mutated.Metadata["mutation_rate"])

	// Test mutator interface
	assert.Equal(t, "ByteSubstitutionMutator", mutator.Name())
	assert.Contains(t, mutator.Description(), "byte")
}

// TestArithmeticMutator tests the arithmetic mutation strategy
func TestArithmeticMutator(t *testing.T) {
	mutator := strategies.NewArithmeticMutator(0.4) // 40% mutation rate

	// Create data with potential numeric values
	originalData := []byte{0x01, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF}
	testCase := &core.TestCase{
		ID:         "test3",
		Data:       originalData,
		Generation: 2,
		CreatedAt:  time.Now(),
		Priority:   75,
	}

	// Test mutation
	mutated, err := mutator.Mutate(testCase)
	require.NoError(t, err)
	assert.NotNil(t, mutated)

	// Verify basic properties
	assert.NotEqual(t, testCase.ID, mutated.ID)
	assert.Equal(t, testCase.ID, mutated.ParentID)
	assert.Equal(t, testCase.Generation+1, mutated.Generation)
	assert.Equal(t, len(originalData), len(mutated.Data))

	// Verify metadata
	assert.Equal(t, "ArithmeticMutator", mutated.Metadata["mutator"])
	assert.Equal(t, 0.4, mutated.Metadata["mutation_rate"])

	// Test mutator interface
	assert.Equal(t, "ArithmeticMutator", mutator.Name())
	assert.Contains(t, mutator.Description(), "arithmetic")
}

// TestStructureAwareMutator tests the structure-aware mutation strategy
func TestStructureAwareMutator(t *testing.T) {
	mutator := strategies.NewStructureAwareMutator(0.2) // 20% mutation rate

	// Create data with potential structure
	originalData := []byte{0x00, 0x05, 0x68, 0x65, 0x6C, 0x6C, 0x6F} // Length + "hello"
	testCase := &core.TestCase{
		ID:         "test4",
		Data:       originalData,
		Generation: 3,
		CreatedAt:  time.Now(),
		Priority:   25,
	}

	// Test mutation
	mutated, err := mutator.Mutate(testCase)
	require.NoError(t, err)
	assert.NotNil(t, mutated)

	// Verify basic properties
	assert.NotEqual(t, testCase.ID, mutated.ID)
	assert.Equal(t, testCase.ID, mutated.ParentID)
	assert.Equal(t, testCase.Generation+1, mutated.Generation)
	assert.Equal(t, len(originalData), len(mutated.Data))

	// Verify metadata
	assert.Equal(t, "StructureAwareMutator", mutated.Metadata["mutator"])
	assert.Equal(t, 0.2, mutated.Metadata["mutation_rate"])

	// Test mutator interface
	assert.Equal(t, "StructureAwareMutator", mutator.Name())
	assert.Contains(t, mutator.Description(), "structure")
}

// TestCrossOverMutator tests the crossover mutation strategy
func TestCrossOverMutator(t *testing.T) {
	mutator := strategies.NewCrossOverMutator(0.6) // 60% mutation rate

	originalData := []byte("crossover test data")
	testCase := &core.TestCase{
		ID:         "test5",
		Data:       originalData,
		Generation: 4,
		CreatedAt:  time.Now(),
		Priority:   10,
	}

	// Test mutation
	mutated, err := mutator.Mutate(testCase)
	require.NoError(t, err)
	assert.NotNil(t, mutated)

	// Verify basic properties
	assert.NotEqual(t, testCase.ID, mutated.ID)
	assert.Equal(t, testCase.ID, mutated.ParentID)
	assert.Equal(t, testCase.Generation+1, mutated.Generation)
	assert.Equal(t, len(originalData), len(mutated.Data))

	// Verify metadata
	assert.Equal(t, "CrossOverMutator", mutated.Metadata["mutator"])
	assert.Equal(t, 0.6, mutated.Metadata["mutation_rate"])

	// Test mutator interface
	assert.Equal(t, "CrossOverMutator", mutator.Name())
	assert.Contains(t, mutator.Description(), "combines")
}

// TestMutationRateZero tests mutation with zero mutation rate
func TestMutationRateZero(t *testing.T) {
	mutator := strategies.NewBitFlipMutator(0.0) // 0% mutation rate

	originalData := []byte{0x00, 0xFF, 0x55, 0xAA}
	testCase := &core.TestCase{
		ID:         "test6",
		Data:       originalData,
		Generation: 0,
		CreatedAt:  time.Now(),
		Priority:   100,
	}

	// Test mutation
	mutated, err := mutator.Mutate(testCase)
	require.NoError(t, err)
	assert.NotNil(t, mutated)

	// With zero mutation rate, data should remain unchanged
	assert.Equal(t, originalData, mutated.Data)
}

// TestMutationRateOne tests mutation with 100% mutation rate
func TestMutationRateOne(t *testing.T) {
	mutator := strategies.NewBitFlipMutator(1.0) // 100% mutation rate

	originalData := []byte{0x00, 0xFF}
	testCase := &core.TestCase{
		ID:         "test7",
		Data:       originalData,
		Generation: 0,
		CreatedAt:  time.Now(),
		Priority:   100,
	}

	// Test mutation
	mutated, err := mutator.Mutate(testCase)
	require.NoError(t, err)
	assert.NotNil(t, mutated)

	// With 100% mutation rate, all bits should be flipped
	expected := []byte{0xFF, 0x00}
	assert.Equal(t, expected, mutated.Data)
}

// TestEmptyTestCase tests mutation of empty test cases
func TestEmptyTestCase(t *testing.T) {
	mutator := strategies.NewByteSubstitutionMutator(0.5)

	emptyTestCase := &core.TestCase{
		ID:         "empty",
		Data:       []byte{},
		Generation: 0,
		CreatedAt:  time.Now(),
		Priority:   100,
	}

	// Test mutation
	mutated, err := mutator.Mutate(emptyTestCase)
	require.NoError(t, err)
	assert.NotNil(t, mutated)
	assert.Equal(t, 0, len(mutated.Data))
}

// TestLargeTestCase tests mutation of large test cases
func TestLargeTestCase(t *testing.T) {
	mutator := strategies.NewArithmeticMutator(0.1) // 10% mutation rate

	// Create large test case
	largeData := make([]byte, 10000)
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}

	testCase := &core.TestCase{
		ID:         "large",
		Data:       largeData,
		Generation: 0,
		CreatedAt:  time.Now(),
		Priority:   100,
	}

	// Test mutation
	mutated, err := mutator.Mutate(testCase)
	require.NoError(t, err)
	assert.NotNil(t, mutated)
	assert.Equal(t, len(largeData), len(mutated.Data))
}

// TestMutationConsistency tests that mutations are consistent
func TestMutationConsistency(t *testing.T) {
	mutator := strategies.NewBitFlipMutator(0.5)

	originalData := []byte{0x00, 0xFF, 0x55, 0xAA}
	testCase := &core.TestCase{
		ID:         "consistency",
		Data:       originalData,
		Generation: 0,
		CreatedAt:  time.Now(),
		Priority:   100,
	}

	// Perform multiple mutations
	results := make([][]byte, 5)
	for i := 0; i < 5; i++ {
		mutated, err := mutator.Mutate(testCase)
		require.NoError(t, err)
		results[i] = mutated.Data
	}

	// Verify that mutations produce different results (due to randomness)
	// At least some mutations should be different
	different := false
	for i := 0; i < len(results); i++ {
		for j := i + 1; j < len(results); j++ {
			if !bytes.Equal(results[i], results[j]) {
				different = true
				break
			}
		}
	}

	// With 50% mutation rate, we should see some differences
	assert.True(t, different, "Mutations should produce different results")
}

// TestMutationPreservesLength tests that mutations preserve data length
func TestMutationPreservesLength(t *testing.T) {
	mutators := []struct {
		name    string
		mutator strategies.Mutator
	}{
		{"BitFlip", strategies.NewBitFlipMutator(0.5)},
		{"ByteSubstitution", strategies.NewByteSubstitutionMutator(0.5)},
		{"Arithmetic", strategies.NewArithmeticMutator(0.5)},
		{"StructureAware", strategies.NewStructureAwareMutator(0.5)},
		{"CrossOver", strategies.NewCrossOverMutator(0.5)},
	}

	originalData := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	testCase := &core.TestCase{
		ID:         "length_test",
		Data:       originalData,
		Generation: 0,
		CreatedAt:  time.Now(),
		Priority:   100,
	}

	for _, m := range mutators {
		t.Run(m.name, func(t *testing.T) {
			mutated, err := m.mutator.Mutate(testCase)
			require.NoError(t, err)
			assert.Equal(t, len(originalData), len(mutated.Data),
				"%s mutator should preserve data length", m.name)
		})
	}
}

// TestMutationMetadata tests that mutations include proper metadata
func TestMutationMetadata(t *testing.T) {
	mutators := []struct {
		name    string
		mutator strategies.Mutator
	}{
		{"BitFlip", strategies.NewBitFlipMutator(0.5)},
		{"ByteSubstitution", strategies.NewByteSubstitutionMutator(0.5)},
		{"Arithmetic", strategies.NewArithmeticMutator(0.5)},
		{"StructureAware", strategies.NewStructureAwareMutator(0.5)},
		{"CrossOver", strategies.NewCrossOverMutator(0.5)},
	}

	testCase := &core.TestCase{
		ID:         "metadata_test",
		Data:       []byte{0x01, 0x02, 0x03},
		Generation: 0,
		CreatedAt:  time.Now(),
		Priority:   100,
	}

	for _, m := range mutators {
		t.Run(m.name, func(t *testing.T) {
			mutated, err := m.mutator.Mutate(testCase)
			require.NoError(t, err)

			// Check that metadata is present
			assert.NotNil(t, mutated.Metadata)
			assert.Equal(t, m.name+"Mutator", mutated.Metadata["mutator"])
			assert.Equal(t, 0.5, mutated.Metadata["mutation_rate"])
		})
	}
}
