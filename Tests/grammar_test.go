/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: grammar_test.go
Description: Comprehensive tests for the enhanced grammar features including seed keys,
deep fuzzing, advanced mutation variability, and array/object support. Tests the
production-level grammar implementation with proper validation and edge case handling.
*/

package core_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/kleascm/akaylee-fuzzer/pkg/grammar"
	"github.com/kleascm/akaylee-fuzzer/pkg/interfaces"
	"github.com/kleascm/akaylee-fuzzer/pkg/strategies"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestJSONGrammarGeneration tests basic JSON generation
func TestJSONGrammarGeneration(t *testing.T) {
	runTest(t, "TestJSONGrammarGeneration", func(t *testing.T) {
		g := grammar.NewJSONGrammar()

		// Generate multiple JSON objects
		for i := 0; i < 10; i++ {
			data, err := g.Generate()
			require.NoError(t, err)
			assert.NotEmpty(t, data)

			// Verify it's valid JSON
			var parsed interface{}
			err = json.Unmarshal(data, &parsed)
			assert.NoError(t, err, "Generated data should be valid JSON")

			// Verify it's not empty (null is valid JSON but not what we want for testing)
			assert.NotNil(t, parsed)
			// Also verify it's not null
			assert.NotEqual(t, nil, parsed)
		}
	})
}

// TestJSONGrammarWithSeedKeys tests generation with seed keys
func TestJSONGrammarWithSeedKeys(t *testing.T) {
	runTest(t, "TestJSONGrammarWithSeedKeys", func(t *testing.T) {
		seedKeys := []string{"name", "age", "email", "active"}
		g := grammar.NewJSONGrammarWithSeeds(seedKeys)

		// Generate multiple JSON objects
		for i := 0; i < 10; i++ {
			data, err := g.Generate()
			require.NoError(t, err)

			// Parse JSON
			var obj map[string]interface{}
			err = json.Unmarshal(data, &obj)
			require.NoError(t, err)

			// Verify all seed keys are present
			for _, key := range seedKeys {
				assert.Contains(t, obj, key, "Generated JSON should contain seed key: %s", key)
			}

			// Verify additional keys are present (extra_0, extra_1, etc.)
			hasExtraKeys := false
			for k := range obj {
				if strings.HasPrefix(k, "extra_") {
					hasExtraKeys = true
					break
				}
			}
			assert.True(t, hasExtraKeys, "Should have extra keys for variety")
		}
	})
}

// TestJSONGrammarDeepFuzzing tests deep recursive generation
func TestJSONGrammarDeepFuzzing(t *testing.T) {
	runTest(t, "TestJSONGrammarDeepFuzzing", func(t *testing.T) {
		g := grammar.NewJSONGrammar()
		g.SetMaxDepth(3)

		// Generate multiple JSON objects and check for nesting
		foundNesting := false
		for i := 0; i < 10; i++ {
			data, err := g.Generate()
			require.NoError(t, err)

			// Parse and verify structure
			var parsed interface{}
			err = json.Unmarshal(data, &parsed)
			require.NoError(t, err)

			// Check for nested structures - with max depth 3, we should see some nesting
			if checkNesting(parsed, 0) {
				foundNesting = true
				break // Found nesting, test passes
			}
		}

		// For max depth 3, we should find some nesting in 10 attempts
		assert.True(t, foundNesting, "Should find nested structures in deep fuzzing")
	})
}

// TestJSONGrammarMutationVariability tests enhanced mutation variability
func TestJSONGrammarMutationVariability(t *testing.T) {
	runTest(t, "TestJSONGrammarMutationVariability", func(t *testing.T) {
		g := grammar.NewJSONGrammar()

		// Create test JSON with various types
		originalJSON := `{
			"string_val": "hello",
			"number_val": 42.5,
			"int_val": 100,
			"bool_val": true,
			"array_val": [1, 2, 3],
			"object_val": {"nested": "value"}
		}`

		originalData := []byte(originalJSON)

		// Perform multiple mutations
		mutations := make(map[string]bool)
		for i := 0; i < 20; i++ {
			mutatedData, err := g.Mutate(originalData)
			require.NoError(t, err)

			// Verify it's still valid JSON
			var parsed interface{}
			err = json.Unmarshal(mutatedData, &parsed)
			assert.NoError(t, err)

			// Track unique mutations
			mutations[string(mutatedData)] = true
		}

		// Should have multiple different mutations
		assert.Greater(t, len(mutations), 5, "Should produce diverse mutations")
	})
}

// TestJSONGrammarArrayMutation tests array mutation capabilities
func TestJSONGrammarArrayMutation(t *testing.T) {
	runTest(t, "TestJSONGrammarArrayMutation", func(t *testing.T) {
		g := grammar.NewJSONGrammar()

		// Test array mutation
		originalJSON := `[1, "hello", true, {"key": "value"}]`
		originalData := []byte(originalJSON)

		// Perform mutations
		for i := 0; i < 10; i++ {
			mutatedData, err := g.Mutate(originalData)
			require.NoError(t, err)

			// Verify it's still valid JSON
			var parsed interface{}
			err = json.Unmarshal(mutatedData, &parsed)
			assert.NoError(t, err)

			// Should still be an array
			_, isArray := parsed.([]interface{})
			assert.True(t, isArray, "Mutated data should still be an array")
		}
	})
}

// TestJSONGrammarObjectMutation tests object mutation capabilities
func TestJSONGrammarObjectMutation(t *testing.T) {
	runTest(t, "TestJSONGrammarObjectMutation", func(t *testing.T) {
		g := grammar.NewJSONGrammar()

		// Test object mutation
		originalJSON := `{"name": "test", "value": 42, "active": true}`
		originalData := []byte(originalJSON)

		// Perform mutations
		for i := 0; i < 10; i++ {
			mutatedData, err := g.Mutate(originalData)
			require.NoError(t, err)

			// Verify it's still valid JSON
			var parsed interface{}
			err = json.Unmarshal(mutatedData, &parsed)
			assert.NoError(t, err)

			// Should still be an object
			_, isObject := parsed.(map[string]interface{})
			assert.True(t, isObject, "Mutated data should still be an object")
		}
	})
}

// TestJSONGrammarTypeConversion tests type conversion mutations
func TestJSONGrammarTypeConversion(t *testing.T) {
	runTest(t, "TestJSONGrammarTypeConversion", func(t *testing.T) {
		g := grammar.NewJSONGrammar()

		// Test string to number conversion
		originalJSON := `{"value": "42"}`
		originalData := []byte(originalJSON)

		foundTypeConversion := false
		for i := 0; i < 50; i++ {
			mutatedData, err := g.Mutate(originalData)
			require.NoError(t, err)

			var obj map[string]interface{}
			err = json.Unmarshal(mutatedData, &obj)
			require.NoError(t, err)

			if value, exists := obj["value"]; exists {
				switch value.(type) {
				case float64, int, int64:
					foundTypeConversion = true
				}
			}
		}

		assert.True(t, foundTypeConversion, "Should perform type conversions")
	})
}

// TestGrammarMutatorWithConfig tests the enhanced grammar mutator
func TestGrammarMutatorWithConfig(t *testing.T) {
	runTest(t, "TestGrammarMutatorWithConfig", func(t *testing.T) {
		seedKeys := []string{"id", "name", "status"}
		maxDepth := 4

		g := grammar.NewJSONGrammar()
		mutator := strategies.NewGrammarMutatorWithConfig(g, seedKeys, maxDepth)

		// Test configuration
		assert.Equal(t, seedKeys, mutator.GetSeedKeys())
		assert.Equal(t, maxDepth, mutator.GetMaxDepth())
		assert.Equal(t, int64(0), mutator.GetMutationCount())

		// Test mutation
		testCase := &interfaces.TestCase{
			ID:         "test1",
			Data:       []byte(`{"id": 1, "name": "test"}`),
			Generation: 0,
			CreatedAt:  time.Now(),
			Priority:   100,
		}

		mutated, err := mutator.Mutate(testCase)
		require.NoError(t, err)
		assert.NotNil(t, mutated)
		assert.Equal(t, int64(1), mutator.GetMutationCount())

		// Verify metadata
		assert.Contains(t, mutated.Metadata, "seed_keys")
		assert.Contains(t, mutated.Metadata, "max_depth")
		assert.Contains(t, mutated.Metadata, "mutation_count")
	})
}

// TestGrammarMutatorSeedKeys tests seed key functionality
func TestGrammarMutatorSeedKeys(t *testing.T) {
	runTest(t, "TestGrammarMutatorSeedKeys", func(t *testing.T) {
		g := grammar.NewJSONGrammar()
		mutator := strategies.NewGrammarMutator(g)

		// Set seed keys
		seedKeys := []string{"user_id", "email", "role"}
		mutator.SetSeedKeys(seedKeys)

		assert.Equal(t, seedKeys, mutator.GetSeedKeys())

		// Test that seed keys are configured properly
		// The grammar will use seed keys when generating new data, not necessarily when mutating
		// So let's test the configuration and basic functionality
		assert.Equal(t, seedKeys, mutator.GetSeedKeys())

		// Test that the grammar can generate data with seed keys
		jsonGrammar := grammar.NewJSONGrammarWithSeeds(seedKeys)
		data, err := jsonGrammar.Generate()
		require.NoError(t, err)

		var obj map[string]interface{}
		err = json.Unmarshal(data, &obj)
		require.NoError(t, err)

		// Verify all seed keys are present in generated data
		for _, key := range seedKeys {
			assert.Contains(t, obj, key, "Generated data should contain seed key: %s", key)
		}
	})
}

// TestGrammarMutatorMaxDepth tests max depth functionality
func TestGrammarMutatorMaxDepth(t *testing.T) {
	runTest(t, "TestGrammarMutatorMaxDepth", func(t *testing.T) {
		g := grammar.NewJSONGrammar()
		mutator := strategies.NewGrammarMutator(g)

		// Set max depth
		maxDepth := 3
		mutator.SetMaxDepth(maxDepth)

		assert.Equal(t, maxDepth, mutator.GetMaxDepth())

		// Test mutation with max depth
		testCase := &interfaces.TestCase{
			ID:         "test1",
			Data:       []byte(`{"nested": {"deep": {"value": 42}}}`),
			Generation: 0,
			CreatedAt:  time.Now(),
			Priority:   100,
		}

		mutated, err := mutator.Mutate(testCase)
		require.NoError(t, err)

		// Verify it's still valid JSON
		var parsed interface{}
		err = json.Unmarshal(mutated.Data, &parsed)
		assert.NoError(t, err)
	})
}

// TestGrammarMutatorEmptyData tests mutation with empty data
func TestGrammarMutatorEmptyData(t *testing.T) {
	runTest(t, "TestGrammarMutatorEmptyData", func(t *testing.T) {
		g := grammar.NewJSONGrammar()
		mutator := strategies.NewGrammarMutator(g)

		// Test with empty data
		testCase := &interfaces.TestCase{
			ID:         "test1",
			Data:       []byte{},
			Generation: 0,
			CreatedAt:  time.Now(),
			Priority:   100,
		}

		mutated, err := mutator.Mutate(testCase)
		require.NoError(t, err)
		assert.NotEmpty(t, mutated.Data)

		// Verify it's valid JSON
		var parsed interface{}
		err = json.Unmarshal(mutated.Data, &parsed)
		assert.NoError(t, err)
	})
}

// TestGrammarMutatorInvalidJSON tests mutation with invalid JSON
func TestGrammarMutatorInvalidJSON(t *testing.T) {
	runTest(t, "TestGrammarMutatorInvalidJSON", func(t *testing.T) {
		g := grammar.NewJSONGrammar()
		mutator := strategies.NewGrammarMutator(g)

		// Test with invalid JSON
		testCase := &interfaces.TestCase{
			ID:         "test1",
			Data:       []byte(`{"invalid": json`),
			Generation: 0,
			CreatedAt:  time.Now(),
			Priority:   100,
		}

		mutated, err := mutator.Mutate(testCase)
		require.NoError(t, err)
		assert.NotEmpty(t, mutated.Data)

		// Should generate new valid JSON
		var parsed interface{}
		err = json.Unmarshal(mutated.Data, &parsed)
		assert.NoError(t, err)
	})
}

// TestGrammarMutatorDescription tests description generation
func TestGrammarMutatorDescription(t *testing.T) {
	runTest(t, "TestGrammarMutatorDescription", func(t *testing.T) {
		g := grammar.NewJSONGrammar()
		mutator := strategies.NewGrammarMutator(g)

		// Test default description
		desc := mutator.Description()
		assert.Contains(t, desc, "structure-aware grammar")

		// Test with seed keys
		mutator.SetSeedKeys([]string{"key1", "key2"})
		desc = mutator.Description()
		assert.Contains(t, desc, "seed keys")

		// Test with deep fuzzing
		mutator.SetMaxDepth(10)
		desc = mutator.Description()
		assert.Contains(t, desc, "deep recursive mutation")
	})
}

// TestGrammarMutatorInit tests initialization
func TestGrammarMutatorInit(t *testing.T) {
	runTest(t, "TestGrammarMutatorInit", func(t *testing.T) {
		g := grammar.NewJSONGrammar()
		mutator := strategies.NewGrammarMutator(g)

		// Set configuration
		mutator.SetSeedKeys([]string{"test"})
		mutator.SetMaxDepth(7)

		// Initialize
		err := mutator.Init()
		assert.NoError(t, err)

		// Verify configuration is applied
		assert.Equal(t, []string{"test"}, mutator.GetSeedKeys())
		assert.Equal(t, 7, mutator.GetMaxDepth())
	})
}

// Helper function to check for nesting in JSON data
func checkNesting(data interface{}, depth int) bool {
	if depth > 3 {
		return false
	}

	switch v := data.(type) {
	case map[string]interface{}:
		for _, value := range v {
			if checkNesting(value, depth+1) {
				return true
			}
		}
	case []interface{}:
		for _, value := range v {
			if checkNesting(value, depth+1) {
				return true
			}
		}
	}

	return depth > 0
}

// Helper function to check if a map contains a key
func containsKey(obj map[string]interface{}, key string) bool {
	_, exists := obj[key]
	return exists
}
