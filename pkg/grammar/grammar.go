/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: grammar.go
Description: Grammar interface and JSONGrammar implementation for grammar-based fuzzing in the Akaylee Fuzzer. Enables structure-aware input generation and mutation with advanced variability and deep fuzzing capabilities.
*/

package grammar

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"strings"
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

// JSONGrammar implements Grammar for JSON data with advanced mutation capabilities.
type JSONGrammar struct {
	SeedKeys []string // Optional seed keys for target-aware generation
	MaxDepth int      // Maximum recursion depth for deep fuzzing
}

// NewJSONGrammar creates a new JSONGrammar instance.
func NewJSONGrammar() *JSONGrammar {
	return &JSONGrammar{
		MaxDepth: 5, // Default max depth for deep fuzzing
	}
}

// NewJSONGrammarWithSeeds creates a new JSONGrammar with seed keys.
func NewJSONGrammarWithSeeds(seedKeys []string) *JSONGrammar {
	return &JSONGrammar{
		SeedKeys: seedKeys,
		MaxDepth: 5,
	}
}

// Generate returns a random valid JSON object as bytes with enhanced variability.
func (g *JSONGrammar) Generate() ([]byte, error) {
	rand.Seed(time.Now().UnixNano())

	// Use seed keys if available, otherwise generate random structure
	if len(g.SeedKeys) > 0 {
		return g.generateWithSeeds()
	}

	return g.generateRandomStructure(0)
}

// generateWithSeeds generates JSON using the provided seed keys.
func (g *JSONGrammar) generateWithSeeds() ([]byte, error) {
	obj := make(map[string]interface{})

	for _, key := range g.SeedKeys {
		obj[key] = g.generateRandomValue(0)
	}

	// Add some additional random keys for variety
	numExtraKeys := rand.Intn(3) + 1
	for i := 0; i < numExtraKeys; i++ {
		key := fmt.Sprintf("extra_%d", i)
		obj[key] = g.generateRandomValue(0)
	}

	return json.Marshal(obj)
}

// generateRandomStructure creates a random JSON structure with arrays and objects.
func (g *JSONGrammar) generateRandomStructure(depth int) ([]byte, error) {
	if depth >= g.MaxDepth {
		// At max depth, return simple values
		return g.generateSimpleValue()
	}

	// Randomly choose between object, array, or simple value
	choice := rand.Intn(3)

	switch choice {
	case 0:
		// Generate object
		return g.generateRandomObject(depth)
	case 1:
		// Generate array
		return g.generateRandomArray(depth)
	default:
		// Generate simple value
		return g.generateSimpleValue()
	}
}

// generateRandomObject creates a random JSON object.
func (g *JSONGrammar) generateRandomObject(depth int) ([]byte, error) {
	obj := make(map[string]interface{})

	// Generate 2-5 random keys
	numKeys := rand.Intn(4) + 2
	for i := 0; i < numKeys; i++ {
		key := fmt.Sprintf("key_%d", i)
		obj[key] = g.generateRandomValue(depth + 1)
	}

	return json.Marshal(obj)
}

// generateRandomArray creates a random JSON array.
func (g *JSONGrammar) generateRandomArray(depth int) ([]byte, error) {
	// Generate array with 1-5 elements
	numElements := rand.Intn(5) + 1
	arr := make([]interface{}, numElements)

	for i := 0; i < numElements; i++ {
		arr[i] = g.generateRandomValue(depth + 1)
	}

	return json.Marshal(arr)
}

// generateSimpleValue creates a simple JSON value (string, number, boolean, null).
func (g *JSONGrammar) generateSimpleValue() ([]byte, error) {
	value := g.generateRandomValue(0)
	return json.Marshal(value)
}

// generateRandomValue generates a random value of any JSON type.
func (g *JSONGrammar) generateRandomValue(depth int) interface{} {
	if depth >= g.MaxDepth {
		// At max depth, only return simple types
		return g.generateSimpleType()
	}

	// Choose type with weighted probability
	typeChoice := rand.Intn(100)

	switch {
	case typeChoice < 30:
		// 30% chance for simple types
		return g.generateSimpleType()
	case typeChoice < 60:
		// 30% chance for arrays
		return g.generateArrayValue(depth + 1)
	case typeChoice < 90:
		// 30% chance for objects
		return g.generateObjectValue(depth + 1)
	default:
		// 10% chance for null
		return nil
	}
}

// generateSimpleType generates a simple JSON type.
func (g *JSONGrammar) generateSimpleType() interface{} {
	typeChoice := rand.Intn(4)

	switch typeChoice {
	case 0:
		// String
		strings := []string{"hello", "world", "test", "data", "value", "key", "json", "fuzz"}
		return strings[rand.Intn(len(strings))]
	case 1:
		// Number (float64)
		return rand.Float64() * 1000
	case 2:
		// Integer
		return rand.Intn(10000)
	default:
		// Boolean
		return rand.Intn(2) == 1
	}
}

// generateArrayValue generates a random array value.
func (g *JSONGrammar) generateArrayValue(depth int) []interface{} {
	numElements := rand.Intn(4) + 1
	arr := make([]interface{}, numElements)

	for i := 0; i < numElements; i++ {
		arr[i] = g.generateRandomValue(depth)
	}

	return arr
}

// generateObjectValue generates a random object value.
func (g *JSONGrammar) generateObjectValue(depth int) map[string]interface{} {
	numKeys := rand.Intn(3) + 1
	obj := make(map[string]interface{})

	for i := 0; i < numKeys; i++ {
		key := fmt.Sprintf("nested_%d", i)
		obj[key] = g.generateRandomValue(depth)
	}

	return obj
}

// Mutate takes a valid JSON input and returns a mutated, still-valid JSON input with enhanced variability.
func (g *JSONGrammar) Mutate(input []byte) ([]byte, error) {
	var data interface{}
	if err := json.Unmarshal(input, &data); err != nil {
		return g.Generate() // fallback to new
	}

	// Apply deep mutation
	mutated := g.mutateValue(data, 0)

	return json.Marshal(mutated)
}

// mutateValue recursively mutates a JSON value with enhanced variability.
func (g *JSONGrammar) mutateValue(value interface{}, depth int) interface{} {
	if depth >= g.MaxDepth {
		return g.generateSimpleType() // Replace with simple type at max depth
	}

	if value == nil {
		return g.generateSimpleType()
	}

	switch v := value.(type) {
	case map[string]interface{}:
		return g.mutateObject(v, depth)
	case []interface{}:
		return g.mutateArray(v, depth)
	case float64:
		// Enhanced numeric mutation
		return g.mutateFloat64(v)
	case string:
		// Enhanced string mutation
		return g.mutateString(v)
	case bool:
		// Enhanced boolean mutation
		return !v
	case int, int32, int64:
		// Enhanced integer mutation
		return g.mutateInt(v)
	default:
		// Unknown type, replace with random value
		return g.generateRandomValue(depth)
	}
}

// mutateObject mutates a JSON object with deep fuzzing capabilities.
func (g *JSONGrammar) mutateObject(obj map[string]interface{}, depth int) map[string]interface{} {
	mutated := make(map[string]interface{})

	// Mutation strategies
	strategy := rand.Intn(100)

	switch {
	case strategy < 40:
		// 40% chance: mutate existing values
		for k, v := range obj {
			if rand.Float64() < 0.7 { // 70% chance to mutate each value
				mutated[k] = g.mutateValue(v, depth+1)
			} else {
				mutated[k] = v
			}
		}
	case strategy < 70:
		// 30% chance: add new keys
		for k, v := range obj {
			mutated[k] = g.mutateValue(v, depth+1)
		}
		// Add 1-3 new keys
		numNewKeys := rand.Intn(3) + 1
		for i := 0; i < numNewKeys; i++ {
			key := fmt.Sprintf("new_key_%d", i)
			mutated[key] = g.generateRandomValue(depth + 1)
		}
	case strategy < 85:
		// 15% chance: remove random keys
		keys := make([]string, 0, len(obj))
		for k := range obj {
			keys = append(keys, k)
		}
		// Keep 70-100% of keys
		keepRatio := 0.7 + rand.Float64()*0.3
		keepCount := int(float64(len(keys)) * keepRatio)
		if keepCount < 1 {
			keepCount = 1
		}

		// Shuffle and keep first keepCount keys
		rand.Shuffle(len(keys), func(i, j int) {
			keys[i], keys[j] = keys[j], keys[i]
		})

		for i := 0; i < keepCount && i < len(keys); i++ {
			k := keys[i]
			mutated[k] = g.mutateValue(obj[k], depth+1)
		}
	default:
		// 15% chance: replace entire object
		return g.generateObjectValue(depth)
	}

	return mutated
}

// mutateArray mutates a JSON array with deep fuzzing capabilities.
func (g *JSONGrammar) mutateArray(arr []interface{}, depth int) []interface{} {
	if len(arr) == 0 {
		return g.generateArrayValue(depth)
	}

	mutated := make([]interface{}, 0, len(arr))

	// Mutation strategies
	strategy := rand.Intn(100)

	switch {
	case strategy < 50:
		// 50% chance: mutate existing elements
		for _, v := range arr {
			if rand.Float64() < 0.8 { // 80% chance to mutate each element
				mutated = append(mutated, g.mutateValue(v, depth+1))
			} else {
				mutated = append(mutated, v)
			}
		}
	case strategy < 75:
		// 25% chance: add new elements
		for _, v := range arr {
			mutated = append(mutated, g.mutateValue(v, depth+1))
		}
		// Add 1-3 new elements
		numNewElements := rand.Intn(3) + 1
		for i := 0; i < numNewElements; i++ {
			mutated = append(mutated, g.generateRandomValue(depth+1))
		}
	case strategy < 90:
		// 15% chance: remove random elements
		keepRatio := 0.6 + rand.Float64()*0.4 // Keep 60-100% of elements
		keepCount := int(float64(len(arr)) * keepRatio)
		if keepCount < 1 {
			keepCount = 1
		}

		for i := 0; i < keepCount && i < len(arr); i++ {
			mutated = append(mutated, g.mutateValue(arr[i], depth+1))
		}
	default:
		// 10% chance: replace entire array
		return g.generateArrayValue(depth)
	}

	return mutated
}

// mutateFloat64 provides enhanced numeric mutation with various operations.
func (g *JSONGrammar) mutateFloat64(v float64) interface{} {
	operations := []func(float64) interface{}{
		func(x float64) interface{} { return x + float64(rand.Intn(10)-5) }, // Add/subtract small value
		func(x float64) interface{} { return x * 2 },                        // Double
		func(x float64) interface{} { return x / 2 },                        // Halve
		func(x float64) interface{} { return -x },                           // Negate
		func(x float64) interface{} { return x + 1000 },                     // Add large value
		func(x float64) interface{} { return x - 1000 },                     // Subtract large value
		func(x float64) interface{} { return float64(rand.Intn(1000)) },     // Replace with random
		func(x float64) interface{} { return int(x) },                       // Convert to int
		func(x float64) interface{} { return fmt.Sprintf("%.2f", x) },       // Convert to string
	}

	return operations[rand.Intn(len(operations))](v)
}

// mutateString provides enhanced string mutation.
func (g *JSONGrammar) mutateString(v string) interface{} {
	operations := []func(string) interface{}{
		func(s string) interface{} { return s + "_mut" },           // Append suffix
		func(s string) interface{} { return "mut_" + s },           // Prepend prefix
		func(s string) interface{} { return strings.ToUpper(s) },   // Uppercase
		func(s string) interface{} { return strings.ToLower(s) },   // Lowercase
		func(s string) interface{} { return strings.Repeat(s, 2) }, // Duplicate
		func(s string) interface{} { return len(s) },               // Convert to length
		func(s string) interface{} { return rand.Intn(1000) },      // Replace with number
		func(s string) interface{} { return rand.Intn(2) == 1 },    // Replace with boolean
		func(s string) interface{} { return nil },                  // Replace with null
	}

	return operations[rand.Intn(len(operations))](v)
}

// mutateInt provides enhanced integer mutation.
func (g *JSONGrammar) mutateInt(v interface{}) interface{} {
	var intVal int64

	// Convert to int64
	switch val := v.(type) {
	case int:
		intVal = int64(val)
	case int32:
		intVal = int64(val)
	case int64:
		intVal = val
	default:
		return rand.Intn(1000)
	}

	operations := []func(int64) interface{}{
		func(x int64) interface{} { return x + int64(rand.Intn(10)-5) }, // Add/subtract small value
		func(x int64) interface{} { return x * 2 },                      // Double
		func(x int64) interface{} { return x / 2 },                      // Halve
		func(x int64) interface{} { return -x },                         // Negate
		func(x int64) interface{} { return x + 1000 },                   // Add large value
		func(x int64) interface{} { return x - 1000 },                   // Subtract large value
		func(x int64) interface{} { return int64(rand.Intn(1000)) },     // Replace with random
		func(x int64) interface{} { return float64(x) },                 // Convert to float
		func(x int64) interface{} { return fmt.Sprintf("%d", x) },       // Convert to string
		func(x int64) interface{} { return x != 0 },                     // Convert to boolean
	}

	return operations[rand.Intn(len(operations))](intVal)
}

// Name returns the name of the grammar.
func (g *JSONGrammar) Name() string {
	return "JSONGrammar"
}

// SetSeedKeys sets the seed keys for target-aware generation.
func (g *JSONGrammar) SetSeedKeys(keys []string) {
	g.SeedKeys = keys
}

// SetMaxDepth sets the maximum recursion depth for deep fuzzing.
func (g *JSONGrammar) SetMaxDepth(depth int) {
	g.MaxDepth = depth
}
