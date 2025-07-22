/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: inference_test.go
Description: Comprehensive tests for the advanced input structure inference system.
Tests JSON structure inference, field type detection, enum recognition, and grammar synthesis.
*/

package core_test

import (
	"encoding/json"
	"testing"

	"github.com/kleascm/akaylee-fuzzer/pkg/inference"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJSONInferenceEngineCreation(t *testing.T) {
	runTest(t, "TestJSONInferenceEngineCreation", func(t *testing.T) {
		engine := inference.NewJSONInferenceEngine()
		require.NotNil(t, engine)
		assert.Equal(t, "json", engine.Format())
	})
}

func TestJSONInferenceBasicStructure(t *testing.T) {
	runTest(t, "TestJSONInferenceBasicStructure", func(t *testing.T) {
		engine := inference.NewJSONInferenceEngine()

		samples := [][]byte{
			[]byte(`{"name": "Alice", "age": 25}`),
			[]byte(`{"name": "Bob", "age": 30}`),
		}

		grammar, err := engine.InferStructure(samples)
		require.NoError(t, err)
		require.NotNil(t, grammar)

		assert.Equal(t, "json", grammar.Format)
		assert.Equal(t, "root", grammar.RootRule)
		assert.Equal(t, 2, grammar.Metadata["samples"])

		// Check root rule
		rootRule := grammar.Rules["root"].(map[string]interface{})
		types := rootRule["types"].([]string)
		assert.Contains(t, types, "object")

		// Check fields
		fields := rootRule["fields"].(map[string]interface{})
		assert.Contains(t, fields, "name")
		assert.Contains(t, fields, "age")

		// Check required fields
		required := rootRule["required"].([]string)
		assert.Contains(t, required, "name")
		assert.Contains(t, required, "age")
	})
}

func TestJSONInferenceEnumDetection(t *testing.T) {
	runTest(t, "TestJSONInferenceEnumDetection", func(t *testing.T) {
		engine := inference.NewJSONInferenceEngine()

		samples := [][]byte{
			[]byte(`{"status": "active"}`),
			[]byte(`{"status": "inactive"}`),
			[]byte(`{"status": "pending"}`),
		}

		grammar, err := engine.InferStructure(samples)
		require.NoError(t, err)

		rootRule := grammar.Rules["root"].(map[string]interface{})
		fields := rootRule["fields"].(map[string]interface{})
		statusField := fields["status"].(map[string]interface{})

		// Should detect enum
		enum := statusField["enum"].([]string)
		assert.Contains(t, enum, "active")
		assert.Contains(t, enum, "inactive")
		assert.Contains(t, enum, "pending")
	})
}

func TestJSONInferenceNumberRanges(t *testing.T) {
	runTest(t, "TestJSONInferenceNumberRanges", func(t *testing.T) {
		engine := inference.NewJSONInferenceEngine()

		samples := [][]byte{
			[]byte(`{"score": 85}`),
			[]byte(`{"score": 92}`),
			[]byte(`{"score": 78}`),
		}

		grammar, err := engine.InferStructure(samples)
		require.NoError(t, err)

		rootRule := grammar.Rules["root"].(map[string]interface{})
		fields := rootRule["fields"].(map[string]interface{})
		scoreField := fields["score"].(map[string]interface{})

		// Should detect min/max
		min := scoreField["min"].(float64)
		max := scoreField["max"].(float64)
		assert.Equal(t, 78.0, min)
		assert.Equal(t, 92.0, max)
	})
}

func TestJSONInferenceOptionalFields(t *testing.T) {
	runTest(t, "TestJSONInferenceOptionalFields", func(t *testing.T) {
		engine := inference.NewJSONInferenceEngine()

		samples := [][]byte{
			[]byte(`{"name": "Alice", "age": 25}`),
			[]byte(`{"name": "Bob", "age": 30, "email": "bob@example.com"}`),
			[]byte(`{"name": "Charlie", "age": 35}`),
		}

		grammar, err := engine.InferStructure(samples)
		require.NoError(t, err)

		rootRule := grammar.Rules["root"].(map[string]interface{})

		// Required fields
		required := rootRule["required"].([]string)
		assert.Contains(t, required, "name")
		assert.Contains(t, required, "age")

		// Optional fields
		optional := rootRule["optional"].([]string)
		assert.Contains(t, optional, "email")
	})
}

func TestJSONInferenceArrayTypes(t *testing.T) {
	runTest(t, "TestJSONInferenceArrayTypes", func(t *testing.T) {
		engine := inference.NewJSONInferenceEngine()

		samples := [][]byte{
			[]byte(`{"tags": ["red", "blue"]}`),
			[]byte(`{"tags": ["green", "yellow", "red"]}`),
		}

		grammar, err := engine.InferStructure(samples)
		require.NoError(t, err)

		rootRule := grammar.Rules["root"].(map[string]interface{})
		fields := rootRule["fields"].(map[string]interface{})
		tagsField := fields["tags"].(map[string]interface{})

		// Should detect array type
		types := tagsField["types"].([]string)
		assert.Contains(t, types, "array")

		// Should have element type
		element := tagsField["element"].(map[string]interface{})
		elementTypes := element["types"].([]string)
		assert.Contains(t, elementTypes, "string")
	})
}

func TestJSONInferenceNestedObjects(t *testing.T) {
	runTest(t, "TestJSONInferenceNestedObjects", func(t *testing.T) {
		engine := inference.NewJSONInferenceEngine()

		samples := [][]byte{
			[]byte(`{"user": {"name": "Alice", "age": 25}}`),
			[]byte(`{"user": {"name": "Bob", "age": 30}}`),
		}

		grammar, err := engine.InferStructure(samples)
		require.NoError(t, err)

		rootRule := grammar.Rules["root"].(map[string]interface{})
		fields := rootRule["fields"].(map[string]interface{})
		userField := fields["user"].(map[string]interface{})

		// Should detect object type
		types := userField["types"].([]string)
		assert.Contains(t, types, "object")

		// Should have nested fields
		nestedFields := userField["fields"].(map[string]interface{})
		assert.Contains(t, nestedFields, "name")
		assert.Contains(t, nestedFields, "age")
	})
}

func TestJSONInferenceMixedTypes(t *testing.T) {
	runTest(t, "TestJSONInferenceMixedTypes", func(t *testing.T) {
		engine := inference.NewJSONInferenceEngine()

		samples := [][]byte{
			[]byte(`{"value": "string"}`),
			[]byte(`{"value": 42}`),
		}

		grammar, err := engine.InferStructure(samples)
		require.NoError(t, err)

		rootRule := grammar.Rules["root"].(map[string]interface{})
		fields := rootRule["fields"].(map[string]interface{})
		valueField := fields["value"].(map[string]interface{})

		// Should detect multiple types
		types := valueField["types"].([]string)
		assert.Contains(t, types, "string")
		assert.Contains(t, types, "number")
	})
}

func TestJSONInferenceBooleanTypes(t *testing.T) {
	runTest(t, "TestJSONInferenceBooleanTypes", func(t *testing.T) {
		engine := inference.NewJSONInferenceEngine()

		samples := [][]byte{
			[]byte(`{"active": true}`),
			[]byte(`{"active": false}`),
		}

		grammar, err := engine.InferStructure(samples)
		require.NoError(t, err)

		rootRule := grammar.Rules["root"].(map[string]interface{})
		fields := rootRule["fields"].(map[string]interface{})
		activeField := fields["active"].(map[string]interface{})

		// Should detect boolean type
		types := activeField["types"].([]string)
		assert.Contains(t, types, "bool")

		// Should detect enum
		enum := activeField["enum"].([]string)
		assert.Contains(t, enum, "true")
		assert.Contains(t, enum, "false")
	})
}

func TestJSONInferenceNullValues(t *testing.T) {
	runTest(t, "TestJSONInferenceNullValues", func(t *testing.T) {
		engine := inference.NewJSONInferenceEngine()

		samples := [][]byte{
			[]byte(`{"value": "string"}`),
			[]byte(`{"value": null}`),
		}

		grammar, err := engine.InferStructure(samples)
		require.NoError(t, err)

		rootRule := grammar.Rules["root"].(map[string]interface{})
		fields := rootRule["fields"].(map[string]interface{})
		valueField := fields["value"].(map[string]interface{})

		// Should detect null type
		types := valueField["types"].([]string)
		assert.Contains(t, types, "string")
		assert.Contains(t, types, "null")
	})
}

func TestJSONInferenceEmptySamples(t *testing.T) {
	runTest(t, "TestJSONInferenceEmptySamples", func(t *testing.T) {
		engine := inference.NewJSONInferenceEngine()

		_, err := engine.InferStructure([][]byte{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no samples provided")
	})
}

func TestJSONInferenceInvalidJSON(t *testing.T) {
	runTest(t, "TestJSONInferenceInvalidJSON", func(t *testing.T) {
		engine := inference.NewJSONInferenceEngine()

		samples := [][]byte{
			[]byte(`{"valid": "json"}`),
			[]byte(`invalid json`),
		}

		_, err := engine.InferStructure(samples)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse sample")
	})
}

func TestJSONInferenceComplexStructure(t *testing.T) {
	runTest(t, "TestJSONInferenceComplexStructure", func(t *testing.T) {
		engine := inference.NewJSONInferenceEngine()

		samples := [][]byte{
			[]byte(`{
				"id": 1,
				"name": "Product A",
				"price": 29.99,
				"tags": ["electronics", "gadget"],
				"metadata": {
					"brand": "TechCorp",
					"in_stock": true
				}
			}`),
			[]byte(`{
				"id": 2,
				"name": "Product B",
				"price": 49.99,
				"tags": ["clothing", "fashion"],
				"metadata": {
					"brand": "FashionCorp",
					"in_stock": false
				}
			}`),
		}

		grammar, err := engine.InferStructure(samples)
		require.NoError(t, err)

		rootRule := grammar.Rules["root"].(map[string]interface{})
		fields := rootRule["fields"].(map[string]interface{})

		// Check all fields are present
		assert.Contains(t, fields, "id")
		assert.Contains(t, fields, "name")
		assert.Contains(t, fields, "price")
		assert.Contains(t, fields, "tags")
		assert.Contains(t, fields, "metadata")

		// Check array field
		tagsField := fields["tags"].(map[string]interface{})
		types := tagsField["types"].([]string)
		assert.Contains(t, types, "array")

		// Check nested object
		metadataField := fields["metadata"].(map[string]interface{})
		types = metadataField["types"].([]string)
		assert.Contains(t, types, "object")

		nestedFields := metadataField["fields"].(map[string]interface{})
		assert.Contains(t, nestedFields, "brand")
		assert.Contains(t, nestedFields, "in_stock")
	})
}

func TestJSONInferenceGrammarOutput(t *testing.T) {
	runTest(t, "TestJSONInferenceGrammarOutput", func(t *testing.T) {
		engine := inference.NewJSONInferenceEngine()

		samples := [][]byte{
			[]byte(`{"name": "Alice", "age": 25}`),
		}

		grammar, err := engine.InferStructure(samples)
		require.NoError(t, err)

		// Test that grammar can be marshaled to JSON
		data, err := json.Marshal(grammar)
		require.NoError(t, err)
		assert.NotEmpty(t, data)

		// Test that grammar can be unmarshaled back
		var unmarshaled inference.Grammar
		err = json.Unmarshal(data, &unmarshaled)
		require.NoError(t, err)
		assert.Equal(t, grammar.Format, unmarshaled.Format)
		assert.Equal(t, grammar.RootRule, unmarshaled.RootRule)
	})
}
