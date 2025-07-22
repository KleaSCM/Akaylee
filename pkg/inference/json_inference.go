/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: json_inference.go
Description: JSON structure inference engine. Analyzes a corpus of JSON samples to infer
field types, nesting, enums, value ranges, and generates a grammar for structure-aware fuzzing.
*/

package inference

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
)

// JSONType represents a JSON type
// Used for type inference and merging
const (
	TypeNull   = "null"
	TypeBool   = "bool"
	TypeNumber = "number"
	TypeString = "string"
	TypeArray  = "array"
	TypeObject = "object"
)

// FieldInfo holds information about a field across samples
type FieldInfo struct {
	Types    map[string]bool       // Set of types seen
	Required int                   // Number of samples where present
	Total    int                   // Total samples
	Values   map[string]int        // For enums: value counts
	Min, Max *float64              // For numbers: min/max
	Children map[string]*FieldInfo // For objects: nested fields
	Elem     *FieldInfo            // For arrays: element type info
	Examples []interface{}         // Example values
}

// NewFieldInfo creates a new FieldInfo
func NewFieldInfo() *FieldInfo {
	return &FieldInfo{
		Types:    make(map[string]bool),
		Values:   make(map[string]int),
		Children: make(map[string]*FieldInfo),
	}
}

// JSONInferenceEngine infers structure from JSON samples
type JSONInferenceEngine struct{}

// NewJSONInferenceEngine creates a new JSON inference engine
func NewJSONInferenceEngine() *JSONInferenceEngine {
	return &JSONInferenceEngine{}
}

// InferStructure analyzes JSON samples and infers a grammar
func (e *JSONInferenceEngine) InferStructure(samples [][]byte) (*Grammar, error) {
	if len(samples) == 0 {
		return nil, fmt.Errorf("no samples provided")
	}

	rootInfo := NewFieldInfo()
	rootInfo.Total = len(samples)

	for _, sample := range samples {
		var v interface{}
		if err := json.Unmarshal(sample, &v); err != nil {
			return nil, fmt.Errorf("failed to parse sample: %w", err)
		}
		analyzeValue(v, rootInfo)
	}

	grammar := &Grammar{
		Format:   "json",
		RootRule: "root",
		Rules:    make(map[string]interface{}),
		Metadata: map[string]interface{}{"samples": len(samples)},
	}

	grammar.Rules["root"] = synthesizeRule(rootInfo)

	return grammar, nil
}

// Format returns the format handled by this engine
func (e *JSONInferenceEngine) Format() string {
	return "json"
}

// analyzeValue recursively analyzes a value and updates FieldInfo
func analyzeValue(v interface{}, info *FieldInfo) {
	if v == nil {
		info.Types[TypeNull] = true
		return
	}

	switch val := v.(type) {
	case bool:
		info.Types[TypeBool] = true
		info.Values[fmt.Sprintf("%v", val)]++
		info.Examples = appendExample(info.Examples, val)
	case float64:
		info.Types[TypeNumber] = true
		if info.Min == nil || val < *info.Min {
			info.Min = new(float64)
			*info.Min = val
		}
		if info.Max == nil || val > *info.Max {
			info.Max = new(float64)
			*info.Max = val
		}
		info.Examples = appendExample(info.Examples, val)
	case string:
		info.Types[TypeString] = true
		info.Values[val]++
		info.Examples = appendExample(info.Examples, val)
	case []interface{}:
		info.Types[TypeArray] = true
		if info.Elem == nil {
			info.Elem = NewFieldInfo()
		}
		for _, elem := range val {
			analyzeValue(elem, info.Elem)
		}
		info.Examples = appendExample(info.Examples, val)
	case map[string]interface{}:
		info.Types[TypeObject] = true
		for k, v2 := range val {
			child, ok := info.Children[k]
			if !ok {
				child = NewFieldInfo()
				info.Children[k] = child
			}
			child.Required++
			analyzeValue(v2, child)
		}
		info.Examples = appendExample(info.Examples, val)
	default:
		// Fallback: record type name
		typeName := reflect.TypeOf(v).String()
		info.Types[typeName] = true
		info.Examples = appendExample(info.Examples, v)
	}
}

// appendExample adds an example value if not already present (up to 5)
func appendExample(examples []interface{}, v interface{}) []interface{} {
	if len(examples) >= 5 {
		return examples
	}
	for _, ex := range examples {
		if reflect.DeepEqual(ex, v) {
			return examples
		}
	}
	return append(examples, v)
}

// synthesizeRule builds a grammar rule from FieldInfo
func synthesizeRule(info *FieldInfo) map[string]interface{} {
	rule := make(map[string]interface{})

	types := sortedKeys(info.Types)
	rule["types"] = types

	if len(types) == 1 {
		switch types[0] {
		case TypeObject:
			fields := make(map[string]interface{})
			for k, child := range info.Children {
				fields[k] = synthesizeRule(child)
			}
			rule["fields"] = fields
			// Mark required/optional
			required := []string{}
			optional := []string{}
			for k, child := range info.Children {
				if child.Required == info.Total {
					required = append(required, k)
				} else {
					optional = append(optional, k)
				}
			}
			rule["required"] = required
			rule["optional"] = optional
		case TypeArray:
			if info.Elem != nil {
				rule["element"] = synthesizeRule(info.Elem)
			}
			// Could add min/max length, etc.
		case TypeNumber:
			if info.Min != nil && info.Max != nil {
				rule["min"] = *info.Min
				rule["max"] = *info.Max
			}
		case TypeString, TypeBool:
			// If few unique values, treat as enum
			if len(info.Values) > 0 && len(info.Values) <= 10 {
				enum := sortedKeys(info.Values)
				rule["enum"] = enum
			}
		}
	}

	// Add examples
	if len(info.Examples) > 0 {
		rule["examples"] = info.Examples
	}

	return rule
}

// sortedKeys returns sorted keys of a map[string]T
func sortedKeys(m interface{}) []string {
	var keys []string
	switch mm := m.(type) {
	case map[string]bool:
		for k := range mm {
			keys = append(keys, k)
		}
	case map[string]int:
		for k := range mm {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys
}
