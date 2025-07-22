/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: inference.go
Description: Main entry point for advanced input structure inference. Provides the
InferenceEngine interface and core logic for grammar-based and protocol-aware structure
mining from sample corpora. Supports JSON, binary, and protocol formats.
*/

package inference

// InferenceEngine defines the interface for structure inference engines
type InferenceEngine interface {
	InferStructure(samples [][]byte) (*Grammar, error)
	Format() string
}

// Grammar represents an inferred grammar (to be defined in detail)
type Grammar struct {
	Format   string                 // e.g., "json", "binary", "http"
	RootRule string                 // Name of the root rule
	Rules    map[string]interface{} // Rule definitions (to be refined)
	Metadata map[string]interface{} // Extra info
}

// NewEngine returns an appropriate inference engine for the given format
func NewEngine(format string) InferenceEngine {
	switch format {
	case "json":
		return NewJSONInferenceEngine()
	case "binary":
		return NewBinaryInferenceEngine()
	default:
		return nil
	}
}
