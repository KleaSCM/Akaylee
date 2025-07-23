/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: state_validators.go
Description: State validator implementations for different target types. Provides
validation logic for database states, API states, and generic states to ensure
consistency and correctness during state-aware fuzzing.
*/

package execution

import (
	"fmt"
	"strings"

	"github.com/kleascm/akaylee-fuzzer/pkg/interfaces"
)

// DatabaseStateValidator validates database states
type DatabaseStateValidator struct {
	config *interfaces.StateConfig
}

// NewDatabaseStateValidator creates a new database state validator
func NewDatabaseStateValidator(config *interfaces.StateConfig) *DatabaseStateValidator {
	return &DatabaseStateValidator{
		config: config,
	}
}

// ValidateState validates a database state
func (v *DatabaseStateValidator) ValidateState(state *interfaces.State) (bool, []string, error) {
	var errors []string

	// Check required fields
	if state.Type != interfaces.StateTypeDatabase {
		errors = append(errors, "invalid state type for database validator")
	}

	// Validate database connection info
	if url, exists := state.Data["database_url"]; !exists || url == "" {
		errors = append(errors, "missing or empty database URL")
	}

	if dbType, exists := state.Data["database_type"]; !exists || dbType == "" {
		errors = append(errors, "missing or empty database type")
	}

	// Validate schema file if specified
	if schemaFile, exists := state.Data["schema_file"]; exists && schemaFile != "" {
		// Could add file existence check here
	}

	// Check state validity
	if !state.Valid {
		errors = append(errors, "state marked as invalid")
	}

	return len(errors) == 0, errors, nil
}

// ValidateTransition validates a database state transition
func (v *DatabaseStateValidator) ValidateTransition(from, to *interfaces.State, transition *interfaces.StateTransition) (bool, []string, error) {
	var errors []string

	// Validate transition structure
	if transition.FromState != from.ID {
		errors = append(errors, "transition from state mismatch")
	}

	if transition.ToState != to.ID {
		errors = append(errors, "transition to state mismatch")
	}

	// Validate transition action
	if transition.Action == "" {
		errors = append(errors, "missing transition action")
	}

	// Validate transition probability
	if transition.Probability < 0 || transition.Probability > 1 {
		errors = append(errors, "invalid transition probability")
	}

	// Database-specific transition validation
	if strings.Contains(transition.Action, "DROP") && !v.config.StrictMode {
		errors = append(errors, "destructive action detected")
	}

	return len(errors) == 0, errors, nil
}

// ValidateConsistency validates consistency across multiple database states
func (v *DatabaseStateValidator) ValidateConsistency(states []*interfaces.State) (bool, []string, error) {
	var errors []string

	if len(states) == 0 {
		return true, errors, nil
	}

	// Check that all states are database states
	for i, state := range states {
		if state.Type != interfaces.StateTypeDatabase {
			errors = append(errors, fmt.Sprintf("state %d is not a database state", i))
		}
	}

	// Check for consistent database type
	firstDBType := states[0].Data["database_type"]
	for i, state := range states {
		if state.Data["database_type"] != firstDBType {
			errors = append(errors, fmt.Sprintf("inconsistent database type at state %d", i))
		}
	}

	return len(errors) == 0, errors, nil
}

// GetValidationRules returns database validation rules
func (v *DatabaseStateValidator) GetValidationRules() map[string]interface{} {
	return map[string]interface{}{
		"require_database_url":      true,
		"require_database_type":     true,
		"allow_destructive_actions": !v.config.StrictMode,
		"max_schema_size":           1024 * 1024, // 1MB
	}
}

// APIStateValidator validates API states
type APIStateValidator struct {
	config *interfaces.StateConfig
}

// NewAPIStateValidator creates a new API state validator
func NewAPIStateValidator(config *interfaces.StateConfig) *APIStateValidator {
	return &APIStateValidator{
		config: config,
	}
}

// ValidateState validates an API state
func (v *APIStateValidator) ValidateState(state *interfaces.State) (bool, []string, error) {
	var errors []string

	// Check required fields
	if state.Type != interfaces.StateTypeAPI {
		errors = append(errors, "invalid state type for API validator")
	}

	// Validate API base URL
	if baseURL, exists := state.Data["base_url"]; !exists || baseURL == "" {
		errors = append(errors, "missing or empty API base URL")
	}

	// Validate API endpoints
	if endpoints, exists := state.Data["endpoints"]; exists {
		if endpointList, ok := endpoints.([]string); ok {
			if len(endpointList) == 0 {
				errors = append(errors, "empty API endpoints list")
			}
		} else {
			errors = append(errors, "invalid API endpoints format")
		}
	}

	// Check state validity
	if !state.Valid {
		errors = append(errors, "state marked as invalid")
	}

	return len(errors) == 0, errors, nil
}

// ValidateTransition validates an API state transition
func (v *APIStateValidator) ValidateTransition(from, to *interfaces.State, transition *interfaces.StateTransition) (bool, []string, error) {
	var errors []string

	// Validate transition structure
	if transition.FromState != from.ID {
		errors = append(errors, "transition from state mismatch")
	}

	if transition.ToState != to.ID {
		errors = append(errors, "transition to state mismatch")
	}

	// Validate transition action
	if transition.Action == "" {
		errors = append(errors, "missing transition action")
	}

	// Validate transition probability
	if transition.Probability < 0 || transition.Probability > 1 {
		errors = append(errors, "invalid transition probability")
	}

	// API-specific transition validation
	if strings.Contains(transition.Action, "DELETE") && !v.config.StrictMode {
		errors = append(errors, "destructive action detected")
	}

	return len(errors) == 0, errors, nil
}

// ValidateConsistency validates consistency across multiple API states
func (v *APIStateValidator) ValidateConsistency(states []*interfaces.State) (bool, []string, error) {
	var errors []string

	if len(states) == 0 {
		return true, errors, nil
	}

	// Check that all states are API states
	for i, state := range states {
		if state.Type != interfaces.StateTypeAPI {
			errors = append(errors, fmt.Sprintf("state %d is not an API state", i))
		}
	}

	// Check for consistent base URL
	firstBaseURL := states[0].Data["base_url"]
	for i, state := range states {
		if state.Data["base_url"] != firstBaseURL {
			errors = append(errors, fmt.Sprintf("inconsistent base URL at state %d", i))
		}
	}

	return len(errors) == 0, errors, nil
}

// GetValidationRules returns API validation rules
func (v *APIStateValidator) GetValidationRules() map[string]interface{} {
	return map[string]interface{}{
		"require_base_url":          true,
		"require_endpoints":         false,
		"allow_destructive_actions": !v.config.StrictMode,
		"max_request_size":          10 * 1024 * 1024, // 10MB
	}
}

// GenericStateValidator validates generic states
type GenericStateValidator struct {
	config *interfaces.StateConfig
}

// NewGenericStateValidator creates a new generic state validator
func NewGenericStateValidator(config *interfaces.StateConfig) *GenericStateValidator {
	return &GenericStateValidator{
		config: config,
	}
}

// ValidateState validates a generic state
func (v *GenericStateValidator) ValidateState(state *interfaces.State) (bool, []string, error) {
	var errors []string

	// Basic state validation
	if state.ID == "" {
		errors = append(errors, "missing state ID")
	}

	if state.Name == "" {
		errors = append(errors, "missing state name")
	}

	if state.Timestamp.IsZero() {
		errors = append(errors, "missing state timestamp")
	}

	// Check state validity
	if !state.Valid {
		errors = append(errors, "state marked as invalid")
	}

	// Validate state hash
	if state.Hash == "" {
		errors = append(errors, "missing state hash")
	}

	return len(errors) == 0, errors, nil
}

// ValidateTransition validates a generic state transition
func (v *GenericStateValidator) ValidateTransition(from, to *interfaces.State, transition *interfaces.StateTransition) (bool, []string, error) {
	var errors []string

	// Validate transition structure
	if transition.ID == "" {
		errors = append(errors, "missing transition ID")
	}

	if transition.Name == "" {
		errors = append(errors, "missing transition name")
	}

	if transition.FromState != from.ID {
		errors = append(errors, "transition from state mismatch")
	}

	if transition.ToState != to.ID {
		errors = append(errors, "transition to state mismatch")
	}

	// Validate transition action
	if transition.Action == "" {
		errors = append(errors, "missing transition action")
	}

	// Validate transition probability
	if transition.Probability < 0 || transition.Probability > 1 {
		errors = append(errors, "invalid transition probability")
	}

	// Validate transition cost
	if transition.Cost < 0 {
		errors = append(errors, "negative transition cost")
	}

	return len(errors) == 0, errors, nil
}

// ValidateConsistency validates consistency across multiple generic states
func (v *GenericStateValidator) ValidateConsistency(states []*interfaces.State) (bool, []string, error) {
	var errors []string

	if len(states) == 0 {
		return true, errors, nil
	}

	// Check for consistent state type
	firstType := states[0].Type
	for i, state := range states {
		if state.Type != firstType {
			errors = append(errors, fmt.Sprintf("inconsistent state type at state %d", i))
		}
	}

	// Check for valid generation sequence
	for i := 1; i < len(states); i++ {
		if states[i].Generation < states[i-1].Generation {
			errors = append(errors, fmt.Sprintf("invalid generation sequence at state %d", i))
		}
	}

	return len(errors) == 0, errors, nil
}

// GetValidationRules returns generic validation rules
func (v *GenericStateValidator) GetValidationRules() map[string]interface{} {
	return map[string]interface{}{
		"require_state_id":        true,
		"require_state_name":      true,
		"require_state_timestamp": true,
		"require_state_hash":      true,
		"max_state_data_size":     1024 * 1024, // 1MB
		"max_metadata_size":       64 * 1024,   // 64KB
	}
}
