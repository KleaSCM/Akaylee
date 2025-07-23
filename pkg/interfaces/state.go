/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: state.go
Description: State management interfaces for state-aware fuzzing. Provides comprehensive
state tracking, transition management, and validation for stateful targets like databases,
APIs, and other systems that maintain internal state. Enables intelligent fuzzing that
understands and respects target state.
*/

package interfaces

import (
	"context"
	"time"
)

// State represents the current state of a target system
// Contains all necessary information to understand and manipulate target state
type State struct {
	ID          string                 `json:"id"`          // Unique state identifier
	Name        string                 `json:"name"`        // Human-readable state name
	Type        StateType              `json:"type"`        // Type of state (database, api, etc.)
	Data        map[string]interface{} `json:"data"`        // State-specific data
	Metadata    map[string]interface{} `json:"metadata"`    // Additional metadata
	Timestamp   time.Time              `json:"timestamp"`   // When state was captured
	Valid       bool                   `json:"valid"`       // Whether state is valid
	Hash        string                 `json:"hash"`        // State hash for deduplication
	ParentID    string                 `json:"parent_id"`   // Parent state ID
	Generation  int                    `json:"generation"`  // State generation number
	Transitions []string               `json:"transitions"` // Available transitions
}

// StateType defines the type of stateful target
type StateType string

const (
	StateTypeDatabase StateType = "database"
	StateTypeAPI      StateType = "api"
	StateTypeNetwork  StateType = "network"
	StateTypeFile     StateType = "file"
	StateTypeMemory   StateType = "memory"
	StateTypeCustom   StateType = "custom"
)

// StateTransition represents a transition between states
// Defines how to move from one state to another
type StateTransition struct {
	ID          string                 `json:"id"`          // Unique transition ID
	Name        string                 `json:"name"`        // Human-readable name
	FromState   string                 `json:"from_state"`  // Source state ID
	ToState     string                 `json:"to_state"`    // Target state ID
	Action      string                 `json:"action"`      // Action to perform
	Input       []byte                 `json:"input"`       // Input data for transition
	Conditions  map[string]interface{} `json:"conditions"`  // Conditions for transition
	Probability float64                `json:"probability"` // Transition probability
	Cost        int                    `json:"cost"`        // Transition cost/effort
	Valid       bool                   `json:"valid"`       // Whether transition is valid
	Metadata    map[string]interface{} `json:"metadata"`    // Additional metadata
}

// StateManager manages the state of a target system
// Provides state capture, restoration, and transition capabilities
type StateManager interface {
	// Initialize the state manager
	Initialize(config *StateConfig) error

	// Capture current state of the target
	CaptureState(ctx context.Context) (*State, error)

	// Restore target to a specific state
	RestoreState(ctx context.Context, state *State) error

	// Get available transitions from current state
	GetTransitions(ctx context.Context, state *State) ([]*StateTransition, error)

	// Execute a state transition
	ExecuteTransition(ctx context.Context, transition *StateTransition) (*State, error)

	// Validate if a state is valid
	ValidateState(ctx context.Context, state *State) (bool, error)

	// Get state history
	GetStateHistory() []*State

	// Cleanup resources
	Cleanup() error
}

// StateValidator validates state consistency and correctness
// Ensures states are valid and transitions are safe
type StateValidator interface {
	// Validate a single state
	ValidateState(state *State) (bool, []string, error)

	// Validate a state transition
	ValidateTransition(from, to *State, transition *StateTransition) (bool, []string, error)

	// Check state consistency across multiple states
	ValidateConsistency(states []*State) (bool, []string, error)

	// Get validation rules
	GetValidationRules() map[string]interface{}
}

// StateAwareExecutor extends Executor with state management capabilities
// Handles stateful targets that require state tracking and management
type StateAwareExecutor interface {
	Executor

	// Get the state manager
	GetStateManager() StateManager

	// Set the state manager
	SetStateManager(manager StateManager)

	// Execute with state awareness
	ExecuteWithState(ctx context.Context, testCase *TestCase, initialState *State) (*ExecutionResult, error)

	// Get current state
	GetCurrentState() *State

	// Reset to initial state
	ResetToInitialState() error
}

// StateAwareMutator extends Mutator with state-aware mutation capabilities
// Creates mutations that respect and manipulate target state
type StateAwareMutator interface {
	Mutator

	// Set the state manager
	SetStateManager(manager StateManager)

	// Mutate with state awareness
	MutateWithState(testCase *TestCase, currentState *State) (*TestCase, error)

	// Get state-dependent mutations
	GetStateDependentMutations(state *State) ([]*TestCase, error)
}

// StateConfig configuration for state management
type StateConfig struct {
	// Target configuration
	TargetPath string            `json:"target_path"` // Path to target executable
	TargetArgs []string          `json:"target_args"` // Target arguments
	TargetEnv  map[string]string `json:"target_env"`  // Target environment
	TargetType StateType         `json:"target_type"` // Type of stateful target

	// State management
	InitialState *State        `json:"initial_state"` // Initial state to restore to
	StateTimeout time.Duration `json:"state_timeout"` // Timeout for state operations
	MaxStates    int           `json:"max_states"`    // Maximum states to track
	StateBackup  bool          `json:"state_backup"`  // Whether to backup states

	// Database-specific (if applicable)
	DatabaseURL  string `json:"database_url"`  // Database connection URL
	DatabaseType string `json:"database_type"` // Database type (postgres, mysql, etc.)
	SchemaFile   string `json:"schema_file"`   // Database schema file

	// API-specific (if applicable)
	APIBaseURL   string   `json:"api_base_url"`   // API base URL
	APIAuthToken string   `json:"api_auth_token"` // API authentication token
	APIEndpoints []string `json:"api_endpoints"`  // Available API endpoints

	// Validation
	ValidationRules map[string]interface{} `json:"validation_rules"` // State validation rules
	StrictMode      bool                   `json:"strict_mode"`      // Strict validation mode

	// Recovery
	AutoRecovery        bool          `json:"auto_recovery"`         // Automatic state recovery
	RecoveryDelay       time.Duration `json:"recovery_delay"`        // Delay before recovery attempts
	MaxRecoveryAttempts int           `json:"max_recovery_attempts"` // Maximum recovery attempts
}

// StateAwareFuzzerConfig extends FuzzerConfig with state-aware capabilities
type StateAwareFuzzerConfig struct {
	FuzzerConfig

	// State management
	StateConfig *StateConfig `json:"state_config"` // State management configuration
	StateAware  bool         `json:"state_aware"`  // Whether to use state-aware fuzzing

	// State-aware fuzzing parameters
	StateMutationRate    float64 `json:"state_mutation_rate"`    // Rate of state mutations
	StateTransitionRate  float64 `json:"state_transition_rate"`  // Rate of state transitions
	StateValidationRate  float64 `json:"state_validation_rate"`  // Rate of state validation
	MaxStateDepth        int     `json:"max_state_depth"`        // Maximum state depth
	StateRecoveryEnabled bool    `json:"state_recovery_enabled"` // Enable state recovery
}

// StateResult contains state-specific execution results
type StateResult struct {
	ExecutionResult

	// State information
	InitialState *State             `json:"initial_state"` // State before execution
	FinalState   *State             `json:"final_state"`   // State after execution
	StateChanges []*StateTransition `json:"state_changes"` // State changes during execution

	// State validation
	StateValid       bool     `json:"state_valid"`       // Whether final state is valid
	ValidationErrors []string `json:"validation_errors"` // State validation errors

	// State metrics
	StateDepth    int     `json:"state_depth"`    // Depth of state exploration
	StateBreadth  int     `json:"state_breadth"`  // Breadth of state exploration
	StateCoverage float64 `json:"state_coverage"` // State coverage percentage
}
