/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: state_aware_mutator.go
Description: State-aware mutator implementation for stateful targets. Extends regular
mutators with state-aware mutation capabilities to create mutations that respect and
manipulate target state. Provides intelligent mutation strategies for databases, APIs,
and other stateful systems.
*/

package strategies

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	"github.com/google/uuid"
	"github.com/kleascm/akaylee-fuzzer/pkg/interfaces"
	"github.com/sirupsen/logrus"
)

// StateAwareMutator implements the StateAwareMutator interface
// Provides state-aware mutation capabilities for stateful targets
type StateAwareMutator struct {
	mutator      interfaces.Mutator
	stateManager interfaces.StateManager
	logger       *logrus.Logger
	config       *interfaces.StateAwareFuzzerConfig

	// State-aware mutation parameters
	stateMutationRate    float64
	stateTransitionRate  float64
	maxStateDepth        int
	stateRecoveryEnabled bool

	// Performance tracking
	mutationCount      int64
	stateMutationCount int64
	transitionCount    int64
	recoveryCount      int64
}

// NewStateAwareMutator creates a new state-aware mutator
func NewStateAwareMutator(mutator interfaces.Mutator, config *interfaces.StateAwareFuzzerConfig, logger *logrus.Logger) *StateAwareMutator {
	return &StateAwareMutator{
		mutator:              mutator,
		config:               config,
		logger:               logger,
		stateMutationRate:    config.StateMutationRate,
		stateTransitionRate:  config.StateTransitionRate,
		maxStateDepth:        config.MaxStateDepth,
		stateRecoveryEnabled: config.StateRecoveryEnabled,
	}
}

// Mutate creates a new test case with state-aware mutations
func (sam *StateAwareMutator) Mutate(testCase *interfaces.TestCase) (*interfaces.TestCase, error) {
	sam.mutationCount++

	// Get current state if state manager is available
	var currentState *interfaces.State
	if sam.stateManager != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		var err error
		currentState, err = sam.stateManager.CaptureState(ctx)
		if err != nil {
			sam.logger.Warnf("Failed to capture current state: %v", err)
		}
	}

	// Perform state-aware mutation
	return sam.MutateWithState(testCase, currentState)
}

// MutateWithState creates a new test case with state-aware mutations
func (sam *StateAwareMutator) MutateWithState(testCase *interfaces.TestCase, currentState *interfaces.State) (*interfaces.TestCase, error) {
	sam.stateMutationCount++

	// Check if we should perform state-aware mutation
	if currentState != nil && rand.Float64() < sam.stateMutationRate {
		return sam.performStateAwareMutation(testCase, currentState)
	}

	// Fall back to regular mutation
	return sam.mutator.Mutate(testCase)
}

// GetStateDependentMutations gets mutations that depend on the current state
func (sam *StateAwareMutator) GetStateDependentMutations(state *interfaces.State) ([]*interfaces.TestCase, error) {
	if sam.stateManager == nil || state == nil {
		return []*interfaces.TestCase{}, nil
	}

	var mutations []*interfaces.TestCase

	// Get available transitions from current state
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	transitions, err := sam.stateManager.GetTransitions(ctx, state)
	if err != nil {
		return nil, fmt.Errorf("failed to get transitions: %w", err)
	}

	// Create mutations based on transitions
	for _, transition := range transitions {
		if rand.Float64() < transition.Probability {
			mutation, err := sam.createTransitionMutation(state, transition)
			if err != nil {
				sam.logger.Warnf("Failed to create transition mutation: %v", err)
				continue
			}
			mutations = append(mutations, mutation)
		}
	}

	// Create state-specific mutations based on state type
	switch state.Type {
	case interfaces.StateTypeDatabase:
		dbMutations, err := sam.createDatabaseMutations(state)
		if err != nil {
			sam.logger.Warnf("Failed to create database mutations: %v", err)
		} else {
			mutations = append(mutations, dbMutations...)
		}
	case interfaces.StateTypeAPI:
		apiMutations, err := sam.createAPIMutations(state)
		if err != nil {
			sam.logger.Warnf("Failed to create API mutations: %v", err)
		} else {
			mutations = append(mutations, apiMutations...)
		}
	case interfaces.StateTypeNetwork:
		networkMutations, err := sam.createNetworkMutations(state)
		if err != nil {
			sam.logger.Warnf("Failed to create network mutations: %v", err)
		} else {
			mutations = append(mutations, networkMutations...)
		}
	}

	return mutations, nil
}

// SetStateManager sets the state manager
func (sam *StateAwareMutator) SetStateManager(manager interfaces.StateManager) {
	sam.stateManager = manager
}

// Name returns the name of this mutator
func (sam *StateAwareMutator) Name() string {
	return fmt.Sprintf("StateAware%s", sam.mutator.Name())
}

// Description returns a description of this mutator
func (sam *StateAwareMutator) Description() string {
	return fmt.Sprintf("State-aware version of %s - creates mutations that respect and manipulate target state", sam.mutator.Description())
}

// Init initializes the state-aware mutator
func (sam *StateAwareMutator) Init() error {
	// Note: The underlying mutator interface doesn't have Init() method
	// This is a state-aware specific initialization

	sam.logger.Infof("State-aware mutator initialized with state mutation rate: %.2f", sam.stateMutationRate)
	return nil
}

// Helper methods

func (sam *StateAwareMutator) performStateAwareMutation(testCase *interfaces.TestCase, currentState *interfaces.State) (*interfaces.TestCase, error) {
	// Check state depth limit
	if currentState.Generation >= sam.maxStateDepth {
		sam.logger.Debugf("State depth limit reached (%d), falling back to regular mutation", sam.maxStateDepth)
		return sam.mutator.Mutate(testCase)
	}

	// Decide mutation strategy based on state type
	switch currentState.Type {
	case interfaces.StateTypeDatabase:
		return sam.performDatabaseMutation(testCase, currentState)
	case interfaces.StateTypeAPI:
		return sam.performAPIMutation(testCase, currentState)
	case interfaces.StateTypeNetwork:
		return sam.performNetworkMutation(testCase, currentState)
	case interfaces.StateTypeFile:
		return sam.performFileMutation(testCase, currentState)
	case interfaces.StateTypeMemory:
		return sam.performMemoryMutation(testCase, currentState)
	default:
		return sam.performGenericStateMutation(testCase, currentState)
	}
}

func (sam *StateAwareMutator) performDatabaseMutation(testCase *interfaces.TestCase, state *interfaces.State) (*interfaces.TestCase, error) {
	// Create database-specific mutations
	mutatedData := make([]byte, len(testCase.Data))
	copy(mutatedData, testCase.Data)

	// Add database-specific mutations
	if dbType, exists := state.Data["database_type"]; exists {
		switch dbType {
		case "postgres":
			mutatedData = sam.mutatePostgreSQLData(mutatedData, state)
		case "mysql":
			mutatedData = sam.mutateMySQLData(mutatedData, state)
		case "sqlite":
			mutatedData = sam.mutateSQLiteData(mutatedData, state)
		default:
			mutatedData = sam.mutateGenericSQLData(mutatedData, state)
		}
	}

	return sam.createStateAwareTestCase(testCase, mutatedData, state, "database_mutation"), nil
}

func (sam *StateAwareMutator) performAPIMutation(testCase *interfaces.TestCase, state *interfaces.State) (*interfaces.TestCase, error) {
	// Create API-specific mutations
	mutatedData := make([]byte, len(testCase.Data))
	copy(mutatedData, testCase.Data)

	// Add API-specific mutations
	if endpoints, exists := state.Data["endpoints"]; exists {
		if endpointList, ok := endpoints.([]string); ok {
			mutatedData = sam.mutateAPIEndpoints(mutatedData, endpointList, state)
		}
	}

	// Add authentication mutations
	if authToken, exists := state.Data["auth_token"]; exists && authToken != "" {
		mutatedData = sam.mutateAPIAuth(mutatedData, authToken.(string), state)
	}

	return sam.createStateAwareTestCase(testCase, mutatedData, state, "api_mutation"), nil
}

func (sam *StateAwareMutator) performNetworkMutation(testCase *interfaces.TestCase, state *interfaces.State) (*interfaces.TestCase, error) {
	// Create network-specific mutations
	mutatedData := make([]byte, len(testCase.Data))
	copy(mutatedData, testCase.Data)

	// Add network-specific mutations
	mutatedData = sam.mutateNetworkProtocol(mutatedData, state)

	return sam.createStateAwareTestCase(testCase, mutatedData, state, "network_mutation"), nil
}

func (sam *StateAwareMutator) performFileMutation(testCase *interfaces.TestCase, state *interfaces.State) (*interfaces.TestCase, error) {
	// Create file-specific mutations
	mutatedData := make([]byte, len(testCase.Data))
	copy(mutatedData, testCase.Data)

	// Add file-specific mutations
	mutatedData = sam.mutateFileFormat(mutatedData, state)

	return sam.createStateAwareTestCase(testCase, mutatedData, state, "file_mutation"), nil
}

func (sam *StateAwareMutator) performMemoryMutation(testCase *interfaces.TestCase, state *interfaces.State) (*interfaces.TestCase, error) {
	// Create memory-specific mutations
	mutatedData := make([]byte, len(testCase.Data))
	copy(mutatedData, testCase.Data)

	// Add memory-specific mutations
	mutatedData = sam.mutateMemoryLayout(mutatedData, state)

	return sam.createStateAwareTestCase(testCase, mutatedData, state, "memory_mutation"), nil
}

func (sam *StateAwareMutator) performGenericStateMutation(testCase *interfaces.TestCase, state *interfaces.State) (*interfaces.TestCase, error) {
	// Create generic state mutations
	mutatedData := make([]byte, len(testCase.Data))
	copy(mutatedData, testCase.Data)

	// Add state metadata to mutation
	mutatedData = sam.mutateWithStateMetadata(mutatedData, state)

	return sam.createStateAwareTestCase(testCase, mutatedData, state, "generic_state_mutation"), nil
}

func (sam *StateAwareMutator) createTransitionMutation(state *interfaces.State, transition *interfaces.StateTransition) (*interfaces.TestCase, error) {
	// Create a test case that triggers the transition
	mutationData := transition.Input
	if len(mutationData) == 0 {
		// Generate default transition data
		mutationData = []byte(fmt.Sprintf("TRANSITION:%s:%s", transition.Action, transition.Name))
	}

	testCase := &interfaces.TestCase{
		ID:         uuid.New().String(),
		Data:       mutationData,
		ParentID:   "",
		Generation: state.Generation + 1,
		CreatedAt:  time.Now(),
		Priority:   100, // High priority for transition mutations
		Metadata:   make(map[string]interface{}),
	}

	testCase.Metadata["mutator"] = sam.Name()
	testCase.Metadata["state_aware"] = true
	testCase.Metadata["transition_id"] = transition.ID
	testCase.Metadata["transition_action"] = transition.Action
	testCase.Metadata["from_state"] = transition.FromState
	testCase.Metadata["to_state"] = transition.ToState
	testCase.Metadata["state_type"] = string(state.Type)

	return testCase, nil
}

func (sam *StateAwareMutator) createStateAwareTestCase(original *interfaces.TestCase, mutatedData []byte, state *interfaces.State, mutationType string) *interfaces.TestCase {
	testCase := &interfaces.TestCase{
		ID:         uuid.New().String(),
		Data:       mutatedData,
		ParentID:   original.ID,
		Generation: original.Generation + 1,
		CreatedAt:  time.Now(),
		Priority:   original.Priority,
		Metadata:   make(map[string]interface{}),
	}

	// Copy original metadata
	for k, v := range original.Metadata {
		testCase.Metadata[k] = v
	}

	// Add state-aware metadata
	testCase.Metadata["mutator"] = sam.Name()
	testCase.Metadata["state_aware"] = true
	testCase.Metadata["mutation_type"] = mutationType
	testCase.Metadata["state_id"] = state.ID
	testCase.Metadata["state_type"] = string(state.Type)
	testCase.Metadata["state_generation"] = state.Generation
	testCase.Metadata["state_hash"] = state.Hash

	return testCase
}

// Database-specific mutation methods (stubs for now)
func (sam *StateAwareMutator) mutatePostgreSQLData(data []byte, state *interfaces.State) []byte {
	// PostgreSQL-specific mutations
	return data
}

func (sam *StateAwareMutator) mutateMySQLData(data []byte, state *interfaces.State) []byte {
	// MySQL-specific mutations
	return data
}

func (sam *StateAwareMutator) mutateSQLiteData(data []byte, state *interfaces.State) []byte {
	// SQLite-specific mutations
	return data
}

func (sam *StateAwareMutator) mutateGenericSQLData(data []byte, state *interfaces.State) []byte {
	// Generic SQL mutations
	return data
}

// API-specific mutation methods (stubs for now)
func (sam *StateAwareMutator) mutateAPIEndpoints(data []byte, endpoints []string, state *interfaces.State) []byte {
	// API endpoint mutations
	return data
}

func (sam *StateAwareMutator) mutateAPIAuth(data []byte, authToken string, state *interfaces.State) []byte {
	// API authentication mutations
	return data
}

// Network-specific mutation methods (stubs for now)
func (sam *StateAwareMutator) mutateNetworkProtocol(data []byte, state *interfaces.State) []byte {
	// Network protocol mutations
	return data
}

// File-specific mutation methods (stubs for now)
func (sam *StateAwareMutator) mutateFileFormat(data []byte, state *interfaces.State) []byte {
	// File format mutations
	return data
}

// Memory-specific mutation methods (stubs for now)
func (sam *StateAwareMutator) mutateMemoryLayout(data []byte, state *interfaces.State) []byte {
	// Memory layout mutations
	return data
}

// Generic state mutation methods
func (sam *StateAwareMutator) mutateWithStateMetadata(data []byte, state *interfaces.State) []byte {
	// Add state metadata to the mutation
	metadata := fmt.Sprintf("STATE:%s:%s:%d", state.ID, state.Type, state.Generation)
	return append(data, []byte(metadata)...)
}

// Database mutation creation methods (stubs for now)
func (sam *StateAwareMutator) createDatabaseMutations(state *interfaces.State) ([]*interfaces.TestCase, error) {
	return []*interfaces.TestCase{}, nil
}

// API mutation creation methods (stubs for now)
func (sam *StateAwareMutator) createAPIMutations(state *interfaces.State) ([]*interfaces.TestCase, error) {
	return []*interfaces.TestCase{}, nil
}

// Network mutation creation methods (stubs for now)
func (sam *StateAwareMutator) createNetworkMutations(state *interfaces.State) ([]*interfaces.TestCase, error) {
	return []*interfaces.TestCase{}, nil
}

// GetMutationStats returns mutation statistics
func (sam *StateAwareMutator) GetMutationStats() map[string]interface{} {
	return map[string]interface{}{
		"total_mutations":     sam.mutationCount,
		"state_mutations":     sam.stateMutationCount,
		"transitions":         sam.transitionCount,
		"recoveries":          sam.recoveryCount,
		"state_mutation_rate": sam.stateMutationRate,
		"transition_rate":     sam.stateTransitionRate,
		"max_state_depth":     sam.maxStateDepth,
		"recovery_enabled":    sam.stateRecoveryEnabled,
	}
}
