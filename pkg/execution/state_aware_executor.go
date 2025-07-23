/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: state_aware_executor.go
Description: State-aware executor implementation for stateful targets. Extends the
regular executor with state management capabilities to handle databases, APIs, and
other stateful systems. Provides intelligent state tracking, restoration, and
transition management during fuzzing.
*/

package execution

import (
	"context"
	"fmt"
	"time"

	"github.com/kleascm/akaylee-fuzzer/pkg/interfaces"
	"github.com/sirupsen/logrus"
)

// StateAwareExecutor implements the StateAwareExecutor interface
// Provides state-aware execution for stateful targets
type StateAwareExecutor struct {
	executor     interfaces.Executor
	stateManager interfaces.StateManager
	logger       *logrus.Logger
	config       *interfaces.StateAwareFuzzerConfig

	// State tracking
	currentState *interfaces.State
	stateHistory []*interfaces.State
	stateStats   *StateExecutionStats

	// Performance tracking
	executionCount    int64
	stateRestoreCount int64
	transitionCount   int64
	validationCount   int64
}

// StateExecutionStats tracks state-aware execution statistics
type StateExecutionStats struct {
	TotalExecutions   int64     `json:"total_executions"`
	StateExecutions   int64     `json:"state_executions"`
	StateRestores     int64     `json:"state_restores"`
	StateTransitions  int64     `json:"state_transitions"`
	StateValidations  int64     `json:"state_validations"`
	StateErrors       int64     `json:"state_errors"`
	AverageStateDepth float64   `json:"average_state_depth"`
	MaxStateDepth     int       `json:"max_state_depth"`
	StartTime         time.Time `json:"start_time"`
	LastExecutionTime time.Time `json:"last_execution_time"`
}

// NewStateAwareExecutor creates a new state-aware executor
func NewStateAwareExecutor(executor interfaces.Executor, config *interfaces.StateAwareFuzzerConfig, logger *logrus.Logger) *StateAwareExecutor {
	return &StateAwareExecutor{
		executor:     executor,
		config:       config,
		logger:       logger,
		stateHistory: make([]*interfaces.State, 0),
		stateStats: &StateExecutionStats{
			StartTime: time.Now(),
		},
	}
}

// Initialize initializes the state-aware executor
func (sae *StateAwareExecutor) Initialize(config *interfaces.FuzzerConfig) error {
	// Initialize the underlying executor
	if err := sae.executor.Initialize(config); err != nil {
		return fmt.Errorf("failed to initialize underlying executor: %w", err)
	}

	// Initialize state manager if provided
	if sae.stateManager != nil {
		if err := sae.stateManager.Initialize(sae.config.StateConfig); err != nil {
			return fmt.Errorf("failed to initialize state manager: %w", err)
		}

		// Capture initial state
		ctx, cancel := context.WithTimeout(context.Background(), sae.config.StateConfig.StateTimeout)
		defer cancel()

		initialState, err := sae.stateManager.CaptureState(ctx)
		if err != nil {
			return fmt.Errorf("failed to capture initial state: %w", err)
		}

		sae.currentState = initialState
		sae.stateHistory = append(sae.stateHistory, initialState)
		sae.logger.Infof("State-aware executor initialized with initial state: %s", initialState.ID)
	}

	return nil
}

// Execute executes a test case with state awareness
func (sae *StateAwareExecutor) Execute(testCase *interfaces.TestCase) (*interfaces.ExecutionResult, error) {
	sae.executionCount++
	sae.stateStats.TotalExecutions++
	sae.stateStats.LastExecutionTime = time.Now()

	// Execute with current state
	ctx, cancel := context.WithTimeout(context.Background(), sae.config.StateConfig.StateTimeout)
	defer cancel()

	return sae.ExecuteWithState(ctx, testCase, sae.currentState)
}

// ExecuteWithState executes a test case with a specific initial state
func (sae *StateAwareExecutor) ExecuteWithState(ctx context.Context, testCase *interfaces.TestCase, initialState *interfaces.State) (*interfaces.ExecutionResult, error) {
	sae.stateStats.StateExecutions++

	// Validate initial state
	if sae.stateManager != nil {
		valid, err := sae.stateManager.ValidateState(ctx, initialState)
		if err != nil {
			sae.stateStats.StateErrors++
			return nil, fmt.Errorf("state validation failed: %w", err)
		}
		if !valid {
			sae.stateStats.StateErrors++
			return nil, fmt.Errorf("invalid initial state: %s", initialState.ID)
		}
		sae.validationCount++
		sae.stateStats.StateValidations++
	}

	// Restore to initial state if different from current
	if sae.currentState == nil || sae.currentState.ID != initialState.ID {
		if sae.stateManager != nil {
			if err := sae.stateManager.RestoreState(ctx, initialState); err != nil {
				sae.stateStats.StateErrors++
				return nil, fmt.Errorf("failed to restore state: %w", err)
			}
			sae.stateRestoreCount++
			sae.stateStats.StateRestores++
		}
		sae.currentState = initialState
	}

	// Execute the test case
	result, err := sae.executor.Execute(testCase)
	if err != nil {
		return nil, fmt.Errorf("execution failed: %w", err)
	}

	// Capture final state
	var finalState *interfaces.State
	if sae.stateManager != nil {
		finalState, err = sae.stateManager.CaptureState(ctx)
		if err != nil {
			sae.logger.Warnf("Failed to capture final state: %v", err)
		} else {
			sae.stateHistory = append(sae.stateHistory, finalState)
			sae.currentState = finalState

			// Update state depth statistics
			stateDepth := len(sae.stateHistory)
			if stateDepth > sae.stateStats.MaxStateDepth {
				sae.stateStats.MaxStateDepth = stateDepth
			}

			// Update average state depth
			totalDepth := float64(sae.stateStats.StateExecutions) * sae.stateStats.AverageStateDepth
			totalDepth += float64(stateDepth)
			sae.stateStats.AverageStateDepth = totalDepth / float64(sae.stateStats.StateExecutions+1)
		}
	}

	// Create state-aware result
	stateResult := &interfaces.StateResult{
		ExecutionResult: *result,
		InitialState:    initialState,
		FinalState:      finalState,
		StateValid:      finalState != nil && finalState.Valid,
		StateDepth:      len(sae.stateHistory),
		StateBreadth:    sae.calculateStateBreadth(),
		StateCoverage:   sae.calculateStateCoverage(),
	}

	// Validate final state
	if finalState != nil && sae.stateManager != nil {
		valid, err := sae.stateManager.ValidateState(ctx, finalState)
		if err != nil {
			sae.logger.Warnf("Final state validation failed: %v", err)
		} else if !valid {
			stateResult.StateValid = false
			stateResult.ValidationErrors = []string{"final state validation failed"}
			sae.logger.Warnf("Invalid final state")
		}
	}

	return &stateResult.ExecutionResult, nil
}

// GetStateManager returns the state manager
func (sae *StateAwareExecutor) GetStateManager() interfaces.StateManager {
	return sae.stateManager
}

// SetStateManager sets the state manager
func (sae *StateAwareExecutor) SetStateManager(manager interfaces.StateManager) {
	sae.stateManager = manager
}

// GetCurrentState returns the current state
func (sae *StateAwareExecutor) GetCurrentState() *interfaces.State {
	return sae.currentState
}

// ResetToInitialState resets to the initial state
func (sae *StateAwareExecutor) ResetToInitialState() error {
	if sae.stateManager == nil || len(sae.stateHistory) == 0 {
		return fmt.Errorf("no state manager or history available")
	}

	initialState := sae.stateHistory[0]
	ctx, cancel := context.WithTimeout(context.Background(), sae.config.StateConfig.StateTimeout)
	defer cancel()

	if err := sae.stateManager.RestoreState(ctx, initialState); err != nil {
		return fmt.Errorf("failed to reset to initial state: %w", err)
	}

	sae.currentState = initialState
	sae.stateHistory = []*interfaces.State{initialState}
	sae.logger.Infof("Reset to initial state: %s", initialState.ID)

	return nil
}

// Cleanup cleans up resources
func (sae *StateAwareExecutor) Cleanup() error {
	// Cleanup state manager
	if sae.stateManager != nil {
		if err := sae.stateManager.Cleanup(); err != nil {
			sae.logger.Warnf("State manager cleanup failed: %v", err)
		}
	}

	// Cleanup underlying executor
	if err := sae.executor.Cleanup(); err != nil {
		return fmt.Errorf("executor cleanup failed: %w", err)
	}

	return nil
}

// GetStateStats returns state execution statistics
func (sae *StateAwareExecutor) GetStateStats() *StateExecutionStats {
	return sae.stateStats
}

// GetStateHistory returns the state history
func (sae *StateAwareExecutor) GetStateHistory() []*interfaces.State {
	history := make([]*interfaces.State, len(sae.stateHistory))
	copy(history, sae.stateHistory)
	return history
}

// ExecuteStateTransition executes a state transition
func (sae *StateAwareExecutor) ExecuteStateTransition(ctx context.Context, transition *interfaces.StateTransition) (*interfaces.State, error) {
	if sae.stateManager == nil {
		return nil, fmt.Errorf("no state manager available")
	}

	newState, err := sae.stateManager.ExecuteTransition(ctx, transition)
	if err != nil {
		return nil, fmt.Errorf("failed to execute transition: %w", err)
	}

	sae.transitionCount++
	sae.stateStats.StateTransitions++
	sae.currentState = newState
	sae.stateHistory = append(sae.stateHistory, newState)

	sae.logger.Debugf("Executed state transition: %s -> %s", transition.FromState, transition.ToState)
	return newState, nil
}

// GetAvailableTransitions gets available transitions from current state
func (sae *StateAwareExecutor) GetAvailableTransitions(ctx context.Context) ([]*interfaces.StateTransition, error) {
	if sae.stateManager == nil || sae.currentState == nil {
		return []*interfaces.StateTransition{}, nil
	}

	return sae.stateManager.GetTransitions(ctx, sae.currentState)
}

// ValidateCurrentState validates the current state
func (sae *StateAwareExecutor) ValidateCurrentState(ctx context.Context) (bool, error) {
	if sae.stateManager == nil || sae.currentState == nil {
		return true, nil
	}

	return sae.stateManager.ValidateState(ctx, sae.currentState)
}

// Helper methods

func (sae *StateAwareExecutor) calculateStateBreadth() int {
	if len(sae.stateHistory) == 0 {
		return 0
	}

	// Count unique states at the same generation level
	generationMap := make(map[int]map[string]bool)
	for _, state := range sae.stateHistory {
		if _, exists := generationMap[state.Generation]; !exists {
			generationMap[state.Generation] = make(map[string]bool)
		}
		generationMap[state.Generation][state.ID] = true
	}

	maxBreadth := 0
	for _, states := range generationMap {
		if len(states) > maxBreadth {
			maxBreadth = len(states)
		}
	}

	return maxBreadth
}

func (sae *StateAwareExecutor) calculateStateCoverage() float64 {
	if len(sae.stateHistory) == 0 {
		return 0.0
	}

	// Calculate coverage based on unique states explored
	uniqueStates := make(map[string]bool)
	for _, state := range sae.stateHistory {
		uniqueStates[state.ID] = true
	}

	// This is a simplified coverage calculation
	// In a real implementation, you might track expected states vs explored states
	totalUniqueStates := float64(len(uniqueStates))
	totalExecutions := float64(sae.stateStats.StateExecutions)

	if totalExecutions == 0 {
		return 0.0
	}

	// Coverage as percentage of unique states explored
	return (totalUniqueStates / totalExecutions) * 100.0
}

// GetExecutionStats returns execution statistics
func (sae *StateAwareExecutor) GetExecutionStats() map[string]interface{} {
	stats := map[string]interface{}{
		"total_executions":    sae.executionCount,
		"state_executions":    sae.stateStats.StateExecutions,
		"state_restores":      sae.stateRestoreCount,
		"state_transitions":   sae.transitionCount,
		"state_validations":   sae.validationCount,
		"current_state_depth": len(sae.stateHistory),
		"max_state_depth":     sae.stateStats.MaxStateDepth,
		"average_state_depth": sae.stateStats.AverageStateDepth,
		"state_breadth":       sae.calculateStateBreadth(),
		"state_coverage":      sae.calculateStateCoverage(),
		"uptime":              time.Since(sae.stateStats.StartTime),
	}

	return stats
}
