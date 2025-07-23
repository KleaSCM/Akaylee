/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: state_manager.go
Description: Core state manager implementation for state-aware fuzzing. Provides
comprehensive state management capabilities for databases, APIs, and other stateful
targets. Implements intelligent state capture, restoration, and transition tracking
with validation and recovery mechanisms.
*/

package execution

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/kleascm/akaylee-fuzzer/pkg/interfaces"
	"github.com/sirupsen/logrus"
)

// StateManager implements the StateManager interface
// Provides comprehensive state management for stateful targets
type StateManager struct {
	config       *interfaces.StateConfig
	logger       *logrus.Logger
	validator    interfaces.StateValidator
	stateHistory []*interfaces.State
	transitions  map[string]*interfaces.StateTransition
	currentState *interfaces.State
	mu           sync.RWMutex

	// State storage
	stateDir   string
	backupDir  string
	stateIndex map[string]*interfaces.State

	// Recovery
	recoveryAttempts int
	lastRecovery     time.Time

	// Performance tracking
	stateCaptureCount int64
	stateRestoreCount int64
	transitionCount   int64
	validationCount   int64
}

// NewStateManager creates a new state manager instance
func NewStateManager(config *interfaces.StateConfig, logger *logrus.Logger) *StateManager {
	return &StateManager{
		config:      config,
		logger:      logger,
		transitions: make(map[string]*interfaces.StateTransition),
		stateIndex:  make(map[string]*interfaces.State),
		stateDir:    filepath.Join("states", string(config.TargetType)),
		backupDir:   filepath.Join("states", string(config.TargetType), "backup"),
	}
}

// Initialize sets up the state manager
func (sm *StateManager) Initialize(config *interfaces.StateConfig) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.config = config

	// Create state directories
	if err := os.MkdirAll(sm.stateDir, 0755); err != nil {
		return fmt.Errorf("failed to create state directory: %w", err)
	}

	if config.StateBackup {
		if err := os.MkdirAll(sm.backupDir, 0755); err != nil {
			return fmt.Errorf("failed to create backup directory: %w", err)
		}
	}

	// Initialize validator based on target type
	sm.validator = sm.createValidator()

	// Capture initial state if provided
	if config.InitialState != nil {
		sm.currentState = config.InitialState
		sm.stateHistory = append(sm.stateHistory, config.InitialState)
		sm.stateIndex[config.InitialState.ID] = config.InitialState
	} else {
		// Capture initial state from target
		initialState, err := sm.captureInitialState()
		if err != nil {
			return fmt.Errorf("failed to capture initial state: %w", err)
		}
		sm.currentState = initialState
		sm.stateHistory = append(sm.stateHistory, initialState)
		sm.stateIndex[initialState.ID] = initialState
	}

	sm.logger.Infof("State manager initialized for target type: %s", config.TargetType)
	return nil
}

// CaptureState captures the current state of the target
func (sm *StateManager) CaptureState(ctx context.Context) (*interfaces.State, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.stateCaptureCount++

	// Create state based on target type
	var state *interfaces.State
	var err error

	switch sm.config.TargetType {
	case interfaces.StateTypeDatabase:
		state, err = sm.captureDatabaseState(ctx)
	case interfaces.StateTypeAPI:
		state, err = sm.captureAPIState(ctx)
	case interfaces.StateTypeNetwork:
		state, err = sm.captureNetworkState(ctx)
	case interfaces.StateTypeFile:
		state, err = sm.captureFileState(ctx)
	case interfaces.StateTypeMemory:
		state, err = sm.captureMemoryState(ctx)
	default:
		state, err = sm.captureGenericState(ctx)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to capture state: %w", err)
	}

	// Validate state
	if sm.validator != nil {
		valid, errors, err := sm.validator.ValidateState(state)
		if err != nil {
			sm.logger.Warnf("State validation failed: %v", err)
		} else if !valid {
			sm.logger.Warnf("Invalid state captured: %v", errors)
			state.Valid = false
		} else {
			state.Valid = true
		}
	}

	// Add to history and index
	sm.stateHistory = append(sm.stateHistory, state)
	sm.stateIndex[state.ID] = state

	// Maintain history size
	if len(sm.stateHistory) > sm.config.MaxStates {
		oldState := sm.stateHistory[0]
		sm.stateHistory = sm.stateHistory[1:]
		delete(sm.stateIndex, oldState.ID)
	}

	// Save state to disk
	if err := sm.saveState(state); err != nil {
		sm.logger.Warnf("Failed to save state: %v", err)
	}

	sm.logger.Debugf("Captured state: %s (valid: %v)", state.ID, state.Valid)
	return state, nil
}

// RestoreState restores the target to a specific state
func (sm *StateManager) RestoreState(ctx context.Context, state *interfaces.State) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.stateRestoreCount++

	// Validate state before restoration
	if sm.validator != nil {
		valid, errors, err := sm.validator.ValidateState(state)
		if err != nil {
			return fmt.Errorf("state validation failed: %w", err)
		}
		if !valid {
			return fmt.Errorf("invalid state for restoration: %v", errors)
		}
	}

	// Restore based on target type
	var err error
	switch sm.config.TargetType {
	case interfaces.StateTypeDatabase:
		err = sm.restoreDatabaseState(ctx, state)
	case interfaces.StateTypeAPI:
		err = sm.restoreAPIState(ctx, state)
	case interfaces.StateTypeNetwork:
		err = sm.restoreNetworkState(ctx, state)
	case interfaces.StateTypeFile:
		err = sm.restoreFileState(ctx, state)
	case interfaces.StateTypeMemory:
		err = sm.restoreMemoryState(ctx, state)
	default:
		err = sm.restoreGenericState(ctx, state)
	}

	if err != nil {
		// Attempt recovery if enabled
		if sm.config.AutoRecovery {
			return sm.attemptRecovery(ctx, state, err)
		}
		return fmt.Errorf("failed to restore state: %w", err)
	}

	sm.currentState = state
	sm.logger.Debugf("Restored to state: %s", state.ID)
	return nil
}

// GetTransitions gets available transitions from current state
func (sm *StateManager) GetTransitions(ctx context.Context, state *interfaces.State) ([]*interfaces.StateTransition, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	var transitions []*interfaces.StateTransition

	// Get transitions based on target type
	switch sm.config.TargetType {
	case interfaces.StateTypeDatabase:
		transitions = sm.getDatabaseTransitions(ctx, state)
	case interfaces.StateTypeAPI:
		transitions = sm.getAPITransitions(ctx, state)
	case interfaces.StateTypeNetwork:
		transitions = sm.getNetworkTransitions(ctx, state)
	case interfaces.StateTypeFile:
		transitions = sm.getFileTransitions(ctx, state)
	case interfaces.StateTypeMemory:
		transitions = sm.getMemoryTransitions(ctx, state)
	default:
		transitions = sm.getGenericTransitions(ctx, state)
	}

	// Filter valid transitions
	var validTransitions []*interfaces.StateTransition
	for _, transition := range transitions {
		if sm.validator != nil {
			valid, _, err := sm.validator.ValidateTransition(state, nil, transition)
			if err != nil {
				sm.logger.Debugf("Transition validation failed: %v", err)
				continue
			}
			if !valid {
				continue
			}
		}
		validTransitions = append(validTransitions, transition)
	}

	return validTransitions, nil
}

// ExecuteTransition executes a state transition
func (sm *StateManager) ExecuteTransition(ctx context.Context, transition *interfaces.StateTransition) (*interfaces.State, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.transitionCount++

	// Validate transition
	if sm.validator != nil {
		valid, errors, err := sm.validator.ValidateTransition(sm.currentState, nil, transition)
		if err != nil {
			return nil, fmt.Errorf("transition validation failed: %w", err)
		}
		if !valid {
			return nil, fmt.Errorf("invalid transition: %v", errors)
		}
	}

	// Execute transition based on target type
	var newState *interfaces.State
	var err error

	switch sm.config.TargetType {
	case interfaces.StateTypeDatabase:
		newState, err = sm.executeDatabaseTransition(ctx, transition)
	case interfaces.StateTypeAPI:
		newState, err = sm.executeAPITransition(ctx, transition)
	case interfaces.StateTypeNetwork:
		newState, err = sm.executeNetworkTransition(ctx, transition)
	case interfaces.StateTypeFile:
		newState, err = sm.executeFileTransition(ctx, transition)
	case interfaces.StateTypeMemory:
		newState, err = sm.executeMemoryTransition(ctx, transition)
	default:
		newState, err = sm.executeGenericTransition(ctx, transition)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to execute transition: %w", err)
	}

	// Update current state
	sm.currentState = newState
	sm.stateHistory = append(sm.stateHistory, newState)
	sm.stateIndex[newState.ID] = newState

	// Save transition
	sm.transitions[transition.ID] = transition

	sm.logger.Debugf("Executed transition: %s -> %s", transition.FromState, transition.ToState)
	return newState, nil
}

// ValidateState validates if a state is valid
func (sm *StateManager) ValidateState(ctx context.Context, state *interfaces.State) (bool, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	sm.validationCount++

	if sm.validator == nil {
		return true, nil
	}

	valid, _, err := sm.validator.ValidateState(state)
	return valid, err
}

// GetStateHistory returns the state history
func (sm *StateManager) GetStateHistory() []*interfaces.State {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	history := make([]*interfaces.State, len(sm.stateHistory))
	copy(history, sm.stateHistory)
	return history
}

// Cleanup cleans up resources
func (sm *StateManager) Cleanup() error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Cleanup based on target type
	switch sm.config.TargetType {
	case interfaces.StateTypeDatabase:
		return sm.cleanupDatabase()
	case interfaces.StateTypeAPI:
		return sm.cleanupAPI()
	case interfaces.StateTypeNetwork:
		return sm.cleanupNetwork()
	case interfaces.StateTypeFile:
		return sm.cleanupFile()
	case interfaces.StateTypeMemory:
		return sm.cleanupMemory()
	default:
		return sm.cleanupGeneric()
	}
}

// Helper methods for different target types

func (sm *StateManager) captureDatabaseState(ctx context.Context) (*interfaces.State, error) {
	// Implementation for database state capture
	// This would connect to the database and capture schema, data, connections, etc.
	state := &interfaces.State{
		ID:        uuid.New().String(),
		Name:      "database_state",
		Type:      interfaces.StateTypeDatabase,
		Data:      make(map[string]interface{}),
		Metadata:  make(map[string]interface{}),
		Timestamp: time.Now(),
		Valid:     true,
		Hash:      sm.calculateStateHash("database"),
	}

	// Capture database-specific state
	state.Data["database_url"] = sm.config.DatabaseURL
	state.Data["database_type"] = sm.config.DatabaseType
	state.Data["schema_file"] = sm.config.SchemaFile

	return state, nil
}

func (sm *StateManager) captureAPIState(ctx context.Context) (*interfaces.State, error) {
	// Implementation for API state capture
	state := &interfaces.State{
		ID:        uuid.New().String(),
		Name:      "api_state",
		Type:      interfaces.StateTypeAPI,
		Data:      make(map[string]interface{}),
		Metadata:  make(map[string]interface{}),
		Timestamp: time.Now(),
		Valid:     true,
		Hash:      sm.calculateStateHash("api"),
	}

	// Capture API-specific state
	state.Data["base_url"] = sm.config.APIBaseURL
	state.Data["auth_token"] = sm.config.APIAuthToken
	state.Data["endpoints"] = sm.config.APIEndpoints

	return state, nil
}

func (sm *StateManager) captureNetworkState(ctx context.Context) (*interfaces.State, error) {
	// Implementation for network state capture
	state := &interfaces.State{
		ID:        uuid.New().String(),
		Name:      "network_state",
		Type:      interfaces.StateTypeNetwork,
		Data:      make(map[string]interface{}),
		Metadata:  make(map[string]interface{}),
		Timestamp: time.Now(),
		Valid:     true,
		Hash:      sm.calculateStateHash("network"),
	}

	return state, nil
}

func (sm *StateManager) captureFileState(ctx context.Context) (*interfaces.State, error) {
	// Implementation for file state capture
	state := &interfaces.State{
		ID:        uuid.New().String(),
		Name:      "file_state",
		Type:      interfaces.StateTypeFile,
		Data:      make(map[string]interface{}),
		Metadata:  make(map[string]interface{}),
		Timestamp: time.Now(),
		Valid:     true,
		Hash:      sm.calculateStateHash("file"),
	}

	return state, nil
}

func (sm *StateManager) captureMemoryState(ctx context.Context) (*interfaces.State, error) {
	// Implementation for memory state capture
	state := &interfaces.State{
		ID:        uuid.New().String(),
		Name:      "memory_state",
		Type:      interfaces.StateTypeMemory,
		Data:      make(map[string]interface{}),
		Metadata:  make(map[string]interface{}),
		Timestamp: time.Now(),
		Valid:     true,
		Hash:      sm.calculateStateHash("memory"),
	}

	return state, nil
}

func (sm *StateManager) captureGenericState(ctx context.Context) (*interfaces.State, error) {
	// Generic state capture for unknown target types
	state := &interfaces.State{
		ID:        uuid.New().String(),
		Name:      "generic_state",
		Type:      interfaces.StateTypeCustom,
		Data:      make(map[string]interface{}),
		Metadata:  make(map[string]interface{}),
		Timestamp: time.Now(),
		Valid:     true,
		Hash:      sm.calculateStateHash("generic"),
	}

	return state, nil
}

func (sm *StateManager) captureInitialState() (*interfaces.State, error) {
	// Capture the initial state of the target
	ctx, cancel := context.WithTimeout(context.Background(), sm.config.StateTimeout)
	defer cancel()

	return sm.CaptureState(ctx)
}

// Restoration methods (stubs for now - would be implemented based on target type)
func (sm *StateManager) restoreDatabaseState(ctx context.Context, state *interfaces.State) error {
	// Implementation for database state restoration
	return nil
}

func (sm *StateManager) restoreAPIState(ctx context.Context, state *interfaces.State) error {
	// Implementation for API state restoration
	return nil
}

func (sm *StateManager) restoreNetworkState(ctx context.Context, state *interfaces.State) error {
	// Implementation for network state restoration
	return nil
}

func (sm *StateManager) restoreFileState(ctx context.Context, state *interfaces.State) error {
	// Implementation for file state restoration
	return nil
}

func (sm *StateManager) restoreMemoryState(ctx context.Context, state *interfaces.State) error {
	// Implementation for memory state restoration
	return nil
}

func (sm *StateManager) restoreGenericState(ctx context.Context, state *interfaces.State) error {
	// Generic state restoration
	return nil
}

// Transition methods (stubs for now)
func (sm *StateManager) getDatabaseTransitions(ctx context.Context, state *interfaces.State) []*interfaces.StateTransition {
	return []*interfaces.StateTransition{}
}

func (sm *StateManager) getAPITransitions(ctx context.Context, state *interfaces.State) []*interfaces.StateTransition {
	return []*interfaces.StateTransition{}
}

func (sm *StateManager) getNetworkTransitions(ctx context.Context, state *interfaces.State) []*interfaces.StateTransition {
	return []*interfaces.StateTransition{}
}

func (sm *StateManager) getFileTransitions(ctx context.Context, state *interfaces.State) []*interfaces.StateTransition {
	return []*interfaces.StateTransition{}
}

func (sm *StateManager) getMemoryTransitions(ctx context.Context, state *interfaces.State) []*interfaces.StateTransition {
	return []*interfaces.StateTransition{}
}

func (sm *StateManager) getGenericTransitions(ctx context.Context, state *interfaces.State) []*interfaces.StateTransition {
	return []*interfaces.StateTransition{}
}

// Transition execution methods (stubs for now)
func (sm *StateManager) executeDatabaseTransition(ctx context.Context, transition *interfaces.StateTransition) (*interfaces.State, error) {
	return sm.createTransitionState(transition), nil
}

func (sm *StateManager) executeAPITransition(ctx context.Context, transition *interfaces.StateTransition) (*interfaces.State, error) {
	return sm.createTransitionState(transition), nil
}

func (sm *StateManager) executeNetworkTransition(ctx context.Context, transition *interfaces.StateTransition) (*interfaces.State, error) {
	return sm.createTransitionState(transition), nil
}

func (sm *StateManager) executeFileTransition(ctx context.Context, transition *interfaces.StateTransition) (*interfaces.State, error) {
	return sm.createTransitionState(transition), nil
}

func (sm *StateManager) executeMemoryTransition(ctx context.Context, transition *interfaces.StateTransition) (*interfaces.State, error) {
	return sm.createTransitionState(transition), nil
}

func (sm *StateManager) executeGenericTransition(ctx context.Context, transition *interfaces.StateTransition) (*interfaces.State, error) {
	return sm.createTransitionState(transition), nil
}

// Cleanup methods (stubs for now)
func (sm *StateManager) cleanupDatabase() error { return nil }
func (sm *StateManager) cleanupAPI() error      { return nil }
func (sm *StateManager) cleanupNetwork() error  { return nil }
func (sm *StateManager) cleanupFile() error     { return nil }
func (sm *StateManager) cleanupMemory() error   { return nil }
func (sm *StateManager) cleanupGeneric() error  { return nil }

// Helper methods
func (sm *StateManager) createValidator() interfaces.StateValidator {
	// Create appropriate validator based on target type
	switch sm.config.TargetType {
	case interfaces.StateTypeDatabase:
		return NewDatabaseStateValidator(sm.config)
	case interfaces.StateTypeAPI:
		return NewAPIStateValidator(sm.config)
	default:
		return NewGenericStateValidator(sm.config)
	}
}

func (sm *StateManager) calculateStateHash(stateType string) string {
	h := sha256.New()
	h.Write([]byte(stateType))
	h.Write([]byte(time.Now().String()))
	return hex.EncodeToString(h.Sum(nil))[:16]
}

func (sm *StateManager) createTransitionState(transition *interfaces.StateTransition) *interfaces.State {
	return &interfaces.State{
		ID:         uuid.New().String(),
		Name:       fmt.Sprintf("state_after_%s", transition.Name),
		Type:       sm.config.TargetType,
		Data:       make(map[string]interface{}),
		Metadata:   make(map[string]interface{}),
		Timestamp:  time.Now(),
		Valid:      true,
		Hash:       sm.calculateStateHash(transition.Name),
		ParentID:   transition.FromState,
		Generation: sm.currentState.Generation + 1,
	}
}

func (sm *StateManager) saveState(state *interfaces.State) error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}

	filename := filepath.Join(sm.stateDir, fmt.Sprintf("%s.json", state.ID))
	return os.WriteFile(filename, data, 0644)
}

func (sm *StateManager) attemptRecovery(ctx context.Context, state *interfaces.State, originalError error) error {
	if sm.recoveryAttempts >= sm.config.MaxRecoveryAttempts {
		return fmt.Errorf("max recovery attempts reached: %w", originalError)
	}

	sm.recoveryAttempts++
	sm.lastRecovery = time.Now()

	sm.logger.Warnf("Attempting state recovery (attempt %d/%d)", sm.recoveryAttempts, sm.config.MaxRecoveryAttempts)

	// Wait before recovery attempt
	time.Sleep(sm.config.RecoveryDelay)

	// Try to restore to initial state first
	if sm.config.InitialState != nil {
		if err := sm.RestoreState(ctx, sm.config.InitialState); err != nil {
			return fmt.Errorf("recovery failed: %w", originalError)
		}
	}

	// Reset recovery attempts on success
	sm.recoveryAttempts = 0
	return nil
}
