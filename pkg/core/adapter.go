/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: adapter.go
Description: Adapter functions to convert between core types and interface types.
Provides seamless integration between the core package and external implementations.
*/

package core

import (
	"github.com/kleascm/akaylee-fuzzer/pkg/interfaces"
)

// AdapterExecutor wraps an interfaces.Executor to implement the core Executor interface
type AdapterExecutor struct {
	executor interfaces.Executor
}

// NewAdapterExecutor creates a new adapter executor
func NewAdapterExecutor(executor interfaces.Executor) *AdapterExecutor {
	return &AdapterExecutor{executor: executor}
}

// Initialize initializes the executor
func (a *AdapterExecutor) Initialize(config *FuzzerConfig) error {
	// Convert core config to interface config
	interfaceConfig := &interfaces.FuzzerConfig{
		Target:        config.Target,
		CorpusDir:     config.CorpusDir,
		OutputDir:     config.OutputDir,
		CrashDir:      config.CrashDir,
		Workers:       config.Workers,
		Timeout:       config.Timeout,
		MemoryLimit:   config.MemoryLimit,
		MaxCorpusSize: config.MaxCorpusSize,
		MutationRate:  config.MutationRate,
		MaxMutations:  config.MaxMutations,
		Strategy:      config.Strategy,
		CoverageType:  config.CoverageType,
		SchedulerType: config.SchedulerType,
		SessionID:     config.SessionID,
	}
	return a.executor.Initialize(interfaceConfig)
}

// Execute executes a test case
func (a *AdapterExecutor) Execute(testCase *TestCase) (*ExecutionResult, error) {
	// Convert core test case to interface test case
	interfaceTestCase := &interfaces.TestCase{
		ID:         testCase.ID,
		Data:       testCase.Data,
		ParentID:   testCase.ParentID,
		Generation: testCase.Generation,
		CreatedAt:  testCase.CreatedAt,
		Executions: testCase.Executions,
		Priority:   testCase.Priority,
		Metadata:   testCase.Metadata,
	}

	// Execute using interface executor
	interfaceResult, err := a.executor.Execute(interfaceTestCase)
	if err != nil {
		return nil, err
	}

	// Convert interface result to core result
	result := &ExecutionResult{
		TestCaseID:  interfaceResult.TestCaseID,
		ExitCode:    interfaceResult.ExitCode,
		Signal:      interfaceResult.Signal,
		Duration:    interfaceResult.Duration,
		MemoryUsage: interfaceResult.MemoryUsage,
		CPUUsage:    interfaceResult.CPUUsage,
		Output:      interfaceResult.Output,
		Error:       interfaceResult.Error,
		Status:      ExecutionStatus(interfaceResult.Status),
	}

	return result, nil
}

// Cleanup performs cleanup
func (a *AdapterExecutor) Cleanup() error {
	return a.executor.Cleanup()
}

// AdapterAnalyzer wraps an interfaces.Analyzer to implement the core Analyzer interface
type AdapterAnalyzer struct {
	analyzer interfaces.Analyzer
}

// NewAdapterAnalyzer creates a new adapter analyzer
func NewAdapterAnalyzer(analyzer interfaces.Analyzer) *AdapterAnalyzer {
	return &AdapterAnalyzer{analyzer: analyzer}
}

// Analyze analyzes an execution result
func (a *AdapterAnalyzer) Analyze(result *ExecutionResult) error {
	// Convert core result to interface result
	interfaceResult := &interfaces.ExecutionResult{
		TestCaseID:  result.TestCaseID,
		ExitCode:    result.ExitCode,
		Signal:      result.Signal,
		Duration:    result.Duration,
		MemoryUsage: result.MemoryUsage,
		CPUUsage:    result.CPUUsage,
		Output:      result.Output,
		Error:       result.Error,
		Status:      interfaces.ExecutionStatus(result.Status),
	}

	return a.analyzer.Analyze(interfaceResult)
}

// IsInteresting checks if a test case is interesting
func (a *AdapterAnalyzer) IsInteresting(testCase *TestCase) bool {
	// Convert core test case to interface test case
	interfaceTestCase := &interfaces.TestCase{
		ID:         testCase.ID,
		Data:       testCase.Data,
		ParentID:   testCase.ParentID,
		Generation: testCase.Generation,
		CreatedAt:  testCase.CreatedAt,
		Executions: testCase.Executions,
		Priority:   testCase.Priority,
		Metadata:   testCase.Metadata,
	}

	return a.analyzer.IsInteresting(interfaceTestCase)
}

// GetCoverage gets coverage information
func (a *AdapterAnalyzer) GetCoverage(result *ExecutionResult) (*Coverage, error) {
	// Convert core result to interface result
	interfaceResult := &interfaces.ExecutionResult{
		TestCaseID:  result.TestCaseID,
		ExitCode:    result.ExitCode,
		Signal:      result.Signal,
		Duration:    result.Duration,
		MemoryUsage: result.MemoryUsage,
		CPUUsage:    result.CPUUsage,
		Output:      result.Output,
		Error:       result.Error,
		Status:      interfaces.ExecutionStatus(result.Status),
	}

	interfaceCoverage, err := a.analyzer.GetCoverage(interfaceResult)
	if err != nil {
		return nil, err
	}

	// Convert interface coverage to core coverage
	coverage := &Coverage{
		Bitmap:        interfaceCoverage.Bitmap,
		EdgeCount:     interfaceCoverage.EdgeCount,
		BlockCount:    interfaceCoverage.BlockCount,
		FunctionCount: interfaceCoverage.FunctionCount,
		Timestamp:     interfaceCoverage.Timestamp,
		Hash:          interfaceCoverage.Hash,
	}

	return coverage, nil
}

// DetectCrash detects crashes
func (a *AdapterAnalyzer) DetectCrash(result *ExecutionResult) (*CrashInfo, error) {
	// Convert core result to interface result
	interfaceResult := &interfaces.ExecutionResult{
		TestCaseID:  result.TestCaseID,
		ExitCode:    result.ExitCode,
		Signal:      result.Signal,
		Duration:    result.Duration,
		MemoryUsage: result.MemoryUsage,
		CPUUsage:    result.CPUUsage,
		Output:      result.Output,
		Error:       result.Error,
		Status:      interfaces.ExecutionStatus(result.Status),
	}

	interfaceCrashInfo, err := a.analyzer.DetectCrash(interfaceResult)
	if err != nil {
		return nil, err
	}

	if interfaceCrashInfo == nil {
		return nil, nil
	}

	// Convert interface crash info to core crash info
	crashInfo := &CrashInfo{
		Type:         interfaceCrashInfo.Type,
		Address:      interfaceCrashInfo.Address,
		StackTrace:   interfaceCrashInfo.StackTrace,
		Registers:    interfaceCrashInfo.Registers,
		Reproducible: interfaceCrashInfo.Reproducible,
		Hash:         interfaceCrashInfo.Hash,
	}

	return crashInfo, nil
}

// DetectHang detects hangs
func (a *AdapterAnalyzer) DetectHang(result *ExecutionResult) (*HangInfo, error) {
	// Convert core result to interface result
	interfaceResult := &interfaces.ExecutionResult{
		TestCaseID:  result.TestCaseID,
		ExitCode:    result.ExitCode,
		Signal:      result.Signal,
		Duration:    result.Duration,
		MemoryUsage: result.MemoryUsage,
		CPUUsage:    result.CPUUsage,
		Output:      result.Output,
		Error:       result.Error,
		Status:      interfaces.ExecutionStatus(result.Status),
	}

	interfaceHangInfo, err := a.analyzer.DetectHang(interfaceResult)
	if err != nil {
		return nil, err
	}

	if interfaceHangInfo == nil {
		return nil, nil
	}

	// Convert interface hang info to core hang info
	hangInfo := &HangInfo{
		Duration:   interfaceHangInfo.Duration,
		LastOutput: interfaceHangInfo.LastOutput,
		StackTrace: interfaceHangInfo.StackTrace,
		ResourceUsage: ResourceUsage{
			PeakMemory: interfaceHangInfo.ResourceUsage.PeakMemory,
			AvgCPU:     interfaceHangInfo.ResourceUsage.AvgCPU,
			IORead:     interfaceHangInfo.ResourceUsage.IORead,
			IOWrite:    interfaceHangInfo.ResourceUsage.IOWrite,
		},
	}

	return hangInfo, nil
}

// AdapterMutator wraps an interfaces.Mutator to implement the core Mutator interface
type AdapterMutator struct {
	mutator interfaces.Mutator
}

// NewAdapterMutator creates a new adapter mutator
func NewAdapterMutator(mutator interfaces.Mutator) *AdapterMutator {
	return &AdapterMutator{mutator: mutator}
}

// Mutate mutates a test case
func (a *AdapterMutator) Mutate(testCase *TestCase) (*TestCase, error) {
	// Convert core test case to interface test case
	interfaceTestCase := &interfaces.TestCase{
		ID:         testCase.ID,
		Data:       testCase.Data,
		ParentID:   testCase.ParentID,
		Generation: testCase.Generation,
		CreatedAt:  testCase.CreatedAt,
		Executions: testCase.Executions,
		Priority:   testCase.Priority,
		Metadata:   testCase.Metadata,
	}

	// Mutate using interface mutator
	interfaceMutated, err := a.mutator.Mutate(interfaceTestCase)
	if err != nil {
		return nil, err
	}

	// Convert interface result to core result
	mutated := &TestCase{
		ID:         interfaceMutated.ID,
		Data:       interfaceMutated.Data,
		ParentID:   interfaceMutated.ParentID,
		Generation: interfaceMutated.Generation,
		CreatedAt:  interfaceMutated.CreatedAt,
		Executions: interfaceMutated.Executions,
		Priority:   interfaceMutated.Priority,
		Metadata:   interfaceMutated.Metadata,
	}

	return mutated, nil
}

// Name returns the name of the mutator
func (a *AdapterMutator) Name() string {
	return a.mutator.Name()
}

// Description returns the description of the mutator
func (a *AdapterMutator) Description() string {
	return a.mutator.Description()
}
