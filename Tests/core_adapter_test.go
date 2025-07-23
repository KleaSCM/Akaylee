/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: core_adapter_test.go
Description: Comprehensive tests for adapter logic. Tests AdapterExecutor, AdapterAnalyzer,
and AdapterMutator with proper interface compliance, edge cases, and error handling.
*/

package core_test

import (
	"testing"
	"time"

	"github.com/kleascm/akaylee-fuzzer/pkg/analysis"
	"github.com/kleascm/akaylee-fuzzer/pkg/core"
	"github.com/kleascm/akaylee-fuzzer/pkg/execution"
	"github.com/kleascm/akaylee-fuzzer/pkg/strategies"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAdapterExecutor tests the AdapterExecutor
func TestAdapterExecutor(t *testing.T) {
	runTest(t, "TestAdapterExecutor", func(t *testing.T) {
		// Create interface executor
		interfaceExecutor := execution.NewProcessExecutor()
		adapter := core.NewAdapterExecutor(interfaceExecutor)
		require.NotNil(t, adapter)

		// Test initialization
		config := &core.FuzzerConfig{
			Target: "/bin/echo",
		}
		err := adapter.Initialize(config)
		require.NoError(t, err)

		// Test execution
		testCase := &core.TestCase{
			ID:   "test1",
			Data: []byte("hello world"),
		}

		result, err := adapter.Execute(testCase)
		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, "test1", result.TestCaseID)
		assert.Equal(t, core.StatusSuccess, result.Status)

		// Test cleanup
		err = adapter.Cleanup()
		require.NoError(t, err)
	})
}

// TestAdapterAnalyzer tests the AdapterAnalyzer
func TestAdapterAnalyzer(t *testing.T) {
	runTest(t, "TestAdapterAnalyzer", func(t *testing.T) {
		// Create interface analyzer
		interfaceAnalyzer := analysis.NewCoverageAnalyzer()
		adapter := core.NewAdapterAnalyzer(interfaceAnalyzer)
		require.NotNil(t, adapter)

		// Test analysis
		result := &core.ExecutionResult{
			TestCaseID: "test1",
			Status:     core.StatusSuccess,
			Output:     []byte("output"),
			Error:      []byte(""),
			Duration:   100 * time.Millisecond,
		}

		err := adapter.Analyze(result)
		require.NoError(t, err)

		// Test interesting test case
		testCase := &core.TestCase{
			ID:   "test1",
			Data: []byte("data"),
		}

		interesting := adapter.IsInteresting(testCase)
		assert.IsType(t, false, interesting)

		// Test coverage
		coverage, err := adapter.GetCoverage(result)
		require.NoError(t, err)
		assert.NotNil(t, coverage)

		// Test crash detection
		_, err = adapter.DetectCrash(result)
		require.NoError(t, err)
		// May be nil if no crash detected, which is OK

		// Test hang detection
		_, err = adapter.DetectHang(result)
		require.NoError(t, err)
		// May be nil if no hang detected, which is OK
	})
}

// TestAdapterMutator tests the AdapterMutator
func TestAdapterMutator(t *testing.T) {
	runTest(t, "TestAdapterMutator", func(t *testing.T) {
		// Create interface mutator
		interfaceMutator := strategies.NewBitFlipMutator(0.1)
		adapter := core.NewAdapterMutator(interfaceMutator)
		require.NotNil(t, adapter)

		// Test mutation
		testCase := &core.TestCase{
			ID:         "test1",
			Data:       []byte{0x00, 0xFF, 0x55, 0xAA},
			Generation: 0,
			CreatedAt:  time.Now(),
			Priority:   100,
		}

		mutated, err := adapter.Mutate(testCase)
		require.NoError(t, err)
		assert.NotNil(t, mutated)
		assert.NotEqual(t, testCase.ID, mutated.ID)
		assert.Equal(t, testCase.ID, mutated.ParentID)
		assert.Equal(t, testCase.Generation+1, mutated.Generation)

		// Test name and description
		assert.Equal(t, "BitFlipMutator", adapter.Name())
		assert.Contains(t, adapter.Description(), "bit")
	})
}

// TestAdapterEdgeCases tests edge cases for adapters
func TestAdapterEdgeCases(t *testing.T) {
	runTest(t, "TestAdapterEdgeCases", func(t *testing.T) {
		// Test nil interface executor
		adapter := core.NewAdapterExecutor(nil)
		require.NotNil(t, adapter)

		// Test nil interface analyzer
		analyzerAdapter := core.NewAdapterAnalyzer(nil)
		require.NotNil(t, analyzerAdapter)

		// Test nil interface mutator
		mutatorAdapter := core.NewAdapterMutator(nil)
		require.NotNil(t, mutatorAdapter)

		// Test with empty test case
		emptyTestCase := &core.TestCase{
			ID:   "empty",
			Data: []byte{},
		}

		// Test mutator with empty data
		interfaceMutator := strategies.NewBitFlipMutator(0.1)
		mutatorAdapter = core.NewAdapterMutator(interfaceMutator)
		mutated, err := mutatorAdapter.Mutate(emptyTestCase)
		require.NoError(t, err)
		assert.NotNil(t, mutated)
		assert.Equal(t, 0, len(mutated.Data))

		// Test analyzer with nil result
		interfaceAnalyzer := analysis.NewCoverageAnalyzer()
		analyzerAdapter = core.NewAdapterAnalyzer(interfaceAnalyzer)
		err = analyzerAdapter.Analyze(nil)
		assert.Error(t, err)

		// Test executor with nil test case
		interfaceExecutor := execution.NewProcessExecutor()
		adapter = core.NewAdapterExecutor(interfaceExecutor)
		config := &core.FuzzerConfig{
			Target: "/bin/echo",
		}
		adapter.Initialize(config)
		_, err = adapter.Execute(nil)
		assert.Error(t, err)
	})
}

// TestAdapterInterfaceCompliance tests interface compliance
func TestAdapterInterfaceCompliance(t *testing.T) {
	runTest(t, "TestAdapterInterfaceCompliance", func(t *testing.T) {
		// Test executor interface compliance
		var executor core.Executor
		interfaceExecutor := execution.NewProcessExecutor()
		adapter := core.NewAdapterExecutor(interfaceExecutor)
		executor = adapter
		assert.NotNil(t, executor)

		// Test analyzer interface compliance
		var analyzer core.Analyzer
		interfaceAnalyzer := analysis.NewCoverageAnalyzer()
		analyzerAdapter := core.NewAdapterAnalyzer(interfaceAnalyzer)
		analyzer = analyzerAdapter
		assert.NotNil(t, analyzer)

		// Test mutator interface compliance
		var mutator core.Mutator
		interfaceMutator := strategies.NewBitFlipMutator(0.1)
		mutatorAdapter := core.NewAdapterMutator(interfaceMutator)
		mutator = mutatorAdapter
		assert.NotNil(t, mutator)
	})
}

// TestAdapterErrorHandling tests error handling in adapters
func TestAdapterErrorHandling(t *testing.T) {
	runTest(t, "TestAdapterErrorHandling", func(t *testing.T) {
		// Test executor with invalid target
		interfaceExecutor := execution.NewProcessExecutor()
		adapter := core.NewAdapterExecutor(interfaceExecutor)
		config := &core.FuzzerConfig{
			Target: "/nonexistent/binary",
		}
		err := adapter.Initialize(config)
		// This might fail, which is expected
		if err != nil {
			t.Logf("Expected error with invalid target: %v", err)
		}

		// Test analyzer with invalid result
		interfaceAnalyzer := analysis.NewCoverageAnalyzer()
		analyzerAdapter := core.NewAdapterAnalyzer(interfaceAnalyzer)
		invalidResult := &core.ExecutionResult{
			TestCaseID: "invalid",
			Status:     core.StatusError,
		}
		err = analyzerAdapter.Analyze(invalidResult)
		// Should handle gracefully
		if err != nil {
			t.Logf("Analyzer error: %v", err)
		}

		// Test mutator with invalid test case
		interfaceMutator := strategies.NewBitFlipMutator(0.1)
		mutatorAdapter := core.NewAdapterMutator(interfaceMutator)
		invalidTestCase := &core.TestCase{
			ID:   "invalid",
			Data: nil, // nil data
		}
		_, err = mutatorAdapter.Mutate(invalidTestCase)
		// Should handle gracefully
		if err != nil {
			t.Logf("Mutator error: %v", err)
		}
	})
}
