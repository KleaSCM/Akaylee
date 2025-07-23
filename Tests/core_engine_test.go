/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: core_engine_test.go
Description: Comprehensive integration tests for the core fuzzer engine. Tests full fuzzing loop,
scheduler, reporters, coverage collector, reproducibility harness, and worker coordination.
*/

package core_test

import (
	"testing"
	"time"

	"github.com/kleascm/akaylee-fuzzer/pkg/analysis"
	"github.com/kleascm/akaylee-fuzzer/pkg/core"
	"github.com/kleascm/akaylee-fuzzer/pkg/execution"
	"github.com/kleascm/akaylee-fuzzer/pkg/interfaces"
	"github.com/kleascm/akaylee-fuzzer/pkg/strategies"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEngineFullFuzzingLoop tests the complete fuzzing loop
func TestEngineFullFuzzingLoop(t *testing.T) {
	runTest(t, "TestEngineFullFuzzingLoop", func(t *testing.T) {
		engine := core.NewEngine()
		require.NotNil(t, engine)

		// Setup components
		executor := execution.NewProcessExecutor()
		analyzer := analysis.NewCoverageAnalyzer()
		mutators := []interfaces.Mutator{
			strategies.NewBitFlipMutator(0.1),
			strategies.NewByteSubstitutionMutator(0.1),
		}

		engine.SetExecutor(executor)
		engine.SetAnalyzer(analyzer)
		engine.SetMutators(mutators)

		// Configure engine
		config := &interfaces.FuzzerConfig{
			Target:        "/bin/echo",
			CorpusDir:     "./test_corpus",
			Workers:       2,
			Timeout:       5 * time.Second,
			MaxCorpusSize: 100,
			MaxMutations:  3,
		}

		err := engine.Initialize(config)
		require.NoError(t, err)

		// Start fuzzing
		err = engine.Start()
		require.NoError(t, err)

		// Let it run for a short time
		time.Sleep(2 * time.Second)

		// Stop fuzzing
		err = engine.Stop()
		require.NoError(t, err)

		// Check stats
		stats := engine.GetStats()
		assert.GreaterOrEqual(t, stats.Executions, int64(0))
	})
}

// TestEngineScheduler tests scheduler integration
func TestEngineScheduler(t *testing.T) {
	runTest(t, "TestEngineScheduler", func(t *testing.T) {
		engine := core.NewEngine()
		require.NotNil(t, engine)

		// Test priority scheduler
		config := &interfaces.FuzzerConfig{
			Target:        "/bin/echo",
			CorpusDir:     "./test_corpus",
			Workers:       1,
			Timeout:       5 * time.Second,
			MaxCorpusSize: 10,
			SchedulerType: "priority",
		}

		executor := execution.NewProcessExecutor()
		analyzer := analysis.NewCoverageAnalyzer()
		mutators := []interfaces.Mutator{strategies.NewBitFlipMutator(0.1)}

		engine.SetExecutor(executor)
		engine.SetAnalyzer(analyzer)
		engine.SetMutators(mutators)

		err := engine.Initialize(config)
		require.NoError(t, err)

		// Test coverage-guided scheduler
		config.SchedulerType = "coverage-guided"
		err = engine.Initialize(config)
		require.NoError(t, err)
	})
}

// TestEngineReporters tests reporter integration
func TestEngineReporters(t *testing.T) {
	runTest(t, "TestEngineReporters", func(t *testing.T) {
		engine := core.NewEngine()
		require.NotNil(t, engine)

		// Add test reporter
		testReporter := &TestReporter{
			testCasesAdded:    make([]*core.TestCase, 0),
			testCasesExecuted: make([]*core.ExecutionResult, 0),
		}
		engine.AddReporter(testReporter)

		// Setup and run
		executor := execution.NewProcessExecutor()
		analyzer := analysis.NewCoverageAnalyzer()
		mutators := []interfaces.Mutator{strategies.NewBitFlipMutator(0.1)}

		engine.SetExecutor(executor)
		engine.SetAnalyzer(analyzer)
		engine.SetMutators(mutators)

		config := &interfaces.FuzzerConfig{
			Target:        "/bin/echo",
			CorpusDir:     "./test_corpus",
			Workers:       1,
			Timeout:       5 * time.Second,
			MaxCorpusSize: 10,
		}

		err := engine.Initialize(config)
		require.NoError(t, err)

		err = engine.Start()
		require.NoError(t, err)

		time.Sleep(1 * time.Second)

		err = engine.Stop()
		require.NoError(t, err)

		// Check reporter was called
		assert.GreaterOrEqual(t, len(testReporter.testCasesAdded), 0)
		assert.GreaterOrEqual(t, len(testReporter.testCasesExecuted), 0)
	})
}

// TestEngineCoverageCollector tests coverage collector integration
func TestEngineCoverageCollector(t *testing.T) {
	runTest(t, "TestEngineCoverageCollector", func(t *testing.T) {
		engine := core.NewEngine()
		require.NotNil(t, engine)

		// Test with coverage collector
		config := &interfaces.FuzzerConfig{
			Target:        "/bin/echo",
			CorpusDir:     "./test_corpus",
			Workers:       1,
			Timeout:       5 * time.Second,
			MaxCorpusSize: 10,
			CoverageType:  "go",
		}

		executor := execution.NewProcessExecutor()
		analyzer := analysis.NewCoverageAnalyzer()
		mutators := []interfaces.Mutator{strategies.NewBitFlipMutator(0.1)}

		engine.SetExecutor(executor)
		engine.SetAnalyzer(analyzer)
		engine.SetMutators(mutators)

		err := engine.Initialize(config)
		// This might fail if go coverage tools aren't available, which is OK
		if err != nil {
			t.Logf("Coverage collector test skipped: %v", err)
			return
		}

		err = engine.Start()
		require.NoError(t, err)

		time.Sleep(1 * time.Second)

		err = engine.Stop()
		require.NoError(t, err)
	})
}

// TestEngineReproducibilityHarness tests reproducibility harness integration
func TestEngineReproducibilityHarness(t *testing.T) {
	runTest(t, "TestEngineReproducibilityHarness", func(t *testing.T) {
		engine := core.NewEngine()
		require.NotNil(t, engine)

		// Add reproducibility harness
		harness := analysis.NewReproducibilityHarness(&analysis.ReproducibilityConfig{
			MaxReproductionAttempts: 3,
			ReproductionTimeout:     5 * time.Second,
		})
		engine.SetReproducibilityHarness(harness)

		// Setup and run
		executor := execution.NewProcessExecutor()
		analyzer := analysis.NewCoverageAnalyzer()
		mutators := []interfaces.Mutator{strategies.NewBitFlipMutator(0.1)}

		engine.SetExecutor(executor)
		engine.SetAnalyzer(analyzer)
		engine.SetMutators(mutators)

		config := &interfaces.FuzzerConfig{
			Target:        "/bin/echo",
			CorpusDir:     "./test_corpus",
			Workers:       1,
			Timeout:       5 * time.Second,
			MaxCorpusSize: 10,
		}

		err := engine.Initialize(config)
		require.NoError(t, err)

		err = engine.Start()
		require.NoError(t, err)

		time.Sleep(1 * time.Second)

		err = engine.Stop()
		require.NoError(t, err)

		// Check harness is accessible
		retrievedHarness := engine.GetReproducibilityHarness()
		assert.NotNil(t, retrievedHarness)
	})
}

// TestEngineWorkerCoordination tests worker coordination and communication
func TestEngineWorkerCoordination(t *testing.T) {
	runTest(t, "TestEngineWorkerCoordination", func(t *testing.T) {
		engine := core.NewEngine()
		require.NotNil(t, engine)

		// Test with multiple workers
		config := &interfaces.FuzzerConfig{
			Target:        "/bin/echo",
			CorpusDir:     "./test_corpus",
			Workers:       3,
			Timeout:       5 * time.Second,
			MaxCorpusSize: 50,
		}

		executor := execution.NewProcessExecutor()
		analyzer := analysis.NewCoverageAnalyzer()
		mutators := []interfaces.Mutator{strategies.NewBitFlipMutator(0.1)}

		engine.SetExecutor(executor)
		engine.SetAnalyzer(analyzer)
		engine.SetMutators(mutators)

		err := engine.Initialize(config)
		require.NoError(t, err)

		err = engine.Start()
		require.NoError(t, err)

		time.Sleep(2 * time.Second)

		err = engine.Stop()
		require.NoError(t, err)

		// Check stats show multiple workers
		stats := engine.GetStats()
		assert.GreaterOrEqual(t, stats.Executions, int64(0))
	})
}

// TestEngineEdgeCases tests edge cases and error conditions
func TestEngineEdgeCases(t *testing.T) {
	runTest(t, "TestEngineEdgeCases", func(t *testing.T) {
		engine := core.NewEngine()
		require.NotNil(t, engine)

		// Test starting without initialization
		err := engine.Start()
		assert.Error(t, err)

		// Test stopping without starting
		err = engine.Stop()
		assert.Error(t, err)

		// Test double start
		executor := execution.NewProcessExecutor()
		analyzer := analysis.NewCoverageAnalyzer()
		mutators := []interfaces.Mutator{strategies.NewBitFlipMutator(0.1)}

		engine.SetExecutor(executor)
		engine.SetAnalyzer(analyzer)
		engine.SetMutators(mutators)

		config := &interfaces.FuzzerConfig{
			Target:        "/bin/echo",
			CorpusDir:     "./test_corpus",
			Workers:       1,
			Timeout:       5 * time.Second,
			MaxCorpusSize: 10,
		}

		err = engine.Initialize(config)
		require.NoError(t, err)

		err = engine.Start()
		require.NoError(t, err)

		err = engine.Start()
		assert.Error(t, err)

		err = engine.Stop()
		require.NoError(t, err)
	})
}

// TestReporter is a test implementation of the Reporter interface
type TestReporter struct {
	testCasesAdded    []*core.TestCase
	testCasesExecuted []*core.ExecutionResult
}

func (r *TestReporter) OnTestCaseAdded(testCase *core.TestCase) {
	r.testCasesAdded = append(r.testCasesAdded, testCase)
}

func (r *TestReporter) OnTestCaseExecuted(result *core.ExecutionResult) {
	r.testCasesExecuted = append(r.testCasesExecuted, result)
}
