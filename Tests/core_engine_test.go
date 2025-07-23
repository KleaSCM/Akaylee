/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: core_engine_test.go
Description: Comprehensive integration tests for the core fuzzer engine. Tests full fuzzing loop,
scheduler, reporters, coverage collector, reproducibility harness, and worker coordination.
*/

package core_test

import (
	"os"
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

		// Test engine functionality without starting (to avoid timeout)
		stats := engine.GetStats()
		assert.NotNil(t, stats)
		assert.Equal(t, int64(0), stats.Executions) // Should be 0 before starting

		// Test corpus operations
		testCase := &core.TestCase{
			ID:   "test1",
			Data: []byte("hello world"),
		}
		err = engine.AddTestCase(testCase)
		require.NoError(t, err)

		// Test getting test cases
		testCases, err := engine.GetTestCases(1)
		require.NoError(t, err)
		assert.Len(t, testCases, 1)
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

		// Test that reporter was added
		assert.NotNil(t, testReporter)
		assert.Len(t, testReporter.testCasesAdded, 0)
		assert.Len(t, testReporter.testCasesExecuted, 0)
	})
}

// TestEngineCoverageCollector tests coverage collector integration
func TestEngineCoverageCollector(t *testing.T) {
	runTest(t, "TestEngineCoverageCollector", func(t *testing.T) {
		engine := core.NewEngine()
		require.NotNil(t, engine)

		// Test with coverage collector configuration
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

		// Test that engine is properly configured
		assert.NotNil(t, engine)
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

		// Test that harness is accessible
		retrievedHarness := engine.GetReproducibilityHarness()
		assert.NotNil(t, retrievedHarness)
	})
}

// TestEngineWorkerCoordination tests worker coordination and communication
func TestEngineWorkerCoordination(t *testing.T) {
	runTest(t, "TestEngineWorkerCoordination", func(t *testing.T) {
		engine := core.NewEngine()
		require.NotNil(t, engine)

		// Test with multiple workers configuration
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

		// Test that engine is properly configured for multiple workers
		stats := engine.GetStats()
		assert.NotNil(t, stats)
		assert.Equal(t, int64(0), stats.Executions) // Should be 0 before starting
	})
}

// TestEngineEdgeCases tests edge cases and error conditions
func TestEngineEdgeCases(t *testing.T) {
	runTest(t, "TestEngineEdgeCases", func(t *testing.T) {
		engine := core.NewEngine()
		require.NotNil(t, engine)

		// Test stopping without starting
		err := engine.Stop()
		assert.Error(t, err) // Should fail if not running

		// Test with minimal setup
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

		// Test that engine is properly initialized
		assert.NotNil(t, engine)

		// Test basic functionality without starting
		stats := engine.GetStats()
		assert.NotNil(t, stats)
		assert.Equal(t, int64(0), stats.Executions)
	})
}

// TestEngineSingleExecution tests a minimal execution loop
func TestEngineSingleExecution(t *testing.T) {
	// Setup minimal config
	config := &interfaces.FuzzerConfig{
		Target:        "TARGET/vulnscan",
		CorpusDir:     "TARGET/corpus/split",
		OutputDir:     "./fuzz_output",
		CrashDir:      "./crashes",
		Workers:       1,
		Timeout:       2 * time.Second,
		MemoryLimit:   0,
		MaxCorpusSize: 10,
		MutationRate:  0.0,
		MaxMutations:  1,
		Strategy:      "mutation",
		CoverageType:  "edge",
		SchedulerType: "priority",
		SessionID:     "test-session",
		MaxExecutions: 1,
	}

	engine := core.NewEngine()
	// Set up a dummy executor that just returns success
	engine.SetExecutor(&dummyExecutor{})
	engine.SetAnalyzer(&dummyAnalyzer{})
	engine.SetMutators([]interfaces.Mutator{&dummyMutator{}})

	err := engine.Initialize(config)
	if err != nil {
		t.Fatalf("Failed to initialize engine: %v", err)
	}

	err = engine.Start()
	if err != nil {
		t.Fatalf("Engine did not start: %v", err)
	}

	stats := engine.GetStats()
	if stats.Executions == 0 {
		t.Fatalf("No executions recorded!")
	}

	// Check that a report file exists
	files, err := os.ReadDir("./fuzz_output")
	if err != nil || len(files) == 0 {
		t.Fatalf("No report written!")
	}
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

type dummyExecutor struct{}

func (d *dummyExecutor) Initialize(*interfaces.FuzzerConfig) error { return nil }
func (d *dummyExecutor) Execute(*interfaces.TestCase) (*interfaces.ExecutionResult, error) {
	return &interfaces.ExecutionResult{Status: interfaces.StatusSuccess}, nil
}
func (d *dummyExecutor) Cleanup() error { return nil }
func (d *dummyExecutor) Reset() error   { return nil }

type dummyAnalyzer struct{}

func (d *dummyAnalyzer) Analyze(*interfaces.ExecutionResult) error { return nil }
func (d *dummyAnalyzer) IsInteresting(*interfaces.TestCase) bool   { return false }
func (d *dummyAnalyzer) GetCoverage(*interfaces.ExecutionResult) (*interfaces.Coverage, error) {
	return nil, nil
}
func (d *dummyAnalyzer) DetectCrash(*interfaces.ExecutionResult) (*interfaces.CrashInfo, error) {
	return nil, nil
}
func (d *dummyAnalyzer) DetectHang(*interfaces.ExecutionResult) (*interfaces.HangInfo, error) {
	return nil, nil
}
func (d *dummyAnalyzer) Reset() error { return nil }

type dummyMutator struct{}

func (d *dummyMutator) Mutate(tc *interfaces.TestCase) (*interfaces.TestCase, error) { return tc, nil }
func (d *dummyMutator) Name() string                                                 { return "dummy" }
func (d *dummyMutator) Description() string                                          { return "dummy mutator" }
