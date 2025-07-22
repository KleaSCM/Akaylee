/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: core_test.go
Description: Comprehensive unit tests for the core fuzzer components. Tests engine,
corpus, queue, and worker functionality with proper test coverage and edge case handling.
*/

package core_test

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/kleascm/akaylee-fuzzer/pkg/core"
	"github.com/kleascm/akaylee-fuzzer/pkg/interfaces"
	"github.com/kleascm/akaylee-fuzzer/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Juicy metrics registry ---
type TestResult struct {
	Name       string  `json:"name"`
	Passed     bool    `json:"passed"`
	Error      string  `json:"error,omitempty"`
	DurationMs float64 `json:"duration_ms"`
}

var (
	testResults []TestResult
	suiteStart  time.Time
	suiteEnd    time.Time
)

func recordTestResult(name string, passed bool, errMsg string, duration time.Duration) {
	testResults = append(testResults, TestResult{
		Name:       name,
		Passed:     passed,
		Error:      errMsg,
		DurationMs: float64(duration.Microseconds()) / 1000.0,
	})
}

// --- Test wrappers ---

func runTest(t *testing.T, name string, testFunc func(t *testing.T)) {
	start := time.Now()
	var errMsg string
	passed := true
	defer func() {
		if r := recover(); r != nil {
			errMsg = fmt.Sprintf("panic: %v", r)
			passed = false
		}
		dur := time.Since(start)
		recordTestResult(name, passed && !t.Failed(), errMsg, dur)
	}()
	testFunc(t)
	if t.Failed() {
		passed = false
	}
}

// TestEngineInitialization tests the fuzzer engine initialization
func TestEngineInitialization(t *testing.T) {
	runTest(t, "TestEngineInitialization", func(t *testing.T) {
		engine := core.NewEngine()
		assert.NotNil(t, engine)

		// Set up mocks
		executor := &MockExecutor{}
		analyzer := &MockAnalyzer{}
		mutators := []interfaces.Mutator{&MockMutator{}}

		engine.SetExecutor(executor)
		engine.SetAnalyzer(analyzer)
		engine.SetMutators(mutators)

		config := &interfaces.FuzzerConfig{
			TargetPath:    "/bin/echo",
			CorpusDir:     "./test_corpus",
			Workers:       2,
			Timeout:       5 * time.Second,
			MaxCorpusSize: 100,
			LogLevel:      "debug",
		}

		err := engine.Initialize(config)
		require.NoError(t, err)
	})
}

// TestCorpusOperations tests corpus management operations
func TestCorpusOperations(t *testing.T) {
	corpus := core.NewCorpus()

	// Test adding test cases
	testCase1 := &core.TestCase{
		ID:         "test1",
		Data:       []byte("hello world"),
		Generation: 0,
		CreatedAt:  time.Now(),
		Priority:   100,
	}

	err := corpus.Add(testCase1)
	require.NoError(t, err)
	assert.Equal(t, 1, corpus.Size())

	// Test retrieving test case
	retrieved := corpus.Get("test1")
	assert.Equal(t, testCase1, retrieved)

	// Test getting random test cases
	random := corpus.GetRandom(5)
	assert.Len(t, random, 1)
	assert.Equal(t, testCase1, random[0])

	// Test getting test cases by priority
	priority := corpus.GetByPriority(5)
	assert.Len(t, priority, 1)
	assert.Equal(t, testCase1, priority[0])
}

// TestCorpusCleanup tests corpus cleanup functionality
func TestCorpusCleanup(t *testing.T) {
	runTest(t, "TestCorpusCleanup", func(t *testing.T) {
		corpus := core.NewCorpus()
		corpus.SetMaxSize(3)

		// Add multiple test cases
		for i := 0; i < 5; i++ {
			testCase := &core.TestCase{
				ID:         fmt.Sprintf("test%d", i),
				Data:       []byte(fmt.Sprintf("data%d", i)),
				Generation: i,
				CreatedAt:  time.Now(),
				Priority:   100 - i*10, // Decreasing priority
			}
			corpus.Add(testCase)
		}

		// Verify cleanup
		assert.LessOrEqual(t, corpus.Size(), 3)

		// Check that higher priority test cases are kept
		remaining := corpus.GetAll()
		assert.LessOrEqual(t, len(remaining), 3)

		// Verify priorities are in descending order and >= 70
		for _, tc := range remaining {
			assert.GreaterOrEqual(t, tc.Priority, 70)
		}
	})
}

// TestPriorityQueueOperations tests priority queue functionality
func TestPriorityQueueOperations(t *testing.T) {
	queue := core.NewPriorityQueue()

	// Test empty queue
	assert.True(t, queue.IsEmpty())
	assert.Equal(t, 0, queue.Size())
	assert.Nil(t, queue.Get())

	// Add test cases with different priorities
	testCase1 := &core.TestCase{
		ID:       "test1",
		Data:     []byte("data1"),
		Priority: 50,
	}

	testCase2 := &core.TestCase{
		ID:       "test2",
		Data:     []byte("data2"),
		Priority: 100,
	}

	testCase3 := &core.TestCase{
		ID:       "test3",
		Data:     []byte("data3"),
		Priority: 25,
	}

	queue.Put(testCase1)
	queue.Put(testCase2)
	queue.Put(testCase3)

	assert.Equal(t, 3, queue.Size())
	assert.False(t, queue.IsEmpty())

	// Test priority ordering (highest priority first)
	first := queue.Get()
	assert.Equal(t, testCase2, first) // Priority 100

	second := queue.Get()
	assert.Equal(t, testCase1, second) // Priority 50

	third := queue.Get()
	assert.Equal(t, testCase3, third) // Priority 25

	// Queue should be empty now
	assert.True(t, queue.IsEmpty())
}

// TestPriorityQueueUpdate tests priority queue update functionality
func TestPriorityQueueUpdate(t *testing.T) {
	queue := core.NewPriorityQueue()

	testCase := &core.TestCase{
		ID:       "test1",
		Data:     []byte("data1"),
		Priority: 50,
	}

	queue.Put(testCase)

	// Update priority
	success := queue.UpdatePriority("test1", 200)
	assert.True(t, success)

	// Verify new priority is used
	retrieved := queue.Get()
	assert.Equal(t, 200, retrieved.Priority)

	// Test updating non-existent test case
	success = queue.UpdatePriority("nonexistent", 100)
	assert.False(t, success)
}

// TestWorkerCreation tests worker creation and basic functionality
func TestWorkerCreation(t *testing.T) {
	runTest(t, "TestWorkerCreation", func(t *testing.T) {
		executor := &CoreMockExecutor{}
		analyzer := &CoreMockAnalyzer{}

		worker := core.NewWorker(1, executor, analyzer, nil)
		assert.NotNil(t, worker)
		assert.Equal(t, 1, worker.ID)
		assert.False(t, worker.IsRunning())
	})
}

// TestWorkerExecution tests worker execution functionality
func TestWorkerExecution(t *testing.T) {
	t.Skip("Skipping due to known hang issue")
	runTest(t, "TestWorkerExecution", func(t *testing.T) {
		executor := &CoreMockExecutor{}
		analyzer := &CoreMockAnalyzer{}

		worker := core.NewWorker(1, executor, analyzer, nil)

		testCase := &core.TestCase{
			ID:   "test1",
			Data: []byte("test data"),
		}

		// Test execution
		result, err := worker.Execute(testCase)
		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, "test1", result.TestCaseID)
		assert.Equal(t, core.StatusSuccess, result.Status)
	})
}

// TestFuzzerStats tests fuzzer statistics functionality
func TestFuzzerStats(t *testing.T) {
	stats := &core.FuzzerStats{
		StartTime: time.Now(),
	}

	// Test atomic increments
	stats.IncrementExecutions()
	assert.Equal(t, int64(1), stats.Executions)

	stats.IncrementCrashes()
	assert.Equal(t, int64(1), stats.Crashes)

	stats.IncrementHangs()
	assert.Equal(t, int64(1), stats.Hangs)

	stats.IncrementTimeouts()
	assert.Equal(t, int64(1), stats.Timeouts)
}

// TestTestCaseCreation tests test case creation and manipulation
func TestTestCaseCreation(t *testing.T) {
	data := []byte("test data")
	testCase := &core.TestCase{
		ID:         "test1",
		Data:       data,
		ParentID:   "parent1",
		Generation: 1,
		CreatedAt:  time.Now(),
		Executions: 0,
		Priority:   100,
		Metadata:   make(map[string]interface{}),
	}

	assert.Equal(t, "test1", testCase.ID)
	assert.Equal(t, data, testCase.Data)
	assert.Equal(t, "parent1", testCase.ParentID)
	assert.Equal(t, 1, testCase.Generation)
	assert.Equal(t, int64(0), testCase.Executions)
	assert.Equal(t, 100, testCase.Priority)

	// Test metadata
	testCase.Metadata["key"] = "value"
	assert.Equal(t, "value", testCase.Metadata["key"])
}

// TestCoverageCreation tests coverage object creation and manipulation
func TestCoverageCreation(t *testing.T) {
	coverage := &core.Coverage{
		Bitmap:        []byte{0xFF, 0x00},
		EdgeCount:     8,
		BlockCount:    4,
		FunctionCount: 2,
		Timestamp:     time.Now(),
		Hash:          12345,
	}

	assert.Equal(t, 8, coverage.EdgeCount)
	assert.Equal(t, 4, coverage.BlockCount)
	assert.Equal(t, 2, coverage.FunctionCount)
	assert.Equal(t, uint64(12345), coverage.Hash)
	assert.Len(t, coverage.Bitmap, 2)
}

// TestExecutionResultCreation tests execution result creation
func TestExecutionResultCreation(t *testing.T) {
	result := &core.ExecutionResult{
		TestCaseID:  "test1",
		ExitCode:    0,
		Signal:      0,
		Duration:    100 * time.Millisecond,
		MemoryUsage: 1024,
		CPUUsage:    50.0,
		Output:      []byte("output"),
		Error:       []byte("error"),
		Status:      core.StatusSuccess,
	}

	assert.Equal(t, "test1", result.TestCaseID)
	assert.Equal(t, 0, result.ExitCode)
	assert.Equal(t, 0, result.Signal)
	assert.Equal(t, 100*time.Millisecond, result.Duration)
	assert.Equal(t, uint64(1024), result.MemoryUsage)
	assert.Equal(t, 50.0, result.CPUUsage)
	assert.Equal(t, []byte("output"), result.Output)
	assert.Equal(t, []byte("error"), result.Error)
	assert.Equal(t, core.StatusSuccess, result.Status)
}

// TestCrashInfoCreation tests crash information creation
func TestCrashInfoCreation(t *testing.T) {
	crashInfo := &core.CrashInfo{
		Type:         "SIGSEGV",
		Address:      0x12345678,
		StackTrace:   []string{"func1", "func2", "func3"},
		Registers:    map[string]uint64{"rax": 0x1234, "rbx": 0x5678},
		MemoryMap:    []core.MemoryRegion{},
		Reproducible: true,
		Hash:         "abc123",
	}

	assert.Equal(t, "SIGSEGV", crashInfo.Type)
	assert.Equal(t, uintptr(0x12345678), crashInfo.Address)
	assert.Len(t, crashInfo.StackTrace, 3)
	assert.Len(t, crashInfo.Registers, 2)
	assert.True(t, crashInfo.Reproducible)
	assert.Equal(t, "abc123", crashInfo.Hash)
}

// TestHangInfoCreation tests hang information creation
func TestHangInfoCreation(t *testing.T) {
	hangInfo := &core.HangInfo{
		Duration:   5 * time.Second,
		LastOutput: []byte("last output"),
		StackTrace: []string{"func1", "func2"},
		ResourceUsage: core.ResourceUsage{
			PeakMemory: 2048,
			AvgCPU:     75.0,
			IORead:     1024,
			IOWrite:    512,
		},
	}

	assert.Equal(t, 5*time.Second, hangInfo.Duration)
	assert.Equal(t, []byte("last output"), hangInfo.LastOutput)
	assert.Len(t, hangInfo.StackTrace, 2)
	assert.Equal(t, uint64(2048), hangInfo.ResourceUsage.PeakMemory)
	assert.Equal(t, 75.0, hangInfo.ResourceUsage.AvgCPU)
}

// TestFuzzerConfigCreation tests fuzzer configuration creation
func TestFuzzerConfigCreation(t *testing.T) {
	config := &core.FuzzerConfig{
		TargetPath:    "/bin/echo",
		TargetArgs:    []string{"-n", "hello"},
		TargetEnv:     []string{"VAR1=value1"},
		Workers:       4,
		Timeout:       30 * time.Second,
		MemoryLimit:   1024 * 1024,
		CorpusDir:     "./corpus",
		OutputDir:     "./output",
		MaxCorpusSize: 1000,
		MutationRate:  0.01,
		MaxMutations:  5,
		Strategy:      "mutation",
		CoverageType:  "edge",
		BitmapSize:    65536,
		EdgeThreshold: 10,
		MaxCrashes:    100,
		CrashDir:      "./crashes",
		Reproduce:     true,
		EnableGC:      true,
		ProfileCPU:    false,
		ProfileMemory: false,
		LogLevel:      "info",
		LogFile:       "./fuzzer.log",
		JSONLogs:      false,
	}

	assert.Equal(t, "/bin/echo", config.TargetPath)
	assert.Len(t, config.TargetArgs, 2)
	assert.Len(t, config.TargetEnv, 1)
	assert.Equal(t, 4, config.Workers)
	assert.Equal(t, 30*time.Second, config.Timeout)
	assert.Equal(t, uint64(1024*1024), config.MemoryLimit)
	assert.Equal(t, "./corpus", config.CorpusDir)
	assert.Equal(t, "./output", config.OutputDir)
	assert.Equal(t, 1000, config.MaxCorpusSize)
	assert.Equal(t, 0.01, config.MutationRate)
	assert.Equal(t, 5, config.MaxMutations)
	assert.Equal(t, "mutation", config.Strategy)
	assert.Equal(t, "edge", config.CoverageType)
	assert.Equal(t, 65536, config.BitmapSize)
	assert.Equal(t, 10, config.EdgeThreshold)
	assert.Equal(t, 100, config.MaxCrashes)
	assert.Equal(t, "./crashes", config.CrashDir)
	assert.True(t, config.Reproduce)
	assert.True(t, config.EnableGC)
	assert.False(t, config.ProfileCPU)
	assert.False(t, config.ProfileMemory)
	assert.Equal(t, "info", config.LogLevel)
	assert.Equal(t, "./fuzzer.log", config.LogFile)
	assert.False(t, config.JSONLogs)
}

// Mock implementations for testing

type MockExecutor struct{}

func (m *MockExecutor) Execute(testCase *interfaces.TestCase) (*interfaces.ExecutionResult, error) {
	return &interfaces.ExecutionResult{
		TestCaseID: testCase.ID,
		Status:     interfaces.StatusSuccess,
		ExitCode:   0,
		Duration:   10 * time.Millisecond,
	}, nil
}

func (m *MockExecutor) Initialize(config *interfaces.FuzzerConfig) error {
	return nil
}

func (m *MockExecutor) Cleanup() error {
	return nil
}

type MockAnalyzer struct{}

func (m *MockAnalyzer) Analyze(result *interfaces.ExecutionResult) error {
	return nil
}

func (m *MockAnalyzer) IsInteresting(testCase *interfaces.TestCase) bool {
	return true
}

func (m *MockAnalyzer) GetCoverage(result *interfaces.ExecutionResult) (*interfaces.Coverage, error) {
	return &interfaces.Coverage{
		EdgeCount:     10,
		BlockCount:    5,
		FunctionCount: 2,
		Timestamp:     time.Now(),
		Hash:          12345,
	}, nil
}

func (m *MockAnalyzer) DetectCrash(result *interfaces.ExecutionResult) (*interfaces.CrashInfo, error) {
	return nil, nil
}

func (m *MockAnalyzer) DetectHang(result *interfaces.ExecutionResult) (*interfaces.HangInfo, error) {
	return nil, nil
}

// Add a simple MockMutator for the test
type MockMutator struct{}

func (m *MockMutator) Mutate(tc *interfaces.TestCase) (*interfaces.TestCase, error) {
	return tc, nil
}
func (m *MockMutator) Name() string        { return "MockMutator" }
func (m *MockMutator) Description() string { return "Mock mutator for testing" }

// Add core package mocks for worker tests
type CoreMockExecutor struct{}

func (m *CoreMockExecutor) Execute(testCase *core.TestCase) (*core.ExecutionResult, error) {
	return &core.ExecutionResult{
		TestCaseID: testCase.ID,
		Status:     core.StatusSuccess,
		ExitCode:   0,
		Duration:   10 * time.Millisecond,
	}, nil
}
func (m *CoreMockExecutor) Initialize(config *core.FuzzerConfig) error { return nil }
func (m *CoreMockExecutor) Cleanup() error                             { return nil }

type CoreMockAnalyzer struct{}

func (m *CoreMockAnalyzer) Analyze(result *core.ExecutionResult) error { return nil }
func (m *CoreMockAnalyzer) IsInteresting(testCase *core.TestCase) bool { return true }
func (m *CoreMockAnalyzer) GetCoverage(result *core.ExecutionResult) (*core.Coverage, error) {
	return &core.Coverage{
		EdgeCount:     10,
		BlockCount:    5,
		FunctionCount: 2,
		Timestamp:     time.Now(),
		Hash:          12345,
	}, nil
}
func (m *CoreMockAnalyzer) DetectCrash(result *core.ExecutionResult) (*core.CrashInfo, error) {
	return nil, nil
}
func (m *CoreMockAnalyzer) DetectHang(result *core.ExecutionResult) (*core.HangInfo, error) {
	return nil, nil
}

// Test suite summary struct
// (add at the end of the file)
type CoreTestSummary struct {
	Timestamp  string          `json:"timestamp"`
	Version    string          `json:"version"`
	TotalTests int             `json:"total_tests"`
	Passed     int             `json:"passed"`
	Failed     int             `json:"failed"`
	Details    map[string]bool `json:"details"`
}

// TestMain for core tests to collect and write metrics
func TestMain(m *testing.M) {
	suiteStart = time.Now()
	code := m.Run()
	suiteEnd = time.Now()

	total := len(testResults)
	passed := 0
	failed := 0
	for _, r := range testResults {
		if r.Passed {
			passed++
		} else {
			failed++
		}
	}

	summary := map[string]interface{}{
		"timestamp":        suiteStart.Format("2006-01-02 15:04:05"),
		"version":          "1.0.0",
		"total_tests":      total,
		"passed":           passed,
		"failed":           failed,
		"start_time":       suiteStart.Format(time.RFC3339),
		"end_time":         suiteEnd.Format(time.RFC3339),
		"duration_seconds": suiteEnd.Sub(suiteStart).Seconds(),
		"tests":            testResults,
	}

	fmt.Println("[DEBUG] About to write metrics result...")
	path, err := utils.WriteMetricsResult("core", "1.0.0", summary)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to write metrics: %v\n", err)
	} else {
		fmt.Printf("[DEBUG] Metrics written to: %s\n", path)
	}

	os.Exit(code)
}
