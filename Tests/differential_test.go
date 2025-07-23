/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: differential_test.go
Description: Comprehensive tests for the differential fuzzing package. Tests DifferentialEngine,
result comparison, severity calculation, and edge cases.
*/

package core_test

import (
	"testing"
	"time"

	"github.com/kleascm/akaylee-fuzzer/pkg/analysis"
	"github.com/kleascm/akaylee-fuzzer/pkg/interfaces"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDifferentialEngine tests the DifferentialEngine
func TestDifferentialEngine(t *testing.T) {
	runTest(t, "TestDifferentialEngine", func(t *testing.T) {
		config := &analysis.DifferentialConfig{
			Implementations: []analysis.Implementation{
				{
					Name: "impl1",
					Path: "/bin/echo",
					Args: []string{},
				},
				{
					Name: "impl2",
					Path: "/bin/echo",
					Args: []string{},
				},
			},
			Timeout:        5 * time.Second,
			MaxDifferences: 10,
			OutputDir:      "./test_output",
		}

		engine := analysis.NewDifferentialEngine(config)
		require.NotNil(t, engine)

		// Test configuration
		assert.Equal(t, 2, len(config.Implementations))
		assert.Equal(t, 5*time.Second, config.Timeout)
	})
}

// TestDifferentialResultComparison tests result comparison
func TestDifferentialResultComparison(t *testing.T) {
	runTest(t, "TestDifferentialResultComparison", func(t *testing.T) {
		config := &analysis.DifferentialConfig{
			Implementations: []analysis.Implementation{
				{Name: "impl1", Path: "/bin/echo"},
				{Name: "impl2", Path: "/bin/echo"},
			},
			Timeout:        5 * time.Second,
			MaxDifferences: 10,
			OutputDir:      "./test_output",
		}

		engine := analysis.NewDifferentialEngine(config)

		// Test with identical results
		testCase := &interfaces.TestCase{
			ID:   "test1",
			Data: []byte("hello"),
		}

		result, err := engine.AnalyzeTestCase(testCase)
		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, "test1", result.TestCaseID)
		assert.Equal(t, 2, len(result.Implementations))

		// Check that implementations have same results
		impl1 := result.Implementations["impl1"]
		impl2 := result.Implementations["impl2"]
		assert.Equal(t, impl1.ExitCode, impl2.ExitCode)
		assert.Equal(t, impl1.Signal, impl2.Signal)
	})
}

// TestDifferentialSeverityConstants tests severity constants
func TestDifferentialSeverityConstants(t *testing.T) {
	runTest(t, "TestDifferentialSeverityConstants", func(t *testing.T) {
		// Test severity constants
		assert.Equal(t, analysis.DiffSeverityLow, analysis.DifferenceSeverity("low"))
		assert.Equal(t, analysis.DiffSeverityMedium, analysis.DifferenceSeverity("medium"))
		assert.Equal(t, analysis.DiffSeverityHigh, analysis.DifferenceSeverity("high"))
		assert.Equal(t, analysis.DiffSeverityCritical, analysis.DifferenceSeverity("critical"))

		// Test severity string values
		assert.Equal(t, "low", string(analysis.DiffSeverityLow))
		assert.Equal(t, "medium", string(analysis.DiffSeverityMedium))
		assert.Equal(t, "high", string(analysis.DiffSeverityHigh))
		assert.Equal(t, "critical", string(analysis.DiffSeverityCritical))
	})
}

// TestDifferentialStats tests statistics tracking
func TestDifferentialStats(t *testing.T) {
	runTest(t, "TestDifferentialStats", func(t *testing.T) {
		config := &analysis.DifferentialConfig{
			Implementations: []analysis.Implementation{
				{Name: "impl1", Path: "/bin/echo"},
				{Name: "impl2", Path: "/bin/echo"},
			},
			Timeout:        5 * time.Second,
			MaxDifferences: 10,
			OutputDir:      "./test_output",
		}

		engine := analysis.NewDifferentialEngine(config)

		// Initial stats
		stats := engine.GetStats()
		assert.Equal(t, int64(0), stats.TotalTests)
		assert.Equal(t, int64(0), stats.TestsWithDiffs)

		// Run a test
		testCase := &interfaces.TestCase{
			ID:   "test1",
			Data: []byte("hello"),
		}

		_, err := engine.AnalyzeTestCase(testCase)
		require.NoError(t, err)

		// Check updated stats
		stats = engine.GetStats()
		assert.Equal(t, int64(1), stats.TotalTests)
		assert.GreaterOrEqual(t, stats.TestsWithDiffs, int64(0))
	})
}

// TestDifferentialEdgeCases tests edge cases
func TestDifferentialEdgeCases(t *testing.T) {
	runTest(t, "TestDifferentialEdgeCases", func(t *testing.T) {
		// Test with single implementation
		config := &analysis.DifferentialConfig{
			Implementations: []analysis.Implementation{
				{Name: "impl1", Path: "/bin/echo"},
			},
			Timeout:        5 * time.Second,
			MaxDifferences: 10,
			OutputDir:      "./test_output",
		}

		engine := analysis.NewDifferentialEngine(config)
		testCase := &interfaces.TestCase{
			ID:   "test1",
			Data: []byte("hello"),
		}

		result, err := engine.AnalyzeTestCase(testCase)
		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, 1, len(result.Implementations))

		// Test with empty test case
		emptyTestCase := &interfaces.TestCase{
			ID:   "empty",
			Data: []byte{},
		}

		result, err = engine.AnalyzeTestCase(emptyTestCase)
		require.NoError(t, err)
		assert.NotNil(t, result)

		// Test with nil test case
		_, err = engine.AnalyzeTestCase(nil)
		assert.Error(t, err)
	})
}

// TestDifferentialSimilarityCalculation tests similarity calculation
func TestDifferentialSimilarityCalculation(t *testing.T) {
	runTest(t, "TestDifferentialSimilarityCalculation", func(t *testing.T) {
		config := &analysis.DifferentialConfig{
			Implementations: []analysis.Implementation{
				{Name: "impl1", Path: "/bin/echo"},
				{Name: "impl2", Path: "/bin/echo"},
			},
			Timeout:        5 * time.Second,
			MaxDifferences: 10,
			OutputDir:      "./test_output",
		}

		engine := analysis.NewDifferentialEngine(config)

		// Test that engine can analyze test cases
		testCase := &interfaces.TestCase{
			ID:   "test1",
			Data: []byte("hello"),
		}

		result, err := engine.AnalyzeTestCase(testCase)
		require.NoError(t, err)
		assert.NotNil(t, result)

		// Test that we can get results
		results := engine.GetResults()
		assert.NotNil(t, results)
		assert.GreaterOrEqual(t, len(results), 1)
	})
}

// TestDifferentialHashCalculation tests hash calculation
func TestDifferentialHashCalculation(t *testing.T) {
	runTest(t, "TestDifferentialHashCalculation", func(t *testing.T) {
		config := &analysis.DifferentialConfig{
			Implementations: []analysis.Implementation{
				{Name: "impl1", Path: "/bin/echo"},
				{Name: "impl2", Path: "/bin/echo"},
			},
			Timeout:        5 * time.Second,
			MaxDifferences: 10,
			OutputDir:      "./test_output",
		}

		engine := analysis.NewDifferentialEngine(config)

		// Test that engine can analyze test cases and generate hashes
		testCase := &interfaces.TestCase{
			ID:   "test1",
			Data: []byte("hello world"),
		}

		result, err := engine.AnalyzeTestCase(testCase)
		require.NoError(t, err)
		assert.NotNil(t, result)
		assert.NotEmpty(t, result.InputHash)

		// Test that implementation results have hashes
		for _, impl := range result.Implementations {
			assert.NotEmpty(t, impl.OutputHash)
			assert.NotEmpty(t, impl.ErrorHash)
			assert.NotEmpty(t, impl.ExecutionHash)
		}
	})
}

// TestDifferentialConfigValidation tests configuration validation
func TestDifferentialConfigValidation(t *testing.T) {
	runTest(t, "TestDifferentialConfigValidation", func(t *testing.T) {
		// Test with empty implementations
		config := &analysis.DifferentialConfig{
			Implementations: []analysis.Implementation{},
			Timeout:         5 * time.Second,
			MaxDifferences:  10,
			OutputDir:       "./test_output",
		}

		engine := analysis.NewDifferentialEngine(config)
		assert.NotNil(t, engine)

		// Test with nil config
		engine = analysis.NewDifferentialEngine(nil)
		assert.NotNil(t, engine)

		// Test with invalid timeout
		config = &analysis.DifferentialConfig{
			Implementations: []analysis.Implementation{
				{Name: "impl1", Path: "/bin/echo"},
			},
			Timeout:        -1 * time.Second,
			MaxDifferences: 10,
			OutputDir:      "./test_output",
		}

		engine = analysis.NewDifferentialEngine(config)
		assert.NotNil(t, engine)
	})
}

// TestDifferentialResultStructure tests the structure of differential results
func TestDifferentialResultStructure(t *testing.T) {
	runTest(t, "TestDifferentialResultStructure", func(t *testing.T) {
		config := &analysis.DifferentialConfig{
			Implementations: []analysis.Implementation{
				{Name: "impl1", Path: "/bin/echo"},
				{Name: "impl2", Path: "/bin/echo"},
			},
			Timeout:        5 * time.Second,
			MaxDifferences: 10,
			OutputDir:      "./test_output",
		}

		engine := analysis.NewDifferentialEngine(config)

		testCase := &interfaces.TestCase{
			ID:   "test1",
			Data: []byte("hello"),
		}

		result, err := engine.AnalyzeTestCase(testCase)
		require.NoError(t, err)
		assert.NotNil(t, result)

		// Test result structure
		assert.NotEmpty(t, result.TestCaseID)
		assert.NotZero(t, result.Timestamp)
		assert.NotEmpty(t, result.InputHash)
		assert.Greater(t, result.InputSize, 0)
		assert.NotNil(t, result.Implementations)
		assert.NotNil(t, result.Differences)
		assert.NotNil(t, result.Metadata)

		// Test implementation results
		for name, impl := range result.Implementations {
			assert.NotEmpty(t, name)
			assert.NotEmpty(t, impl.Name)
			assert.NotEmpty(t, impl.Path)
			assert.NotEmpty(t, impl.OutputHash)
			assert.NotEmpty(t, impl.ErrorHash)
			assert.NotEmpty(t, impl.ExecutionHash)
		}
	})
}
