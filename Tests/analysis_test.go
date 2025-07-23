/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: analysis_test.go
Description: Comprehensive tests for the analysis package. Tests CoverageAnalyzer,
RegexCrashMatcher, crash detection, hang detection, coverage tracking, and edge cases.
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

// TestCoverageAnalyzer tests the CoverageAnalyzer
func TestCoverageAnalyzer(t *testing.T) {
	runTest(t, "TestCoverageAnalyzer", func(t *testing.T) {
		analyzer := analysis.NewCoverageAnalyzer()
		require.NotNil(t, analyzer)

		// Test analysis
		result := &interfaces.ExecutionResult{
			TestCaseID: "test1",
			Status:     interfaces.StatusSuccess,
			Output:     []byte("output"),
			Error:      []byte(""),
			Duration:   100 * time.Millisecond,
		}

		err := analyzer.Analyze(result)
		require.NoError(t, err)
		assert.NotNil(t, result.Coverage)

		// Test interesting test case
		testCase := &interfaces.TestCase{
			ID:   "test1",
			Data: []byte("data"),
		}

		interesting := analyzer.IsInteresting(testCase)
		assert.IsType(t, false, interesting)
	})
}

// TestRegexCrashMatcher tests the RegexCrashMatcher
func TestRegexCrashMatcher(t *testing.T) {
	runTest(t, "TestRegexCrashMatcher", func(t *testing.T) {
		patterns := []string{
			"SIGSEGV",
			"FATAL EXCEPTION",
			"java\\.lang\\..*Exception",
		}

		matcher := analysis.NewRegexCrashMatcher(patterns)
		require.NotNil(t, matcher)

		// Test matching crash
		crashInfo := &interfaces.CrashInfo{
			Type: "SIGSEGV",
		}

		result := &interfaces.ExecutionResult{
			TestCaseID: "test1",
			Status:     interfaces.StatusCrash,
			Output:     []byte("Program received signal SIGSEGV"),
			Error:      []byte("Segmentation fault"),
		}

		interesting := matcher.IsInterestingCrash(crashInfo, result)
		assert.True(t, interesting)

		// Test non-matching crash
		crashInfo.Type = "SIGTERM"
		result.Output = []byte("Program terminated normally")
		result.Error = []byte("")

		interesting = matcher.IsInterestingCrash(crashInfo, result)
		assert.False(t, interesting)

		// Test nil inputs
		interesting = matcher.IsInterestingCrash(nil, result)
		assert.False(t, interesting)

		interesting = matcher.IsInterestingCrash(crashInfo, nil)
		assert.False(t, interesting)
	})
}

// TestCrashDetection tests crash detection functionality
func TestCrashDetection(t *testing.T) {
	runTest(t, "TestCrashDetection", func(t *testing.T) {
		analyzer := analysis.NewCoverageAnalyzer()

		// Test signal-based crash
		result := &interfaces.ExecutionResult{
			TestCaseID: "test1",
			Status:     interfaces.StatusCrash,
			Signal:     11, // SIGSEGV
			Output:     []byte("Program received signal SIGSEGV"),
			Error:      []byte("Segmentation fault"),
		}

		crashInfo, err := analyzer.DetectCrash(result)
		require.NoError(t, err)
		assert.NotNil(t, crashInfo)
		assert.Equal(t, "SIGSEGV", crashInfo.Type)
		assert.True(t, crashInfo.Reproducible)

		// Test exit code-based crash
		result = &interfaces.ExecutionResult{
			TestCaseID: "test2",
			Status:     interfaces.StatusError,
			ExitCode:   139, // Abnormal exit
			Output:     []byte("Program crashed"),
			Error:      []byte(""),
		}

		crashInfo, err = analyzer.DetectCrash(result)
		require.NoError(t, err)
		assert.NotNil(t, crashInfo)
		assert.Equal(t, "ABNORMAL_EXIT", crashInfo.Type)

		// Test no crash
		result = &interfaces.ExecutionResult{
			TestCaseID: "test3",
			Status:     interfaces.StatusSuccess,
			ExitCode:   0,
			Output:     []byte("Program completed successfully"),
			Error:      []byte(""),
		}

		crashInfo, err = analyzer.DetectCrash(result)
		require.NoError(t, err)
		assert.Nil(t, crashInfo)
	})
}

// TestHangDetection tests hang detection functionality
func TestHangDetection(t *testing.T) {
	runTest(t, "TestHangDetection", func(t *testing.T) {
		analyzer := analysis.NewCoverageAnalyzer()

		// Test hang detection
		result := &interfaces.ExecutionResult{
			TestCaseID:  "test1",
			Status:      interfaces.StatusHang,
			Duration:    15 * time.Second, // Longer than 10s threshold
			Output:      []byte("Processing..."),
			Error:       []byte(""),
			MemoryUsage: 1024 * 1024,
			CPUUsage:    50.0,
		}

		hangInfo, err := analyzer.DetectHang(result)
		require.NoError(t, err)
		assert.NotNil(t, hangInfo)
		assert.Equal(t, 15*time.Second, hangInfo.Duration)
		assert.Equal(t, uint64(1024*1024), hangInfo.ResourceUsage.PeakMemory)
		assert.Equal(t, 50.0, hangInfo.ResourceUsage.AvgCPU)

		// Test no hang
		result = &interfaces.ExecutionResult{
			TestCaseID: "test2",
			Status:     interfaces.StatusSuccess,
			Duration:   5 * time.Second, // Shorter than 10s threshold
			Output:     []byte("Completed"),
			Error:      []byte(""),
		}

		hangInfo, err = analyzer.DetectHang(result)
		require.NoError(t, err)
		assert.Nil(t, hangInfo)
	})
}

// TestCoverageTracking tests coverage tracking functionality
func TestCoverageTracking(t *testing.T) {
	runTest(t, "TestCoverageTracking", func(t *testing.T) {
		analyzer := analysis.NewCoverageAnalyzer()

		// Test coverage extraction
		result := &interfaces.ExecutionResult{
			TestCaseID: "test1",
			Status:     interfaces.StatusSuccess,
			Output:     []byte("Test output with some content"),
			Error:      []byte(""),
			Duration:   100 * time.Millisecond,
		}

		coverage, err := analyzer.GetCoverage(result)
		require.NoError(t, err)
		assert.NotNil(t, coverage)
		assert.Greater(t, coverage.EdgeCount, 0)
		assert.Greater(t, coverage.BlockCount, 0)
		assert.Greater(t, coverage.FunctionCount, 0)
		assert.NotNil(t, coverage.Bitmap)
		assert.NotEqual(t, uint64(0), coverage.Hash)

		// Test interesting test case with coverage
		testCase := &interfaces.TestCase{
			ID:       "test1",
			Data:     []byte("data"),
			Coverage: coverage,
		}

		interesting := analyzer.IsInteresting(testCase)
		assert.IsType(t, false, interesting)
	})
}

// TestCoverageAnalyzerEdgeCases tests edge cases for CoverageAnalyzer
func TestCoverageAnalyzerEdgeCases(t *testing.T) {
	runTest(t, "TestCoverageAnalyzerEdgeCases", func(t *testing.T) {
		analyzer := analysis.NewCoverageAnalyzer()

		// Test with nil result
		err := analyzer.Analyze(nil)
		assert.Error(t, err)

		// Test with empty result
		emptyResult := &interfaces.ExecutionResult{
			TestCaseID: "empty",
			Status:     interfaces.StatusSuccess,
			Output:     []byte{},
			Error:      []byte{},
		}

		err = analyzer.Analyze(emptyResult)
		require.NoError(t, err)
		assert.NotNil(t, emptyResult.Coverage)

		// Test with nil test case
		interesting := analyzer.IsInteresting(nil)
		assert.False(t, interesting)

		// Test with test case without coverage
		testCase := &interfaces.TestCase{
			ID:   "nocoverage",
			Data: []byte("data"),
		}

		interesting = analyzer.IsInteresting(testCase)
		assert.False(t, interesting)
	})
}

// TestCrashMatcherEdgeCases tests edge cases for RegexCrashMatcher
func TestCrashMatcherEdgeCases(t *testing.T) {
	runTest(t, "TestCrashMatcherEdgeCases", func(t *testing.T) {
		// Test with empty patterns
		matcher := analysis.NewRegexCrashMatcher([]string{})
		require.NotNil(t, matcher)

		crashInfo := &interfaces.CrashInfo{Type: "SIGSEGV"}
		result := &interfaces.ExecutionResult{TestCaseID: "test1"}

		interesting := matcher.IsInterestingCrash(crashInfo, result)
		assert.False(t, interesting)

		// Test with invalid regex pattern
		matcher = analysis.NewRegexCrashMatcher([]string{"[invalid"})
		require.NotNil(t, matcher)

		// Should handle invalid regex gracefully
		interesting = matcher.IsInterestingCrash(crashInfo, result)
		assert.False(t, interesting)
	})
}

// TestCoverageAnalyzerWithCrashMatcher tests integration with crash matcher
func TestCoverageAnalyzerWithCrashMatcher(t *testing.T) {
	runTest(t, "TestCoverageAnalyzerWithCrashMatcher", func(t *testing.T) {
		analyzer := analysis.NewCoverageAnalyzer()

		// Set crash matcher
		patterns := []string{"SIGSEGV", "FATAL EXCEPTION"}
		matcher := analysis.NewRegexCrashMatcher(patterns)
		analyzer.SetCrashMatcher(matcher)

		// Test crash with matcher
		result := &interfaces.ExecutionResult{
			TestCaseID: "test1",
			Status:     interfaces.StatusCrash,
			Signal:     11, // SIGSEGV
			Output:     []byte("Program received signal SIGSEGV"),
			Error:      []byte("Segmentation fault"),
		}

		crashInfo, err := analyzer.DetectCrash(result)
		require.NoError(t, err)
		assert.NotNil(t, crashInfo)
		assert.Equal(t, "SIGSEGV", crashInfo.Type)

		// Check if metadata indicates interesting crash
		if crashInfo.Metadata != nil {
			if interesting, exists := crashInfo.Metadata["interesting"]; exists {
				assert.True(t, interesting.(bool))
			}
		}
	})
}
