/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: analyzer.go
Description: Coverage analyzer implementation for the Akaylee Fuzzer. Provides comprehensive
coverage tracking, crash detection, and hang detection for execution results. Implements
intelligent analysis algorithms for determining interesting test cases.
*/

package analysis

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash/fnv"
	"regexp"
	"time"

	"github.com/kleascm/akaylee-fuzzer/pkg/interfaces"
)

// CrashMatcher defines the interface for matching interesting crashes.
// Allows regex or ruleset-based detection of likely OOB or exploitable crashes.
type CrashMatcher interface {
	IsInterestingCrash(crash *interfaces.CrashInfo, result *interfaces.ExecutionResult) bool
}

// RegexCrashMatcher implements CrashMatcher using regex patterns.
type RegexCrashMatcher struct {
	patterns []*regexp.Regexp
}

// NewRegexCrashMatcher creates a new RegexCrashMatcher with given patterns.
func NewRegexCrashMatcher(patterns []string) *RegexCrashMatcher {
	compiled := make([]*regexp.Regexp, 0, len(patterns))
	for _, pat := range patterns {
		if re, err := regexp.Compile(pat); err == nil {
			compiled = append(compiled, re)
		}
	}
	return &RegexCrashMatcher{patterns: compiled}
}

// IsInterestingCrash returns true if any pattern matches the crash info or output.
func (m *RegexCrashMatcher) IsInterestingCrash(crash *interfaces.CrashInfo, result *interfaces.ExecutionResult) bool {
	if crash == nil || result == nil {
		return false
	}
	for _, re := range m.patterns {
		if re.MatchString(crash.Type) || re.MatchString(string(result.Output)) || re.MatchString(string(result.Error)) {
			return true
		}
	}
	return false
}

// CoverageAnalyzer implements the Analyzer interface
// Provides coverage tracking and result analysis capabilities
// Now supports crash matching
type CoverageAnalyzer struct {
	globalCoverage map[uint64]bool // Global coverage bitmap
	edgeThreshold  int             // Minimum edges for interesting test case
	crashMatcher   CrashMatcher    // Optional crash matcher
}

// NewCoverageAnalyzer creates a new coverage analyzer instance
func NewCoverageAnalyzer() *CoverageAnalyzer {
	return &CoverageAnalyzer{
		globalCoverage: make(map[uint64]bool),
		edgeThreshold:  10, // Default threshold
	}
}

// SetCrashMatcher sets the crash matcher for the analyzer.
func (a *CoverageAnalyzer) SetCrashMatcher(matcher CrashMatcher) {
	a.crashMatcher = matcher
}

// Analyze analyzes an execution result
// Extracts coverage information and updates global coverage tracking
func (a *CoverageAnalyzer) Analyze(result *interfaces.ExecutionResult) error {
	// Extract coverage information
	coverage, err := a.GetCoverage(result)
	if err != nil {
		return fmt.Errorf("failed to get coverage: %w", err)
	}

	result.Coverage = coverage

	// Update global coverage
	a.updateGlobalCoverage(coverage)

	return nil
}

// IsInteresting determines if a test case is interesting based on coverage
// Returns true if the test case provides new coverage or meets other criteria
func (a *CoverageAnalyzer) IsInteresting(testCase *interfaces.TestCase) bool {
	if testCase.Coverage == nil {
		return false
	}

	// Check if test case provides new coverage
	for _, edge := range a.getCoveredEdges(testCase.Coverage) {
		if !a.globalCoverage[edge] {
			return true
		}
	}

	// Check if test case meets edge threshold
	if testCase.Coverage.EdgeCount >= a.edgeThreshold {
		return true
	}

	// Check if test case found a crash
	if testCase.Metadata != nil {
		if _, hasCrash := testCase.Metadata["found_crash"]; hasCrash {
			return true
		}
	}

	return false
}

// GetCoverage extracts coverage information from execution
// Creates a coverage object with bitmap and statistics
func (a *CoverageAnalyzer) GetCoverage(result *interfaces.ExecutionResult) (*interfaces.Coverage, error) {
	// This is a simplified implementation
	// In production, would extract coverage from instrumentation or tracing

	coverage := &interfaces.Coverage{
		Timestamp: time.Now(),
	}

	// Generate mock coverage based on execution characteristics
	// In reality, this would come from actual coverage instrumentation
	coverage.EdgeCount = a.generateMockEdgeCount(result)
	coverage.BlockCount = coverage.EdgeCount / 2
	coverage.FunctionCount = coverage.EdgeCount / 10

	// Create bitmap
	coverage.Bitmap = a.createCoverageBitmap(coverage.EdgeCount)

	// Calculate hash
	coverage.Hash = a.calculateCoverageHash(coverage)

	return coverage, nil
}

// DetectCrash detects if an execution resulted in a crash
// Analyzes exit codes, signals, and output for crash indicators
// Now uses crash matcher if set
func (a *CoverageAnalyzer) DetectCrash(result *interfaces.ExecutionResult) (*interfaces.CrashInfo, error) {
	var crashInfo *interfaces.CrashInfo
	if result.Signal != 0 {
		crashInfo = &interfaces.CrashInfo{
			Type:         a.getSignalName(result.Signal),
			Address:      0, // Would be extracted from crash analysis
			Reproducible: true,
			Hash:         a.calculateCrashHash(result),
			StackTrace:   a.extractStackTrace(result),
		}
	} else if result.ExitCode != 0 && result.ExitCode != 1 {
		crashInfo = &interfaces.CrashInfo{
			Type:         "ABNORMAL_EXIT",
			Address:      0,
			Reproducible: true,
			Hash:         a.calculateCrashHash(result),
		}
	}
	if crashInfo != nil && a.crashMatcher != nil {
		if a.crashMatcher.IsInterestingCrash(crashInfo, result) {
			crashInfo.Metadata = map[string]interface{}{"interesting": true}
		}
	}
	if crashInfo != nil {
		return crashInfo, nil
	}
	return nil, nil
}

// DetectHang detects if an execution resulted in a hang
// Analyzes execution duration and resource usage
func (a *CoverageAnalyzer) DetectHang(result *interfaces.ExecutionResult) (*interfaces.HangInfo, error) {
	// Check if execution took too long
	if result.Duration > 10*time.Second {
		hangInfo := &interfaces.HangInfo{
			Duration:   result.Duration,
			LastOutput: result.Output,
			ResourceUsage: interfaces.ResourceUsage{
				PeakMemory: result.MemoryUsage,
				AvgCPU:     result.CPUUsage,
			},
		}

		return hangInfo, nil
	}

	return nil, nil
}

// updateGlobalCoverage updates the global coverage tracking
// Maintains a global view of all coverage seen during fuzzing
func (a *CoverageAnalyzer) updateGlobalCoverage(coverage *interfaces.Coverage) {
	for _, edge := range a.getCoveredEdges(coverage) {
		a.globalCoverage[edge] = true
	}
}

// getCoveredEdges extracts covered edges from coverage bitmap
// Converts bitmap to list of covered edge IDs
func (a *CoverageAnalyzer) getCoveredEdges(coverage *interfaces.Coverage) []uint64 {
	edges := make([]uint64, 0, coverage.EdgeCount)

	// Parse bitmap to find covered edges
	for i := 0; i < len(coverage.Bitmap)*8; i++ {
		byteIndex := i / 8
		bitIndex := i % 8

		if byteIndex < len(coverage.Bitmap) && (coverage.Bitmap[byteIndex]&(1<<bitIndex)) != 0 {
			edges = append(edges, uint64(i))
		}
	}

	return edges
}

// generateMockEdgeCount generates a mock edge count for testing
// In production, this would come from actual coverage instrumentation
func (a *CoverageAnalyzer) generateMockEdgeCount(result *interfaces.ExecutionResult) int {
	// Use execution characteristics to generate realistic coverage
	baseCount := len(result.Output) / 100
	if baseCount < 5 {
		baseCount = 5
	}
	if baseCount > 100 {
		baseCount = 100
	}

	// Add some randomness
	baseCount += int(result.Duration.Milliseconds() % 20)

	return baseCount
}

// createCoverageBitmap creates a coverage bitmap from edge count
// In production, this would be populated from actual coverage data
func (a *CoverageAnalyzer) createCoverageBitmap(edgeCount int) []byte {
	bitmapSize := (edgeCount + 7) / 8
	bitmap := make([]byte, bitmapSize)

	// Set bits based on edge count (simplified)
	for i := 0; i < edgeCount && i < len(bitmap)*8; i++ {
		byteIndex := i / 8
		bitIndex := i % 8
		bitmap[byteIndex] |= 1 << bitIndex
	}

	return bitmap
}

// calculateCoverageHash calculates a hash of the coverage information
// Used for quick comparison and deduplication
func (a *CoverageAnalyzer) calculateCoverageHash(coverage *interfaces.Coverage) uint64 {
	h := fnv.New64a()
	h.Write(coverage.Bitmap)
	h.Write([]byte(fmt.Sprintf("%d", coverage.EdgeCount)))
	return h.Sum64()
}

// calculateCrashHash calculates a hash for crash deduplication
// Uses crash characteristics to identify unique crashes
func (a *CoverageAnalyzer) calculateCrashHash(result *interfaces.ExecutionResult) string {
	h := sha256.New()
	h.Write([]byte(fmt.Sprintf("%d", result.Signal)))
	h.Write([]byte(fmt.Sprintf("%d", result.ExitCode)))
	h.Write(result.Output)
	h.Write(result.Error)

	return hex.EncodeToString(h.Sum(nil))[:16]
}

// getSignalName converts signal number to signal name
func (a *CoverageAnalyzer) getSignalName(signal int) string {
	signalNames := map[int]string{
		1:  "SIGHUP",
		2:  "SIGINT",
		3:  "SIGQUIT",
		4:  "SIGILL",
		5:  "SIGTRAP",
		6:  "SIGABRT",
		7:  "SIGBUS",
		8:  "SIGFPE",
		9:  "SIGKILL",
		10: "SIGUSR1",
		11: "SIGSEGV",
		12: "SIGUSR2",
		13: "SIGPIPE",
		14: "SIGALRM",
		15: "SIGTERM",
	}

	if name, exists := signalNames[signal]; exists {
		return name
	}

	return fmt.Sprintf("SIG%d", signal)
}

// extractStackTrace extracts stack trace from execution result
// In production, this would parse actual stack traces
func (a *CoverageAnalyzer) extractStackTrace(result *interfaces.ExecutionResult) []string {
	// Simplified implementation
	// In production, would parse actual stack traces from output/error
	return []string{
		"main.main()",
		"runtime.main()",
		"runtime.goexit()",
	}
}
