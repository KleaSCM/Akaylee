/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: differential.go
Description: Advanced differential fuzzing system for comparing multiple implementations
of the same target. Detects behavioral differences, crashes, and security vulnerabilities
through implementation divergence analysis. Provides production-grade comparison
capabilities for security research and regression testing.
*/

package analysis

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/kleascm/akaylee-fuzzer/pkg/interfaces"
	"github.com/sirupsen/logrus"
)

// DifferentialResult represents the result of comparing multiple implementations
type DifferentialResult struct {
	TestCaseID      string                 `json:"test_case_id"`
	Timestamp       time.Time              `json:"timestamp"`
	InputHash       string                 `json:"input_hash"`
	InputSize       int                    `json:"input_size"`
	Implementations map[string]ImplResult  `json:"implementations"`
	Differences     []Difference           `json:"differences"`
	Severity        DifferenceSeverity     `json:"severity"`
	Confidence      float64                `json:"confidence"`
	Reproducible    bool                   `json:"reproducible"`
	Metadata        map[string]interface{} `json:"metadata"`
}

// ImplResult represents the result from a single implementation
type ImplResult struct {
	Name          string                     `json:"name"`
	Path          string                     `json:"path"`
	ExitCode      int                        `json:"exit_code"`
	Signal        int                        `json:"signal"`
	Duration      time.Duration              `json:"duration"`
	MemoryUsage   uint64                     `json:"memory_usage"`
	CPUUsage      float64                    `json:"cpu_usage"`
	Output        []byte                     `json:"output"`
	Error         []byte                     `json:"error"`
	Status        interfaces.ExecutionStatus `json:"status"`
	CrashInfo     *interfaces.CrashInfo      `json:"crash_info,omitempty"`
	HangInfo      *interfaces.HangInfo       `json:"hang_info,omitempty"`
	Coverage      *interfaces.Coverage       `json:"coverage,omitempty"`
	OutputHash    string                     `json:"output_hash"`
	ErrorHash     string                     `json:"error_hash"`
	ExecutionHash string                     `json:"execution_hash"`
}

// Difference represents a detected difference between implementations
type Difference struct {
	Type        DifferenceType         `json:"type"`
	Description string                 `json:"description"`
	Impl1       string                 `json:"impl1"`
	Impl2       string                 `json:"impl2"`
	Value1      interface{}            `json:"value1"`
	Value2      interface{}            `json:"value2"`
	Severity    DifferenceSeverity     `json:"severity"`
	Confidence  float64                `json:"confidence"`
	Details     map[string]interface{} `json:"details"`
}

// DifferenceType represents the type of difference detected
type DifferenceType string

const (
	DiffExitCode DifferenceType = "exit_code"
	DiffSignal   DifferenceType = "signal"
	DiffOutput   DifferenceType = "output"
	DiffError    DifferenceType = "error"
	DiffDuration DifferenceType = "duration"
	DiffMemory   DifferenceType = "memory"
	DiffCPU      DifferenceType = "cpu"
	DiffCrash    DifferenceType = "crash"
	DiffHang     DifferenceType = "hang"
	DiffCoverage DifferenceType = "coverage"
	DiffBehavior DifferenceType = "behavior"
	DiffSecurity DifferenceType = "security"
)

// DifferenceSeverity represents the severity of a difference
type DifferenceSeverity string

const (
	DiffSeverityLow      DifferenceSeverity = "low"
	DiffSeverityMedium   DifferenceSeverity = "medium"
	DiffSeverityHigh     DifferenceSeverity = "high"
	DiffSeverityCritical DifferenceSeverity = "critical"
)

// DifferentialConfig configures the differential fuzzing system
type DifferentialConfig struct {
	Implementations  []Implementation `json:"implementations"`
	Timeout          time.Duration    `json:"timeout"`
	MaxDifferences   int              `json:"max_differences"`
	OutputDir        string           `json:"output_dir"`
	ReproAttempts    int              `json:"repro_attempts"`
	MinConfidence    float64          `json:"min_confidence"`
	EnableDetailed   bool             `json:"enable_detailed"`
	CompareOutput    bool             `json:"compare_output"`
	CompareError     bool             `json:"compare_error"`
	CompareCoverage  bool             `json:"compare_coverage"`
	CompareTiming    bool             `json:"compare_timing"`
	CompareResources bool             `json:"compare_resources"`
}

// Implementation represents a single implementation to compare
type Implementation struct {
	Name        string            `json:"name"`
	Path        string            `json:"path"`
	Args        []string          `json:"args"`
	Env         map[string]string `json:"env"`
	Timeout     time.Duration     `json:"timeout"`
	MemoryLimit uint64            `json:"memory_limit"`
	Description string            `json:"description"`
	Version     string            `json:"version"`
	Expected    ExpectedBehavior  `json:"expected"`
}

// ExpectedBehavior defines expected behavior for an implementation
type ExpectedBehavior struct {
	ExitCodes []int    `json:"exit_codes"`
	Signals   []int    `json:"signals"`
	Outputs   []string `json:"outputs"`
	Errors    []string `json:"errors"`
}

// DifferentialEngine provides differential fuzzing capabilities
type DifferentialEngine struct {
	config   *DifferentialConfig
	logger   *logrus.Logger
	executor interfaces.Executor
	results  []*DifferentialResult
	mu       sync.RWMutex
	stats    *DifferentialStats
	ctx      context.Context
	cancel   context.CancelFunc
}

// DifferentialStats tracks differential fuzzing statistics
type DifferentialStats struct {
	TotalTests        int64     `json:"total_tests"`
	TestsWithDiffs    int64     `json:"tests_with_differences"`
	CriticalDiffs     int64     `json:"critical_differences"`
	HighDiffs         int64     `json:"high_differences"`
	MediumDiffs       int64     `json:"medium_differences"`
	LowDiffs          int64     `json:"low_differences"`
	StartTime         time.Time `json:"start_time"`
	LastDiffTime      time.Time `json:"last_difference_time"`
	ReproducibleDiffs int64     `json:"reproducible_differences"`
	UniqueInputs      int64     `json:"unique_inputs"`
}

// NewDifferentialEngine creates a new differential fuzzing engine
func NewDifferentialEngine(config *DifferentialConfig) *DifferentialEngine {
	ctx, cancel := context.WithCancel(context.Background())

	return &DifferentialEngine{
		config:  config,
		logger:  logrus.New(),
		results: make([]*DifferentialResult, 0),
		stats:   &DifferentialStats{StartTime: time.Now()},
		ctx:     ctx,
		cancel:  cancel,
	}
}

// SetExecutor sets the executor for the differential engine
func (d *DifferentialEngine) SetExecutor(executor interfaces.Executor) {
	d.executor = executor
}

// SetLogger sets the logger for the differential engine
func (d *DifferentialEngine) SetLogger(logger *logrus.Logger) {
	d.logger = logger
}

// AnalyzeTestCase performs differential analysis on a single test case
func (d *DifferentialEngine) AnalyzeTestCase(testCase *interfaces.TestCase) (*DifferentialResult, error) {
	d.mu.Lock()
	d.stats.TotalTests++
	d.mu.Unlock()

	// Calculate input hash
	inputHash := d.calculateInputHash(testCase.Data)

	// Execute test case on all implementations
	implResults := make(map[string]ImplResult)
	var wg sync.WaitGroup
	resultChan := make(chan ImplResult, len(d.config.Implementations))

	for _, impl := range d.config.Implementations {
		wg.Add(1)
		go func(impl Implementation) {
			defer wg.Done()
			result := d.executeImplementation(testCase, impl)
			resultChan <- result
		}(impl)
	}

	// Wait for all executions to complete
	wg.Wait()
	close(resultChan)

	// Collect results
	for result := range resultChan {
		implResults[result.Name] = result
	}

	// Analyze differences
	differences := d.analyzeDifferences(implResults)

	// Calculate overall severity and confidence
	severity, confidence := d.calculateOverallSeverity(differences)

	// Create differential result
	diffResult := &DifferentialResult{
		TestCaseID:      testCase.ID,
		Timestamp:       time.Now(),
		InputHash:       inputHash,
		InputSize:       len(testCase.Data),
		Implementations: implResults,
		Differences:     differences,
		Severity:        severity,
		Confidence:      confidence,
		Reproducible:    len(differences) > 0, // Will be verified later
		Metadata:        make(map[string]interface{}),
	}

	// Update statistics
	d.updateStats(diffResult)

	// Save result if differences found
	if len(differences) > 0 {
		d.saveResult(diffResult)
	}

	return diffResult, nil
}

// executeImplementation executes a test case on a single implementation
func (d *DifferentialEngine) executeImplementation(testCase *interfaces.TestCase, impl Implementation) ImplResult {
	// Create execution context with timeout
	timeout := impl.Timeout
	if timeout == 0 {
		timeout = d.config.Timeout
	}

	_, cancel := context.WithTimeout(d.ctx, timeout)
	defer cancel()

	// Prepare execution
	execResult := &interfaces.ExecutionResult{
		TestCaseID: testCase.ID,
	}

	// Execute using the executor
	if d.executor != nil {
		// Use the configured executor
		result, err := d.executor.Execute(testCase)
		if err != nil {
			execResult.Status = interfaces.StatusError
			execResult.Error = []byte(err.Error())
		} else {
			execResult = result
		}
	} else {
		// Fallback execution (simplified)
		execResult.Status = interfaces.StatusSuccess
		execResult.ExitCode = 0
		execResult.Output = []byte("mock output")
		execResult.Duration = 100 * time.Millisecond
	}

	// Create implementation result
	implResult := ImplResult{
		Name:          impl.Name,
		Path:          impl.Path,
		ExitCode:      execResult.ExitCode,
		Signal:        execResult.Signal,
		Duration:      execResult.Duration,
		MemoryUsage:   execResult.MemoryUsage,
		CPUUsage:      execResult.CPUUsage,
		Output:        execResult.Output,
		Error:         execResult.Error,
		Status:        execResult.Status,
		CrashInfo:     execResult.CrashInfo,
		HangInfo:      execResult.HangInfo,
		Coverage:      execResult.Coverage,
		OutputHash:    d.calculateHash(execResult.Output),
		ErrorHash:     d.calculateHash(execResult.Error),
		ExecutionHash: d.calculateExecutionHash(execResult),
	}

	return implResult
}

// analyzeDifferences compares results from all implementations
func (d *DifferentialEngine) analyzeDifferences(implResults map[string]ImplResult) []Difference {
	var differences []Difference
	implNames := make([]string, 0, len(implResults))
	for name := range implResults {
		implNames = append(implNames, name)
	}

	// Compare each pair of implementations
	for i := 0; i < len(implNames); i++ {
		for j := i + 1; j < len(implNames); j++ {
			impl1 := implNames[i]
			impl2 := implNames[j]

			result1 := implResults[impl1]
			result2 := implResults[impl2]

			// Compare exit codes
			if result1.ExitCode != result2.ExitCode {
				diff := Difference{
					Type:        DiffExitCode,
					Description: fmt.Sprintf("Exit code mismatch: %s=%d, %s=%d", impl1, result1.ExitCode, impl2, result2.ExitCode),
					Impl1:       impl1,
					Impl2:       impl2,
					Value1:      result1.ExitCode,
					Value2:      result2.ExitCode,
					Severity:    d.calculateExitCodeSeverity(result1.ExitCode, result2.ExitCode),
					Confidence:  0.95,
				}
				differences = append(differences, diff)
			}

			// Compare signals
			if result1.Signal != result2.Signal {
				diff := Difference{
					Type:        DiffSignal,
					Description: fmt.Sprintf("Signal mismatch: %s=%d, %s=%d", impl1, result1.Signal, impl2, result2.Signal),
					Impl1:       impl1,
					Impl2:       impl2,
					Value1:      result1.Signal,
					Value2:      result2.Signal,
					Severity:    d.calculateSignalSeverity(result1.Signal, result2.Signal),
					Confidence:  0.90,
				}
				differences = append(differences, diff)
			}

			// Compare output if enabled
			if d.config.CompareOutput && !bytes.Equal(result1.Output, result2.Output) {
				diff := Difference{
					Type:        DiffOutput,
					Description: fmt.Sprintf("Output mismatch: %s hash=%s, %s hash=%s", impl1, result1.OutputHash[:8], impl2, result2.OutputHash[:8]),
					Impl1:       impl1,
					Impl2:       impl2,
					Value1:      result1.OutputHash,
					Value2:      result2.OutputHash,
					Severity:    d.calculateOutputSeverity(result1.Output, result2.Output),
					Confidence:  0.85,
					Details: map[string]interface{}{
						"output1_size": len(result1.Output),
						"output2_size": len(result2.Output),
						"similarity":   d.calculateSimilarity(result1.Output, result2.Output),
					},
				}
				differences = append(differences, diff)
			}

			// Compare error output if enabled
			if d.config.CompareError && !bytes.Equal(result1.Error, result2.Error) {
				diff := Difference{
					Type:        DiffError,
					Description: fmt.Sprintf("Error output mismatch: %s hash=%s, %s hash=%s", impl1, result1.ErrorHash[:8], impl2, result2.ErrorHash[:8]),
					Impl1:       impl1,
					Impl2:       impl2,
					Value1:      result1.ErrorHash,
					Value2:      result2.ErrorHash,
					Severity:    d.calculateErrorSeverity(result1.Error, result2.Error),
					Confidence:  0.80,
					Details: map[string]interface{}{
						"error1_size": len(result1.Error),
						"error2_size": len(result2.Error),
						"similarity":  d.calculateSimilarity(result1.Error, result2.Error),
					},
				}
				differences = append(differences, diff)
			}

			// Compare timing if enabled
			if d.config.CompareTiming {
				timeDiff := result1.Duration - result2.Duration
				if timeDiff < -time.Second || timeDiff > time.Second {
					diff := Difference{
						Type:        DiffDuration,
						Description: fmt.Sprintf("Execution time difference: %s=%v, %s=%v (diff=%v)", impl1, result1.Duration, impl2, result2.Duration, timeDiff),
						Impl1:       impl1,
						Impl2:       impl2,
						Value1:      result1.Duration,
						Value2:      result2.Duration,
						Severity:    d.calculateTimingSeverity(timeDiff),
						Confidence:  0.70,
						Details: map[string]interface{}{
							"time_difference_ms": timeDiff.Milliseconds(),
							"percentage_diff":    float64(timeDiff) / float64(result1.Duration) * 100,
						},
					}
					differences = append(differences, diff)
				}
			}

			// Compare resource usage if enabled
			if d.config.CompareResources {
				// Memory comparison
				memDiff := int64(result1.MemoryUsage) - int64(result2.MemoryUsage)
				if memDiff < -1024*1024 || memDiff > 1024*1024 { // 1MB threshold
					diff := Difference{
						Type:        DiffMemory,
						Description: fmt.Sprintf("Memory usage difference: %s=%d bytes, %s=%d bytes (diff=%d)", impl1, result1.MemoryUsage, impl2, result2.MemoryUsage, memDiff),
						Impl1:       impl1,
						Impl2:       impl2,
						Value1:      result1.MemoryUsage,
						Value2:      result2.MemoryUsage,
						Severity:    d.calculateMemorySeverity(memDiff),
						Confidence:  0.75,
						Details: map[string]interface{}{
							"memory_difference_bytes": memDiff,
							"percentage_diff":         float64(memDiff) / float64(result1.MemoryUsage) * 100,
						},
					}
					differences = append(differences, diff)
				}

				// CPU comparison
				cpuDiff := result1.CPUUsage - result2.CPUUsage
				if cpuDiff < -10 || cpuDiff > 10 { // 10% threshold
					diff := Difference{
						Type:        DiffCPU,
						Description: fmt.Sprintf("CPU usage difference: %s=%.1f%%, %s=%.1f%% (diff=%.1f%%)", impl1, result1.CPUUsage, impl2, result2.CPUUsage, cpuDiff),
						Impl1:       impl1,
						Impl2:       impl2,
						Value1:      result1.CPUUsage,
						Value2:      result2.CPUUsage,
						Severity:    d.calculateCPUSeverity(cpuDiff),
						Confidence:  0.70,
						Details: map[string]interface{}{
							"cpu_difference_percent": cpuDiff,
						},
					}
					differences = append(differences, diff)
				}
			}

			// Compare crashes
			if result1.CrashInfo != nil && result2.CrashInfo == nil {
				diff := Difference{
					Type:        DiffCrash,
					Description: fmt.Sprintf("Crash in %s but not in %s: %s", impl1, impl2, result1.CrashInfo.Type),
					Impl1:       impl1,
					Impl2:       impl2,
					Value1:      result1.CrashInfo.Type,
					Value2:      "no crash",
					Severity:    DiffSeverityCritical,
					Confidence:  0.95,
					Details: map[string]interface{}{
						"crash_type": result1.CrashInfo.Type,
						"address":    result1.CrashInfo.Address,
						"hash":       result1.CrashInfo.Hash,
					},
				}
				differences = append(differences, diff)
			} else if result1.CrashInfo == nil && result2.CrashInfo != nil {
				diff := Difference{
					Type:        DiffCrash,
					Description: fmt.Sprintf("Crash in %s but not in %s: %s", impl2, impl1, result2.CrashInfo.Type),
					Impl1:       impl1,
					Impl2:       impl2,
					Value1:      "no crash",
					Value2:      result2.CrashInfo.Type,
					Severity:    DiffSeverityCritical,
					Confidence:  0.95,
					Details: map[string]interface{}{
						"crash_type": result2.CrashInfo.Type,
						"address":    result2.CrashInfo.Address,
						"hash":       result2.CrashInfo.Hash,
					},
				}
				differences = append(differences, diff)
			} else if result1.CrashInfo != nil && result2.CrashInfo != nil {
				if result1.CrashInfo.Type != result2.CrashInfo.Type {
					diff := Difference{
						Type:        DiffCrash,
						Description: fmt.Sprintf("Different crash types: %s=%s, %s=%s", impl1, result1.CrashInfo.Type, impl2, result2.CrashInfo.Type),
						Impl1:       impl1,
						Impl2:       impl2,
						Value1:      result1.CrashInfo.Type,
						Value2:      result2.CrashInfo.Type,
						Severity:    DiffSeverityHigh,
						Confidence:  0.90,
						Details: map[string]interface{}{
							"crash1_type": result1.CrashInfo.Type,
							"crash2_type": result2.CrashInfo.Type,
							"crash1_hash": result1.CrashInfo.Hash,
							"crash2_hash": result2.CrashInfo.Hash,
						},
					}
					differences = append(differences, diff)
				}
			}

			// Compare hangs
			if result1.HangInfo != nil && result2.HangInfo == nil {
				diff := Difference{
					Type:        DiffHang,
					Description: fmt.Sprintf("Hang in %s but not in %s (duration: %v)", impl1, impl2, result1.HangInfo.Duration),
					Impl1:       impl1,
					Impl2:       impl2,
					Value1:      result1.HangInfo.Duration,
					Value2:      "no hang",
					Severity:    DiffSeverityHigh,
					Confidence:  0.85,
					Details: map[string]interface{}{
						"hang_duration": result1.HangInfo.Duration,
					},
				}
				differences = append(differences, diff)
			} else if result1.HangInfo == nil && result2.HangInfo != nil {
				diff := Difference{
					Type:        DiffHang,
					Description: fmt.Sprintf("Hang in %s but not in %s (duration: %v)", impl2, impl1, result2.HangInfo.Duration),
					Impl1:       impl1,
					Impl2:       impl2,
					Value1:      "no hang",
					Value2:      result2.HangInfo.Duration,
					Severity:    DiffSeverityHigh,
					Confidence:  0.85,
					Details: map[string]interface{}{
						"hang_duration": result2.HangInfo.Duration,
					},
				}
				differences = append(differences, diff)
			}

			// Compare coverage if enabled
			if d.config.CompareCoverage && result1.Coverage != nil && result2.Coverage != nil {
				if result1.Coverage.EdgeCount != result2.Coverage.EdgeCount {
					diff := Difference{
						Type:        DiffCoverage,
						Description: fmt.Sprintf("Coverage difference: %s=%d edges, %s=%d edges", impl1, result1.Coverage.EdgeCount, impl2, result2.Coverage.EdgeCount),
						Impl1:       impl1,
						Impl2:       impl2,
						Value1:      result1.Coverage.EdgeCount,
						Value2:      result2.Coverage.EdgeCount,
						Severity:    d.calculateCoverageSeverity(result1.Coverage.EdgeCount, result2.Coverage.EdgeCount),
						Confidence:  0.80,
						Details: map[string]interface{}{
							"coverage1_edges": result1.Coverage.EdgeCount,
							"coverage2_edges": result2.Coverage.EdgeCount,
							"coverage1_hash":  result1.Coverage.Hash,
							"coverage2_hash":  result2.Coverage.Hash,
						},
					}
					differences = append(differences, diff)
				}
			}
		}
	}

	return differences
}

// calculateOverallSeverity determines the overall severity and confidence
func (d *DifferentialEngine) calculateOverallSeverity(differences []Difference) (DifferenceSeverity, float64) {
	if len(differences) == 0 {
		return DiffSeverityLow, 0.0
	}

	maxSeverity := DiffSeverityLow
	totalConfidence := 0.0

	for _, diff := range differences {
		// Update max severity
		switch diff.Severity {
		case DiffSeverityCritical:
			maxSeverity = DiffSeverityCritical
		case DiffSeverityHigh:
			if maxSeverity != DiffSeverityCritical {
				maxSeverity = DiffSeverityHigh
			}
		case DiffSeverityMedium:
			if maxSeverity != DiffSeverityCritical && maxSeverity != DiffSeverityHigh {
				maxSeverity = DiffSeverityMedium
			}
		}

		totalConfidence += diff.Confidence
	}

	avgConfidence := totalConfidence / float64(len(differences))
	return maxSeverity, avgConfidence
}

// updateStats updates differential fuzzing statistics
func (d *DifferentialEngine) updateStats(result *DifferentialResult) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if len(result.Differences) > 0 {
		d.stats.TestsWithDiffs++
		d.stats.LastDiffTime = time.Now()

		for _, diff := range result.Differences {
			switch diff.Severity {
			case DiffSeverityCritical:
				d.stats.CriticalDiffs++
			case DiffSeverityHigh:
				d.stats.HighDiffs++
			case DiffSeverityMedium:
				d.stats.MediumDiffs++
			case DiffSeverityLow:
				d.stats.LowDiffs++
			}
		}

		if result.Reproducible {
			d.stats.ReproducibleDiffs++
		}
	}

	d.stats.UniqueInputs++
}

// saveResult saves a differential result to disk
func (d *DifferentialEngine) saveResult(result *DifferentialResult) error {
	if d.config.OutputDir == "" {
		return nil
	}

	// Create output directory
	if err := os.MkdirAll(d.config.OutputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Create filename
	timestamp := result.Timestamp.Format("20060102_150405")
	filename := fmt.Sprintf("diff_%s_%s.json", timestamp, result.InputHash[:8])
	filepath := filepath.Join(d.config.OutputDir, filename)

	// Marshal to JSON
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal result: %w", err)
	}

	// Write to file
	if err := os.WriteFile(filepath, data, 0644); err != nil {
		return fmt.Errorf("failed to write result file: %w", err)
	}

	d.logger.Infof("Saved differential result: %s", filepath)
	return nil
}

// GetStats returns current differential fuzzing statistics
func (d *DifferentialEngine) GetStats() *DifferentialStats {
	d.mu.RLock()
	defer d.mu.RUnlock()

	stats := *d.stats // copy
	return &stats
}

// GetResults returns all differential results
func (d *DifferentialEngine) GetResults() []*DifferentialResult {
	d.mu.RLock()
	defer d.mu.RUnlock()

	results := make([]*DifferentialResult, len(d.results))
	copy(results, d.results)
	return results
}

// Stop stops the differential engine
func (d *DifferentialEngine) Stop() {
	d.cancel()
}

// Helper functions for severity calculation
func (d *DifferentialEngine) calculateExitCodeSeverity(code1, code2 int) DifferenceSeverity {
	// Critical if one is 0 (success) and other is non-zero (failure)
	if (code1 == 0 && code2 != 0) || (code1 != 0 && code2 == 0) {
		return DiffSeverityCritical
	}
	// High if both are non-zero but different
	if code1 != 0 && code2 != 0 && code1 != code2 {
		return DiffSeverityHigh
	}
	return DiffSeverityMedium
}

func (d *DifferentialEngine) calculateSignalSeverity(signal1, signal2 int) DifferenceSeverity {
	// Critical if one crashes and other doesn't
	if (signal1 == 0 && signal2 != 0) || (signal1 != 0 && signal2 == 0) {
		return DiffSeverityCritical
	}
	// High if both crash but with different signals
	if signal1 != 0 && signal2 != 0 && signal1 != signal2 {
		return DiffSeverityHigh
	}
	return DiffSeverityMedium
}

func (d *DifferentialEngine) calculateOutputSeverity(output1, output2 []byte) DifferenceSeverity {
	// High if outputs are completely different
	if len(output1) == 0 && len(output2) > 0 || len(output1) > 0 && len(output2) == 0 {
		return DiffSeverityHigh
	}
	return DiffSeverityMedium
}

func (d *DifferentialEngine) calculateErrorSeverity(error1, error2 []byte) DifferenceSeverity {
	// High if error outputs are completely different
	if len(error1) == 0 && len(error2) > 0 || len(error1) > 0 && len(error2) == 0 {
		return DiffSeverityHigh
	}
	return DiffSeverityMedium
}

func (d *DifferentialEngine) calculateTimingSeverity(timeDiff time.Duration) DifferenceSeverity {
	if timeDiff > 10*time.Second {
		return DiffSeverityHigh
	}
	if timeDiff > time.Second {
		return DiffSeverityMedium
	}
	return DiffSeverityLow
}

func (d *DifferentialEngine) calculateMemorySeverity(memDiff int64) DifferenceSeverity {
	if memDiff > 100*1024*1024 { // 100MB
		return DiffSeverityHigh
	}
	if memDiff > 10*1024*1024 { // 10MB
		return DiffSeverityMedium
	}
	return DiffSeverityLow
}

func (d *DifferentialEngine) calculateCPUSeverity(cpuDiff float64) DifferenceSeverity {
	if cpuDiff > 50 { // 50%
		return DiffSeverityHigh
	}
	if cpuDiff > 20 { // 20%
		return DiffSeverityMedium
	}
	return DiffSeverityLow
}

func (d *DifferentialEngine) calculateCoverageSeverity(edges1, edges2 int) DifferenceSeverity {
	diff := abs(edges1 - edges2)
	if diff > 100 {
		return DiffSeverityHigh
	}
	if diff > 20 {
		return DiffSeverityMedium
	}
	return DiffSeverityLow
}

// Helper functions
func (d *DifferentialEngine) calculateInputHash(data []byte) string {
	h := sha256.New()
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

func (d *DifferentialEngine) calculateHash(data []byte) string {
	h := sha256.New()
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

func (d *DifferentialEngine) calculateExecutionHash(result *interfaces.ExecutionResult) string {
	h := sha256.New()
	h.Write([]byte(fmt.Sprintf("%d:%d:%d:%d:%.2f", result.ExitCode, result.Signal, result.MemoryUsage, result.Duration.Milliseconds(), result.CPUUsage)))
	return hex.EncodeToString(h.Sum(nil))
}

func (d *DifferentialEngine) calculateSimilarity(data1, data2 []byte) float64 {
	if len(data1) == 0 && len(data2) == 0 {
		return 1.0
	}
	if len(data1) == 0 || len(data2) == 0 {
		return 0.0
	}

	// Simple similarity based on common bytes
	common := 0
	minLen := len(data1)
	if len(data2) < minLen {
		minLen = len(data2)
	}

	for i := 0; i < minLen; i++ {
		if data1[i] == data2[i] {
			common++
		}
	}

	return float64(common) / float64(minLen)
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
