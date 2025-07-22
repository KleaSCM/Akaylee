/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: reproducibility.go
Description: Advanced reproducibility harness for the Akaylee Fuzzer. Provides automatic
crash replay, minimal test case generation, detailed crash analysis, and root cause
investigation. Essential for production security research and vulnerability analysis.
*/

package analysis

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kleascm/akaylee-fuzzer/pkg/interfaces"
	"github.com/sirupsen/logrus"
)

// ReproducibilityResult contains the results of crash reproduction analysis
type ReproducibilityResult struct {
	CrashInfo            *interfaces.CrashInfo
	Reproducible         bool                   // Whether crash can be reproduced
	ReproductionRate     float64                // Success rate of reproductions (0.0-1.0)
	MinimalTestCase      *interfaces.TestCase   // Smallest reproducing test case
	ReproductionAttempts int                    // Number of attempts made
	ReproductionTime     time.Duration          // Time taken for reproduction
	StackTraces          []string               // All collected stack traces
	RootCauseAnalysis    *RootCauseAnalysis     // Automated root cause analysis
	Exploitability       *ExploitabilityReport  // Detailed exploitability assessment
	Metadata             map[string]interface{} // Additional analysis data
}

// RootCauseAnalysis provides automated analysis of crash root causes
type RootCauseAnalysis struct {
	PrimaryCause    string                 // Main cause (e.g., "buffer overflow", "null pointer")
	SecondaryCauses []string               // Contributing factors
	Confidence      float64                // Analysis confidence (0.0-1.0)
	Evidence        []string               // Supporting evidence
	Recommendations []string               // Suggested fixes
	CVSSScore       *CVSSScore             // Common Vulnerability Scoring System
	Metadata        map[string]interface{} // Additional analysis data
}

// CVSSScore represents a Common Vulnerability Scoring System score
type CVSSScore struct {
	BaseScore          float64 `json:"base_score"`
	TemporalScore      float64 `json:"temporal_score"`
	EnvironmentalScore float64 `json:"environmental_score"`
	Vector             string  `json:"vector"`
	Severity           string  `json:"severity"`
}

// ExploitabilityReport provides detailed exploitability assessment
type ExploitabilityReport struct {
	Exploitability  Exploitability         // Overall exploitability level
	AttackVector    string                 // How the vulnerability can be exploited
	Complexity      string                 // Exploitation complexity
	Privileges      string                 // Required privileges
	UserInteraction string                 // User interaction required
	Scope           string                 // Impact scope
	Confidence      float64                // Assessment confidence
	ProofOfConcept  *ProofOfConcept        // Generated proof of concept
	Metadata        map[string]interface{} // Additional data
}

// ProofOfConcept represents a generated proof of concept exploit
type ProofOfConcept struct {
	Code         string                 // Exploit code
	Description  string                 // How to use
	Requirements []string               // Requirements for exploitation
	SuccessRate  float64                // Expected success rate
	RiskLevel    string                 // Risk level of running PoC
	Metadata     map[string]interface{} // Additional data
}

// ReproducibilityHarness provides comprehensive crash reproduction and analysis
type ReproducibilityHarness struct {
	config       *ReproducibilityConfig
	triageEngine *CrashTriageEngine
	executor     interfaces.Executor
	logger       *logrus.Logger
	results      map[string]*ReproducibilityResult // Cache results by crash hash
}

// ReproducibilityConfig configures the reproducibility harness
type ReproducibilityConfig struct {
	MaxReproductionAttempts int           // Maximum attempts to reproduce crash
	ReproductionTimeout     time.Duration // Timeout per reproduction attempt
	MinimalTestCaseSize     int           // Target size for minimal test cases
	EnableRootCauseAnalysis bool          // Enable automated root cause analysis
	EnableExploitability    bool          // Enable exploitability assessment
	EnableProofOfConcept    bool          // Generate proof of concept exploits
	OutputDirectory         string        // Directory for reproduction reports
	DetailedLogging         bool          // Enable detailed reproduction logging
}

// NewReproducibilityHarness creates a new reproducibility harness
func NewReproducibilityHarness(config *ReproducibilityConfig) *ReproducibilityHarness {
	if config == nil {
		config = &ReproducibilityConfig{
			MaxReproductionAttempts: 10,
			ReproductionTimeout:     30 * time.Second,
			MinimalTestCaseSize:     1024,
			EnableRootCauseAnalysis: true,
			EnableExploitability:    true,
			EnableProofOfConcept:    false, // Disabled by default for safety
			OutputDirectory:         "./reproductions",
			DetailedLogging:         true,
		}
	}

	return &ReproducibilityHarness{
		config:       config,
		triageEngine: NewCrashTriageEngine(),
		results:      make(map[string]*ReproducibilityResult),
	}
}

// SetExecutor sets the executor for reproduction attempts
func (h *ReproducibilityHarness) SetExecutor(executor interfaces.Executor) {
	h.executor = executor
}

// SetLogger sets the logger for detailed reproduction logging
func (h *ReproducibilityHarness) SetLogger(logger *logrus.Logger) {
	h.logger = logger
}

// AnalyzeCrash performs comprehensive crash reproduction and analysis
func (h *ReproducibilityHarness) AnalyzeCrash(
	testCase *interfaces.TestCase,
	originalResult *interfaces.ExecutionResult,
) (*ReproducibilityResult, error) {
	startTime := time.Now()

	// Create crash hash for caching
	crashHash := h.calculateCrashHash(originalResult)
	if cached, exists := h.results[crashHash]; exists {
		return cached, nil
	}

	result := &ReproducibilityResult{
		CrashInfo:            originalResult.CrashInfo,
		Reproducible:         false,
		ReproductionRate:     0.0,
		ReproductionAttempts: 0,
		StackTraces:          make([]string, 0),
		Metadata:             make(map[string]interface{}),
	}

	// Perform crash triage first
	triage := h.triageEngine.TriageCrash(originalResult.CrashInfo, originalResult)
	result.Metadata["triage"] = triage

	// Attempt to reproduce the crash
	h.attemptReproduction(testCase, originalResult, result)

	// Generate minimal test case if reproducible
	if result.Reproducible {
		h.generateMinimalTestCase(testCase, originalResult, result)
	}

	// Perform root cause analysis if enabled
	if h.config.EnableRootCauseAnalysis {
		result.RootCauseAnalysis = h.analyzeRootCause(result, triage)
	}

	// Perform exploitability assessment if enabled
	if h.config.EnableExploitability {
		result.Exploitability = h.assessExploitability(result, triage)
	}

	// Generate proof of concept if enabled and appropriate
	if h.config.EnableProofOfConcept && result.Exploitability != nil {
		if result.Exploitability.Exploitability == ExploitabilityHigh ||
			result.Exploitability.Exploitability == ExploitabilityConfirmed {
			result.Exploitability.ProofOfConcept = h.generateProofOfConcept(result)
		}
	}

	result.ReproductionTime = time.Since(startTime)

	// Save detailed report
	h.saveReproductionReport(result)

	// Cache result
	h.results[crashHash] = result

	return result, nil
}

// attemptReproduction attempts to reproduce the crash multiple times
func (h *ReproducibilityHarness) attemptReproduction(
	testCase *interfaces.TestCase,
	originalResult *interfaces.ExecutionResult,
	result *ReproducibilityResult,
) {
	successfulReproductions := 0
	originalCrashHash := h.calculateCrashHash(originalResult)

	for attempt := 1; attempt <= h.config.MaxReproductionAttempts; attempt++ {
		if h.logger != nil && h.config.DetailedLogging {
			h.logger.Infof("Reproduction attempt %d/%d", attempt, h.config.MaxReproductionAttempts)
		}

		// Execute the test case
		reproductionResult, err := h.executor.Execute(testCase)
		if err != nil {
			if h.logger != nil {
				h.logger.Warnf("Reproduction attempt %d failed: %v", attempt, err)
			}
			continue
		}

		// Check if it reproduced the same crash
		reproductionHash := h.calculateCrashHash(reproductionResult)
		if reproductionHash == originalCrashHash {
			successfulReproductions++
			if h.logger != nil && h.config.DetailedLogging {
				h.logger.Infof("Reproduction attempt %d successful", attempt)
			}
		}

		// Collect stack trace if available
		if reproductionResult.CrashInfo != nil && len(reproductionResult.CrashInfo.StackTrace) > 0 {
			stackTrace := strings.Join(reproductionResult.CrashInfo.StackTrace, "\n")
			if !h.containsStackTrace(result.StackTraces, stackTrace) {
				result.StackTraces = append(result.StackTraces, stackTrace)
			}
		}

		result.ReproductionAttempts++
	}

	// Calculate reproduction rate
	result.ReproductionRate = float64(successfulReproductions) / float64(h.config.MaxReproductionAttempts)
	result.Reproducible = result.ReproductionRate > 0.5 // Consider reproducible if >50% success rate

	if h.logger != nil {
		h.logger.Infof("Crash reproduction: %d/%d successful (%.1f%%)",
			successfulReproductions, h.config.MaxReproductionAttempts, result.ReproductionRate*100)
	}
}

// generateMinimalTestCase creates the smallest test case that still reproduces the crash
func (h *ReproducibilityHarness) generateMinimalTestCase(
	testCase *interfaces.TestCase,
	originalResult *interfaces.ExecutionResult,
	result *ReproducibilityResult,
) {
	if h.logger != nil {
		h.logger.Info("Generating minimal test case...")
	}

	// Use the crash minimizer to reduce the test case
	minimized, err := h.triageEngine.MinimizeCrash(testCase, originalResult)
	if err != nil {
		if h.logger != nil {
			h.logger.Warnf("Failed to minimize test case: %v", err)
		}
		result.MinimalTestCase = testCase // Use original if minimization fails
		return
	}

	// Verify the minimized test case still reproduces the crash
	verificationResult, err := h.executor.Execute(minimized)
	if err == nil && h.calculateCrashHash(verificationResult) == h.calculateCrashHash(originalResult) {
		result.MinimalTestCase = minimized
		if h.logger != nil {
			h.logger.Infof("Minimal test case generated: %d bytes (reduced from %d bytes)",
				len(minimized.Data), len(testCase.Data))
		}
	} else {
		result.MinimalTestCase = testCase // Use original if verification fails
		if h.logger != nil {
			h.logger.Warn("Minimized test case failed verification, using original")
		}
	}
}

// analyzeRootCause performs automated root cause analysis
func (h *ReproducibilityHarness) analyzeRootCause(
	result *ReproducibilityResult,
	triage *TriageResult,
) *RootCauseAnalysis {
	analysis := &RootCauseAnalysis{
		PrimaryCause:    "unknown",
		SecondaryCauses: make([]string, 0),
		Confidence:      0.5,
		Evidence:        make([]string, 0),
		Recommendations: make([]string, 0),
		Metadata:        make(map[string]interface{}),
	}

	// Analyze based on crash type
	switch triage.CrashType {
	case CrashTypeBufferOverflow:
		analysis.PrimaryCause = "buffer overflow"
		analysis.Confidence = 0.9
		analysis.Evidence = append(analysis.Evidence, "Crash type indicates memory corruption")
		analysis.Recommendations = append(analysis.Recommendations,
			"Add bounds checking", "Use safe string functions", "Validate input sizes")
		analysis.CVSSScore = &CVSSScore{
			BaseScore: 8.1,
			Vector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			Severity:  "HIGH",
		}

	case CrashTypeUseAfterFree:
		analysis.PrimaryCause = "use after free"
		analysis.Confidence = 0.85
		analysis.Evidence = append(analysis.Evidence, "Crash type indicates memory management error")
		analysis.Recommendations = append(analysis.Recommendations,
			"Use smart pointers", "Implement proper cleanup", "Add memory tracking")
		analysis.CVSSScore = &CVSSScore{
			BaseScore: 7.5,
			Vector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			Severity:  "HIGH",
		}

	case CrashTypeNullPointer:
		analysis.PrimaryCause = "null pointer dereference"
		analysis.Confidence = 0.8
		analysis.Evidence = append(analysis.Evidence, "Crash type indicates null pointer access")
		analysis.Recommendations = append(analysis.Recommendations,
			"Add null checks", "Initialize pointers", "Use defensive programming")
		analysis.CVSSScore = &CVSSScore{
			BaseScore: 5.3,
			Vector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
			Severity:  "MEDIUM",
		}

	case CrashTypeSegfault:
		analysis.PrimaryCause = "segmentation fault"
		analysis.Confidence = 0.7
		analysis.Evidence = append(analysis.Evidence, "Crash type indicates memory access violation")
		analysis.Recommendations = append(analysis.Recommendations,
			"Check memory bounds", "Validate pointers", "Use memory sanitizers")
		analysis.CVSSScore = &CVSSScore{
			BaseScore: 6.5,
			Vector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
			Severity:  "MEDIUM",
		}
	}

	// Analyze exploitability
	if triage.Exploitability == ExploitabilityHigh || triage.Exploitability == ExploitabilityConfirmed {
		analysis.SecondaryCauses = append(analysis.SecondaryCauses, "highly exploitable")
		analysis.Confidence += 0.1
	}

	// Analyze based on stack traces
	if len(result.StackTraces) > 0 {
		analysis.Evidence = append(analysis.Evidence, fmt.Sprintf("Collected %d stack traces", len(result.StackTraces)))
	}

	// Cap confidence at 1.0
	if analysis.Confidence > 1.0 {
		analysis.Confidence = 1.0
	}

	return analysis
}

// assessExploitability provides detailed exploitability assessment
func (h *ReproducibilityHarness) assessExploitability(
	result *ReproducibilityResult,
	triage *TriageResult,
) *ExploitabilityReport {
	report := &ExploitabilityReport{
		Exploitability:  triage.Exploitability,
		AttackVector:    "network",
		Complexity:      "low",
		Privileges:      "none",
		UserInteraction: "none",
		Scope:           "unchanged",
		Confidence:      triage.Confidence,
		Metadata:        make(map[string]interface{}),
	}

	// Refine assessment based on crash type and reproduction rate
	switch triage.CrashType {
	case CrashTypeBufferOverflow:
		if result.ReproductionRate > 0.8 {
			report.Complexity = "low"
			report.AttackVector = "network"
		} else {
			report.Complexity = "medium"
		}
		report.Metadata["overflow_type"] = "stack_or_heap"

	case CrashTypeUseAfterFree:
		report.Complexity = "medium"
		report.Metadata["memory_management"] = "use_after_free"

	case CrashTypeNullPointer:
		report.Complexity = "high"
		report.AttackVector = "local"
		report.Metadata["null_pointer_type"] = "dereference"
	}

	// Adjust based on reproduction rate
	if result.ReproductionRate < 0.5 {
		report.Complexity = "high"
		report.Confidence *= 0.8
	}

	return report
}

// generateProofOfConcept creates a proof of concept exploit
func (h *ReproducibilityHarness) generateProofOfConcept(
	result *ReproducibilityResult,
) *ProofOfConcept {
	poc := &ProofOfConcept{
		Code:         "// Proof of Concept Exploit\n// WARNING: Use only in controlled environment\n\n",
		Description:  "Generated proof of concept for vulnerability analysis",
		Requirements: []string{"Controlled test environment", "Target binary", "Debugger"},
		SuccessRate:  result.ReproductionRate,
		RiskLevel:    "HIGH",
		Metadata:     make(map[string]interface{}),
	}

	// Generate basic PoC code based on crash type
	if result.RootCauseAnalysis != nil {
		switch result.RootCauseAnalysis.PrimaryCause {
		case "buffer overflow":
			poc.Code += `#include <stdio.h>
#include <string.h>

int main() {
    char buffer[64];
    char exploit[128];
    
    // Create exploit payload
    memset(exploit, 'A', sizeof(exploit));
    
    // Trigger buffer overflow
    strcpy(buffer, exploit);
    
    return 0;
}`
			poc.Description = "Buffer overflow proof of concept - demonstrates memory corruption"

		case "null pointer dereference":
			poc.Code += `#include <stdio.h>

int main() {
    int* ptr = NULL;
    
    // Trigger null pointer dereference
    *ptr = 42;
    
    return 0;
}`
			poc.Description = "Null pointer dereference proof of concept"

		default:
			poc.Code += `// Generic proof of concept
// Use the minimal test case data to reproduce the crash
// Target: [TARGET_BINARY]
// Input: [MINIMAL_TEST_CASE_DATA]`
			poc.Description = "Generic proof of concept using minimal test case"
		}
	}

	return poc
}

// saveReproductionReport saves a detailed reproduction report
func (h *ReproducibilityHarness) saveReproductionReport(result *ReproducibilityResult) {
	if h.config.OutputDirectory == "" {
		return
	}

	// Create output directory
	if err := os.MkdirAll(h.config.OutputDirectory, 0755); err != nil {
		if h.logger != nil {
			h.logger.Errorf("Failed to create output directory: %v", err)
		}
		return
	}

	// Create report filename
	timestamp := time.Now().Format("20060102_150405")
	filename := fmt.Sprintf("reproduction_%s_%s.json", timestamp, result.CrashInfo.Hash)
	filepath := filepath.Join(h.config.OutputDirectory, filename)

	// Marshal report to JSON
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		if h.logger != nil {
			h.logger.Errorf("Failed to marshal reproduction report: %v", err)
		}
		return
	}

	// Write report
	if err := os.WriteFile(filepath, data, 0644); err != nil {
		if h.logger != nil {
			h.logger.Errorf("Failed to write reproduction report: %v", err)
		}
		return
	}

	if h.logger != nil {
		h.logger.Infof("Reproduction report saved: %s", filepath)
	}
}

// calculateCrashHash creates a hash for crash deduplication
func (h *ReproducibilityHarness) calculateCrashHash(result *interfaces.ExecutionResult) string {
	hash := sha256.New()
	hash.Write([]byte(fmt.Sprintf("%d", result.Signal)))
	hash.Write([]byte(fmt.Sprintf("%d", result.ExitCode)))
	hash.Write(result.Output)
	hash.Write(result.Error)
	return hex.EncodeToString(hash.Sum(nil))[:16]
}

// containsStackTrace checks if a stack trace is already in the collection
func (h *ReproducibilityHarness) containsStackTrace(traces []string, newTrace string) bool {
	for _, trace := range traces {
		if trace == newTrace {
			return true
		}
	}
	return false
}

// GetReproductionStats returns statistics about reproduction attempts
func (h *ReproducibilityHarness) GetReproductionStats() map[string]interface{} {
	totalCrashes := len(h.results)
	reproducibleCrashes := 0
	totalAttempts := 0
	avgReproductionRate := 0.0

	for _, result := range h.results {
		if result.Reproducible {
			reproducibleCrashes++
		}
		totalAttempts += result.ReproductionAttempts
		avgReproductionRate += result.ReproductionRate
	}

	if totalCrashes > 0 {
		avgReproductionRate /= float64(totalCrashes)
	}

	return map[string]interface{}{
		"total_crashes":          totalCrashes,
		"reproducible_crashes":   reproducibleCrashes,
		"reproduction_rate":      float64(reproducibleCrashes) / float64(totalCrashes),
		"total_attempts":         totalAttempts,
		"avg_reproduction_rate":  avgReproductionRate,
		"avg_attempts_per_crash": float64(totalAttempts) / float64(totalCrashes),
	}
}
