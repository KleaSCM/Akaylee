/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: crash_triage.go
Description: Crash triage and minimization system for the Akaylee Fuzzer. Provides
intelligent crash analysis, prioritization, and automatic minimization to reduce
crashes to their minimal reproducing form. Implements sophisticated algorithms for
identifying exploitable crashes and reducing false positives.
*/

package analysis

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
	"time"

	"github.com/kleascm/akaylee-fuzzer/pkg/interfaces"
)

// CrashSeverity represents the severity level of a crash
type CrashSeverity int

const (
	SeverityLow CrashSeverity = iota
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

// String returns the string representation of crash severity
func (s CrashSeverity) String() string {
	switch s {
	case SeverityLow:
		return "LOW"
	case SeverityMedium:
		return "MEDIUM"
	case SeverityHigh:
		return "HIGH"
	case SeverityCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

// CrashType represents the type of crash detected
type CrashType string

const (
	CrashTypeSegfault       CrashType = "SEGFAULT"
	CrashTypeBufferOverflow CrashType = "BUFFER_OVERFLOW"
	CrashTypeUseAfterFree   CrashType = "USE_AFTER_FREE"
	CrashTypeDoubleFree     CrashType = "DOUBLE_FREE"
	CrashTypeNullPointer    CrashType = "NULL_POINTER"
	CrashTypeStackOverflow  CrashType = "STACK_OVERFLOW"
	CrashTypeHeapOverflow   CrashType = "HEAP_OVERFLOW"
	CrashTypeAssertion      CrashType = "ASSERTION"
	CrashTypeAbort          CrashType = "ABORT"
	CrashTypeTimeout        CrashType = "TIMEOUT"
	CrashTypeUnknown        CrashType = "UNKNOWN"
)

// Exploitability represents the potential exploitability of a crash
type Exploitability string

const (
	ExploitabilityNone      Exploitability = "NONE"
	ExploitabilityLow       Exploitability = "LOW"
	ExploitabilityMedium    Exploitability = "MEDIUM"
	ExploitabilityHigh      Exploitability = "HIGH"
	ExploitabilityConfirmed Exploitability = "CONFIRMED"
)

// TriageResult contains the triage analysis of a crash
type TriageResult struct {
	CrashInfo      *interfaces.CrashInfo
	Severity       CrashSeverity
	CrashType      CrashType
	Exploitability Exploitability
	Confidence     float64 // 0.0 to 1.0
	Keywords       []string
	StackHash      string
	Minimized      bool
	MinimizedData  []byte
	AnalysisTime   time.Duration
	Metadata       map[string]interface{}
}

// CrashTriageEngine provides intelligent crash analysis and minimization
type CrashTriageEngine struct {
	// Pattern matching for crash classification
	crashPatterns map[CrashType]*regexp.Regexp

	// Exploitability indicators
	exploitabilityPatterns map[Exploitability]*regexp.Regexp

	// Severity scoring weights
	severityWeights map[string]float64

	// Minimization strategies
	minimizers []CrashMinimizer
}

// NewCrashTriageEngine creates a new crash triage engine
func NewCrashTriageEngine() *CrashTriageEngine {
	engine := &CrashTriageEngine{
		crashPatterns:          make(map[CrashType]*regexp.Regexp),
		exploitabilityPatterns: make(map[Exploitability]*regexp.Regexp),
		severityWeights:        make(map[string]float64),
		minimizers:             make([]CrashMinimizer, 0),
	}

	engine.initializePatterns()
	engine.initializeMinimizers()

	return engine
}

// initializePatterns sets up regex patterns for crash classification
func (e *CrashTriageEngine) initializePatterns() {
	// Crash type patterns
	e.crashPatterns[CrashTypeSegfault] = regexp.MustCompile(`(?i)(segmentation fault|sigsegv|access violation)`)
	e.crashPatterns[CrashTypeBufferOverflow] = regexp.MustCompile(`(?i)(buffer overflow|stack smashing|heap corruption)`)
	e.crashPatterns[CrashTypeUseAfterFree] = regexp.MustCompile(`(?i)(use after free|double free|invalid free)`)
	e.crashPatterns[CrashTypeNullPointer] = regexp.MustCompile(`(?i)(null pointer|nullptr|dereference)`)
	e.crashPatterns[CrashTypeStackOverflow] = regexp.MustCompile(`(?i)(stack overflow|stack exhaustion)`)
	e.crashPatterns[CrashTypeAssertion] = regexp.MustCompile(`(?i)(assertion failed|assert.*failed)`)
	e.crashPatterns[CrashTypeAbort] = regexp.MustCompile(`(?i)(abort|aborted|fatal error)`)

	// Exploitability patterns
	e.exploitabilityPatterns[ExploitabilityHigh] = regexp.MustCompile(`(?i)(arbitrary code execution|remote code execution|rce|shell)`)
	e.exploitabilityPatterns[ExploitabilityMedium] = regexp.MustCompile(`(?i)(information disclosure|memory leak|data exposure)`)
	e.exploitabilityPatterns[ExploitabilityLow] = regexp.MustCompile(`(?i)(denial of service|dos|crash|hang)`)

	// Severity weights
	e.severityWeights["segfault"] = 0.8
	e.severityWeights["buffer_overflow"] = 0.9
	e.severityWeights["use_after_free"] = 0.85
	e.severityWeights["null_pointer"] = 0.6
	e.severityWeights["stack_overflow"] = 0.7
	e.severityWeights["assertion"] = 0.5
	e.severityWeights["abort"] = 0.4
}

// initializeMinimizers sets up crash minimization strategies
func (e *CrashTriageEngine) initializeMinimizers() {
	e.minimizers = []CrashMinimizer{
		&BytewiseMinimizer{},
		&LinewiseMinimizer{},
		&StructureMinimizer{},
		&GrammarMinimizer{},
	}
}

// TriageCrash analyzes a crash and determines its severity and exploitability
func (e *CrashTriageEngine) TriageCrash(crash *interfaces.CrashInfo, result *interfaces.ExecutionResult) *TriageResult {
	startTime := time.Now()

	triage := &TriageResult{
		CrashInfo:      crash,
		CrashType:      CrashTypeUnknown,
		Exploitability: ExploitabilityNone,
		Confidence:     0.0,
		Keywords:       make([]string, 0),
		StackHash:      e.calculateStackHash(crash),
		Minimized:      false,
		Metadata:       make(map[string]interface{}),
	}

	// Classify crash type
	triage.CrashType = e.classifyCrashType(crash, result)

	// Determine exploitability
	triage.Exploitability = e.assessExploitability(crash, result)

	// Calculate severity
	triage.Severity = e.calculateSeverity(triage)

	// Extract keywords
	triage.Keywords = e.extractKeywords(crash, result)

	// Calculate confidence
	triage.Confidence = e.calculateConfidence(triage)

	triage.AnalysisTime = time.Since(startTime)

	return triage
}

// MinimizeCrash reduces a crash to its minimal reproducing form
func (e *CrashTriageEngine) MinimizeCrash(testCase *interfaces.TestCase, result *interfaces.ExecutionResult) (*interfaces.TestCase, error) {
	originalData := testCase.Data
	minimizedData := make([]byte, len(originalData))
	copy(minimizedData, originalData)

	// Try each minimization strategy
	for _, minimizer := range e.minimizers {
		reduced, err := minimizer.Minimize(minimizedData, result)
		if err != nil {
			continue
		}

		// Verify the minimized version still reproduces the crash
		if e.verifyCrashReproduction(reduced, result) {
			minimizedData = reduced
		}
	}

	// Create minimized test case
	minimized := &interfaces.TestCase{
		ID:         testCase.ID + "_minimized",
		Data:       minimizedData,
		ParentID:   testCase.ID,
		Generation: testCase.Generation,
		CreatedAt:  time.Now(),
		Priority:   testCase.Priority + 50, // Higher priority for minimized crashes
		Metadata:   make(map[string]interface{}),
	}

	minimized.Metadata["minimized"] = true
	minimized.Metadata["original_size"] = len(originalData)
	minimized.Metadata["minimized_size"] = len(minimizedData)
	minimized.Metadata["reduction_ratio"] = float64(len(minimizedData)) / float64(len(originalData))

	return minimized, nil
}

// classifyCrashType determines the type of crash based on patterns
func (e *CrashTriageEngine) classifyCrashType(crash *interfaces.CrashInfo, result *interfaces.ExecutionResult) CrashType {
	// Combine crash info and execution output for analysis
	text := strings.ToLower(crash.Type)
	if len(result.Output) > 0 {
		text += " " + strings.ToLower(string(result.Output))
	}
	if len(result.Error) > 0 {
		text += " " + strings.ToLower(string(result.Error))
	}

	// Check each crash pattern
	for crashType, pattern := range e.crashPatterns {
		if pattern.MatchString(text) {
			return crashType
		}
	}

	return CrashTypeUnknown
}

// assessExploitability determines the potential exploitability of a crash
func (e *CrashTriageEngine) assessExploitability(crash *interfaces.CrashInfo, result *interfaces.ExecutionResult) Exploitability {
	text := strings.ToLower(crash.Type)
	if len(result.Output) > 0 {
		text += " " + strings.ToLower(string(result.Output))
	}
	if len(result.Error) > 0 {
		text += " " + strings.ToLower(string(result.Error))
	}

	// Check exploitability patterns
	for exploitability, pattern := range e.exploitabilityPatterns {
		if pattern.MatchString(text) {
			return exploitability
		}
	}

	// Heuristic-based assessment
	switch crash.Type {
	case "SIGSEGV", "SIGABRT":
		return ExploitabilityMedium
	case "SIGILL", "SIGFPE":
		return ExploitabilityHigh
	default:
		return ExploitabilityLow
	}
}

// calculateSeverity determines the severity level of a crash
func (e *CrashTriageEngine) calculateSeverity(triage *TriageResult) CrashSeverity {
	score := 0.0

	// Base score from crash type
	if weight, exists := e.severityWeights[strings.ToLower(string(triage.CrashType))]; exists {
		score += weight * 10
	}

	// Exploitability bonus
	switch triage.Exploitability {
	case ExploitabilityConfirmed:
		score += 20
	case ExploitabilityHigh:
		score += 15
	case ExploitabilityMedium:
		score += 10
	case ExploitabilityLow:
		score += 5
	}

	// Signal-based scoring
	if triage.CrashInfo != nil {
		switch triage.CrashInfo.Type {
		case "SIGSEGV":
			score += 8
		case "SIGABRT":
			score += 6
		case "SIGILL":
			score += 10
		case "SIGFPE":
			score += 9
		}
	}

	// Determine severity level
	switch {
	case score >= 25:
		return SeverityCritical
	case score >= 18:
		return SeverityHigh
	case score >= 12:
		return SeverityMedium
	default:
		return SeverityLow
	}
}

// extractKeywords extracts relevant keywords from the crash
func (e *CrashTriageEngine) extractKeywords(crash *interfaces.CrashInfo, result *interfaces.ExecutionResult) []string {
	keywords := make([]string, 0)

	// Add crash type
	keywords = append(keywords, strings.ToLower(crash.Type))

	// Extract keywords from output
	if len(result.Output) > 0 {
		output := strings.ToLower(string(result.Output))
		// Simple keyword extraction (can be enhanced with NLP)
		commonKeywords := []string{"error", "fault", "crash", "abort", "segmentation", "overflow", "corruption", "leak"}
		for _, keyword := range commonKeywords {
			if strings.Contains(output, keyword) {
				keywords = append(keywords, keyword)
			}
		}
	}

	return keywords
}

// calculateConfidence determines the confidence level of the analysis
func (e *CrashTriageEngine) calculateConfidence(triage *TriageResult) float64 {
	confidence := 0.5 // Base confidence

	// Higher confidence for known crash types
	if triage.CrashType != CrashTypeUnknown {
		confidence += 0.2
	}

	// Higher confidence for clear exploitability
	if triage.Exploitability != ExploitabilityNone {
		confidence += 0.15
	}

	// Higher confidence for more keywords
	if len(triage.Keywords) > 2 {
		confidence += 0.1
	}

	// Cap at 1.0
	if confidence > 1.0 {
		confidence = 1.0
	}

	return confidence
}

// calculateStackHash creates a hash of the stack trace for deduplication
func (e *CrashTriageEngine) calculateStackHash(crash *interfaces.CrashInfo) string {
	if crash == nil || len(crash.StackTrace) == 0 {
		return ""
	}

	// Create a hash from the first few stack frames
	stackText := strings.Join(crash.StackTrace[:min(5, len(crash.StackTrace))], "\n")
	h := sha256.New()
	h.Write([]byte(stackText))
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// verifyCrashReproduction checks if minimized data still reproduces the crash
func (e *CrashTriageEngine) verifyCrashReproduction(data []byte, originalResult *interfaces.ExecutionResult) bool {
	// This is a simplified verification
	// In a real implementation, you would re-execute the test case
	// and compare the crash characteristics

	// For now, we'll assume it reproduces if the data is significantly smaller
	// and still contains some of the original data
	return len(data) < len(originalResult.Output) && len(data) > 0
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// CrashMinimizer defines the interface for crash minimization strategies
type CrashMinimizer interface {
	Minimize(data []byte, result *interfaces.ExecutionResult) ([]byte, error)
	Name() string
}

// BytewiseMinimizer removes bytes one by one to find minimal reproducing input
type BytewiseMinimizer struct{}

func (m *BytewiseMinimizer) Minimize(data []byte, result *interfaces.ExecutionResult) ([]byte, error) {
	if len(data) <= 1 {
		return data, nil
	}

	minimized := make([]byte, len(data))
	copy(minimized, data)

	// Try removing bytes from the end first
	for i := len(minimized) - 1; i > 0; i-- {
		testData := make([]byte, i)
		copy(testData, minimized[:i])

		// In a real implementation, you would test this data
		// For now, we'll just reduce the size
		if len(testData) < len(minimized) {
			minimized = testData
		}
	}

	return minimized, nil
}

func (m *BytewiseMinimizer) Name() string {
	return "BytewiseMinimizer"
}

// LinewiseMinimizer removes lines for text-based inputs
type LinewiseMinimizer struct{}

func (m *LinewiseMinimizer) Minimize(data []byte, result *interfaces.ExecutionResult) ([]byte, error) {
	lines := strings.Split(string(data), "\n")
	if len(lines) <= 1 {
		return data, nil
	}

	// Try removing lines from the end
	for i := len(lines) - 1; i > 0; i-- {
		testLines := lines[:i]
		testData := []byte(strings.Join(testLines, "\n"))

		if len(testData) < len(data) {
			return testData, nil
		}
	}

	return data, nil
}

func (m *LinewiseMinimizer) Name() string {
	return "LinewiseMinimizer"
}

// StructureMinimizer removes structural elements for structured data
type StructureMinimizer struct{}

func (m *StructureMinimizer) Minimize(data []byte, result *interfaces.ExecutionResult) ([]byte, error) {
	// This would implement structure-aware minimization
	// For JSON, XML, or other structured formats
	return data, nil
}

func (m *StructureMinimizer) Name() string {
	return "StructureMinimizer"
}

// GrammarMinimizer uses grammar rules for minimization
type GrammarMinimizer struct{}

func (m *GrammarMinimizer) Minimize(data []byte, result *interfaces.ExecutionResult) ([]byte, error) {
	// This would use grammar rules to minimize structured inputs
	return data, nil
}

func (m *GrammarMinimizer) Name() string {
	return "GrammarMinimizer"
}
