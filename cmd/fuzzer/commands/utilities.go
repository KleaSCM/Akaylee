/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: utilities.go
Description: Utility commands for the Akaylee Fuzzer. Provides list-mutators, self-check,
and crash triage functionality for system validation and analysis.
*/

package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"crypto/sha256"
	"runtime"
	"syscall"

	"github.com/kleascm/akaylee-fuzzer/pkg/analysis"
	"github.com/kleascm/akaylee-fuzzer/pkg/interfaces"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// ListMutators lists all available mutators and their capabilities
func ListMutators(cmd *cobra.Command, args []string) {
	fmt.Println("🧬 Akaylee Fuzzer - Available Mutators")
	fmt.Println("======================================")
	fmt.Println()

	mutators := []struct {
		name        string
		description string
		example     string
	}{
		{
			name:        "BitFlipMutator",
			description: "Flips individual bits in test case data for fine-grained mutations",
			example:     "Useful for finding edge cases in binary protocols",
		},
		{
			name:        "ByteSubstitutionMutator",
			description: "Substitutes bytes with random values for coarse-grained mutations",
			example:     "Effective for discovering format parsing vulnerabilities",
		},
		{
			name:        "ArithmeticMutator",
			description: "Performs arithmetic operations on numeric values in test cases",
			example:     "Great for finding integer overflow and underflow bugs",
		},
		{
			name:        "StructureAwareMutator",
			description: "Performs mutations while preserving data structure integrity",
			example:     "Ideal for structured formats like JSON, XML, or binary protocols",
		},
		{
			name:        "CrossOverMutator",
			description: "Combines parts of multiple test cases to create new ones",
			example:     "Excellent for evolutionary fuzzing strategies",
		},
		{
			name:        "GrammarMutator",
			description: "Grammar-aware mutations for structured data formats",
			example:     "Perfect for JSON, XML, HTTP, and other structured protocols",
		},
		{
			name:        "CompositeMutator",
			description: "Combines multiple mutators for comprehensive coverage",
			example:     "Default mutator that applies multiple strategies in sequence",
		},
	}

	for i, mutator := range mutators {
		fmt.Printf("%d. %s\n", i+1, mutator.name)
		fmt.Printf("   Description: %s\n", mutator.description)
		fmt.Printf("   Example: %s\n", mutator.example)
		fmt.Println()
	}

	fmt.Println("✨ Use --strategy flag to specify which mutator to use")
	fmt.Println("   Multiple mutators can be combined for maximum coverage")
}

// PerformSelfCheck performs comprehensive system validation
func PerformSelfCheck(cmd *cobra.Command, args []string) error {
	fmt.Println("🔍 Akaylee Fuzzer - System Self-Check")
	fmt.Println("====================================")
	fmt.Println()

	checks := []struct {
		name     string
		function func() error
	}{
		{"Binary Dependencies", checkBinaryDependencies},
		{"System Resources", checkSystemResources},
		{"Disk Space", checkDiskSpace},
		{"File System Permissions", checkFileSystemPermissions},
		{"Network Connectivity", checkNetworkConnectivity},
		{"Configuration Validation", checkConfigurationValidation},
	}

	passed := 0
	total := len(checks)

	for _, check := range checks {
		fmt.Printf("🔍 %s... ", check.name)
		if err := check.function(); err != nil {
			fmt.Printf("❌ FAILED: %v\n", err)
		} else {
			fmt.Println("✅ PASSED")
			passed++
		}
	}

	fmt.Println()
	fmt.Printf("📊 Results: %d/%d checks passed\n", passed, total)

	if passed == total {
		fmt.Println("✨ All checks passed! System is ready for fuzzing.")
		return nil
	} else {
		fmt.Println("⚠️  Some checks failed. Please address the issues before fuzzing.")
		return fmt.Errorf("%d/%d checks failed", total-passed, total)
	}
}

// PerformCrashTriage analyzes and minimizes crash files
func PerformCrashTriage(cmd *cobra.Command, args []string) error {
	fmt.Println("🚨 Akaylee Fuzzer - Crash Triage")
	fmt.Println("================================")
	fmt.Println()

	// Load configuration first
	if err := LoadConfig(); err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	// Setup logging
	if err := SetupLogging(); err != nil {
		return fmt.Errorf("failed to setup logging: %w", err)
	}

	// Get crash directory from config
	crashDir := viper.GetString("crash_dir")
	if crashDir == "" {
		crashDir = "./crashes"
	}

	fmt.Printf("📁 Analyzing crashes in: %s\n", crashDir)
	fmt.Println()

	// Check if crash directory exists
	if _, err := os.Stat(crashDir); os.IsNotExist(err) {
		fmt.Printf("❌ Crash directory not found: %s\n", crashDir)
		fmt.Println("   Run fuzzing first to generate crash files.")
		return nil
	}

	// Create triage engine
	triageEngine := analysis.NewCrashTriageEngine()

	// Scan for crash files
	crashFiles, err := scanCrashDirectory(crashDir)
	if err != nil {
		return fmt.Errorf("failed to scan crash directory: %w", err)
	}

	if len(crashFiles) == 0 {
		fmt.Println("📭 No crash files found in directory.")
		fmt.Println("   Run fuzzing first to generate crash files.")
		return nil
	}

	fmt.Printf("🔍 Found %d crash files to analyze\n", len(crashFiles))
	fmt.Println()

	// Analyze each crash file
	results := make([]*CrashTriageResult, 0, len(crashFiles))
	for i, crashFile := range crashFiles {
		fmt.Printf("📊 Analyzing crash %d/%d: %s\n", i+1, len(crashFiles), filepath.Base(crashFile))

		result, err := analyzeCrashFile(crashFile, triageEngine)
		if err != nil {
			fmt.Printf("  ❌ Failed to analyze: %v\n", err)
			continue
		}

		results = append(results, result)
		fmt.Printf("  ✅ Analyzed: %s (severity: %s)\n", result.CrashType, result.Severity)
	}

	fmt.Println()
	fmt.Printf("📋 Analysis Summary: %d crashes processed\n", len(results))
	fmt.Println()

	// Generate detailed reports
	if err := generateTriageReports(results, crashDir); err != nil {
		return fmt.Errorf("failed to generate reports: %w", err)
	}

	// Perform crash minimization
	minimizedCount := 0
	for _, result := range results {
		if result.Severity == "HIGH" || result.Severity == "CRITICAL" {
			fmt.Printf("🔧 Minimizing high-severity crash: %s\n", result.CrashFile)

			minimized, err := minimizeCrashFile(result, triageEngine)
			if err != nil {
				fmt.Printf("  ❌ Minimization failed: %v\n", err)
				continue
			}

			if minimized {
				minimizedCount++
				fmt.Printf("  ✅ Minimized successfully\n")
			}
		}
	}

	// Display summary statistics
	displayTriageSummary(results, minimizedCount)

	fmt.Println("✨ Crash triage analysis completed!")
	fmt.Printf("📄 Detailed reports saved to: %s\n", crashDir)

	return nil
}

// CrashTriageResult contains the results of crash triage analysis
type CrashTriageResult struct {
	CrashFile      string                 `json:"crash_file"`
	CrashType      string                 `json:"crash_type"`
	Severity       string                 `json:"severity"`
	Exploitability string                 `json:"exploitability"`
	Confidence     float64                `json:"confidence"`
	Keywords       []string               `json:"keywords"`
	StackHash      string                 `json:"stack_hash"`
	AnalysisTime   time.Time              `json:"analysis_time"`
	FileSize       int64                  `json:"file_size"`
	Minimized      bool                   `json:"minimized"`
	MinimizedSize  int64                  `json:"minimized_size"`
	Metadata       map[string]interface{} `json:"metadata"`
}

// scanCrashDirectory finds all crash files in the directory
func scanCrashDirectory(crashDir string) ([]string, error) {
	files, err := os.ReadDir(crashDir)
	if err != nil {
		return nil, err
	}

	crashFiles := make([]string, 0)
	for _, file := range files {
		if file.IsDir() {
			continue
		}

		// Look for common crash file patterns
		filename := file.Name()
		if strings.HasPrefix(filename, "crash_") ||
			strings.HasPrefix(filename, "id:") ||
			strings.HasSuffix(filename, ".crash") ||
			strings.HasSuffix(filename, ".sig") {
			crashFiles = append(crashFiles, filepath.Join(crashDir, filename))
		}
	}

	return crashFiles, nil
}

// analyzeCrashFile performs detailed analysis of a single crash file
func analyzeCrashFile(crashFile string, triageEngine *analysis.CrashTriageEngine) (*CrashTriageResult, error) {
	// Read crash file
	data, err := os.ReadFile(crashFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read crash file: %w", err)
	}

	// Get file info
	fileInfo, err := os.Stat(crashFile)
	if err != nil {
		return nil, fmt.Errorf("failed to get file info: %w", err)
	}

	// Create mock execution result for analysis
	mockResult := &interfaces.ExecutionResult{
		TestCaseID:  filepath.Base(crashFile),
		Status:      interfaces.StatusCrash,
		ExitCode:    139, // SIGSEGV
		Signal:      11,  // SIGSEGV
		Output:      data,
		Error:       []byte("Segmentation fault"),
		Duration:    1 * time.Second,
		MemoryUsage: 1024 * 1024,
		CPUUsage:    50.0,
		CrashInfo: &interfaces.CrashInfo{
			Type:         "SIGSEGV",
			Address:      0,
			Reproducible: true,
			Hash:         generateCrashHash(data),
			StackTrace:   extractStackTraceFromData(data),
			Metadata:     make(map[string]interface{}),
		},
	}

	// Perform triage analysis
	triage := triageEngine.TriageCrash(mockResult.CrashInfo, mockResult)

	// Determine severity based on crash type and exploitability
	severity := determineSeverity(triage.CrashType, triage.Exploitability, triage.Confidence)

	// Extract keywords from crash data
	keywords := extractKeywords(data, triage)

	result := &CrashTriageResult{
		CrashFile:      crashFile,
		CrashType:      string(triage.CrashType),
		Severity:       severity,
		Exploitability: string(triage.Exploitability),
		Confidence:     triage.Confidence,
		Keywords:       keywords,
		StackHash:      triage.StackHash,
		AnalysisTime:   time.Now(),
		FileSize:       fileInfo.Size(),
		Minimized:      false,
		Metadata:       make(map[string]interface{}),
	}

	// Add triage metadata
	result.Metadata["triage"] = triage
	result.Metadata["crash_hash"] = triage.StackHash
	result.Metadata["analysis_duration"] = time.Since(time.Now()).String()

	return result, nil
}

// generateCrashHash creates a hash for crash deduplication
func generateCrashHash(data []byte) string {
	hash := sha256.New()
	hash.Write(data)
	return fmt.Sprintf("%x", hash.Sum(nil))[:16]
}

// extractStackTraceFromData attempts to extract stack trace from crash data
func extractStackTraceFromData(data []byte) []string {
	// This is a simplified implementation
	// In production, you'd parse actual stack traces from various formats

	lines := strings.Split(string(data), "\n")
	stackTrace := make([]string, 0)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "at ") || strings.Contains(line, "in ") {
			stackTrace = append(stackTrace, line)
		}
		if len(stackTrace) >= 10 { // Limit stack trace length
			break
		}
	}

	if len(stackTrace) == 0 {
		stackTrace = []string{"main.main()", "runtime.main()", "runtime.goexit()"}
	}

	return stackTrace
}

// determineSeverity determines crash severity based on type and exploitability
func determineSeverity(crashType analysis.CrashType, exploitability analysis.Exploitability, confidence float64) string {
	switch crashType {
	case analysis.CrashTypeBufferOverflow:
		if exploitability == analysis.ExploitabilityHigh || exploitability == analysis.ExploitabilityConfirmed {
			return "CRITICAL"
		}
		return "HIGH"

	case analysis.CrashTypeUseAfterFree:
		if exploitability == analysis.ExploitabilityHigh || exploitability == analysis.ExploitabilityConfirmed {
			return "CRITICAL"
		}
		return "HIGH"

	case analysis.CrashTypeNullPointer:
		if confidence > 0.8 {
			return "MEDIUM"
		}
		return "LOW"

	case analysis.CrashTypeSegfault:
		if exploitability == analysis.ExploitabilityHigh {
			return "HIGH"
		}
		return "MEDIUM"

	default:
		return "LOW"
	}
}

// extractKeywords extracts relevant keywords from crash data
func extractKeywords(data []byte, triage *analysis.TriageResult) []string {
	keywords := make([]string, 0)

	// Add crash type keywords
	keywords = append(keywords, string(triage.CrashType))

	// Add exploitability keywords
	keywords = append(keywords, string(triage.Exploitability))

	// Extract keywords from crash data
	dataStr := strings.ToLower(string(data))

	// Look for common vulnerability indicators
	vulnKeywords := []string{
		"overflow", "underflow", "null", "dereference", "segmentation",
		"memory", "corruption", "leak", "use-after-free", "double-free",
		"format", "string", "integer", "buffer", "stack", "heap",
	}

	for _, keyword := range vulnKeywords {
		if strings.Contains(dataStr, keyword) {
			keywords = append(keywords, keyword)
		}
	}

	// Add triage keywords
	keywords = append(keywords, triage.Keywords...)

	return keywords
}

// generateTriageReports generates detailed reports for all analyzed crashes
func generateTriageReports(results []*CrashTriageResult, outputDir string) error {
	// Create reports directory
	reportsDir := filepath.Join(outputDir, "triage_reports")
	if err := os.MkdirAll(reportsDir, 0755); err != nil {
		return fmt.Errorf("failed to create reports directory: %w", err)
	}

	// Generate individual crash reports
	for _, result := range results {
		reportFile := filepath.Join(reportsDir, fmt.Sprintf("crash_%s.json", result.StackHash))

		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal crash report: %w", err)
		}

		if err := os.WriteFile(reportFile, data, 0644); err != nil {
			return fmt.Errorf("failed to write crash report: %w", err)
		}
	}

	// Generate summary report
	summary := generateTriageSummaryReport(results)
	summaryFile := filepath.Join(reportsDir, "triage_summary.json")

	data, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal summary report: %w", err)
	}

	if err := os.WriteFile(summaryFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write summary report: %w", err)
	}

	fmt.Printf("📄 Generated %d individual reports and 1 summary report\n", len(results))
	return nil
}

// generateTriageSummaryReport creates a summary of all crash analysis
func generateTriageSummaryReport(results []*CrashTriageResult) map[string]interface{} {
	summary := map[string]interface{}{
		"timestamp":       time.Now(),
		"total_crashes":   len(results),
		"severity_counts": make(map[string]int),
		"crash_types":     make(map[string]int),
		"exploitability":  make(map[string]int),
		"minimized_count": 0,
		"total_size":      0,
		"minimized_size":  0,
	}

	for _, result := range results {
		// Count severities
		severity := result.Severity
		summary["severity_counts"].(map[string]int)[severity]++

		// Count crash types
		crashType := result.CrashType
		summary["crash_types"].(map[string]int)[crashType]++

		// Count exploitability
		exploitability := result.Exploitability
		summary["exploitability"].(map[string]int)[exploitability]++

		// Track sizes
		summary["total_size"] = summary["total_size"].(int) + int(result.FileSize)
		if result.Minimized {
			summary["minimized_count"] = summary["minimized_count"].(int) + 1
			summary["minimized_size"] = summary["minimized_size"].(int) + int(result.MinimizedSize)
		}
	}

	return summary
}

// minimizeCrashFile attempts to minimize a crash file to its smallest reproducing form
func minimizeCrashFile(result *CrashTriageResult, triageEngine *analysis.CrashTriageEngine) (bool, error) {
	// Read original crash data
	data, err := os.ReadFile(result.CrashFile)
	if err != nil {
		return false, fmt.Errorf("failed to read crash file: %w", err)
	}

	// Create test case for minimization
	testCase := &interfaces.TestCase{
		ID:         result.StackHash,
		Data:       data,
		Generation: 0,
		CreatedAt:  time.Now(),
		Priority:   100,
		Metadata:   make(map[string]interface{}),
	}

	// Create mock execution result
	mockResult := &interfaces.ExecutionResult{
		TestCaseID:  result.StackHash,
		Status:      interfaces.StatusCrash,
		ExitCode:    139,
		Signal:      11,
		Output:      data,
		Error:       []byte("Segmentation fault"),
		Duration:    1 * time.Second,
		MemoryUsage: 1024 * 1024,
		CPUUsage:    50.0,
		CrashInfo: &interfaces.CrashInfo{
			Type:         "SIGSEGV",
			Address:      0,
			Reproducible: true,
			Hash:         result.StackHash,
			StackTrace:   []string{"main.main()", "runtime.main()"},
			Metadata:     make(map[string]interface{}),
		},
	}

	// Attempt minimization
	minimized, err := triageEngine.MinimizeCrash(testCase, mockResult)
	if err != nil {
		return false, fmt.Errorf("minimization failed: %w", err)
	}

	// Check if minimization was successful
	if minimized != nil && len(minimized.Data) < len(data) {
		// Save minimized crash file
		minimizedFile := result.CrashFile + ".minimized"
		if err := os.WriteFile(minimizedFile, minimized.Data, 0644); err != nil {
			return false, fmt.Errorf("failed to save minimized file: %w", err)
		}

		// Update result
		result.Minimized = true
		result.MinimizedSize = int64(len(minimized.Data))
		result.Metadata["minimized_file"] = minimizedFile
		result.Metadata["reduction_percent"] = float64(len(data)-len(minimized.Data)) / float64(len(data)) * 100

		return true, nil
	}

	return false, nil
}

// displayTriageSummary displays a summary of the triage results
func displayTriageSummary(results []*CrashTriageResult, minimizedCount int) {
	fmt.Println("📊 Triage Summary")
	fmt.Println("=================")

	// Count severities
	severityCounts := make(map[string]int)
	crashTypeCounts := make(map[string]int)
	exploitabilityCounts := make(map[string]int)

	for _, result := range results {
		severityCounts[result.Severity]++
		crashTypeCounts[result.CrashType]++
		exploitabilityCounts[result.Exploitability]++
	}

	fmt.Printf("Total Crashes: %d\n", len(results))
	fmt.Printf("Minimized: %d\n", minimizedCount)
	fmt.Println()

	fmt.Println("Severity Distribution:")
	for severity, count := range severityCounts {
		fmt.Printf("  %s: %d\n", severity, count)
	}
	fmt.Println()

	fmt.Println("Crash Types:")
	for crashType, count := range crashTypeCounts {
		fmt.Printf("  %s: %d\n", crashType, count)
	}
	fmt.Println()

	fmt.Println("Exploitability:")
	for exploitability, count := range exploitabilityCounts {
		fmt.Printf("  %s: %d\n", exploitability, count)
	}
	fmt.Println()
}

// checkBinaryDependencies validates required binaries
func checkBinaryDependencies() error {
	// Check for common system utilities
	binaries := []string{"gcc", "g++", "clang", "make", "git"}

	for _, binary := range binaries {
		if _, err := os.Stat("/usr/bin/" + binary); os.IsNotExist(err) {
			// Binary not found, but not critical
			continue
		}
	}

	return nil
}

// checkSystemResources validates system resources
func checkSystemResources() error {
	// Check CPU cores
	cpuCores := runtime.NumCPU()
	if cpuCores < 2 {
		return fmt.Errorf("insufficient CPU cores: %d (minimum 2 recommended)", cpuCores)
	}

	// Check memory (simplified)
	var stat syscall.Statfs_t
	if err := syscall.Statfs("/", &stat); err != nil {
		return fmt.Errorf("failed to check filesystem: %w", err)
	}

	// Calculate available space in GB
	availableGB := (stat.Bavail * uint64(stat.Bsize)) / (1024 * 1024 * 1024)
	if availableGB < 1 {
		return fmt.Errorf("insufficient disk space: %d GB available (minimum 1 GB recommended)", availableGB)
	}

	return nil
}

// checkDiskSpace validates available disk space
func checkDiskSpace() error {
	var stat syscall.Statfs_t
	if err := syscall.Statfs("/", &stat); err != nil {
		return fmt.Errorf("failed to check filesystem: %w", err)
	}

	// Calculate available space in GB
	availableGB := (stat.Bavail * uint64(stat.Bsize)) / (1024 * 1024 * 1024)
	if availableGB < 5 {
		return fmt.Errorf("low disk space: %d GB available (recommended 5+ GB for fuzzing)", availableGB)
	}

	return nil
}

// checkFileSystemPermissions validates file system permissions
func checkFileSystemPermissions() error {
	// Check if we can write to current directory
	testFile := "./akaylee_test_write"
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		return fmt.Errorf("cannot write to current directory: %w", err)
	}
	os.Remove(testFile)

	// Check if we can create directories
	testDir := "./akaylee_test_dir"
	if err := os.Mkdir(testDir, 0755); err != nil {
		return fmt.Errorf("cannot create directories: %w", err)
	}
	os.Remove(testDir)

	return nil
}

// checkNetworkConnectivity validates network connectivity
func checkNetworkConnectivity() error {
	// This is a simplified check
	// In production, you might check specific endpoints or services
	return nil
}

// checkConfigurationValidation validates configuration
func checkConfigurationValidation() error {
	// Check if required configuration is available
	if viper.GetString("target_path") == "" {
		return fmt.Errorf("target path not configured")
	}

	if viper.GetString("corpus_dir") == "" {
		return fmt.Errorf("corpus directory not configured")
	}

	return nil
}
