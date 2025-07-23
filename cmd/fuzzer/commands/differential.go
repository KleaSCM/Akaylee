/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: differential.go
Description: CLI command implementation for differential fuzzing. Provides a user-friendly
interface to compare multiple implementations of the same target, detect behavioral
differences, and identify security vulnerabilities through implementation divergence.
*/

package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kleascm/akaylee-fuzzer/pkg/analysis"
	"github.com/kleascm/akaylee-fuzzer/pkg/execution"
	"github.com/kleascm/akaylee-fuzzer/pkg/interfaces"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// PerformDifferentialFuzzing executes differential fuzzing on multiple implementations
func PerformDifferentialFuzzing(cmd *cobra.Command, args []string) error {
	fmt.Println("🚀 Akaylee Differential Fuzzer - Starting Implementation Comparison")
	fmt.Println("================================================================")

	// Load configuration
	if err := LoadConfig(); err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	// Setup logging
	if err := SetupLogging(); err != nil {
		return fmt.Errorf("failed to setup logging: %w", err)
	}

	// Create differential configuration
	diffConfig, err := createDifferentialConfig()
	if err != nil {
		return fmt.Errorf("failed to create differential configuration: %w", err)
	}

	// Validate implementations
	if err := validateImplementations(diffConfig.Implementations); err != nil {
		return fmt.Errorf("implementation validation failed: %w", err)
	}

	// Create differential engine
	engine := analysis.NewDifferentialEngine(diffConfig)
	engine.SetLogger(logrus.New())

	// Create executor
	executor := execution.NewProcessExecutor()
	engine.SetExecutor(executor)

	// Load test cases from corpus
	testCases, err := loadTestCasesForDifferential()
	if err != nil {
		return fmt.Errorf("failed to load test cases: %w", err)
	}

	fmt.Printf("📊 Loaded %d test cases for differential analysis\n", len(testCases))
	fmt.Printf("🔍 Comparing %d implementations\n", len(diffConfig.Implementations))

	// Perform differential analysis
	results, err := performDifferentialAnalysis(engine, testCases)
	if err != nil {
		return fmt.Errorf("differential analysis failed: %w", err)
	}

	// Generate reports
	if err := generateDifferentialReports(results, diffConfig.OutputDir); err != nil {
		return fmt.Errorf("failed to generate reports: %w", err)
	}

	// Display summary
	displayDifferentialSummary(results, engine.GetStats())

	return nil
}

// createDifferentialConfig creates the differential fuzzing configuration
func createDifferentialConfig() (*analysis.DifferentialConfig, error) {
	// Get implementations from configuration
	implConfigs := viper.GetStringSlice("differential.implementations")
	if len(implConfigs) == 0 {
		return nil, fmt.Errorf("no implementations specified for differential fuzzing")
	}

	implementations := make([]analysis.Implementation, 0, len(implConfigs))

	for _, implStr := range implConfigs {
		// Parse implementation string (format: "name:path:args")
		parts := strings.Split(implStr, ":")
		if len(parts) < 2 {
			return nil, fmt.Errorf("invalid implementation format: %s (expected name:path[:args])", implStr)
		}

		name := parts[0]
		path := parts[1]
		var args []string
		if len(parts) > 2 {
			args = parts[2:]
		}

		// Validate implementation exists
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return nil, fmt.Errorf("implementation not found: %s", path)
		}

		impl := analysis.Implementation{
			Name:        name,
			Path:        path,
			Args:        args,
			Env:         make(map[string]string),
			Timeout:     viper.GetDuration("differential.timeout"),
			MemoryLimit: viper.GetUint64("differential.memory_limit"),
			Description: fmt.Sprintf("Implementation %s at %s", name, path),
			Version:     "1.0.0", // Could be extracted from binary
		}

		implementations = append(implementations, impl)
	}

	config := &analysis.DifferentialConfig{
		Implementations:  implementations,
		Timeout:          viper.GetDuration("differential.timeout"),
		MaxDifferences:   viper.GetInt("differential.max_differences"),
		OutputDir:        viper.GetString("differential.output_dir"),
		ReproAttempts:    viper.GetInt("differential.repro_attempts"),
		MinConfidence:    viper.GetFloat64("differential.min_confidence"),
		EnableDetailed:   viper.GetBool("differential.enable_detailed"),
		CompareOutput:    viper.GetBool("differential.compare_output"),
		CompareError:     viper.GetBool("differential.compare_error"),
		CompareCoverage:  viper.GetBool("differential.compare_coverage"),
		CompareTiming:    viper.GetBool("differential.compare_timing"),
		CompareResources: viper.GetBool("differential.compare_resources"),
	}

	// Set defaults if not specified
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}
	if config.MaxDifferences == 0 {
		config.MaxDifferences = 1000
	}
	if config.OutputDir == "" {
		config.OutputDir = "./differential_output"
	}
	if config.ReproAttempts == 0 {
		config.ReproAttempts = 5
	}
	if config.MinConfidence == 0 {
		config.MinConfidence = 0.7
	}

	return config, nil
}

// validateImplementations validates that all implementations are accessible
func validateImplementations(implementations []analysis.Implementation) error {
	fmt.Println("🔍 Validating implementations...")

	for _, impl := range implementations {
		// Check if file exists and is executable
		info, err := os.Stat(impl.Path)
		if err != nil {
			return fmt.Errorf("implementation %s not found: %s", impl.Name, impl.Path)
		}

		// Check if it's executable (simplified check)
		if info.Mode()&0111 == 0 {
			return fmt.Errorf("implementation %s is not executable: %s", impl.Name, impl.Path)
		}

		fmt.Printf("  ✅ %s: %s\n", impl.Name, impl.Path)
	}

	return nil
}

// loadTestCasesForDifferential loads test cases for differential analysis
func loadTestCasesForDifferential() ([]*interfaces.TestCase, error) {
	corpusDir := viper.GetString("corpus_dir")
	if corpusDir == "" {
		return nil, fmt.Errorf("corpus directory not specified")
	}

	// Load test cases from corpus directory
	files, err := filepath.Glob(filepath.Join(corpusDir, "*"))
	if err != nil {
		return nil, fmt.Errorf("failed to glob corpus files: %w", err)
	}

	testCases := make([]*interfaces.TestCase, 0)

	for _, file := range files {
		info, err := os.Stat(file)
		if err != nil || info.IsDir() {
			continue
		}

		data, err := os.ReadFile(file)
		if err != nil {
			fmt.Printf("⚠️  Warning: Failed to read corpus file %s: %v\n", file, err)
			continue
		}

		testCase := &interfaces.TestCase{
			ID:         filepath.Base(file),
			Data:       data,
			Generation: 0,
			CreatedAt:  time.Now(),
			Priority:   100,
			Metadata:   make(map[string]interface{}),
		}

		testCases = append(testCases, testCase)
	}

	return testCases, nil
}

// performDifferentialAnalysis performs differential analysis on test cases
func performDifferentialAnalysis(engine *analysis.DifferentialEngine, testCases []*interfaces.TestCase) ([]*analysis.DifferentialResult, error) {
	fmt.Println("🚀 Starting differential analysis...")

	var results []*analysis.DifferentialResult
	totalTests := len(testCases)

	for i, testCase := range testCases {
		fmt.Printf("  🔍 Analyzing test case %d/%d: %s (%d bytes)\n",
			i+1, totalTests, testCase.ID, len(testCase.Data))

		result, err := engine.AnalyzeTestCase(testCase)
		if err != nil {
			fmt.Printf("⚠️  Warning: Failed to analyze test case %s: %v\n", testCase.ID, err)
			continue
		}

		if len(result.Differences) > 0 {
			fmt.Printf("  🚨 Found %d differences (severity: %s, confidence: %.1f%%)\n",
				len(result.Differences), result.Severity, result.Confidence*100)

			// Display critical differences immediately
			for _, diff := range result.Differences {
				if diff.Severity == "critical" {
					fmt.Printf("    🔥 CRITICAL: %s\n", diff.Description)
				}
			}
		}

		results = append(results, result)

		// Progress update every 10 tests
		if (i+1)%10 == 0 {
			stats := engine.GetStats()
			fmt.Printf("  📊 Progress: %d/%d tests, %d with differences\n",
				i+1, totalTests, stats.TestsWithDiffs)
		}
	}

	return results, nil
}

// generateDifferentialReports generates comprehensive reports
func generateDifferentialReports(results []*analysis.DifferentialResult, outputDir string) error {
	fmt.Printf("📊 Generating reports in %s...\n", outputDir)

	// Create output directory
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Generate summary report
	if err := generateSummaryReport(results, outputDir); err != nil {
		return fmt.Errorf("failed to generate summary report: %w", err)
	}

	// Generate detailed results
	if err := generateDetailedResults(results, outputDir); err != nil {
		return fmt.Errorf("failed to generate detailed results: %w", err)
	}

	// Generate severity breakdown
	if err := generateSeverityBreakdown(results, outputDir); err != nil {
		return fmt.Errorf("failed to generate severity breakdown: %w", err)
	}

	return nil
}

// generateSummaryReport generates a summary report
func generateSummaryReport(results []*analysis.DifferentialResult, outputDir string) error {
	summary := map[string]interface{}{
		"timestamp":        time.Now(),
		"total_tests":      len(results),
		"tests_with_diffs": 0,
		"critical_diffs":   0,
		"high_diffs":       0,
		"medium_diffs":     0,
		"low_diffs":        0,
		"implementations":  make(map[string]int),
		"difference_types": make(map[string]int),
	}

	for _, result := range results {
		if len(result.Differences) > 0 {
			summary["tests_with_diffs"] = summary["tests_with_diffs"].(int) + 1
		}

		for _, diff := range result.Differences {
			// Count by severity
			switch string(diff.Severity) {
			case "critical":
				summary["critical_diffs"] = summary["critical_diffs"].(int) + 1
			case "high":
				summary["high_diffs"] = summary["high_diffs"].(int) + 1
			case "medium":
				summary["medium_diffs"] = summary["medium_diffs"].(int) + 1
			case "low":
				summary["low_diffs"] = summary["low_diffs"].(int) + 1
			}

			// Count by type
			diffType := string(diff.Type)
			summary["difference_types"].(map[string]int)[diffType]++
		}

		// Count implementations involved
		for implName := range result.Implementations {
			summary["implementations"].(map[string]int)[implName]++
		}
	}

	// Write summary report
	summaryFile := filepath.Join(outputDir, "summary.json")
	data, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal summary: %w", err)
	}

	if err := os.WriteFile(summaryFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write summary file: %w", err)
	}

	fmt.Printf("  📄 Summary report: %s\n", summaryFile)
	return nil
}

// generateDetailedResults generates detailed results
func generateDetailedResults(results []*analysis.DifferentialResult, outputDir string) error {
	// Filter results with differences
	var diffResults []*analysis.DifferentialResult
	for _, result := range results {
		if len(result.Differences) > 0 {
			diffResults = append(diffResults, result)
		}
	}

	if len(diffResults) == 0 {
		fmt.Println("  ✅ No differences found - all implementations behave consistently")
		return nil
	}

	// Write detailed results
	detailedFile := filepath.Join(outputDir, "detailed_results.json")
	data, err := json.MarshalIndent(diffResults, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal detailed results: %w", err)
	}

	if err := os.WriteFile(detailedFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write detailed results file: %w", err)
	}

	fmt.Printf("  📄 Detailed results: %s (%d results with differences)\n", detailedFile, len(diffResults))
	return nil
}

// generateSeverityBreakdown generates severity breakdown report
func generateSeverityBreakdown(results []*analysis.DifferentialResult, outputDir string) error {
	severityCounts := map[string]int{
		"critical": 0,
		"high":     0,
		"medium":   0,
		"low":      0,
	}

	for _, result := range results {
		for _, diff := range result.Differences {
			severityCounts[string(diff.Severity)]++
		}
	}

	// Write severity breakdown
	severityFile := filepath.Join(outputDir, "severity_breakdown.json")
	data, err := json.MarshalIndent(severityCounts, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal severity breakdown: %w", err)
	}

	if err := os.WriteFile(severityFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write severity breakdown file: %w", err)
	}

	fmt.Printf("  📄 Severity breakdown: %s\n", severityFile)
	return nil
}

// displayDifferentialSummary displays a summary of differential analysis
func displayDifferentialSummary(results []*analysis.DifferentialResult, stats *analysis.DifferentialStats) {
	fmt.Println("\n🎯 Differential Analysis Summary")
	fmt.Println("================================")

	totalTests := len(results)
	testsWithDiffs := 0
	criticalDiffs := 0
	highDiffs := 0
	mediumDiffs := 0
	lowDiffs := 0

	for _, result := range results {
		if len(result.Differences) > 0 {
			testsWithDiffs++
		}

		for _, diff := range result.Differences {
			switch string(diff.Severity) {
			case "critical":
				criticalDiffs++
			case "high":
				highDiffs++
			case "medium":
				mediumDiffs++
			case "low":
				lowDiffs++
			}
		}
	}

	fmt.Printf("📊 Total Tests Analyzed: %d\n", totalTests)
	fmt.Printf("🚨 Tests with Differences: %d (%.1f%%)\n", testsWithDiffs, float64(testsWithDiffs)/float64(totalTests)*100)
	fmt.Printf("🔥 Critical Differences: %d\n", criticalDiffs)
	fmt.Printf("⚠️  High Differences: %d\n", highDiffs)
	fmt.Printf("📈 Medium Differences: %d\n", mediumDiffs)
	fmt.Printf("📉 Low Differences: %d\n", lowDiffs)

	if criticalDiffs > 0 {
		fmt.Printf("\n🚨 CRITICAL FINDINGS DETECTED!\n")
		fmt.Printf("   These differences may indicate security vulnerabilities or serious bugs.\n")
	}

	if highDiffs > 0 {
		fmt.Printf("\n⚠️  HIGH SEVERITY DIFFERENCES DETECTED!\n")
		fmt.Printf("   These differences may indicate implementation bugs or inconsistencies.\n")
	}

	if testsWithDiffs == 0 {
		fmt.Printf("\n✅ All implementations behave consistently!\n")
		fmt.Printf("   No behavioral differences detected across all test cases.\n")
	}

	fmt.Printf("\n📁 Reports saved to: %s\n", viper.GetString("differential.output_dir"))
}
