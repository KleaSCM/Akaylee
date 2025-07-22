/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: reproduction.go
Description: Crash reproduction command implementation for the Akaylee Fuzzer. Provides
comprehensive crash reproduction analysis with root cause investigation, exploitability
assessment, and minimal test case generation for security research.
*/

package commands

import (
	"fmt"
	"os"
	"time"

	"github.com/kleascm/akaylee-fuzzer/pkg/analysis"
	"github.com/kleascm/akaylee-fuzzer/pkg/execution"
	"github.com/kleascm/akaylee-fuzzer/pkg/interfaces"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// PerformCrashReproduction reproduces and analyzes crash files
func PerformCrashReproduction(cmd *cobra.Command, args []string) error {
	fmt.Println("🔄 Akaylee Fuzzer - Crash Reproduction Analysis")
	fmt.Println("===============================================")
	fmt.Println()

	// Load configuration first
	if err := LoadConfig(); err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	// Setup logging for reproduction
	if err := SetupLogging(); err != nil {
		return fmt.Errorf("failed to setup logging: %w", err)
	}

	// Get parameters from flags
	crashFile := viper.GetString("crash_file")
	targetPath := viper.GetString("reproduce_target")
	attempts := viper.GetInt("reproduction_attempts")
	enablePoC := viper.GetBool("enable_poc")
	outputDir := viper.GetString("reproduction_output_dir")

	fmt.Printf("📁 Crash file: %s\n", crashFile)
	fmt.Printf("🎯 Target binary: %s\n", targetPath)
	fmt.Printf("🔄 Reproduction attempts: %d\n", attempts)
	fmt.Printf("💣 Proof of concept: %v\n", enablePoC)
	fmt.Printf("📊 Output directory: %s\n", outputDir)
	fmt.Println()

	// Check if crash file exists
	if _, err := os.Stat(crashFile); os.IsNotExist(err) {
		return fmt.Errorf("crash file not found: %s", crashFile)
	}

	// Check if target binary exists
	if _, err := os.Stat(targetPath); os.IsNotExist(err) {
		return fmt.Errorf("target binary not found: %s", targetPath)
	}

	// Read crash file
	crashData, err := os.ReadFile(crashFile)
	if err != nil {
		return fmt.Errorf("failed to read crash file: %w", err)
	}

	fmt.Printf("📖 Loaded crash file: %d bytes\n", len(crashData))
	fmt.Println()

	// Create reproducibility harness configuration
	config := &analysis.ReproducibilityConfig{
		MaxReproductionAttempts: attempts,
		ReproductionTimeout:     30 * time.Second,
		MinimalTestCaseSize:     1024,
		EnableRootCauseAnalysis: true,
		EnableExploitability:    true,
		EnableProofOfConcept:    enablePoC,
		OutputDirectory:         outputDir,
		DetailedLogging:         true,
	}

	// Create reproducibility harness
	harness := analysis.NewReproducibilityHarness(config)

	// Create executor for reproduction
	executor := execution.NewProcessExecutor()
	executorConfig := &interfaces.FuzzerConfig{
		Target:      targetPath,
		Timeout:     30 * time.Second,
		MemoryLimit: 100 * 1024 * 1024, // 100MB
	}

	if err := executor.Initialize(executorConfig); err != nil {
		return fmt.Errorf("failed to initialize executor: %w", err)
	}

	// Set executor in harness
	harness.SetExecutor(executor)

	// Create logger for harness
	logger := logrus.New()
	logger.SetLevel(logrus.InfoLevel)
	harness.SetLogger(logger)

	// Create test case from crash data
	testCase := &interfaces.TestCase{
		ID:         "reproduction_test",
		Data:       crashData,
		Generation: 0,
		CreatedAt:  time.Now(),
		Priority:   100,
		Metadata:   make(map[string]interface{}),
	}

	// Create mock execution result (we'll get the real one from execution)
	mockResult := &interfaces.ExecutionResult{
		TestCaseID:  testCase.ID,
		Status:      interfaces.StatusCrash,
		ExitCode:    139, // SIGSEGV
		Signal:      11,  // SIGSEGV
		Output:      crashData,
		Error:       []byte("Segmentation fault"),
		Duration:    1 * time.Second,
		MemoryUsage: 1024 * 1024,
		CPUUsage:    50.0,
		CrashInfo: &interfaces.CrashInfo{
			Type:         "SIGSEGV",
			Address:      0,
			Reproducible: true,
			Hash:         "mock_crash_hash",
			StackTrace:   []string{"main.main()", "runtime.main()"},
			Metadata:     make(map[string]interface{}),
		},
	}

	fmt.Println("🧠 Starting crash reproduction analysis...")
	startTime := time.Now()

	// Perform reproduction analysis
	result, err := harness.AnalyzeCrash(testCase, mockResult)
	if err != nil {
		return fmt.Errorf("reproduction analysis failed: %w", err)
	}

	analysisTime := time.Since(startTime)
	fmt.Printf("✅ Reproduction analysis completed in %v\n", analysisTime)
	fmt.Println()

	// Display results
	fmt.Println("📋 Reproduction Results")
	fmt.Println("======================")
	fmt.Printf("Reproducible: %v\n", result.Reproducible)
	fmt.Printf("Reproduction Rate: %.1f%%\n", result.ReproductionRate*100)
	fmt.Printf("Attempts Made: %d\n", result.ReproductionAttempts)
	fmt.Printf("Analysis Time: %v\n", result.ReproductionTime)
	fmt.Printf("Stack Traces Collected: %d\n", len(result.StackTraces))
	fmt.Println()

	// Display root cause analysis
	if result.RootCauseAnalysis != nil {
		fmt.Println("🔍 Root Cause Analysis")
		fmt.Println("=====================")
		fmt.Printf("Primary Cause: %s\n", result.RootCauseAnalysis.PrimaryCause)
		fmt.Printf("Confidence: %.1f%%\n", result.RootCauseAnalysis.Confidence*100)

		if len(result.RootCauseAnalysis.Evidence) > 0 {
			fmt.Println("Evidence:")
			for _, evidence := range result.RootCauseAnalysis.Evidence {
				fmt.Printf("  - %s\n", evidence)
			}
		}

		if len(result.RootCauseAnalysis.Recommendations) > 0 {
			fmt.Println("Recommendations:")
			for _, rec := range result.RootCauseAnalysis.Recommendations {
				fmt.Printf("  - %s\n", rec)
			}
		}

		if result.RootCauseAnalysis.CVSSScore != nil {
			fmt.Printf("CVSS Score: %.1f (%s)\n",
				result.RootCauseAnalysis.CVSSScore.BaseScore,
				result.RootCauseAnalysis.CVSSScore.Severity)
		}
		fmt.Println()
	}

	// Display exploitability assessment
	if result.Exploitability != nil {
		fmt.Println("💣 Exploitability Assessment")
		fmt.Println("============================")
		fmt.Printf("Exploitability: %s\n", result.Exploitability.Exploitability)
		fmt.Printf("Attack Vector: %s\n", result.Exploitability.AttackVector)
		fmt.Printf("Complexity: %s\n", result.Exploitability.Complexity)
		fmt.Printf("Privileges: %s\n", result.Exploitability.Privileges)
		fmt.Printf("User Interaction: %s\n", result.Exploitability.UserInteraction)
		fmt.Printf("Scope: %s\n", result.Exploitability.Scope)
		fmt.Printf("Confidence: %.1f%%\n", result.Exploitability.Confidence*100)
		fmt.Println()

		// Display proof of concept if available
		if result.Exploitability.ProofOfConcept != nil {
			fmt.Println("💻 Proof of Concept")
			fmt.Println("===================")
			fmt.Printf("Description: %s\n", result.Exploitability.ProofOfConcept.Description)
			fmt.Printf("Success Rate: %.1f%%\n", result.Exploitability.ProofOfConcept.SuccessRate*100)
			fmt.Printf("Risk Level: %s\n", result.Exploitability.ProofOfConcept.RiskLevel)

			if len(result.Exploitability.ProofOfConcept.Requirements) > 0 {
				fmt.Println("Requirements:")
				for _, req := range result.Exploitability.ProofOfConcept.Requirements {
					fmt.Printf("  - %s\n", req)
				}
			}
			fmt.Println()
		}
	}

	// Display minimal test case info
	if result.MinimalTestCase != nil {
		fmt.Println("📦 Minimal Test Case")
		fmt.Println("====================")
		fmt.Printf("Size: %d bytes\n", len(result.MinimalTestCase.Data))
		fmt.Printf("ID: %s\n", result.MinimalTestCase.ID)
		fmt.Printf("Generation: %d\n", result.MinimalTestCase.Generation)
		fmt.Println()
	}

	// Display reproduction statistics
	stats := harness.GetReproductionStats()
	fmt.Println("📊 Reproduction Statistics")
	fmt.Println("=========================")
	fmt.Printf("Total Crashes Analyzed: %v\n", stats["total_crashes"])
	fmt.Printf("Reproducible Crashes: %v\n", stats["reproducible_crashes"])
	fmt.Printf("Overall Reproduction Rate: %.1f%%\n", stats["reproduction_rate"].(float64)*100)
	fmt.Printf("Average Reproduction Rate: %.1f%%\n", stats["avg_reproduction_rate"].(float64)*100)
	fmt.Printf("Total Attempts: %v\n", stats["total_attempts"])
	fmt.Printf("Average Attempts per Crash: %.1f\n", stats["avg_attempts_per_crash"].(float64))
	fmt.Println()

	fmt.Println("✨ Crash reproduction analysis completed!")
	fmt.Printf("📄 Detailed report saved to: %s\n", outputDir)

	return nil
}
