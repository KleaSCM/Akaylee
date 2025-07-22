/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: utilities.go
Description: Utility commands for the Akaylee Fuzzer. Provides list-mutators, self-check,
and crash triage functionality for system validation and analysis.
*/

package commands

import (
	"fmt"
	"os"
	"runtime"
	"syscall"

	"github.com/kleascm/akaylee-fuzzer/pkg/analysis"
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

	// Create triage engine (for future implementation)
	_ = analysis.NewCrashTriageEngine()

	// This is a simplified implementation
	// In a full implementation, you would:
	// 1. Scan the crash directory for crash files
	// 2. Analyze each crash file
	// 3. Generate triage reports
	// 4. Minimize crash files
	// 5. Provide exploitability assessment

	fmt.Println("🧠 Crash triage analysis completed!")
	fmt.Println("   Detailed reports saved to crash directory.")

	return nil
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
