/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: fuzz.go
Description: Fuzz command implementation for the Akaylee Fuzzer. Handles the main
fuzzing process with comprehensive configuration, execution management, and
real-time statistics reporting.
*/

package commands

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/kleascm/akaylee-fuzzer/pkg/analysis"
	"github.com/kleascm/akaylee-fuzzer/pkg/core"
	"github.com/kleascm/akaylee-fuzzer/pkg/execution"
	"github.com/kleascm/akaylee-fuzzer/pkg/grammar"
	"github.com/kleascm/akaylee-fuzzer/pkg/interfaces"
	"github.com/kleascm/akaylee-fuzzer/pkg/strategies"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// RunFuzz executes the main fuzzing process
func RunFuzz(cmd *cobra.Command, args []string) error {
	fmt.Println("🚀 Akaylee Fuzzer - Starting Fuzzing Session")
	fmt.Println("============================================")
	fmt.Println()

	// Load configuration first
	if err := LoadConfig(); err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	// Setup logging
	if err := SetupLogging(); err != nil {
		return fmt.Errorf("failed to setup logging: %w", err)
	}

	// Create fuzzer configuration
	config := createFuzzerConfig()

	// Perform dry run if requested
	if viper.GetBool("dry_run") {
		return performDryRun(config)
	}

	// Validate configuration
	if err := validateFuzzerConfig(config); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	// Create fuzzer engine
	engine := core.NewEngine()

	// Set up components
	if err := setupFuzzerComponents(engine, config); err != nil {
		return fmt.Errorf("failed to setup fuzzer components: %w", err)
	}

	// Initialize engine
	if err := engine.Initialize(config); err != nil {
		return fmt.Errorf("failed to initialize engine: %w", err)
	}

	// Set up signal handling for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Println("\n🛑 Received shutdown signal, stopping fuzzer...")
		cancel()
	}()

	// Start fuzzer
	if err := engine.Start(); err != nil {
		return fmt.Errorf("failed to start fuzzer: %w", err)
	}

	// Start statistics reporting
	go reportStats(ctx, engine)

	// Wait for completion or interruption
	<-ctx.Done()

	// Stop fuzzer gracefully
	if err := engine.Stop(); err != nil {
		return fmt.Errorf("failed to stop fuzzer: %w", err)
	}

	// Print final statistics
	printFinalStats(engine)

	fmt.Println("\n✨ Fuzzing session completed!")
	return nil
}

// setupFuzzerComponents configures all fuzzer components
func setupFuzzerComponents(engine *core.Engine, config *interfaces.FuzzerConfig) error {
	// Create executor
	executor := execution.NewProcessExecutor()
	engine.SetExecutor(executor)

	// Create analyzer
	analyzer := analysis.NewCoverageAnalyzer()
	engine.SetAnalyzer(analyzer)

	// Create mutators
	mutators := createMutators(config)
	engine.SetMutators(mutators)

	// Set up reproducibility harness if enabled
	if viper.GetBool("enable_reproducibility") {
		harnessConfig := &analysis.ReproducibilityConfig{
			MaxReproductionAttempts: viper.GetInt("reproduction_attempts"),
			ReproductionTimeout:     30 * time.Second,
			MinimalTestCaseSize:     1024,
			EnableRootCauseAnalysis: true,
			EnableExploitability:    true,
			EnableProofOfConcept:    viper.GetBool("enable_poc"),
			OutputDirectory:         viper.GetString("reproduction_output_dir"),
			DetailedLogging:         true,
		}
		harness := analysis.NewReproducibilityHarness(harnessConfig)
		harness.SetExecutor(executor)
		engine.SetReproducibilityHarness(harness)
	}

	// Add reporters
	logger := logrus.New()
	engine.AddReporter(core.NewLoggerReporter(logger))

	return nil
}

// createMutators creates the mutator chain based on configuration
func createMutators(config *interfaces.FuzzerConfig) []interfaces.Mutator {
	mutators := make([]interfaces.Mutator, 0)

	// Add standard mutators
	mutationRate := config.MutationRate
	mutators = append(mutators, strategies.NewBitFlipMutator(mutationRate))
	mutators = append(mutators, strategies.NewByteSubstitutionMutator(mutationRate))
	mutators = append(mutators, strategies.NewArithmeticMutator(mutationRate))
	mutators = append(mutators, strategies.NewStructureAwareMutator(mutationRate))
	mutators = append(mutators, strategies.NewCrossOverMutator(mutationRate))

	// Add grammar-based mutator if enabled
	if viper.GetString("grammar_type") != "" {
		grammar := grammar.NewJSONGrammar()
		grammarMutator := strategies.NewGrammarMutator(grammar)
		mutators = append(mutators, grammarMutator)
	}

	// Create composite mutator
	composite := strategies.NewCompositeMutator(mutators, 3, true)
	return []interfaces.Mutator{composite}
}

// validateFuzzerConfig validates the fuzzer configuration
func validateFuzzerConfig(config *interfaces.FuzzerConfig) error {
	if config.Target == "" {
		return fmt.Errorf("target binary is required")
	}

	if config.CorpusDir == "" {
		return fmt.Errorf("corpus directory is required")
	}

	if _, err := os.Stat(config.Target); os.IsNotExist(err) {
		return fmt.Errorf("target binary not found: %s", config.Target)
	}

	if _, err := os.Stat(config.CorpusDir); os.IsNotExist(err) {
		return fmt.Errorf("corpus directory not found: %s", config.CorpusDir)
	}

	return nil
}

// reportStats periodically reports fuzzer statistics
func reportStats(ctx context.Context, engine *core.Engine) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			stats := engine.GetStats()
			fmt.Printf("\r🔄 Executions: %d | Crashes: %d | Hangs: %d | Rate: %.1f/sec | Coverage: %d",
				stats.Executions, stats.Crashes, stats.Hangs, stats.ExecutionsPerSecond, stats.CoveragePoints)
		}
	}
}

// printFinalStats prints comprehensive final statistics
func printFinalStats(engine *core.Engine) {
	stats := engine.GetStats()
	duration := time.Since(stats.StartTime)

	fmt.Println("\n📊 Final Statistics")
	fmt.Println("==================")
	fmt.Printf("Total Runtime: %v\n", duration)
	fmt.Printf("Total Executions: %d\n", stats.Executions)
	fmt.Printf("Total Crashes: %d\n", stats.Crashes)
	fmt.Printf("Total Hangs: %d\n", stats.Hangs)
	fmt.Printf("Total Timeouts: %d\n", stats.Timeouts)
	fmt.Printf("Unique Crashes: %d\n", stats.UniqueCrashes)
	fmt.Printf("Coverage Edges: %d\n", stats.CoverageEdges)
	fmt.Printf("Coverage Blocks: %d\n", stats.CoverageBlocks)
	fmt.Printf("Coverage Points: %d\n", stats.CoveragePoints)
	fmt.Printf("Average Rate: %.1f executions/sec\n", float64(stats.Executions)/duration.Seconds())

	if stats.Crashes > 0 {
		fmt.Printf("Last Crash: %v\n", stats.LastCrashTime.Format("2006-01-02 15:04:05"))
	}
}

// createFuzzerConfig creates the fuzzer configuration from viper
func createFuzzerConfig() *interfaces.FuzzerConfig {
	return &interfaces.FuzzerConfig{
		Target:        viper.GetString("target_path"),
		CorpusDir:     viper.GetString("corpus_dir"),
		OutputDir:     viper.GetString("output_dir"),
		CrashDir:      viper.GetString("crash_dir"),
		Workers:       viper.GetInt("workers"),
		Timeout:       viper.GetDuration("timeout"),
		MemoryLimit:   viper.GetInt64("memory_limit"),
		MaxCorpusSize: viper.GetInt("max_corpus_size"),
		MutationRate:  viper.GetFloat64("mutation_rate"),
		MaxMutations:  viper.GetInt("max_mutations"),
		Strategy:      viper.GetString("strategy"),
		CoverageType:  viper.GetString("coverage_type"),
		SchedulerType: viper.GetString("scheduler_type"),
		SessionID:     viper.GetString("session_id"),
	}
}

// performDryRun validates configuration without starting fuzzing
func performDryRun(config *interfaces.FuzzerConfig) error {
	fmt.Println("🔍 Performing dry run validation...")
	fmt.Println()

	// Validate target binary
	if _, err := os.Stat(config.Target); err != nil {
		return fmt.Errorf("target binary validation failed: %w", err)
	}
	fmt.Printf("✅ Target binary: %s\n", config.Target)

	// Validate corpus directory
	if _, err := os.Stat(config.CorpusDir); err != nil {
		return fmt.Errorf("corpus directory validation failed: %w", err)
	}
	fmt.Printf("✅ Corpus directory: %s\n", config.CorpusDir)

	// Check corpus files
	files, err := os.ReadDir(config.CorpusDir)
	if err != nil {
		return fmt.Errorf("failed to read corpus directory: %w", err)
	}
	fmt.Printf("✅ Corpus files: %d found\n", len(files))

	// Validate output directories
	dirs := []string{config.OutputDir, config.CrashDir}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
		fmt.Printf("✅ Output directory: %s\n", dir)
	}

	// Validate system resources
	if err := validateSystemResources(); err != nil {
		return fmt.Errorf("system resource validation failed: %w", err)
	}
	fmt.Println("✅ System resources: sufficient")

	fmt.Println("\n✨ Dry run validation completed successfully!")
	fmt.Println("   Configuration is valid and ready for fuzzing.")
	return nil
}

// validateSystemResources checks if system has sufficient resources
func validateSystemResources() error {
	var errors []string
	var warnings []string

	// Check CPU cores and capabilities
	if err := validateCPU(); err != nil {
		errors = append(errors, err.Error())
	}

	// Check system memory
	if err := validateMemory(); err != nil {
		errors = append(errors, err.Error())
	}

	// Check disk space and I/O
	if err := validateDisk(); err != nil {
		errors = append(errors, err.Error())
	}

	// Check process capabilities
	if err := validateProcessCapabilities(); err != nil {
		errors = append(errors, err.Error())
	}

	// Check file system permissions
	if err := validateFileSystem(); err != nil {
		errors = append(errors, err.Error())
	}

	// Check network connectivity (optional)
	if warning := validateNetwork(); warning != "" {
		warnings = append(warnings, warning)
	}

	// Display warnings
	for _, warning := range warnings {
		fmt.Printf("⚠️  Warning: %s\n", warning)
	}

	// Return combined errors if any
	if len(errors) > 0 {
		return fmt.Errorf("system resource validation failed:\n  %s", strings.Join(errors, "\n  "))
	}

	return nil
}

// validateCPU checks CPU cores and capabilities
func validateCPU() error {
	cpuCores := runtime.NumCPU()

	if cpuCores < 2 {
		return fmt.Errorf("insufficient CPU cores: %d (minimum 2 recommended for fuzzing)", cpuCores)
	}

	// Check CPU architecture
	arch := runtime.GOARCH
	if arch != "amd64" && arch != "arm64" {
		return fmt.Errorf("unsupported CPU architecture: %s (only amd64 and arm64 are fully supported)", arch)
	}

	// Check if we can use multiple goroutines effectively
	done := make(chan bool, cpuCores)
	for i := 0; i < cpuCores; i++ {
		go func() {
			// Simulate CPU work
			for j := 0; j < 1000000; j++ {
				_ = j * j
			}
			done <- true
		}()
	}

	// Wait for all goroutines with timeout
	timeout := time.After(5 * time.Second)
	for i := 0; i < cpuCores; i++ {
		select {
		case <-done:
			continue
		case <-timeout:
			return fmt.Errorf("CPU concurrency test failed: goroutines not completing in time")
		}
	}

	return nil
}

// validateMemory checks available system memory
func validateMemory() error {
	// Try to get memory info from /proc/meminfo on Linux
	if runtime.GOOS == "linux" {
		return validateMemoryLinux()
	}

	// Fallback for other operating systems
	return validateMemoryGeneric()
}

// validateMemoryLinux checks memory using /proc/meminfo
func validateMemoryLinux() error {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return validateMemoryGeneric()
	}

	lines := strings.Split(string(data), "\n")
	var totalMem, availableMem uint64

	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		switch fields[0] {
		case "MemTotal:":
			if val, err := strconv.ParseUint(fields[1], 10, 64); err == nil {
				totalMem = val * 1024 // Convert KB to bytes
			}
		case "MemAvailable:":
			if val, err := strconv.ParseUint(fields[1], 10, 64); err == nil {
				availableMem = val * 1024 // Convert KB to bytes
			}
		}
	}

	// Check minimum requirements
	minTotal := uint64(4 * 1024 * 1024 * 1024)     // 4GB total
	minAvailable := uint64(2 * 1024 * 1024 * 1024) // 2GB available

	if totalMem < minTotal {
		return fmt.Errorf("insufficient total memory: %d MB (minimum 4GB recommended)", totalMem/(1024*1024))
	}

	if availableMem < minAvailable {
		return fmt.Errorf("insufficient available memory: %d MB (minimum 2GB available)", availableMem/(1024*1024))
	}

	return nil
}

// validateMemoryGeneric checks memory using allocation tests
func validateMemoryGeneric() error {
	// Test allocation of reasonable amounts of memory
	testSizes := []uint64{
		100 * 1024 * 1024,  // 100MB
		500 * 1024 * 1024,  // 500MB
		1024 * 1024 * 1024, // 1GB
	}

	for _, size := range testSizes {
		// Try to allocate memory
		buf := make([]byte, size)
		if buf == nil {
			return fmt.Errorf("cannot allocate %d MB of memory", size/(1024*1024))
		}

		// Test memory access
		for i := 0; i < len(buf); i += 1024 {
			buf[i] = byte(i % 256)
		}

		// Force garbage collection to free memory
		runtime.GC()
	}

	return nil
}

// validateDisk checks disk space and I/O capabilities
func validateDisk() error {
	// Check current working directory
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("cannot get current working directory: %v", err)
	}

	var stat syscall.Statfs_t
	if err := syscall.Statfs(cwd, &stat); err != nil {
		return fmt.Errorf("cannot check filesystem: %v", err)
	}

	// Calculate available space
	availableBytes := stat.Bavail * uint64(stat.Bsize)
	availableGB := availableBytes / (1024 * 1024 * 1024)

	if availableGB < 5 {
		return fmt.Errorf("insufficient disk space: %d GB available (minimum 5GB recommended for fuzzing)", availableGB)
	}

	// Test disk I/O performance
	if err := testDiskIO(); err != nil {
		return fmt.Errorf("disk I/O test failed: %v", err)
	}

	return nil
}

// testDiskIO tests disk I/O performance
func testDiskIO() error {
	// Create a temporary file for I/O testing
	tempFile, err := os.CreateTemp("", "akaylee_io_test_")
	if err != nil {
		return fmt.Errorf("cannot create temporary file: %v", err)
	}
	defer os.Remove(tempFile.Name())
	defer tempFile.Close()

	// Test write performance
	testData := make([]byte, 10*1024*1024) // 10MB
	for i := range testData {
		testData[i] = byte(i % 256)
	}

	start := time.Now()
	_, err = tempFile.Write(testData)
	if err != nil {
		return fmt.Errorf("write test failed: %v", err)
	}
	tempFile.Sync()

	writeTime := time.Since(start)
	writeSpeed := float64(len(testData)) / writeTime.Seconds() / (1024 * 1024) // MB/s

	if writeSpeed < 10 { // Less than 10 MB/s
		return fmt.Errorf("disk write speed too slow: %.1f MB/s (minimum 10 MB/s recommended)", writeSpeed)
	}

	// Test read performance
	tempFile.Seek(0, 0)
	readData := make([]byte, len(testData))

	start = time.Now()
	_, err = tempFile.Read(readData)
	if err != nil {
		return fmt.Errorf("read test failed: %v", err)
	}

	readTime := time.Since(start)
	readSpeed := float64(len(readData)) / readTime.Seconds() / (1024 * 1024) // MB/s

	if readSpeed < 20 { // Less than 20 MB/s
		return fmt.Errorf("disk read speed too slow: %.1f MB/s (minimum 20 MB/s recommended)", readSpeed)
	}

	return nil
}

// validateProcessCapabilities checks if we can spawn and manage processes
func validateProcessCapabilities() error {
	// Test basic process spawning
	cmd := exec.Command("echo", "test")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("cannot spawn basic processes: %v", err)
	}

	// Test process with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd = exec.CommandContext(ctx, "sleep", "1")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("cannot spawn processes with timeout: %v", err)
	}

	// Test process with environment variables
	cmd = exec.Command("env")
	cmd.Env = append(os.Environ(), "AKAYLEE_TEST=1")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("cannot spawn processes with custom environment: %v", err)
	}

	if !strings.Contains(string(output), "AKAYLEE_TEST=1") {
		return fmt.Errorf("environment variable not passed to child process")
	}

	return nil
}

// validateFileSystem checks file system permissions and capabilities
func validateFileSystem() error {
	// Test file creation
	testFile := "akaylee_test_file"
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		return fmt.Errorf("cannot create files: %v", err)
	}
	defer os.Remove(testFile)

	// Test file reading
	if _, err := os.ReadFile(testFile); err != nil {
		return fmt.Errorf("cannot read files: %v", err)
	}

	// Test directory creation
	testDir := "akaylee_test_dir"
	if err := os.Mkdir(testDir, 0755); err != nil {
		return fmt.Errorf("cannot create directories: %v", err)
	}
	defer os.Remove(testDir)

	// Test file in subdirectory
	subFile := filepath.Join(testDir, "test.txt")
	if err := os.WriteFile(subFile, []byte("test"), 0644); err != nil {
		return fmt.Errorf("cannot create files in subdirectories: %v", err)
	}

	// Test file permissions
	if err := os.Chmod(testFile, 0400); err != nil {
		return fmt.Errorf("cannot change file permissions: %v", err)
	}

	// Test symbolic links (if supported)
	if runtime.GOOS != "windows" {
		symlink := "akaylee_test_symlink"
		if err := os.Symlink(testFile, symlink); err == nil {
			os.Remove(symlink)
		}
	}

	return nil
}

// validateNetwork checks network connectivity (optional)
func validateNetwork() string {
	// Test basic connectivity
	timeout := 5 * time.Second

	// Test DNS resolution
	conn, err := net.DialTimeout("tcp", "8.8.8.8:53", timeout)
	if err != nil {
		return "No internet connectivity detected (optional for local fuzzing)"
	}
	conn.Close()

	// Test HTTP connectivity
	conn, err = net.DialTimeout("tcp", "httpbin.org:80", timeout)
	if err != nil {
		return "Limited internet connectivity (optional for local fuzzing)"
	}
	conn.Close()

	return ""
}
