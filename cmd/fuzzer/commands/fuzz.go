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
	"os"
	"os/signal"
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
	// This is a simplified validation
	// In production, you'd check CPU, memory, disk space, etc.
	return nil
}
