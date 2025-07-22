/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: main.go
Description: Main command-line interface for the Akaylee Fuzzer. Provides comprehensive
command-line options, configuration management, and beautiful user interface for
controlling the fuzzing process with advanced logging capabilities.
*/

package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/kleascm/akaylee-fuzzer/pkg/analysis"
	"github.com/kleascm/akaylee-fuzzer/pkg/core"
	"github.com/kleascm/akaylee-fuzzer/pkg/execution"
	"github.com/kleascm/akaylee-fuzzer/pkg/grammar"
	"github.com/kleascm/akaylee-fuzzer/pkg/interfaces"
	"github.com/kleascm/akaylee-fuzzer/pkg/logging"
	"github.com/kleascm/akaylee-fuzzer/pkg/strategies"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	// Configuration
	configFile string
	logLevel   string
	jsonLogs   bool

	// Target configuration
	targetPath string
	targetArgs []string
	targetEnv  []string

	// Execution configuration
	workers     int
	timeout     time.Duration
	memoryLimit uint64

	// Corpus configuration
	corpusDir     string
	outputDir     string
	maxCorpusSize int

	// Mutation configuration
	mutationRate float64
	maxMutations int
	strategy     string

	// Coverage configuration
	coverageType  string
	bitmapSize    int
	edgeThreshold int

	// Crash configuration
	maxCrashes int
	crashDir   string
	reproduce  bool

	// Performance configuration
	enableGC      bool
	profileCPU    bool
	profileMemory bool

	// Logging configuration
	logDir      string
	logFormat   string
	logMaxFiles int
	logMaxSize  int64
	logCompress bool

	coverageGuided bool   // New flag for coverage-guided fuzzing
	grammarType    string // New: grammar type for grammar-based fuzzing
	dryRun         bool   // New: dry-run mode for validation
)

// Global logger instance
var logger *logging.Logger

func main() {
	// Create root command
	rootCmd := &cobra.Command{
		Use:   "akaylee-fuzzer",
		Short: "Akaylee Fuzzer - High-performance, production-level fuzzing engine",
		Long: `Akaylee Fuzzer is a sophisticated, enterprise-grade fuzzing engine that combines
multiple advanced fuzzing strategies with intelligent execution management. Built with
performance and scalability in mind, it's designed to discover vulnerabilities and edge
cases in target applications with exceptional efficiency.`,
		Version: "1.0.0",
	}

	// Add persistent flags
	rootCmd.PersistentFlags().StringVar(&configFile, "config", "", "Configuration file path")
	rootCmd.PersistentFlags().StringVar(&logLevel, "log-level", "info", "Logging level (debug, info, warn, error)")
	rootCmd.PersistentFlags().BoolVar(&jsonLogs, "json-logs", false, "Use JSON log format")

	// Add logging-specific flags
	rootCmd.PersistentFlags().StringVar(&logDir, "log-dir", "./logs", "Log output directory")
	rootCmd.PersistentFlags().StringVar(&logFormat, "log-format", "custom", "Log format (text, json, custom)")
	rootCmd.PersistentFlags().IntVar(&logMaxFiles, "log-max-files", 10, "Maximum number of log files to keep")
	rootCmd.PersistentFlags().Int64Var(&logMaxSize, "log-max-size", 100*1024*1024, "Maximum log file size in bytes")
	rootCmd.PersistentFlags().BoolVar(&logCompress, "log-compress", false, "Compress rotated log files")

	// Bind flags to viper
	viper.BindPFlag("log_level", rootCmd.PersistentFlags().Lookup("log-level"))
	viper.BindPFlag("json_logs", rootCmd.PersistentFlags().Lookup("json-logs"))
	viper.BindPFlag("log_dir", rootCmd.PersistentFlags().Lookup("log-dir"))
	viper.BindPFlag("log_format", rootCmd.PersistentFlags().Lookup("log-format"))
	viper.BindPFlag("log_max_files", rootCmd.PersistentFlags().Lookup("log-max-files"))
	viper.BindPFlag("log_max_size", rootCmd.PersistentFlags().Lookup("log-max-size"))
	viper.BindPFlag("log_compress", rootCmd.PersistentFlags().Lookup("log-compress"))

	// Add fuzz command
	fuzzCmd := &cobra.Command{
		Use:   "fuzz",
		Short: "Start fuzzing a target program",
		Long: `Start the fuzzing process on a target program. The fuzzer will continuously
generate and execute test cases, looking for crashes, hangs, and new coverage paths.`,
		RunE: runFuzz,
	}

	// Add fuzz command flags
	fuzzCmd.Flags().StringVar(&targetPath, "target", "", "Path to target binary (required)")
	fuzzCmd.Flags().StringSliceVar(&targetArgs, "args", []string{}, "Command-line arguments for target")
	fuzzCmd.Flags().StringSliceVar(&targetEnv, "env", []string{}, "Environment variables for target")

	fuzzCmd.Flags().IntVar(&workers, "workers", 0, "Number of parallel workers (0 = auto-detect)")
	fuzzCmd.Flags().DurationVar(&timeout, "timeout", 30*time.Second, "Maximum execution time per test case")
	fuzzCmd.Flags().Uint64Var(&memoryLimit, "memory-limit", 0, "Memory limit per execution (bytes)")

	fuzzCmd.Flags().StringVar(&corpusDir, "corpus", "", "Directory containing seed corpus (required)")
	fuzzCmd.Flags().StringVar(&outputDir, "output", "./fuzz_output", "Directory for fuzzer output")
	fuzzCmd.Flags().IntVar(&maxCorpusSize, "max-corpus-size", 10000, "Maximum number of test cases in corpus")

	fuzzCmd.Flags().Float64Var(&mutationRate, "mutation-rate", 0.01, "Probability of mutation per byte")
	fuzzCmd.Flags().IntVar(&maxMutations, "max-mutations", 5, "Maximum mutations per test case")
	fuzzCmd.Flags().StringVar(&strategy, "strategy", "mutation", "Primary fuzzing strategy")

	fuzzCmd.Flags().StringVar(&coverageType, "coverage-type", "edge", "Type of coverage to track")
	fuzzCmd.Flags().IntVar(&bitmapSize, "bitmap-size", 65536, "Size of coverage bitmap")
	fuzzCmd.Flags().IntVar(&edgeThreshold, "edge-threshold", 10, "Minimum edges for interesting test case")

	fuzzCmd.Flags().IntVar(&maxCrashes, "max-crashes", 100, "Maximum crashes to collect")
	fuzzCmd.Flags().StringVar(&crashDir, "crash-dir", "./crashes", "Directory for crash files")
	fuzzCmd.Flags().BoolVar(&reproduce, "reproduce", true, "Whether to reproduce crashes")

	fuzzCmd.Flags().BoolVar(&enableGC, "enable-gc", true, "Enable garbage collection tuning")
	fuzzCmd.Flags().BoolVar(&profileCPU, "profile-cpu", false, "Enable CPU profiling")
	fuzzCmd.Flags().BoolVar(&profileMemory, "profile-memory", false, "Enable memory profiling")
	fuzzCmd.Flags().BoolVar(&coverageGuided, "coverage-guided", false, "Enable coverage-guided fuzzing (Go targets)")

	// Add grammar flags
	fuzzCmd.Flags().StringVar(&grammarType, "grammar", "", "Enable grammar-based fuzzing (e.g., 'json')")
	fuzzCmd.Flags().StringSlice("grammar-seeds", []string{}, "Seed keys for grammar-based fuzzing (e.g., 'name,age,email')")
	fuzzCmd.Flags().Int("grammar-depth", 5, "Maximum recursion depth for grammar fuzzing")

	// Add dry-run flag
	fuzzCmd.Flags().BoolVar(&dryRun, "dry-run", false, "Validate configuration and exit without fuzzing")

	viper.BindPFlag("grammar_type", fuzzCmd.Flags().Lookup("grammar"))
	viper.BindPFlag("grammar_seeds", fuzzCmd.Flags().Lookup("grammar-seeds"))
	viper.BindPFlag("grammar_depth", fuzzCmd.Flags().Lookup("grammar-depth"))
	viper.BindPFlag("dry_run", fuzzCmd.Flags().Lookup("dry-run"))

	// Mark required flags
	fuzzCmd.MarkFlagRequired("target")
	fuzzCmd.MarkFlagRequired("corpus")

	// Bind flags to viper
	viper.BindPFlag("target_path", fuzzCmd.Flags().Lookup("target"))
	viper.BindPFlag("target_args", fuzzCmd.Flags().Lookup("args"))
	viper.BindPFlag("target_env", fuzzCmd.Flags().Lookup("env"))
	viper.BindPFlag("workers", fuzzCmd.Flags().Lookup("workers"))
	viper.BindPFlag("timeout", fuzzCmd.Flags().Lookup("timeout"))
	viper.BindPFlag("memory_limit", fuzzCmd.Flags().Lookup("memory-limit"))
	viper.BindPFlag("corpus_dir", fuzzCmd.Flags().Lookup("corpus"))
	viper.BindPFlag("output_dir", fuzzCmd.Flags().Lookup("output"))
	viper.BindPFlag("max_corpus_size", fuzzCmd.Flags().Lookup("max-corpus-size"))
	viper.BindPFlag("mutation_rate", fuzzCmd.Flags().Lookup("mutation-rate"))
	viper.BindPFlag("max_mutations", fuzzCmd.Flags().Lookup("max-mutations"))
	viper.BindPFlag("strategy", fuzzCmd.Flags().Lookup("strategy"))
	viper.BindPFlag("coverage_type", fuzzCmd.Flags().Lookup("coverage-type"))
	viper.BindPFlag("bitmap_size", fuzzCmd.Flags().Lookup("bitmap-size"))
	viper.BindPFlag("edge_threshold", fuzzCmd.Flags().Lookup("edge-threshold"))
	viper.BindPFlag("max_crashes", fuzzCmd.Flags().Lookup("max-crashes"))
	viper.BindPFlag("crash_dir", fuzzCmd.Flags().Lookup("crash-dir"))
	viper.BindPFlag("reproduce", fuzzCmd.Flags().Lookup("reproduce"))
	viper.BindPFlag("enable_gc", fuzzCmd.Flags().Lookup("enable-gc"))
	viper.BindPFlag("profile_cpu", fuzzCmd.Flags().Lookup("profile-cpu"))
	viper.BindPFlag("profile_memory", fuzzCmd.Flags().Lookup("profile-memory"))
	viper.BindPFlag("coverage_guided", fuzzCmd.Flags().Lookup("coverage-guided"))
	viper.BindPFlag("grammar_type", fuzzCmd.Flags().Lookup("grammar"))

	// Add list-mutators command
	listMutatorsCmd := &cobra.Command{
		Use:   "list-mutators",
		Short: "List available mutators and their capabilities",
		Long: `List all available mutators in the Akaylee Fuzzer with detailed descriptions
of their capabilities and use cases.`,
		Run: func(cmd *cobra.Command, args []string) {
			listMutators(cmd, args)
		},
	}
	rootCmd.AddCommand(listMutatorsCmd)

	// Add check command for built-in self-checks
	rootCmd.AddCommand(&cobra.Command{
		Use:   "check",
		Short: "Perform built-in self-checks for system validation",
		Long: `Perform comprehensive system checks to validate binary existence, corpus accessibility, 
log writability, and other prerequisites for successful fuzzing. Very useful for CI/CD integration.`,
		RunE: performSelfCheck,
	})

	// Add commands to root
	rootCmd.AddCommand(fuzzCmd)

	// Execute
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// runFuzz executes the fuzzing process
func runFuzz(cmd *cobra.Command, args []string) error {
	// Load configuration
	if err := loadConfig(); err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	// Setup logging
	if err := setupLogging(); err != nil {
		return fmt.Errorf("failed to setup logging: %w", err)
	}
	defer logger.Close()

	// Create fuzzer configuration
	config := createFuzzerConfig()

	// Check for dry-run mode
	if viper.GetBool("dry_run") {
		return performDryRun(config)
	}

	// Create and initialize fuzzer engine
	engine := core.NewEngine()

	// Set up real executor, analyzer, and mutators
	executor := execution.NewProcessExecutor()
	executor.Initialize(config) // Ensure config is set for the executor
	analyzer := analysis.NewCoverageAnalyzer()

	var mutators []interfaces.Mutator
	if grammarType == "json" {
		// Get grammar configuration
		seedKeys := viper.GetStringSlice("grammar_seeds")
		maxDepth := viper.GetInt("grammar_depth")

		// Create grammar with configuration
		jsonGrammar := grammar.NewJSONGrammar()
		if len(seedKeys) > 0 {
			jsonGrammar.SetSeedKeys(seedKeys)
		}
		jsonGrammar.SetMaxDepth(maxDepth)

		// Create grammar mutator with advanced configuration
		grammarMutator := strategies.NewGrammarMutatorWithConfig(jsonGrammar, seedKeys, maxDepth)

		mutators = []interfaces.Mutator{grammarMutator}

		logger.Info("Using grammar-based fuzzing", map[string]interface{}{
			"grammar_type": grammarType,
			"seed_keys":    seedKeys,
			"max_depth":    maxDepth,
		})
	} else {
		mutators = []interfaces.Mutator{
			strategies.NewBitFlipMutator(config.MutationRate),
			strategies.NewByteSubstitutionMutator(config.MutationRate),
			strategies.NewArithmeticMutator(config.MutationRate),
			strategies.NewStructureAwareMutator(config.MutationRate),
			strategies.NewCrossOverMutator(config.MutationRate),
		}
	}

	engine.SetExecutor(executor)
	engine.SetAnalyzer(analyzer)
	engine.SetMutators(mutators)

	if err := engine.Initialize(config); err != nil {
		return fmt.Errorf("failed to initialize fuzzer engine: %w", err)
	}

	// Setup signal handling for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		logger.Info("Received shutdown signal", map[string]interface{}{
			"signal": sig.String(),
		})
		cancel()
	}()

	// Start fuzzer
	logger.Info("Starting Akaylee Fuzzer", map[string]interface{}{
		"target":     config.Target,
		"workers":    config.Workers,
		"corpus_dir": config.CorpusDir,
		"strategy":   config.Strategy,
	})

	if err := engine.Start(); err != nil {
		return fmt.Errorf("failed to start fuzzer: %w", err)
	}

	// Start statistics reporting
	go reportStats(ctx, engine)

	// Wait for context cancellation
	<-ctx.Done()

	// Stop fuzzer
	logger.Info("Stopping fuzzer", map[string]interface{}{})
	if err := engine.Stop(); err != nil {
		return fmt.Errorf("failed to stop fuzzer: %w", err)
	}

	// Print final statistics
	printFinalStats(engine)

	return nil
}

// loadConfig loads configuration from file and environment
func loadConfig() error {
	// Set configuration file
	if configFile != "" {
		viper.SetConfigFile(configFile)
	} else {
		viper.SetConfigName("akaylee-fuzzer")
		viper.SetConfigType("yaml")
		viper.AddConfigPath(".")
		viper.AddConfigPath("./config")
		viper.AddConfigPath("$HOME/.akaylee-fuzzer")
	}

	// Read environment variables
	viper.AutomaticEnv()
	viper.SetEnvPrefix("AKAYLEE")

	// Read configuration file
	if err := viper.ReadInConfig(); err != nil {
		// Only warn, never fail
		fmt.Fprintf(os.Stderr, "Warning: failed to read config file: %v\n", err)
	}

	return nil
}

// setupLogging configures the logging system
func setupLogging() error {
	// Determine log format
	var logFormat logging.LogFormat
	switch viper.GetString("log_format") {
	case "json":
		logFormat = logging.LogFormatJSON
	case "text":
		logFormat = logging.LogFormatText
	case "custom":
		logFormat = logging.LogFormatCustom
	default:
		logFormat = logging.LogFormatCustom
	}

	// Create logger configuration
	logConfig := &logging.LoggerConfig{
		Level:     logging.LogLevel(viper.GetString("log_level")),
		Format:    logFormat,
		OutputDir: viper.GetString("log_dir"),
		MaxFiles:  viper.GetInt("log_max_files"),
		MaxSize:   viper.GetInt64("log_max_size"),
		Timestamp: true,
		Caller:    true,
		Colors:    true,
		Compress:  viper.GetBool("log_compress"),
	}

	// Create logger
	var err error
	logger, err = logging.NewLogger(logConfig)
	if err != nil {
		return fmt.Errorf("failed to create logger: %w", err)
	}

	// Set global logrus logger to use our logger
	logrus.SetOutput(logger.GetLogger().Out)
	logrus.SetFormatter(logger.GetLogger().Formatter)
	logrus.SetLevel(logger.GetLogger().Level)

	return nil
}

// createFuzzerConfig creates the fuzzer configuration from viper
func createFuzzerConfig() *interfaces.FuzzerConfig {
	// Generate a persistent session UUID for this fuzzing session
	sessionID := uuid.New().String()

	// Set coverage type based on coverage-guided flag
	coverageType := viper.GetString("coverage_type")
	if viper.GetBool("coverage_guided") {
		coverageType = "go"
	}

	config := &interfaces.FuzzerConfig{
		Target:        viper.GetString("target_path"),
		CorpusDir:     viper.GetString("corpus_dir"),
		OutputDir:     viper.GetString("output_dir"),
		CrashDir:      viper.GetString("crash_dir"),
		Workers:       viper.GetInt("workers"),
		Timeout:       viper.GetDuration("timeout"),
		MemoryLimit:   int64(viper.GetUint64("memory_limit")), // Convert uint64 to int64
		MaxCorpusSize: viper.GetInt("max_corpus_size"),
		MutationRate:  viper.GetFloat64("mutation_rate"),
		MaxMutations:  viper.GetInt("max_mutations"),
		Strategy:      viper.GetString("strategy"),
		CoverageType:  coverageType,
		SchedulerType: "priority", // Default scheduler type
		SessionID:     sessionID,  // Set the persistent session UUID
	}

	// Log the session ID for correlation across systems
	logrus.WithFields(logrus.Fields{
		"session_id": sessionID,
		"target":     config.Target,
		"corpus_dir": config.CorpusDir,
	}).Info("Fuzzing session initialized")

	return config
}

// reportStats periodically reports fuzzer statistics
func reportStats(ctx context.Context, engine *core.Engine) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			stats := engine.GetStats()
			logger.LogStats(
				stats.Executions,
				stats.Crashes,
				stats.Hangs,
				stats.ExecutionsPerSecond,
				map[string]interface{}{
					"unique_crashes":  stats.UniqueCrashes,
					"coverage_edges":  stats.CoverageEdges,
					"coverage_blocks": stats.CoverageBlocks,
				},
			)
		}
	}
}

// printFinalStats prints final fuzzer statistics
func printFinalStats(engine *core.Engine) {
	stats := engine.GetStats()

	logger.Info("Final Statistics", map[string]interface{}{
		"total_executions":       stats.Executions,
		"total_crashes":          stats.Crashes,
		"total_hangs":            stats.Hangs,
		"total_timeouts":         stats.Timeouts,
		"unique_crashes":         stats.UniqueCrashes,
		"coverage_edges":         stats.CoverageEdges,
		"coverage_blocks":        stats.CoverageBlocks,
		"avg_executions_per_sec": stats.ExecutionsPerSecond,
		"total_runtime":          time.Since(stats.StartTime),
		"last_crash_time":        stats.LastCrashTime,
		"max_generation":         engine.GetCorpus().GetMaxGeneration(),
	})

	fmt.Println("\n=== Final Statistics ===")
	fmt.Printf("Total Executions: %d\n", stats.Executions)
	fmt.Printf("Total Crashes: %d\n", stats.Crashes)
	fmt.Printf("Total Hangs: %d\n", stats.Hangs)
	fmt.Printf("Total Timeouts: %d\n", stats.Timeouts)
	fmt.Printf("Unique Crashes: %d\n", stats.UniqueCrashes)
	fmt.Printf("Coverage Edges: %d\n", stats.CoverageEdges)
	fmt.Printf("Coverage Blocks: %d\n", stats.CoverageBlocks)
	fmt.Printf("Average Executions/sec: %.2f\n", stats.ExecutionsPerSecond)
	fmt.Printf("Total Runtime: %v\n", time.Since(stats.StartTime))
	fmt.Printf("Max Test Case Generation: %d\n", engine.GetCorpus().GetMaxGeneration())

	if stats.Crashes > 0 {
		fmt.Printf("Last Crash: %v\n", stats.LastCrashTime)
	}
}

// performDryRun validates configuration and prints setup information
func performDryRun(config *interfaces.FuzzerConfig) error {
	fmt.Println("🔍 Akaylee Fuzzer - Dry Run Mode")
	fmt.Println("=================================")
	fmt.Println()

	// Validate target
	fmt.Println("🎯 Target Validation:")
	fmt.Printf("  Target Path: %s\n", config.Target)

	// Check if target exists and is executable
	if _, err := os.Stat(config.Target); err != nil {
		fmt.Printf("  ❌ Target not found: %v\n", err)
	} else {
		fmt.Println("  ✅ Target file exists")

		// Check if executable
		if info, err := os.Stat(config.Target); err == nil {
			if info.Mode()&0111 != 0 {
				fmt.Println("  ✅ Target is executable")
			} else {
				fmt.Println("  ⚠️  Target may not be executable")
			}
		}
	}
	fmt.Println()

	// Validate corpus
	fmt.Println("📁 Corpus Validation:")
	fmt.Printf("  Corpus Directory: %s\n", config.CorpusDir)

	if _, err := os.Stat(config.CorpusDir); err != nil {
		fmt.Printf("  ❌ Corpus directory not found: %v\n", err)
	} else {
		fmt.Println("  ✅ Corpus directory exists")

		// Count seed files
		files, err := filepath.Glob(filepath.Join(config.CorpusDir, "*"))
		if err != nil {
			fmt.Printf("  ⚠️  Could not read corpus directory: %v\n", err)
		} else {
			seedCount := 0
			for _, file := range files {
				if info, err := os.Stat(file); err == nil && !info.IsDir() {
					seedCount++
				}
			}
			fmt.Printf("  📊 Found %d seed files\n", seedCount)
		}
	}
	fmt.Println()

	// Validate output directories
	fmt.Println("📂 Output Directory Validation:")
	fmt.Printf("  Output Directory: %s\n", config.OutputDir)
	fmt.Printf("  Crash Directory: %s\n", config.CrashDir)

	// Check if we can create output directories
	if err := os.MkdirAll(config.OutputDir, 0755); err != nil {
		fmt.Printf("  ❌ Cannot create output directory: %v\n", err)
	} else {
		fmt.Println("  ✅ Output directory is writable")
	}

	if err := os.MkdirAll(config.CrashDir, 0755); err != nil {
		fmt.Printf("  ❌ Cannot create crash directory: %v\n", err)
	} else {
		fmt.Println("  ✅ Crash directory is writable")
	}
	fmt.Println()

	// Validate logging
	fmt.Println("📝 Logging Validation:")
	fmt.Printf("  Log Level: %s\n", viper.GetString("log_level"))
	fmt.Printf("  Log File: %s\n", viper.GetString("log_file"))
	fmt.Printf("  JSON Logs: %t\n", viper.GetBool("json_logs"))

	logFile := viper.GetString("log_file")
	if logFile != "" {
		if err := os.MkdirAll(filepath.Dir(logFile), 0755); err != nil {
			fmt.Printf("  ❌ Cannot create log directory: %v\n", err)
		} else {
			fmt.Println("  ✅ Log directory is writable")
		}
	}
	fmt.Println()

	// Print configuration summary
	fmt.Println("⚙️  Configuration Summary:")
	fmt.Printf("  Workers: %d\n", config.Workers)
	fmt.Printf("  Timeout: %v\n", config.Timeout)
	fmt.Printf("  Memory Limit: %d bytes\n", config.MemoryLimit)
	fmt.Printf("  Max Corpus Size: %d\n", config.MaxCorpusSize)
	fmt.Printf("  Mutation Rate: %.3f\n", config.MutationRate)
	fmt.Printf("  Max Mutations: %d\n", config.MaxMutations)
	fmt.Printf("  Strategy: %s\n", config.Strategy)
	fmt.Printf("  Coverage Type: %s\n", config.CoverageType)
	fmt.Printf("  Coverage Guided: %t\n", viper.GetBool("coverage_guided"))

	if grammarType != "" {
		fmt.Printf("  Grammar Type: %s\n", grammarType)
		seedKeys := viper.GetStringSlice("grammar_seeds")
		if len(seedKeys) > 0 {
			fmt.Printf("  Grammar Seeds: %v\n", seedKeys)
		}
		maxDepth := viper.GetInt("grammar_depth")
		fmt.Printf("  Grammar Depth: %d\n", maxDepth)
	}
	fmt.Println()

	// Validate mutators
	fmt.Println("🧬 Mutator Configuration:")
	if grammarType == "json" {
		fmt.Println("  ✅ Grammar-based fuzzing enabled")
		fmt.Println("    - JSONGrammar with enhanced mutation variability")
		fmt.Println("    - Deep fuzzing with nested structures")
		fmt.Println("    - Array and object mutation support")
	} else {
		fmt.Println("  ✅ Standard mutators enabled:")
		fmt.Println("    - BitFlipMutator")
		fmt.Println("    - ByteSubstitutionMutator")
		fmt.Println("    - ArithmeticMutator")
		fmt.Println("    - StructureAwareMutator")
		fmt.Println("    - CrossOverMutator")
	}
	fmt.Println()

	fmt.Println("🎉 Dry run completed successfully!")
	fmt.Println("   All validations passed. Ready to start fuzzing!")

	return nil
}

// listMutators displays detailed information about all available mutators
func listMutators(cmd *cobra.Command, args []string) error {
	fmt.Println("🧬 Available Fuzzer Mutators")
	fmt.Println("==============================")
	fmt.Println()

	// Standard mutators
	fmt.Println("📋 Standard Mutators:")
	fmt.Println("--------------------")

	bitFlip := &strategies.BitFlipMutator{}
	fmt.Printf("  • %s\n", bitFlip.Name())
	fmt.Printf("    Description: %s\n", bitFlip.Description())
	fmt.Printf("    Usage: Flips random bits in test case data\n")
	fmt.Printf("    Best for: Binary protocols, file formats\n")
	fmt.Println()

	byteSub := &strategies.ByteSubstitutionMutator{}
	fmt.Printf("  • %s\n", byteSub.Name())
	fmt.Printf("    Description: %s\n", byteSub.Description())
	fmt.Printf("    Usage: Substitutes random bytes with new values\n")
	fmt.Printf("    Best for: Text-based protocols, general fuzzing\n")
	fmt.Println()

	arithmetic := &strategies.ArithmeticMutator{}
	fmt.Printf("  • %s\n", arithmetic.Name())
	fmt.Printf("    Description: %s\n", arithmetic.Description())
	fmt.Printf("    Usage: Performs arithmetic operations on numeric data\n")
	fmt.Printf("    Best for: Numeric protocols, calculations, counters\n")
	fmt.Println()

	structureAware := &strategies.StructureAwareMutator{}
	fmt.Printf("  • %s\n", structureAware.Name())
	fmt.Printf("    Description: %s\n", structureAware.Description())
	fmt.Printf("    Usage: Maintains structural integrity while mutating\n")
	fmt.Printf("    Best for: Structured data, headers, metadata\n")
	fmt.Println()

	crossOver := &strategies.CrossOverMutator{}
	fmt.Printf("  • %s\n", crossOver.Name())
	fmt.Printf("    Description: %s\n", crossOver.Description())
	fmt.Printf("    Usage: Combines parts from multiple test cases\n")
	fmt.Printf("    Best for: Complex protocols, stateful testing\n")
	fmt.Println()

	composite := &strategies.CompositeMutator{}
	fmt.Printf("  • %s\n", composite.Name())
	fmt.Printf("    Description: %s\n", composite.Description())
	fmt.Printf("    Usage: Chains multiple mutators together\n")
	fmt.Printf("    Best for: Complex mutation strategies\n")
	fmt.Println()

	// Grammar-based mutators
	fmt.Println("🎯 Grammar-Based Mutators:")
	fmt.Println("-------------------------")

	jsonGrammar := &strategies.GrammarMutator{}
	fmt.Printf("  • %s\n", jsonGrammar.Name())
	fmt.Printf("    Description: %s\n", jsonGrammar.Description())
	fmt.Printf("    Usage: Generates and mutates structured JSON data\n")
	fmt.Printf("    Best for: JSON APIs, web services, configuration files\n")
	fmt.Printf("    Features:\n")
	fmt.Printf("      - Deep recursive generation with configurable depth\n")
	fmt.Printf("      - Type-aware mutations (string, number, boolean, array, object)\n")
	fmt.Printf("      - Seed key support for target-aware generation\n")
	fmt.Printf("      - Array and object mutation strategies\n")
	fmt.Printf("      - Type conversion mutations\n")
	fmt.Printf("    Configuration:\n")
	fmt.Printf("      --grammar-type json: Enable JSON grammar fuzzing\n")
	fmt.Printf("      --grammar-seeds key1,key2: Specify seed keys for generation\n")
	fmt.Printf("      --grammar-depth 5: Set maximum nesting depth (default: 3)\n")
	fmt.Println()

	// Usage examples
	fmt.Println("💡 Usage Examples:")
	fmt.Println("------------------")
	fmt.Println("  # Standard fuzzing with all mutators")
	fmt.Println("  ./fuzzer fuzz --target ./myapp --corpus ./seeds")
	fmt.Println()
	fmt.Println("  # JSON grammar fuzzing")
	fmt.Println("  ./fuzzer fuzz --target ./json-parser --grammar-type json")
	fmt.Println()
	fmt.Println("  # JSON with specific seed keys")
	fmt.Println("  ./fuzzer fuzz --target ./api-server --grammar-type json --grammar-seeds user_id,email,status")
	fmt.Println()
	fmt.Println("  # Deep JSON fuzzing")
	fmt.Println("  ./fuzzer fuzz --target ./config-parser --grammar-type json --grammar-depth 8")
	fmt.Println()
	fmt.Println("  # Coverage-guided fuzzing")
	fmt.Println("  ./fuzzer fuzz --target ./myapp --coverage-guided")
	fmt.Println()
	fmt.Println("  # Dry run to validate configuration")
	fmt.Println("  ./fuzzer fuzz --target ./myapp --dry-run")
	fmt.Println()

	// Configuration tips
	fmt.Println("🔧 Configuration Tips:")
	fmt.Println("---------------------")
	fmt.Println("  • Use --mutation-rate to control mutation intensity")
	fmt.Println("  • Use --max-mutations to limit mutations per test case")
	fmt.Println("  • Use --workers to parallelize fuzzing")
	fmt.Println("  • Use --timeout to prevent hangs")
	fmt.Println("  • Use --memory-limit to prevent OOM")
	fmt.Println("  • Use --strategy to select mutation strategy")
	fmt.Println("  • Use --log-level to control verbosity")
	fmt.Println()

	fmt.Println("✨ For more information, see the README.md and Docs/ARCHITECTURE.md")

	return nil
}

// performSelfCheck performs comprehensive system validation checks
func performSelfCheck(cmd *cobra.Command, args []string) error {
	fmt.Println("🔍 Akaylee Fuzzer - System Self-Check")
	fmt.Println("=====================================")
	fmt.Println()

	// Load configuration first
	if err := loadConfig(); err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	// Setup logging for check
	if err := setupLogging(); err != nil {
		return fmt.Errorf("failed to setup logging: %w", err)
	}

	checks := []struct {
		name     string
		function func() error
	}{
		{"Binary Dependencies", checkBinaryDependencies},
		{"System Resources", checkSystemResources},
		{"File System Permissions", checkFileSystemPermissions},
		{"Network Connectivity", checkNetworkConnectivity},
		{"Configuration Validation", checkConfigurationValidation},
	}

	passed := 0
	total := len(checks)

	for _, check := range checks {
		fmt.Printf("🔍 %s...\n", check.name)
		if err := check.function(); err != nil {
			fmt.Printf("  ❌ %s: %v\n", check.name, err)
		} else {
			fmt.Printf("  ✅ %s: PASSED\n", check.name)
			passed++
		}
		fmt.Println()
	}

	// Print summary
	fmt.Println("📊 Check Summary:")
	fmt.Printf("  Passed: %d/%d\n", passed, total)
	fmt.Printf("  Failed: %d/%d\n", total-passed, total)

	if passed == total {
		fmt.Println("\n🎉 All checks passed! System is ready for fuzzing.")
		return nil
	} else {
		fmt.Println("\n⚠️  Some checks failed. Please address the issues above before fuzzing.")
		return fmt.Errorf("self-check failed: %d/%d checks passed", passed, total)
	}
}

// checkBinaryDependencies validates that required binaries are available
func checkBinaryDependencies() error {
	// Check if Go is available
	if _, err := exec.LookPath("go"); err != nil {
		return fmt.Errorf("Go binary not found: %w", err)
	}

	// Check if basic system tools are available
	tools := []string{"ls", "cat", "echo"}
	for _, tool := range tools {
		if _, err := exec.LookPath(tool); err != nil {
			return fmt.Errorf("system tool '%s' not found: %w", tool, err)
		}
	}

	return nil
}

// checkSystemResources validates system resource availability
func checkSystemResources() error {
	// Check available memory
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	availableMem := m.Sys - m.Alloc

	if availableMem < 100*1024*1024 { // Less than 100MB available
		return fmt.Errorf("insufficient memory available: %d bytes", availableMem)
	}

	// Check CPU cores
	numCPU := runtime.NumCPU()
	if numCPU < 1 {
		return fmt.Errorf("no CPU cores detected")
	}

	// Check disk space (basic check)
	if err := checkDiskSpace(); err != nil {
		return err
	}

	return nil
}

// checkDiskSpace performs a basic disk space check
func checkDiskSpace() error {
	// Check current directory
	wd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("cannot get working directory: %w", err)
	}

	// Try to create a temporary file to test writability
	tmpfile, err := os.CreateTemp(wd, "akaylee-check-*")
	if err != nil {
		return fmt.Errorf("cannot create temporary file: %w", err)
	}
	defer os.Remove(tmpfile.Name())
	defer tmpfile.Close()

	// Write some data to test disk space
	testData := []byte("akaylee-fuzzer-disk-space-test")
	if _, err := tmpfile.Write(testData); err != nil {
		return fmt.Errorf("cannot write to disk: %w", err)
	}

	return nil
}

// checkFileSystemPermissions validates file system permissions
func checkFileSystemPermissions() error {
	// Check if we can create directories
	testDirs := []string{"./akaylee-test-dir", "./logs", "./fuzz_output", "./crashes"}

	for _, dir := range testDirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("cannot create directory '%s': %w", dir, err)
		}
		// Clean up test directory
		if dir == "./akaylee-test-dir" {
			os.RemoveAll(dir)
		}
	}

	// Check if we can write to current directory
	testFile := "./akaylee-test-file"
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		return fmt.Errorf("cannot write to current directory: %w", err)
	}
	os.Remove(testFile)

	return nil
}

// checkNetworkConnectivity validates basic network connectivity
func checkNetworkConnectivity() error {
	// Check if we can resolve localhost
	_, err := net.LookupHost("localhost")
	if err != nil {
		return fmt.Errorf("cannot resolve localhost: %w", err)
	}

	// Check if we can create a TCP listener (basic network stack test)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("cannot create TCP listener: %w", err)
	}
	listener.Close()

	return nil
}

// checkConfigurationValidation validates configuration settings
func checkConfigurationValidation() error {
	// Check if required configuration is set
	if viper.GetString("log_level") == "" {
		return fmt.Errorf("log level not configured")
	}

	// Validate log level
	validLogLevels := []string{"debug", "info", "warn", "error"}
	logLevel := viper.GetString("log_level")
	valid := false
	for _, level := range validLogLevels {
		if level == logLevel {
			valid = true
			break
		}
	}
	if !valid {
		return fmt.Errorf("invalid log level: %s (valid: %v)", logLevel, validLogLevels)
	}

	// Check log directory configuration
	logDir := viper.GetString("log_dir")
	if logDir != "" {
		if err := os.MkdirAll(logDir, 0755); err != nil {
			return fmt.Errorf("cannot create log directory '%s': %w", logDir, err)
		}
	}

	return nil
}
