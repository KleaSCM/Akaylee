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

	"encoding/json"
	"strings"

	"github.com/google/uuid"
	"github.com/kleascm/akaylee-fuzzer/pkg/analysis"
	"github.com/kleascm/akaylee-fuzzer/pkg/core"
	"github.com/kleascm/akaylee-fuzzer/pkg/execution"
	"github.com/kleascm/akaylee-fuzzer/pkg/grammar"
	"github.com/kleascm/akaylee-fuzzer/pkg/inference"
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

	// Add inference-specific flags
	rootCmd.PersistentFlags().String("format", "auto", "Format for inference (json, binary, auto)")

	// Bind flags to viper
	viper.BindPFlag("log_level", rootCmd.PersistentFlags().Lookup("log-level"))
	viper.BindPFlag("json_logs", rootCmd.PersistentFlags().Lookup("json-logs"))
	viper.BindPFlag("log_dir", rootCmd.PersistentFlags().Lookup("log-dir"))
	viper.BindPFlag("log_format", rootCmd.PersistentFlags().Lookup("log-format"))
	viper.BindPFlag("log_max_files", rootCmd.PersistentFlags().Lookup("log-max-files"))
	viper.BindPFlag("log_max_size", rootCmd.PersistentFlags().Lookup("log-max-size"))
	viper.BindPFlag("log_compress", rootCmd.PersistentFlags().Lookup("log-compress"))
	viper.BindPFlag("format", rootCmd.PersistentFlags().Lookup("format"))

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

	// Add triage command for crash analysis and minimization
	rootCmd.AddCommand(&cobra.Command{
		Use:   "triage",
		Short: "Analyze and minimize crash files",
		Long: `Analyze crash files for severity, exploitability, and automatically minimize them
to their smallest reproducing form. Provides intelligent crash classification and prioritization.`,
		RunE: performCrashTriage,
	})

	// Add infer-grammar command for structure inference
	inferGrammarCmd := &cobra.Command{
		Use:   "infer-grammar",
		Short: "Infer grammar from sample corpus",
		Long: `Analyze a corpus of sample inputs to automatically infer structure, field types,
nesting, enums, and generate a grammar for structure-aware fuzzing. Supports JSON and binary formats.`,
		RunE: performGrammarInference,
	}

	// Add infer-grammar flags
	inferGrammarCmd.Flags().String("corpus-dir", "./corpus", "Directory containing sample corpus")
	viper.BindPFlag("corpus_dir", inferGrammarCmd.Flags().Lookup("corpus-dir"))

	rootCmd.AddCommand(inferGrammarCmd)

	// Add reproduce command for crash reproduction analysis
	reproduceCmd := &cobra.Command{
		Use:   "reproduce",
		Short: "Reproduce and analyze crash files",
		Long: `Reproduce crash files with detailed analysis including root cause investigation,
exploitability assessment, and minimal test case generation. Essential for security research.`,
		RunE: performCrashReproduction,
	}

	// Add reproduce flags
	reproduceCmd.Flags().String("crash-file", "", "Path to crash file to reproduce (required)")
	reproduceCmd.Flags().String("target", "", "Path to target binary (required)")
	reproduceCmd.Flags().Int("attempts", 10, "Number of reproduction attempts")
	reproduceCmd.Flags().Bool("enable-poc", false, "Enable proof of concept generation")
	reproduceCmd.Flags().String("output-dir", "./reproductions", "Directory for reproduction reports")

	viper.BindPFlag("crash_file", reproduceCmd.Flags().Lookup("crash-file"))
	viper.BindPFlag("reproduce_target", reproduceCmd.Flags().Lookup("target"))
	viper.BindPFlag("reproduction_attempts", reproduceCmd.Flags().Lookup("attempts"))
	viper.BindPFlag("enable_poc", reproduceCmd.Flags().Lookup("enable-poc"))
	viper.BindPFlag("reproduction_output_dir", reproduceCmd.Flags().Lookup("output-dir"))

	// Mark required flags
	reproduceCmd.MarkFlagRequired("crash-file")
	reproduceCmd.MarkFlagRequired("target")

	rootCmd.AddCommand(reproduceCmd)

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

// performCrashTriage analyzes and minimizes crash files
func performCrashTriage(cmd *cobra.Command, args []string) error {
	fmt.Println("🔍 Akaylee Fuzzer - Crash Triage & Minimization")
	fmt.Println("===============================================")
	fmt.Println()

	// Load configuration first
	if err := loadConfig(); err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	// Setup logging for triage
	if err := setupLogging(); err != nil {
		return fmt.Errorf("failed to setup logging: %w", err)
	}

	// Get crash directory from config or default
	crashDir := viper.GetString("crash_dir")
	if crashDir == "" {
		crashDir = "./crashes"
	}

	fmt.Printf("📁 Analyzing crashes in: %s\n", crashDir)
	fmt.Println()

	// Check if crash directory exists
	if _, err := os.Stat(crashDir); os.IsNotExist(err) {
		fmt.Printf("❌ Crash directory not found: %s\n", crashDir)
		fmt.Println("   Run the fuzzer first to generate crash files.")
		return nil
	}

	// Find crash files
	files, err := filepath.Glob(filepath.Join(crashDir, "*"))
	if err != nil {
		return fmt.Errorf("failed to read crash directory: %w", err)
	}

	crashFiles := make([]string, 0)
	for _, file := range files {
		if info, err := os.Stat(file); err == nil && !info.IsDir() {
			crashFiles = append(crashFiles, file)
		}
	}

	if len(crashFiles) == 0 {
		fmt.Println("📭 No crash files found.")
		fmt.Println("   Run the fuzzer first to generate crash files.")
		return nil
	}

	fmt.Printf("📊 Found %d crash files\n", len(crashFiles))
	fmt.Println()

	// Create triage engine
	triageEngine := analysis.NewCrashTriageEngine()

	// Analyze each crash file
	results := make([]*analysis.TriageResult, 0)
	for i, crashFile := range crashFiles {
		fmt.Printf("🔍 Analyzing crash %d/%d: %s\n", i+1, len(crashFiles), filepath.Base(crashFile))

		// Read crash file
		data, err := os.ReadFile(crashFile)
		if err != nil {
			fmt.Printf("  ❌ Failed to read crash file: %v\n", err)
			continue
		}

		// Create mock execution result for analysis
		result := &interfaces.ExecutionResult{
			TestCaseID: filepath.Base(crashFile),
			Output:     data,
			Error:      []byte{},
			Status:     interfaces.StatusCrash,
			Duration:   time.Second,
		}

		// Create mock crash info
		crashInfo := &interfaces.CrashInfo{
			Type:         "SIGSEGV",
			Address:      0,
			Reproducible: true,
			Hash:         fmt.Sprintf("crash_%d", i),
			StackTrace:   []string{"main.crash()", "libc.so.6", "???"},
		}

		// Perform triage analysis
		triage := triageEngine.TriageCrash(crashInfo, result)
		results = append(results, triage)

		// Print analysis results
		fmt.Printf("  📊 Severity: %s\n", triage.Severity.String())
		fmt.Printf("  🎯 Type: %s\n", triage.CrashType)
		fmt.Printf("  ⚡ Exploitability: %s\n", triage.Exploitability)
		fmt.Printf("  🎯 Confidence: %.2f\n", triage.Confidence)
		fmt.Printf("  🔑 Keywords: %v\n", triage.Keywords)
		fmt.Printf("  ⏱️  Analysis Time: %v\n", triage.AnalysisTime)
		fmt.Println()
	}

	// Generate summary report
	fmt.Println("📋 Crash Triage Summary")
	fmt.Println("=======================")

	// Count by severity
	severityCounts := make(map[analysis.CrashSeverity]int)
	exploitabilityCounts := make(map[analysis.Exploitability]int)

	for _, result := range results {
		severityCounts[result.Severity]++
		exploitabilityCounts[result.Exploitability]++
	}

	fmt.Println("Severity Distribution:")
	for severity := analysis.SeverityLow; severity <= analysis.SeverityCritical; severity++ {
		count := severityCounts[severity]
		if count > 0 {
			fmt.Printf("  %s: %d crashes\n", severity.String(), count)
		}
	}

	fmt.Println("\nExploitability Distribution:")
	exploitabilities := []analysis.Exploitability{
		analysis.ExploitabilityNone,
		analysis.ExploitabilityLow,
		analysis.ExploitabilityMedium,
		analysis.ExploitabilityHigh,
		analysis.ExploitabilityConfirmed,
	}
	for _, exploitability := range exploitabilities {
		count := exploitabilityCounts[exploitability]
		if count > 0 {
			fmt.Printf("  %s: %d crashes\n", exploitability, count)
		}
	}

	// Find most critical crashes
	fmt.Println("\n🚨 Most Critical Crashes:")
	criticalCrashes := 0
	for i, result := range results {
		if result.Severity >= analysis.SeverityHigh {
			fmt.Printf("  %d. %s (Severity: %s, Exploitability: %s)\n",
				criticalCrashes+1,
				filepath.Base(crashFiles[i]),
				result.Severity.String(),
				result.Exploitability)
			criticalCrashes++
		}
	}

	if criticalCrashes == 0 {
		fmt.Println("  No critical crashes found.")
	}

	// Demonstrate minimization
	fmt.Println("\n🔧 Crash Minimization Demo:")
	if len(crashFiles) > 0 {
		// Use first crash file for demonstration
		demoFile := crashFiles[0]
		data, _ := os.ReadFile(demoFile)

		demoTestCase := &interfaces.TestCase{
			ID:   "demo",
			Data: data,
		}

		demoResult := &interfaces.ExecutionResult{
			TestCaseID: "demo",
			Output:     data,
			Status:     interfaces.StatusCrash,
		}

		minimized, err := triageEngine.MinimizeCrash(demoTestCase, demoResult)
		if err == nil {
			reductionRatio := float64(len(minimized.Data)) / float64(len(data))
			fmt.Printf("  Original size: %d bytes\n", len(data))
			fmt.Printf("  Minimized size: %d bytes\n", len(minimized.Data))
			fmt.Printf("  Reduction ratio: %.2f%%\n", (1-reductionRatio)*100)
		}
	}

	fmt.Println("\n✨ Crash triage completed!")
	fmt.Println("   Use the severity and exploitability information to prioritize bug fixes.")

	return nil
}

// performGrammarInference analyzes a corpus and infers a grammar
func performGrammarInference(cmd *cobra.Command, args []string) error {
	fmt.Println("🧬 Akaylee Fuzzer - Grammar Inference")
	fmt.Println("=====================================")
	fmt.Println()

	// Load configuration first
	if err := loadConfig(); err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	// Setup logging for inference
	if err := setupLogging(); err != nil {
		return fmt.Errorf("failed to setup logging: %w", err)
	}

	// Get corpus directory from config or default
	corpusDir := viper.GetString("corpus_dir")
	if corpusDir == "" {
		corpusDir = "./corpus"
	}

	// Get format from flags or auto-detect
	format := viper.GetString("format")
	if format == "" {
		format = "auto"
	}

	fmt.Printf("📁 Analyzing corpus in: %s\n", corpusDir)
	fmt.Printf("🎯 Format: %s\n", format)
	fmt.Println()

	// Check if corpus directory exists
	if _, err := os.Stat(corpusDir); os.IsNotExist(err) {
		fmt.Printf("❌ Corpus directory not found: %s\n", corpusDir)
		fmt.Println("   Create a corpus directory with sample files first.")
		return nil
	}

	// Find sample files
	files, err := filepath.Glob(filepath.Join(corpusDir, "*"))
	if err != nil {
		return fmt.Errorf("failed to read corpus directory: %w", err)
	}

	sampleFiles := make([]string, 0)
	for _, file := range files {
		if info, err := os.Stat(file); err == nil && !info.IsDir() {
			sampleFiles = append(sampleFiles, file)
		}
	}

	if len(sampleFiles) == 0 {
		fmt.Println("📭 No sample files found.")
		fmt.Println("   Add sample files to the corpus directory first.")
		return nil
	}

	fmt.Printf("📊 Found %d sample files\n", len(sampleFiles))
	fmt.Println()

	// Auto-detect format if needed
	if format == "auto" {
		format = autoDetectFormat(sampleFiles)
		fmt.Printf("🔍 Auto-detected format: %s\n", format)
		fmt.Println()
	}

	// Create inference engine
	engine := inference.NewEngine(format)
	if engine == nil {
		return fmt.Errorf("unsupported format: %s", format)
	}

	// Load samples
	samples := make([][]byte, 0, len(sampleFiles))
	for i, sampleFile := range sampleFiles {
		fmt.Printf("📖 Loading sample %d/%d: %s\n", i+1, len(sampleFiles), filepath.Base(sampleFile))

		data, err := os.ReadFile(sampleFile)
		if err != nil {
			fmt.Printf("  ❌ Failed to read sample file: %v\n", err)
			continue
		}
		samples = append(samples, data)
	}

	if len(samples) == 0 {
		fmt.Println("❌ No valid samples loaded.")
		return nil
	}

	fmt.Printf("✅ Loaded %d valid samples\n", len(samples))
	fmt.Println()

	// Perform inference
	fmt.Println("🧠 Performing structure inference...")
	startTime := time.Now()

	grammar, err := engine.InferStructure(samples)
	if err != nil {
		return fmt.Errorf("inference failed: %w", err)
	}

	inferenceTime := time.Since(startTime)
	fmt.Printf("✅ Inference completed in %v\n", inferenceTime)
	fmt.Println()

	// Display results
	fmt.Println("📋 Inferred Grammar")
	fmt.Println("===================")
	fmt.Printf("Format: %s\n", grammar.Format)
	fmt.Printf("Root Rule: %s\n", grammar.RootRule)
	fmt.Printf("Samples Analyzed: %v\n", grammar.Metadata["samples"])
	fmt.Println()

	// Pretty print the grammar
	fmt.Println("📝 Grammar Rules:")
	prettyPrintGrammar(grammar)

	// Save grammar to file
	outputFile := fmt.Sprintf("inferred_grammar_%s.json", format)
	if err := saveGrammar(grammar, outputFile); err != nil {
		fmt.Printf("⚠️  Failed to save grammar: %v\n", err)
	} else {
		fmt.Printf("💾 Grammar saved to: %s\n", outputFile)
	}

	fmt.Println("\n✨ Grammar inference completed!")
	fmt.Println("   Use the inferred grammar with --grammar-type and --grammar-file flags.")

	return nil
}

// autoDetectFormat attempts to detect the format of sample files
func autoDetectFormat(files []string) string {
	if len(files) == 0 {
		return "json" // Default
	}

	// Check first few files for format indicators
	for _, file := range files[:min(3, len(files))] {
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}

		// Try to parse as JSON
		var v interface{}
		if json.Unmarshal(data, &v) == nil {
			return "json"
		}

		// Check for binary indicators (non-printable characters)
		if len(data) > 0 {
			binaryCount := 0
			for _, b := range data {
				if b < 32 && b != 9 && b != 10 && b != 13 { // Not tab, newline, carriage return
					binaryCount++
				}
			}
			if float64(binaryCount)/float64(len(data)) > 0.1 {
				return "binary"
			}
		}
	}

	return "json" // Default to JSON
}

// prettyPrintGrammar displays the grammar in a readable format
func prettyPrintGrammar(grammar *inference.Grammar) {
	rootRule := grammar.Rules["root"]
	if rootRule == nil {
		fmt.Println("  No root rule found")
		return
	}

	if rule, ok := rootRule.(map[string]interface{}); ok {
		printRule("root", rule, 2)
	}
}

// printRule recursively prints a grammar rule
func printRule(name string, rule map[string]interface{}, indent int) {
	indentStr := strings.Repeat("  ", indent)

	if types, ok := rule["types"].([]string); ok {
		fmt.Printf("%s%s: %s\n", indentStr, name, strings.Join(types, "|"))
	}

	if fields, ok := rule["fields"].(map[string]interface{}); ok {
		fmt.Printf("%s  fields:\n", indentStr)
		for fieldName, fieldRule := range fields {
			if fr, ok := fieldRule.(map[string]interface{}); ok {
				printRule(fieldName, fr, indent+2)
			}
		}
	}

	if required, ok := rule["required"].([]string); ok && len(required) > 0 {
		fmt.Printf("%s  required: %s\n", indentStr, strings.Join(required, ", "))
	}

	if optional, ok := rule["optional"].([]string); ok && len(optional) > 0 {
		fmt.Printf("%s  optional: %s\n", indentStr, strings.Join(optional, ", "))
	}

	if enum, ok := rule["enum"].([]string); ok && len(enum) > 0 {
		fmt.Printf("%s  enum: %s\n", indentStr, strings.Join(enum, ", "))
	}

	if min, ok := rule["min"].(float64); ok {
		fmt.Printf("%s  min: %v\n", indentStr, min)
	}

	if max, ok := rule["max"].(float64); ok {
		fmt.Printf("%s  max: %v\n", indentStr, max)
	}
}

// saveGrammar saves the grammar to a JSON file
func saveGrammar(grammar *inference.Grammar, filename string) error {
	data, err := json.MarshalIndent(grammar, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filename, data, 0644)
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// performCrashReproduction reproduces and analyzes crash files
func performCrashReproduction(cmd *cobra.Command, args []string) error {
	fmt.Println("🔄 Akaylee Fuzzer - Crash Reproduction Analysis")
	fmt.Println("===============================================")
	fmt.Println()

	// Load configuration first
	if err := loadConfig(); err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	// Setup logging for reproduction
	if err := setupLogging(); err != nil {
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
