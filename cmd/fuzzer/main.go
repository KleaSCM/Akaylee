/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: main.go
Description: Main command-line interface for the Akaylee Fuzzer. Provides comprehensive
command-line options, configuration management, and beautiful user interface for
controlling the fuzzing process.
*/

package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kleascm/akaylee-fuzzer/pkg/core"
	"github.com/kleascm/akaylee-fuzzer/pkg/interfaces"
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
)

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

	// Bind flags to viper
	viper.BindPFlag("log_level", rootCmd.PersistentFlags().Lookup("log-level"))
	viper.BindPFlag("json_logs", rootCmd.PersistentFlags().Lookup("json-logs"))

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

	// Create fuzzer configuration
	config := createFuzzerConfig()

	// Create and initialize fuzzer engine
	engine := core.NewEngine()
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
		logrus.Infof("Received signal %v, shutting down gracefully...", sig)
		cancel()
	}()

	// Start fuzzer
	logrus.Info("Starting Akaylee Fuzzer...")
	if err := engine.Start(); err != nil {
		return fmt.Errorf("failed to start fuzzer: %w", err)
	}

	// Start statistics reporting
	go reportStats(ctx, engine)

	// Wait for context cancellation
	<-ctx.Done()

	// Stop fuzzer
	logrus.Info("Stopping fuzzer...")
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
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return fmt.Errorf("failed to read config file: %w", err)
		}
	}

	return nil
}

// setupLogging configures the logging system
func setupLogging() error {
	level, err := logrus.ParseLevel(viper.GetString("log_level"))
	if err != nil {
		level = logrus.InfoLevel
	}
	logrus.SetLevel(level)

	if viper.GetBool("json_logs") {
		logrus.SetFormatter(&logrus.JSONFormatter{})
	} else {
		logrus.SetFormatter(&logrus.TextFormatter{
			FullTimestamp: true,
			ForceColors:   true,
		})
	}

	return nil
}

// createFuzzerConfig creates the fuzzer configuration from viper
func createFuzzerConfig() *interfaces.FuzzerConfig {
	return &interfaces.FuzzerConfig{
		// Target configuration
		TargetPath: viper.GetString("target_path"),
		TargetArgs: viper.GetStringSlice("target_args"),
		TargetEnv:  viper.GetStringSlice("target_env"),

		// Execution configuration
		Workers:     viper.GetInt("workers"),
		Timeout:     viper.GetDuration("timeout"),
		MemoryLimit: viper.GetUint64("memory_limit"),

		// Corpus configuration
		CorpusDir:     viper.GetString("corpus_dir"),
		OutputDir:     viper.GetString("output_dir"),
		MaxCorpusSize: viper.GetInt("max_corpus_size"),

		// Mutation configuration
		MutationRate: viper.GetFloat64("mutation_rate"),
		MaxMutations: viper.GetInt("max_mutations"),
		Strategy:     viper.GetString("strategy"),

		// Coverage configuration
		CoverageType:  viper.GetString("coverage_type"),
		BitmapSize:    viper.GetInt("bitmap_size"),
		EdgeThreshold: viper.GetInt("edge_threshold"),

		// Crash configuration
		MaxCrashes: viper.GetInt("max_crashes"),
		CrashDir:   viper.GetString("crash_dir"),
		Reproduce:  viper.GetBool("reproduce"),

		// Performance configuration
		EnableGC:      viper.GetBool("enable_gc"),
		ProfileCPU:    viper.GetBool("profile_cpu"),
		ProfileMemory: viper.GetBool("profile_memory"),

		// Logging configuration
		LogLevel: viper.GetString("log_level"),
		LogFile:  viper.GetString("log_file"),
		JSONLogs: viper.GetBool("json_logs"),
	}
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
			logrus.Infof("Stats: Executions=%d, Crashes=%d, Hangs=%d, Exec/sec=%.2f",
				stats.Executions, stats.Crashes, stats.Hangs, stats.ExecutionsPerSecond)
		}
	}
}

// printFinalStats prints final fuzzer statistics
func printFinalStats(engine *core.Engine) {
	stats := engine.GetStats()

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

	if stats.Crashes > 0 {
		fmt.Printf("Last Crash: %v\n", stats.LastCrashTime)
	}
}
