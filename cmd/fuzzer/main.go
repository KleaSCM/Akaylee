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
	"fmt"
	"os"
	"time"

	"github.com/kleascm/akaylee-fuzzer/cmd/fuzzer/commands"
	"github.com/kleascm/akaylee-fuzzer/pkg/logging"
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

	// Add expansion (auto-expansion) flags
	rootCmd.PersistentFlags().Bool("expansion-enabled", false, "Enable seed corpus auto-expansion from real-world data")
	rootCmd.PersistentFlags().String("expansion-interval", "1h", "Interval for auto-expansion (e.g. 10m, 1h)")
	rootCmd.PersistentFlags().StringSlice("expansion-dataset-sources", []string{}, "Dataset URLs or file paths for auto-expansion")
	rootCmd.PersistentFlags().StringSlice("expansion-dataset-formats", []string{}, "Dataset formats (json, csv, txt, bin)")
	rootCmd.PersistentFlags().StringSlice("expansion-api-sources", []string{}, "API endpoint URLs for auto-expansion")
	rootCmd.PersistentFlags().StringSlice("expansion-api-formats", []string{}, "API formats (json, csv, txt)")
	rootCmd.PersistentFlags().StringSlice("expansion-api-methods", []string{}, "API HTTP methods (GET, POST)")
	rootCmd.PersistentFlags().StringSlice("expansion-api-headers", []string{}, "API headers (e.g. Authorization: Bearer ...)")
	rootCmd.PersistentFlags().StringSlice("expansion-api-bodies", []string{}, "API POST bodies (optional)")
	rootCmd.PersistentFlags().String("expansion-timeout", "10s", "Timeout for expansion requests")

	// Add web fuzzing flags
	rootCmd.PersistentFlags().String("web-target", "", "Web application target URL")
	rootCmd.PersistentFlags().StringSlice("web-scope", []string{}, "Web fuzzing scope (domains/paths)")
	rootCmd.PersistentFlags().String("web-auth", "", "Web authentication type (basic, form, oauth)")
	rootCmd.PersistentFlags().StringSlice("web-auth-config", []string{}, "Web authentication config (key=value)")
	rootCmd.PersistentFlags().StringSlice("web-cookies", []string{}, "Web cookies (key=value)")
	rootCmd.PersistentFlags().StringSlice("web-headers", []string{}, "Web headers (key=value)")
	rootCmd.PersistentFlags().String("web-login-script", "", "Web login JavaScript (for custom login flows)")
	rootCmd.PersistentFlags().String("web-browser", "chrome", "Browser to use (chrome, firefox)")
	rootCmd.PersistentFlags().Bool("web-headless", true, "Run browser in headless mode")
	rootCmd.PersistentFlags().Int("web-parallel", 2, "Number of parallel browser contexts")
	rootCmd.PersistentFlags().String("web-wordlist", "", "Path to wordlist for web input mutation")

	// Bind flags to viper
	viper.BindPFlag("log_level", rootCmd.PersistentFlags().Lookup("log-level"))
	viper.BindPFlag("json_logs", rootCmd.PersistentFlags().Lookup("json-logs"))
	viper.BindPFlag("log_dir", rootCmd.PersistentFlags().Lookup("log-dir"))
	viper.BindPFlag("log_format", rootCmd.PersistentFlags().Lookup("log-format"))
	viper.BindPFlag("log_max_files", rootCmd.PersistentFlags().Lookup("log-max-files"))
	viper.BindPFlag("log_max_size", rootCmd.PersistentFlags().Lookup("log-max-size"))
	viper.BindPFlag("log_compress", rootCmd.PersistentFlags().Lookup("log-compress"))
	viper.BindPFlag("format", rootCmd.PersistentFlags().Lookup("format"))
	viper.BindPFlag("expansion.enabled", rootCmd.PersistentFlags().Lookup("expansion-enabled"))
	viper.BindPFlag("expansion.interval", rootCmd.PersistentFlags().Lookup("expansion-interval"))
	viper.BindPFlag("expansion.dataset_sources", rootCmd.PersistentFlags().Lookup("expansion-dataset-sources"))
	viper.BindPFlag("expansion.dataset_formats", rootCmd.PersistentFlags().Lookup("expansion-dataset-formats"))
	viper.BindPFlag("expansion.api_sources", rootCmd.PersistentFlags().Lookup("expansion-api-sources"))
	viper.BindPFlag("expansion.api_formats", rootCmd.PersistentFlags().Lookup("expansion-api-formats"))
	viper.BindPFlag("expansion.api_methods", rootCmd.PersistentFlags().Lookup("expansion-api-methods"))
	viper.BindPFlag("expansion.api_headers", rootCmd.PersistentFlags().Lookup("expansion-api-headers"))
	viper.BindPFlag("expansion.api_bodies", rootCmd.PersistentFlags().Lookup("expansion-api-bodies"))
	viper.BindPFlag("expansion.timeout", rootCmd.PersistentFlags().Lookup("expansion-timeout"))
	viper.BindPFlag("web.target", rootCmd.PersistentFlags().Lookup("web-target"))
	viper.BindPFlag("web.scope", rootCmd.PersistentFlags().Lookup("web-scope"))
	viper.BindPFlag("web.auth", rootCmd.PersistentFlags().Lookup("web-auth"))
	viper.BindPFlag("web.auth_config", rootCmd.PersistentFlags().Lookup("web-auth-config"))
	viper.BindPFlag("web.cookies", rootCmd.PersistentFlags().Lookup("web-cookies"))
	viper.BindPFlag("web.headers", rootCmd.PersistentFlags().Lookup("web-headers"))
	viper.BindPFlag("web.login_script", rootCmd.PersistentFlags().Lookup("web-login-script"))
	viper.BindPFlag("web.browser", rootCmd.PersistentFlags().Lookup("web-browser"))
	viper.BindPFlag("web.headless", rootCmd.PersistentFlags().Lookup("web-headless"))
	viper.BindPFlag("web.parallel", rootCmd.PersistentFlags().Lookup("web-parallel"))
	viper.BindPFlag("web.wordlist", rootCmd.PersistentFlags().Lookup("web-wordlist"))

	// Add fuzz command
	fuzzCmd := &cobra.Command{
		Use:   "fuzz",
		Short: "Start fuzzing a target program",
		Long: `Start the fuzzing process on a target program. The fuzzer will continuously
generate and execute test cases, looking for crashes, hangs, and new coverage paths.`,
		RunE: commands.RunFuzz,
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
			commands.ListMutators(cmd, args)
		},
	}
	rootCmd.AddCommand(listMutatorsCmd)

	// Add check command for built-in self-checks
	rootCmd.AddCommand(&cobra.Command{
		Use:   "check",
		Short: "Perform built-in self-checks for system validation",
		Long: `Perform comprehensive system checks to validate binary existence, corpus accessibility, 
log writability, and other prerequisites for successful fuzzing. Very useful for CI/CD integration.`,
		RunE: commands.PerformSelfCheck,
	})

	// Add triage command for crash analysis and minimization
	rootCmd.AddCommand(&cobra.Command{
		Use:   "triage",
		Short: "Analyze and minimize crash files",
		Long: `Analyze crash files for severity, exploitability, and automatically minimize them
to their smallest reproducing form. Provides intelligent crash classification and prioritization.`,
		RunE: commands.PerformCrashTriage,
	})

	// Add infer-grammar command for structure inference
	inferGrammarCmd := &cobra.Command{
		Use:   "infer-grammar",
		Short: "Infer grammar from sample corpus",
		Long: `Analyze a corpus of sample inputs to automatically infer structure, field types,
nesting, enums, and generate a grammar for structure-aware fuzzing. Supports JSON and binary formats.`,
		RunE: commands.PerformGrammarInference,
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
		RunE: commands.PerformCrashReproduction,
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

	// Add differential fuzzing command
	differentialCmd := &cobra.Command{
		Use:   "differential",
		Short: "Perform differential fuzzing on multiple implementations",
		Long: `Compare multiple implementations of the same target to detect behavioral
differences, crashes, and security vulnerabilities. Essential for finding
implementation bugs and security issues through divergence analysis.`,
		RunE: commands.PerformDifferentialFuzzing,
	}

	// Add differential flags
	differentialCmd.Flags().StringSlice("implementations", []string{}, "Implementations to compare (format: name:path[:args])")
	differentialCmd.Flags().Duration("timeout", 30*time.Second, "Execution timeout per test case")
	differentialCmd.Flags().Int("max-differences", 1000, "Maximum differences to collect")
	differentialCmd.Flags().String("output-dir", "./differential_output", "Output directory for reports")
	differentialCmd.Flags().Int("repro-attempts", 5, "Number of reproduction attempts")
	differentialCmd.Flags().Float64("min-confidence", 0.7, "Minimum confidence threshold")
	differentialCmd.Flags().Bool("enable-detailed", true, "Enable detailed analysis")
	differentialCmd.Flags().Bool("compare-output", true, "Compare output differences")
	differentialCmd.Flags().Bool("compare-error", true, "Compare error output differences")
	differentialCmd.Flags().Bool("compare-coverage", false, "Compare coverage differences")
	differentialCmd.Flags().Bool("compare-timing", true, "Compare timing differences")
	differentialCmd.Flags().Bool("compare-resources", true, "Compare resource usage differences")

	// Mark required flags
	differentialCmd.MarkFlagRequired("implementations")

	// Bind flags to viper
	viper.BindPFlag("differential.implementations", differentialCmd.Flags().Lookup("implementations"))
	viper.BindPFlag("differential.timeout", differentialCmd.Flags().Lookup("timeout"))
	viper.BindPFlag("differential.max_differences", differentialCmd.Flags().Lookup("max-differences"))
	viper.BindPFlag("differential.output_dir", differentialCmd.Flags().Lookup("output-dir"))
	viper.BindPFlag("differential.repro_attempts", differentialCmd.Flags().Lookup("repro-attempts"))
	viper.BindPFlag("differential.min_confidence", differentialCmd.Flags().Lookup("min-confidence"))
	viper.BindPFlag("differential.enable_detailed", differentialCmd.Flags().Lookup("enable-detailed"))
	viper.BindPFlag("differential.compare_output", differentialCmd.Flags().Lookup("compare-output"))
	viper.BindPFlag("differential.compare_error", differentialCmd.Flags().Lookup("compare-error"))
	viper.BindPFlag("differential.compare_coverage", differentialCmd.Flags().Lookup("compare-coverage"))
	viper.BindPFlag("differential.compare_timing", differentialCmd.Flags().Lookup("compare-timing"))
	viper.BindPFlag("differential.compare_resources", differentialCmd.Flags().Lookup("compare-resources"))

	rootCmd.AddCommand(differentialCmd)

	// Add dashboard command for beautiful HTML reports
	dashboardCmd := &cobra.Command{
		Use:   "dashboard",
		Short: "Generate beautiful HTML dashboard reports",
		Long: `Generate comprehensive HTML dashboards with interactive charts,
real-time metrics, crash analysis, coverage tracking, and state exploration
visualizations. Perfect for sharing results and monitoring fuzzing progress.`,
		RunE: commands.PerformDashboardGeneration,
	}

	// Add dashboard flags
	dashboardCmd.Flags().String("output-dir", "./dashboard", "Output directory for dashboard files")
	dashboardCmd.Flags().String("title", "Akaylee Fuzzer Report", "Dashboard title")
	dashboardCmd.Flags().Bool("include-crashes", true, "Include crash analysis in dashboard")
	dashboardCmd.Flags().Bool("include-states", true, "Include state exploration data in dashboard")
	dashboardCmd.Flags().Bool("include-coverage", true, "Include coverage analysis in dashboard")
	dashboardCmd.Flags().Bool("include-performance", true, "Include performance metrics in dashboard")
	dashboardCmd.Flags().Bool("auto-open", false, "Automatically open dashboard in browser")
	dashboardCmd.Flags().String("format", "html", "Dashboard format (html, json)")

	// Bind dashboard flags to viper
	viper.BindPFlag("dashboard.output_dir", dashboardCmd.Flags().Lookup("output-dir"))
	viper.BindPFlag("dashboard.title", dashboardCmd.Flags().Lookup("title"))
	viper.BindPFlag("dashboard.include_crashes", dashboardCmd.Flags().Lookup("include-crashes"))
	viper.BindPFlag("dashboard.include_states", dashboardCmd.Flags().Lookup("include-states"))
	viper.BindPFlag("dashboard.include_coverage", dashboardCmd.Flags().Lookup("include-coverage"))
	viper.BindPFlag("dashboard.include_performance", dashboardCmd.Flags().Lookup("include-performance"))
	viper.BindPFlag("dashboard.auto_open", dashboardCmd.Flags().Lookup("auto-open"))
	viper.BindPFlag("dashboard.format", dashboardCmd.Flags().Lookup("format"))

	rootCmd.AddCommand(dashboardCmd)

	// Add commands to root
	rootCmd.AddCommand(fuzzCmd)

	// Execute root command
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
