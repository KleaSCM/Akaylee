/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: types.go
Description: Core types and interfaces for the Akaylee Fuzzer engine. Defines the fundamental
data structures used throughout the fuzzing process including test cases, coverage tracking,
execution results, and configuration parameters.
*/

package core

import (
	"sync/atomic"
	"time"
)

// TestCase represents a single test case to be executed by the fuzzer
// This is the fundamental unit of work in our fuzzing engine
type TestCase struct {
	ID         string                 `json:"id"`         // Unique identifier for the test case
	Data       []byte                 `json:"data"`       // The actual test data to be executed
	ParentID   string                 `json:"parent_id"`  // ID of the parent test case that generated this one
	Generation int                    `json:"generation"` // Generation number (0 = seed, 1+ = mutated)
	CreatedAt  time.Time              `json:"created_at"` // When this test case was created
	Executions int64                  `json:"executions"` // Number of times this test case has been executed
	Coverage   *Coverage              `json:"coverage"`   // Coverage information from last execution
	Fitness    float64                `json:"fitness"`    // Fitness score for evolutionary algorithms
	Priority   int                    `json:"priority"`   // Priority for scheduling (higher = more important)
	Metadata   map[string]interface{} `json:"metadata"`   // Additional metadata
}

// Coverage represents the execution coverage information for a test case
// Uses bitmap-based tracking for efficient storage and comparison
type Coverage struct {
	Bitmap        []byte    `json:"bitmap"`         // Bitmap representation of covered edges/blocks
	EdgeCount     int       `json:"edge_count"`     // Number of unique edges covered
	BlockCount    int       `json:"block_count"`    // Number of basic blocks covered
	FunctionCount int       `json:"function_count"` // Number of functions entered
	Timestamp     time.Time `json:"timestamp"`      // When this coverage was recorded
	Hash          uint64    `json:"hash"`           // Hash of the coverage for quick comparison
}

// ExecutionResult represents the result of executing a test case
// Contains all information about the execution including crashes, hangs, and performance metrics
type ExecutionResult struct {
	TestCaseID  string          `json:"test_case_id"` // ID of the executed test case
	ExitCode    int             `json:"exit_code"`    // Process exit code
	Signal      int             `json:"signal"`       // Signal that terminated the process (if any)
	Duration    time.Duration   `json:"duration"`     // How long the execution took
	MemoryUsage uint64          `json:"memory_usage"` // Peak memory usage in bytes
	CPUUsage    float64         `json:"cpu_usage"`    // CPU usage percentage
	Output      []byte          `json:"output"`       // Standard output
	Error       []byte          `json:"error"`        // Standard error
	Coverage    *Coverage       `json:"coverage"`     // Coverage information
	Status      ExecutionStatus `json:"status"`       // Execution status
	CrashInfo   *CrashInfo      `json:"crash_info"`   // Crash information if applicable
	HangInfo    *HangInfo       `json:"hang_info"`    // Hang information if applicable
}

// ExecutionStatus represents the status of a test case execution
type ExecutionStatus int

const (
	StatusSuccess ExecutionStatus = iota
	StatusCrash
	StatusHang
	StatusTimeout
	StatusError
	StatusSkipped
)

// CrashInfo contains detailed information about a crash
// Used for crash triaging and deduplication
type CrashInfo struct {
	Type         string            `json:"type"`         // Type of crash (SIGSEGV, SIGABRT, etc.)
	Address      uintptr           `json:"address"`      // Memory address where crash occurred
	StackTrace   []string          `json:"stack_trace"`  // Stack trace at crash point
	Registers    map[string]uint64 `json:"registers"`    // CPU register state
	MemoryMap    []MemoryRegion    `json:"memory_map"`   // Memory map at crash time
	Reproducible bool              `json:"reproducible"` // Whether the crash is reproducible
	Hash         string            `json:"hash"`         // Unique hash for crash deduplication
}

// HangInfo contains information about a test case that hung
type HangInfo struct {
	Duration      time.Duration `json:"duration"`       // How long the hang lasted
	LastOutput    []byte        `json:"last_output"`    // Last output before hang
	StackTrace    []string      `json:"stack_trace"`    // Stack trace when hang detected
	ResourceUsage ResourceUsage `json:"resource_usage"` // Resource usage during hang
}

// MemoryRegion represents a memory region in the target process
type MemoryRegion struct {
	Start       uintptr `json:"start"`       // Start address
	End         uintptr `json:"end"`         // End address
	Permissions string  `json:"permissions"` // Memory permissions (r/w/x)
	Path        string  `json:"path"`        // File path if mapped from file
}

// ResourceUsage tracks resource consumption during execution
type ResourceUsage struct {
	PeakMemory      uint64  `json:"peak_memory"`      // Peak memory usage in bytes
	AvgCPU          float64 `json:"avg_cpu"`          // Average CPU usage percentage
	IORead          uint64  `json:"io_read"`          // Bytes read from disk/network
	IOWrite         uint64  `json:"io_write"`         // Bytes written to disk/network
	ContextSwitches int64   `json:"context_switches"` // Number of context switches
}

// FuzzerStats tracks overall fuzzer statistics
// Uses atomic operations for thread-safe updates
type FuzzerStats struct {
	Executions          int64     `json:"executions"`            // Total number of executions
	Crashes             int64     `json:"crashes"`               // Total number of crashes found
	Hangs               int64     `json:"hangs"`                 // Total number of hangs detected
	Timeouts            int64     `json:"timeouts"`              // Total number of timeouts
	UniqueCrashes       int64     `json:"unique_crashes"`        // Number of unique crashes
	CoverageEdges       int64     `json:"coverage_edges"`        // Total unique edges covered
	CoverageBlocks      int64     `json:"coverage_blocks"`       // Total unique blocks covered
	StartTime           time.Time `json:"start_time"`            // When fuzzing started
	LastCrashTime       time.Time `json:"last_crash_time"`       // When last crash was found
	ExecutionsPerSecond float64   `json:"executions_per_second"` // Current execution rate
}

// IncrementExecutions atomically increments the execution counter
func (s *FuzzerStats) IncrementExecutions() {
	atomic.AddInt64(&s.Executions, 1)
}

// IncrementCrashes atomically increments the crash counter
func (s *FuzzerStats) IncrementCrashes() {
	atomic.AddInt64(&s.Crashes, 1)
}

// IncrementHangs atomically increments the hang counter
func (s *FuzzerStats) IncrementHangs() {
	atomic.AddInt64(&s.Hangs, 1)
}

// IncrementTimeouts atomically increments the timeout counter
func (s *FuzzerStats) IncrementTimeouts() {
	atomic.AddInt64(&s.Timeouts, 1)
}

// FuzzerConfig contains all configuration parameters for the fuzzer
// Supports both command-line flags and configuration files
type FuzzerConfig struct {
	// Target configuration
	TargetPath string   `json:"target_path"` // Path to the target binary
	TargetArgs []string `json:"target_args"` // Command-line arguments for target
	TargetEnv  []string `json:"target_env"`  // Environment variables for target

	// Execution configuration
	Workers     int           `json:"workers"`      // Number of parallel workers
	Timeout     time.Duration `json:"timeout"`      // Maximum execution time per test case
	MemoryLimit uint64        `json:"memory_limit"` // Memory limit per execution (bytes)
	CPUAffinity []int         `json:"cpu_affinity"` // CPU cores to use (empty = all)

	// Corpus configuration
	CorpusDir     string `json:"corpus_dir"`      // Directory containing seed corpus
	OutputDir     string `json:"output_dir"`      // Directory for fuzzer output
	MaxCorpusSize int    `json:"max_corpus_size"` // Maximum number of test cases in corpus

	// Mutation configuration
	MutationRate float64 `json:"mutation_rate"` // Probability of mutation per byte
	MaxMutations int     `json:"max_mutations"` // Maximum mutations per test case
	Strategy     string  `json:"strategy"`      // Primary fuzzing strategy to use

	// Coverage configuration
	CoverageType  string `json:"coverage_type"`  // Type of coverage to track
	BitmapSize    int    `json:"bitmap_size"`    // Size of coverage bitmap
	EdgeThreshold int    `json:"edge_threshold"` // Minimum edges for interesting test case

	// Crash configuration
	MaxCrashes int    `json:"max_crashes"` // Maximum crashes to collect
	CrashDir   string `json:"crash_dir"`   // Directory for crash files
	Reproduce  bool   `json:"reproduce"`   // Whether to reproduce crashes

	// Performance configuration
	EnableGC      bool `json:"enable_gc"`      // Enable garbage collection tuning
	ProfileCPU    bool `json:"profile_cpu"`    // Enable CPU profiling
	ProfileMemory bool `json:"profile_memory"` // Enable memory profiling

	// Logging configuration
	LogLevel string `json:"log_level"` // Logging level (debug, info, warn, error)
	LogFile  string `json:"log_file"`  // Log file path
	JSONLogs bool   `json:"json_logs"` // Use JSON log format
}

// FuzzerEngine is the main interface for the fuzzing engine
// Defines the contract that all fuzzer implementations must satisfy
type FuzzerEngine interface {
	// Initialize initializes the fuzzer with the given configuration
	Initialize(config *FuzzerConfig) error

	// Start begins the fuzzing process
	Start() error

	// Stop gracefully stops the fuzzing process
	Stop() error

	// GetStats returns current fuzzer statistics
	GetStats() *FuzzerStats

	// AddTestCase adds a test case to the corpus
	AddTestCase(testCase *TestCase) error

	// GetTestCases returns test cases from the corpus
	GetTestCases(count int) ([]*TestCase, error)

	// ReportCrash reports a crash to the fuzzer
	ReportCrash(result *ExecutionResult) error

	// ReportHang reports a hang to the fuzzer
	ReportHang(result *ExecutionResult) error
}

// Mutator defines the interface for test case mutation strategies
// Allows for pluggable mutation algorithms
type Mutator interface {
	// Mutate creates a new test case by mutating the given test case
	Mutate(testCase *TestCase) (*TestCase, error)

	// Name returns the name of this mutator
	Name() string

	// Description returns a description of this mutator
	Description() string
}

// Executor defines the interface for test case execution
// Handles the actual running of target programs
type Executor interface {
	// Execute runs a test case and returns the execution result
	Execute(testCase *TestCase) (*ExecutionResult, error)

	// Initialize prepares the executor for use
	Initialize(config *FuzzerConfig) error

	// Cleanup performs any necessary cleanup
	Cleanup() error
}

// Analyzer defines the interface for execution analysis
// Handles coverage tracking, crash detection, and result analysis
type Analyzer interface {
	// Analyze analyzes an execution result
	Analyze(result *ExecutionResult) error

	// IsInteresting determines if a test case is interesting based on coverage
	IsInteresting(testCase *TestCase) bool

	// GetCoverage extracts coverage information from execution
	GetCoverage(result *ExecutionResult) (*Coverage, error)

	// DetectCrash detects if an execution resulted in a crash
	DetectCrash(result *ExecutionResult) (*CrashInfo, error)

	// DetectHang detects if an execution resulted in a hang
	DetectHang(result *ExecutionResult) (*HangInfo, error)
}
