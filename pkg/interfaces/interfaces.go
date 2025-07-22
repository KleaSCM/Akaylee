/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: interfaces.go
Description: Shared interfaces for the Akaylee Fuzzer. Defines the core interfaces
used across all packages to break import cycles and enable proper modular design.
*/

package interfaces

import (
	"time"
)

// TestCase represents a single test case for fuzzing
type TestCase struct {
	ID         string
	Data       []byte
	ParentID   string
	Generation int
	CreatedAt  time.Time
	Executions int64
	Priority   int
	Coverage   *Coverage
	Metadata   map[string]interface{}
}

// Coverage represents execution coverage information
type Coverage struct {
	Bitmap        []byte
	EdgeCount     int
	BlockCount    int
	FunctionCount int
	Timestamp     time.Time
	Hash          uint64
}

// ExecutionResult represents the result of executing a test case
type ExecutionResult struct {
	TestCaseID  string
	ExitCode    int
	Signal      int
	Duration    time.Duration
	MemoryUsage uint64
	CPUUsage    float64
	Output      []byte
	Error       []byte
	Status      ExecutionStatus
	Coverage    *Coverage
	CrashInfo   *CrashInfo
	HangInfo    *HangInfo
}

// ExecutionStatus represents the status of an execution
type ExecutionStatus int

const (
	StatusSuccess ExecutionStatus = iota
	StatusError
	StatusCrash
	StatusHang
	StatusTimeout
)

// CrashInfo represents information about a crash
type CrashInfo struct {
	Type         string
	Address      uintptr
	StackTrace   []string
	Registers    map[string]uint64
	MemoryMap    []MemoryRegion
	Reproducible bool
	Hash         string
	Metadata     map[string]interface{} // Extensible metadata for crash analysis
}

// HangInfo represents information about a hang
type HangInfo struct {
	Duration      time.Duration
	LastOutput    []byte
	StackTrace    []string
	ResourceUsage ResourceUsage
}

// MemoryRegion represents a memory region
type MemoryRegion struct {
	Start   uintptr
	End     uintptr
	Protect uint32
	Path    string
}

// ResourceUsage represents resource usage information
type ResourceUsage struct {
	PeakMemory uint64
	AvgCPU     float64
	IORead     uint64
	IOWrite    uint64
}

// FuzzerConfig represents the configuration for the fuzzer
type FuzzerConfig struct {
	TargetPath    string
	TargetArgs    []string
	TargetEnv     []string
	Workers       int
	Timeout       time.Duration
	MemoryLimit   uint64
	CorpusDir     string
	OutputDir     string
	MaxCorpusSize int
	MutationRate  float64
	MaxMutations  int
	Strategy      string
	CoverageType  string
	BitmapSize    int
	EdgeThreshold int
	MaxCrashes    int
	CrashDir      string
	Reproduce     bool
	EnableGC      bool
	ProfileCPU    bool
	ProfileMemory bool
	LogLevel      string
	LogFile       string
	JSONLogs      bool
	SchedulerType string // Scheduler type: "priority" (default), "coverage-guided", etc.
}

// Executor interface for executing test cases
// Now supports Reset() for hot reload/config reload
type Executor interface {
	Initialize(config *FuzzerConfig) error
	Execute(testCase *TestCase) (*ExecutionResult, error)
	Cleanup() error
	Reset() error // New: Reset executor state
}

// Analyzer interface for analyzing execution results
// Now supports Reset() for hot reload/config reload
type Analyzer interface {
	Analyze(result *ExecutionResult) error
	IsInteresting(testCase *TestCase) bool
	GetCoverage(result *ExecutionResult) (*Coverage, error)
	DetectCrash(result *ExecutionResult) (*CrashInfo, error)
	DetectHang(result *ExecutionResult) (*HangInfo, error)
	Reset() error // New: Reset analyzer state
}

// Mutator interface for mutating test cases
type Mutator interface {
	Mutate(testCase *TestCase) (*TestCase, error)
	Name() string
	Description() string
}
