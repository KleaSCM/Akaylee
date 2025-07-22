/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: engine.go
Description: Main fuzzer engine implementation. Provides the core fuzzing logic with advanced
scheduling algorithms, worker pool management, and intelligent test case prioritization.
Implements the FuzzerEngine interface with production-level performance optimizations.
*/

package core

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"crypto/sha256"

	"github.com/google/uuid"
	"github.com/kleascm/akaylee-fuzzer/pkg/coverage"
	"github.com/kleascm/akaylee-fuzzer/pkg/interfaces"
	"github.com/sirupsen/logrus"
)

// Engine implements the FuzzerEngine interface
// Provides the main fuzzing logic with advanced scheduling and optimization
type Engine struct {
	config *interfaces.FuzzerConfig
	stats  *FuzzerStats
	logger *logrus.Logger

	// Core components
	executor Executor
	analyzer Analyzer
	mutators []interfaces.Mutator

	// Corpus management
	corpus    *Corpus
	scheduler Scheduler // Use Scheduler abstraction

	// Type conversion helpers
	interfaceToCore func(*interfaces.TestCase) *TestCase
	coreToInterface func(*TestCase) *interfaces.TestCase

	// Worker management
	workers    []*Worker
	workerPool chan *Worker

	// Synchronization
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// State management
	running bool
	mu      sync.RWMutex

	// Performance tracking
	lastStatsUpdate time.Time
	executionRate   float64

	coverageCollector  coverage.CoverageCollector // For real code coverage
	seenCoverageHashes map[string]bool            // To avoid duplicate coverage
	reporters          []Reporter                 // Registered reporters for telemetry
}

// NewEngine creates a new fuzzer engine instance
// Initializes all components with proper configuration
func NewEngine() *Engine {
	return &Engine{
		stats: &FuzzerStats{
			StartTime: time.Now(),
		},
		logger:             logrus.New(),
		corpus:             NewCorpus(),
		scheduler:          NewPriorityScheduler(), // Default to priority scheduler
		seenCoverageHashes: make(map[string]bool),
	}
}

// Initialize sets up the fuzzer engine with the given configuration
// Prepares all components for execution including executor, analyzer, and mutators
func (e *Engine) Initialize(config *interfaces.FuzzerConfig) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.config = config
	e.ctx, e.cancel = context.WithCancel(context.Background())

	// Configure logging
	e.setupLogging()

	// Select scheduler type based on config
	// If config.SchedulerType is not set or unknown, use PriorityScheduler
	switch config.SchedulerType {
	case "coverage-guided":
		e.scheduler = NewCoverageGuidedScheduler()
	default:
		e.scheduler = NewPriorityScheduler()
	}

	// Initialize coverage collector if enabled
	if config.CoverageType == "go" {
		collector := &coverage.GoCoverageCollector{}
		err := collector.Prepare(config.TargetPath, config.TargetArgs)
		if err != nil {
			return fmt.Errorf("failed to prepare coverage collector: %w", err)
		}
		e.coverageCollector = collector
	}

	// Initialize executor (will be set by dependency injection)
	if e.executor == nil {
		return fmt.Errorf("executor not set - use SetExecutor() before Initialize()")
	}

	// Initialize analyzer (will be set by dependency injection)
	if e.analyzer == nil {
		return fmt.Errorf("analyzer not set - use SetAnalyzer() before Initialize()")
	}

	// Initialize mutators (will be set by dependency injection)
	if len(e.mutators) == 0 {
		return fmt.Errorf("mutators not set - use SetMutators() before Initialize()")
	}

	// Initialize corpus
	if err := e.initializeCorpus(); err != nil {
		return fmt.Errorf("failed to initialize corpus: %w", err)
	}

	// Initialize workers
	e.initializeWorkers()

	e.logger.Info("Fuzzer engine initialized successfully")
	return nil
}

// SetExecutor sets the executor for the engine
func (e *Engine) SetExecutor(executor interfaces.Executor) {
	e.executor = NewAdapterExecutor(executor)
}

// SetAnalyzer sets the analyzer for the engine
func (e *Engine) SetAnalyzer(analyzer interfaces.Analyzer) {
	e.analyzer = NewAdapterAnalyzer(analyzer)
}

// SetMutators sets the mutators for the engine
func (e *Engine) SetMutators(mutators []interfaces.Mutator) {
	// Store interface mutators directly
	e.mutators = make([]interfaces.Mutator, len(mutators))
	copy(e.mutators, mutators)

	// Set up conversion helpers
	e.interfaceToCore = func(itc *interfaces.TestCase) *TestCase {
		return &TestCase{
			ID:         itc.ID,
			Data:       itc.Data,
			ParentID:   itc.ParentID,
			Generation: itc.Generation,
			CreatedAt:  itc.CreatedAt,
			Executions: itc.Executions,
			Priority:   itc.Priority,
			Metadata:   itc.Metadata,
		}
	}

	e.coreToInterface = func(ctc *TestCase) *interfaces.TestCase {
		return &interfaces.TestCase{
			ID:         ctc.ID,
			Data:       ctc.Data,
			ParentID:   ctc.ParentID,
			Generation: ctc.Generation,
			CreatedAt:  ctc.CreatedAt,
			Executions: ctc.Executions,
			Priority:   ctc.Priority,
			Metadata:   ctc.Metadata,
		}
	}
}

// SetCoverageCollector sets the coverage collector for the engine
func (e *Engine) SetCoverageCollector(collector coverage.CoverageCollector) {
	e.coverageCollector = collector
}

// AddReporter registers a Reporter for telemetry and live reporting.
func (e *Engine) AddReporter(reporter Reporter) {
	e.reporters = append(e.reporters, reporter)
}

// setupLogging configures the logging system based on configuration
func (e *Engine) setupLogging() {
	level, err := logrus.ParseLevel(e.config.LogLevel)
	if err != nil {
		level = logrus.InfoLevel
	}
	e.logger.SetLevel(level)

	if e.config.LogFile != "" {
		file, err := os.OpenFile(e.config.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err == nil {
			e.logger.SetOutput(file)
		}
	}

	if e.config.JSONLogs {
		e.logger.SetFormatter(&logrus.JSONFormatter{})
	}
}

// initializeCorpus loads the initial seed corpus from the configured directory
// Processes seed files and creates initial test cases
func (e *Engine) initializeCorpus() error {
	if e.config.CorpusDir == "" {
		return fmt.Errorf("corpus directory not specified")
	}

	// Create corpus directory if it doesn't exist
	if err := os.MkdirAll(e.config.CorpusDir, 0755); err != nil {
		return fmt.Errorf("failed to create corpus directory: %w", err)
	}

	// Load seed files
	files, err := filepath.Glob(filepath.Join(e.config.CorpusDir, "*"))
	if err != nil {
		return fmt.Errorf("failed to glob corpus files: %w", err)
	}

	seedCount := 0
	for _, file := range files {
		if info, err := os.Stat(file); err == nil && !info.IsDir() {
			data, err := os.ReadFile(file)
			if err != nil {
				e.logger.Warnf("Failed to read seed file %s: %v", file, err)
				continue
			}

			testCase := &TestCase{
				ID:         uuid.New().String(),
				Data:       data,
				Generation: 0, // Seed generation
				CreatedAt:  time.Now(),
				Priority:   100, // High priority for seeds
			}

			if err := e.corpus.Add(testCase); err != nil {
				e.logger.Warnf("Failed to add seed test case: %v", err)
				continue
			}

			seedCount++
		}
	}

	e.logger.Infof("Loaded %d seed test cases from corpus", seedCount)
	return nil
}

// initializeWorkers creates the worker pool for parallel execution
// Sets up the specified number of workers with proper resource allocation
func (e *Engine) initializeWorkers() {
	numWorkers := e.config.Workers
	if numWorkers <= 0 {
		numWorkers = runtime.NumCPU()
	}

	e.workers = make([]*Worker, numWorkers)
	e.workerPool = make(chan *Worker, numWorkers)

	for i := 0; i < numWorkers; i++ {
		worker := NewWorker(i, e.executor, e.analyzer, e.logger)
		e.workers[i] = worker
		e.workerPool <- worker
	}

	e.logger.Infof("Initialized %d workers", numWorkers)
}

// Start begins the fuzzing process
// Launches all workers and begins the main fuzzing loop
func (e *Engine) Start() error {
	e.mu.Lock()
	if e.running {
		e.mu.Unlock()
		return fmt.Errorf("fuzzer is already running")
	}
	e.running = true
	e.mu.Unlock()

	e.logger.Info("Starting fuzzer engine")

	// Start statistics update goroutine
	e.wg.Add(1)
	go e.updateStats()

	// Start all workers
	for _, worker := range e.workers {
		e.wg.Add(1)
		go func(w *Worker) {
			defer e.wg.Done()
			e.runWorker(w)
		}(worker)
	}

	// Start scheduler
	e.wg.Add(1)
	go e.runScheduler()

	e.logger.Info("Fuzzer engine started successfully")
	return nil
}

// Stop gracefully stops the fuzzing process
// Signals all workers to stop and waits for completion
func (e *Engine) Stop() error {
	e.mu.Lock()
	if !e.running {
		e.mu.Unlock()
		return fmt.Errorf("fuzzer is not running")
	}
	e.running = false
	e.mu.Unlock()

	e.logger.Info("Stopping fuzzer engine")

	// Cancel context to signal all goroutines to stop
	e.cancel()

	// Wait for all workers to complete
	e.wg.Wait()

	// Cleanup executor
	if e.executor != nil {
		e.executor.Cleanup()
	}

	e.logger.Info("Fuzzer engine stopped successfully")
	return nil
}

// runWorker is the main worker loop
// Continuously processes test cases from the scheduler until stopped
func (e *Engine) runWorker(worker *Worker) {
	for {
		select {
		case <-e.ctx.Done():
			return
		default:
			// Get test case from scheduler
			testCase := e.scheduler.Next()
			if testCase == nil {
				// Scheduler is empty, try to generate new test cases
				e.generateTestCases()
				time.Sleep(10 * time.Millisecond)
				continue
			}

			// Execute test case
			result, err := worker.Execute(testCase)
			if err != nil {
				e.logger.Errorf("Worker %d failed to execute test case: %v", worker.ID, err)
				continue
			}

			// Process result
			e.processResult(result)

			// Update statistics
			e.stats.IncrementExecutions()
		}
	}
}

// runScheduler manages the test case queue and scheduling
// Implements intelligent scheduling algorithms for optimal coverage
func (e *Engine) runScheduler() {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-e.ctx.Done():
			return
		case <-ticker.C:
			// Update queue priorities based on coverage
			e.updateQueuePriorities()

			// Generate new test cases if needed
			if e.scheduler.Size() < e.config.MaxCorpusSize/2 {
				e.generateTestCases()
			}

			// Clean up old test cases
			e.cleanupCorpus()
		}
	}
}

// generateTestCases creates new test cases through mutation
// Uses multiple mutation strategies to create diverse test cases
func (e *Engine) generateTestCases() {
	// Get test cases to mutate
	sources := e.corpus.GetRandom(10)
	if len(sources) == 0 {
		return
	}

	for _, source := range sources {
		// Select mutator based on strategy
		mutator := e.selectMutator(source)

		// Generate multiple mutations
		for i := 0; i < e.config.MaxMutations; i++ {
			// Convert source to interface type
			interfaceSource := e.coreToInterface(source)

			mutated, err := mutator.Mutate(interfaceSource)
			if err != nil {
				e.logger.Debugf("Mutation failed: %v", err)
				continue
			}

			// Set metadata
			mutated.ParentID = source.ID
			mutated.Generation = source.Generation + 1
			mutated.CreatedAt = time.Now()

			// Convert back to core type for priority calculation
			coreMutated := e.interfaceToCore(mutated)
			coreMutated.Priority = e.calculatePriority(coreMutated)

			// Add to corpus and scheduler
			if err := e.corpus.Add(coreMutated); err == nil {
				e.scheduler.Push(coreMutated)
				// Notify reporters of new test case
				for _, r := range e.reporters {
					r.OnTestCaseAdded(coreMutated)
				}
			}
		}
	}
}

// selectMutator chooses the best mutator for a given test case
// Implements adaptive mutation strategy selection
func (e *Engine) selectMutator(testCase *TestCase) interfaces.Mutator {
	// Simple strategy: rotate through mutators
	index := testCase.Executions % int64(len(e.mutators))
	return e.mutators[index]
}

// calculatePriority determines the priority of a test case for scheduling
// Higher priority test cases are executed more frequently
func (e *Engine) calculatePriority(testCase *TestCase) int {
	priority := 100 // Base priority

	// Higher priority for seeds
	if testCase.Generation == 0 {
		priority += 50
	}

	// Higher priority for test cases with good coverage
	if testCase.Coverage != nil {
		priority += testCase.Coverage.EdgeCount * 2
	}

	// Higher priority for test cases that haven't been executed much
	if testCase.Executions < 10 {
		priority += 20
	}

	// Higher priority for test cases that found crashes
	if testCase.Metadata != nil {
		if _, hasCrash := testCase.Metadata["found_crash"]; hasCrash {
			priority += 100
		}
	}

	return priority
}

// processResult handles the result of a test case execution
// Updates coverage, detects crashes, and manages the corpus
func (e *Engine) processResult(result *ExecutionResult) {
	// Analyze result
	if err := e.analyzer.Analyze(result); err != nil {
		e.logger.Errorf("Failed to analyze result: %v", err)
		return
	}

	// Collect real coverage if enabled
	var newCoverage bool
	if e.coverageCollector != nil {
		covInfo, err := e.coverageCollector.Collect(result.Output, nil)
		if err != nil {
			e.logger.Warnf("Coverage collection failed: %v", err)
		} else {
			// Use the raw profile as a hash for simplicity (can be improved)
			covHash := coverageHash(covInfo.RawProfile)
			if !e.seenCoverageHashes[covHash] {
				e.seenCoverageHashes[covHash] = true
				newCoverage = true
				e.logger.Infof("New coverage found! Hash: %s", covHash)
				e.logger.Infof("Total unique coverage points: %d", len(e.seenCoverageHashes))
			} else {
				newCoverage = false
			}
			// Optionally, update result.Coverage or log coverage info
			e.logger.Debugf("Collected coverage: %d blocks", len(covInfo.CoveredBlocks))
		}
	}

	// Get test case from corpus
	testCase := e.corpus.Get(result.TestCaseID)
	if testCase == nil {
		return
	}

	// Update test case with execution information
	testCase.Executions++
	testCase.Coverage = result.Coverage

	// Handle crashes
	if result.Status == StatusCrash {
		e.handleCrash(result)
		testCase.Metadata["found_crash"] = true
	}

	// Handle hangs
	if result.Status == StatusHang {
		e.handleHang(result)
	}

	// Check if test case is interesting (new coverage or analyzer says so)
	if newCoverage || e.analyzer.IsInteresting(testCase) {
		testCase.Priority = e.calculatePriority(testCase) + 100 // Boost for new coverage
		e.scheduler.Push(testCase)
	}

	// Notify reporters of execution
	for _, r := range e.reporters {
		r.OnTestCaseExecuted(result)
	}
}

// handleCrash processes a crash result
// Saves crash information and updates statistics
func (e *Engine) handleCrash(result *ExecutionResult) {
	e.stats.IncrementCrashes()
	e.stats.LastCrashTime = time.Now()

	// Save crash file
	if e.config.CrashDir != "" {
		e.saveCrashFile(result)
	}

	e.logger.Warnf("Crash detected: %s", result.CrashInfo.Type)
}

// handleHang processes a hang result
// Updates statistics and logs hang information
func (e *Engine) handleHang(result *ExecutionResult) {
	e.stats.IncrementHangs()

	e.logger.Warnf("Hang detected: duration=%v", result.HangInfo.Duration)
}

// saveCrashFile saves crash information to a file
// Creates reproducible crash files for analysis
func (e *Engine) saveCrashFile(result *ExecutionResult) {
	crashDir := e.config.CrashDir
	if err := os.MkdirAll(crashDir, 0755); err != nil {
		e.logger.Errorf("Failed to create crash directory: %v", err)
		return
	}

	// Create crash file name
	timestamp := time.Now().Format("20060102_150405")
	filename := fmt.Sprintf("crash_%s_%s", timestamp, result.CrashInfo.Hash)
	filepath := filepath.Join(crashDir, filename)

	// Save crash data
	if err := os.WriteFile(filepath, result.Output, 0644); err != nil {
		e.logger.Errorf("Failed to save crash file: %v", err)
	}
}

// updateQueuePriorities recalculates priorities for test cases in the queue
// Ensures optimal scheduling based on current coverage and performance
func (e *Engine) updateQueuePriorities() {
	// This is a simplified implementation
	// In a full implementation, this would analyze coverage trends
	// and adjust priorities accordingly
}

// cleanupCorpus removes old or uninteresting test cases
// Maintains corpus size within configured limits
func (e *Engine) cleanupCorpus() {
	if e.corpus.Size() <= e.config.MaxCorpusSize {
		return
	}

	// Remove test cases with low priority and high execution count
	removed := e.corpus.Cleanup(e.config.MaxCorpusSize)
	if removed > 0 {
		e.logger.Debugf("Cleaned up %d test cases from corpus", removed)
	}
}

// updateStats periodically updates execution statistics
// Calculates execution rate and other performance metrics
func (e *Engine) updateStats() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-e.ctx.Done():
			return
		case <-ticker.C:
			e.calculateExecutionRate()
		}
	}
}

// calculateExecutionRate computes the current execution rate
// Used for performance monitoring and optimization
func (e *Engine) calculateExecutionRate() {
	now := time.Now()
	duration := now.Sub(e.lastStatsUpdate).Seconds()

	if duration > 0 {
		executions := e.stats.Executions
		rate := float64(executions) / duration
		e.stats.ExecutionsPerSecond = rate
		e.executionRate = rate // Store in engine field for performance tracking
	}

	e.lastStatsUpdate = now
}

// GetStats returns current fuzzer statistics
func (e *Engine) GetStats() *FuzzerStats {
	stats := *e.stats // copy
	if e.seenCoverageHashes != nil {
		stats.CoveragePoints = len(e.seenCoverageHashes)
	}
	return &stats
}

// AddTestCase adds a test case to the corpus
func (e *Engine) AddTestCase(testCase *TestCase) error {
	return e.corpus.Add(testCase)
}

// GetTestCases returns test cases from the corpus
func (e *Engine) GetTestCases(count int) ([]*TestCase, error) {
	return e.corpus.GetRandom(count), nil
}

// ReportCrash reports a crash to the fuzzer
func (e *Engine) ReportCrash(result *ExecutionResult) error {
	e.handleCrash(result)
	return nil
}

// ReportHang reports a hang to the fuzzer
func (e *Engine) ReportHang(result *ExecutionResult) error {
	e.handleHang(result)
	return nil
}

// GetCorpus returns the corpus managed by the engine.
func (e *Engine) GetCorpus() *Corpus {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.corpus
}

// Helper to hash coverage profiles (simple, can be improved)
func coverageHash(profile string) string {
	// Use SHA256 for robust coverage profile hashing
	h := sha256.New()
	h.Write([]byte(profile))
	return fmt.Sprintf("%x", h.Sum(nil))
}
