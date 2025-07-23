/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: worker.go
Description: Worker implementation for parallel test case execution in the Akaylee Fuzzer.
Provides efficient resource management, crash detection, and performance monitoring
for individual worker threads in the fuzzing process.
*/

package core

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// Worker represents a single worker thread in the fuzzing process
// Handles test case execution, resource monitoring, and result processing
type Worker struct {
	ID       int            // Unique worker identifier
	executor Executor       // Test case executor
	analyzer Analyzer       // Result analyzer
	logger   *logrus.Logger // Worker-specific logger

	// Add target name for logging
	Target string // Target name for logging

	// Performance tracking
	executions int64     // Number of test cases executed
	crashes    int64     // Number of crashes found
	hangs      int64     // Number of hangs detected
	startTime  time.Time // When worker started

	// Resource monitoring
	peakMemory uint64  // Peak memory usage
	avgCPU     float64 // Average CPU usage

	// State management
	running bool               // Whether worker is running
	ctx     context.Context    // Worker context
	cancel  context.CancelFunc // Cancel function

	// Synchronization
	mu sync.RWMutex   // Thread safety
	wg sync.WaitGroup // Wait group for cleanup
}

// NewWorker creates a new worker instance
// Initializes all components for test case execution
func NewWorker(id int, executor Executor, analyzer Analyzer, logger *logrus.Logger, target string) *Worker {
	ctx, cancel := context.WithCancel(context.Background())

	return &Worker{
		ID:        id,
		executor:  executor,
		analyzer:  analyzer,
		logger:    logger,
		Target:    target,
		startTime: time.Now(),
		ctx:       ctx,
		cancel:    cancel,
	}
}

// Execute runs a test case and returns the execution result
// Handles all aspects of test case execution including resource monitoring
func (w *Worker) Execute(testCase *TestCase) (*ExecutionResult, error) {
	w.mu.Lock()
	w.executions++
	w.mu.Unlock()

	// Create execution result
	result := &ExecutionResult{
		TestCaseID: testCase.ID,
		Status:     StatusSuccess,
	}

	// Start resource monitoring
	monitorCtx, monitorCancel := context.WithCancel(w.ctx)
	defer monitorCancel()

	// Start resource monitoring goroutine
	var peakMemory uint64
	var avgCPU float64

	w.wg.Add(1)
	go func() {
		defer w.wg.Done()
		peakMemory, avgCPU, _ = w.monitorResources(monitorCtx)
	}()

	// Execute test case with timeout
	_, execCancel := context.WithTimeout(w.ctx, 30*time.Second) // Default timeout
	defer execCancel()

	startTime := time.Now()

	// Execute the test case
	execResult, err := w.executor.Execute(testCase)
	if err != nil {
		result.Status = StatusError
		result.Error = []byte(err.Error())
		result.Duration = time.Since(startTime)
		// Add target and test name to log fields
		fields := map[string]interface{}{
			"target": w.Target,
		}
		if name, ok := testCase.Metadata["name"]; ok {
			fields["test_name"] = name
		}
		w.logger.WithFields(fields).Errorf("Execution failed: %v", err)
		return result, fmt.Errorf("execution failed: %w", err)
	}

	// Wait for resource monitoring to complete
	monitorCancel()
	w.wg.Wait()

	// Update result with execution information
	result.ExitCode = execResult.ExitCode
	result.Signal = execResult.Signal
	result.Duration = time.Since(startTime)
	result.MemoryUsage = peakMemory
	result.CPUUsage = avgCPU
	result.Output = execResult.Output
	result.Error = execResult.Error

	// Add target and test name to log fields for execution
	fields := map[string]interface{}{
		"target": w.Target,
	}
	if name, ok := testCase.Metadata["name"]; ok {
		fields["test_name"] = name
	}
	w.logger.WithFields(fields).Info("Test case executed")

	// Analyze the result
	if err := w.analyzer.Analyze(result); err != nil {
		w.logger.WithFields(fields).Errorf("Worker %d: Failed to analyze result: %v", w.ID, err)
	}

	// Detect crashes
	if crashInfo, err := w.analyzer.DetectCrash(result); err == nil && crashInfo != nil {
		result.Status = StatusCrash
		result.CrashInfo = crashInfo
		w.mu.Lock()
		w.crashes++
		w.mu.Unlock()
		w.logger.WithFields(fields).Warnf("Worker %d: Crash detected: %s", w.ID, crashInfo.Type)
	}

	// Detect hangs
	if hangInfo, err := w.analyzer.DetectHang(result); err == nil && hangInfo != nil {
		result.Status = StatusHang
		result.HangInfo = hangInfo
		w.mu.Lock()
		w.hangs++
		w.mu.Unlock()
		w.logger.WithFields(fields).Warnf("Worker %d: Hang detected", w.ID)
	}

	// Update resource tracking
	w.updateResourceStats(peakMemory, avgCPU)

	return result, nil
}

// calculateAvgCPU computes the average of a slice of float64 values.
func calculateAvgCPU(samples []float64) float64 {
	if len(samples) == 0 {
		return 0.0
	}
	total := 0.0
	for _, sample := range samples {
		total += sample
	}
	return total / float64(len(samples))
}

// monitorResources monitors resource usage during test case execution
// Tracks memory and CPU usage for performance analysis
func (w *Worker) monitorResources(ctx context.Context) (uint64, float64, error) {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	var peakMemory uint64
	var cpuSamples []float64

	for {
		select {
		case <-ctx.Done():
			avgCPU := calculateAvgCPU(cpuSamples)
			return peakMemory, avgCPU, nil
		case <-ticker.C:
			// Get current memory usage
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			if m.Alloc > peakMemory {
				peakMemory = m.Alloc
			}

			// Get CPU usage (simplified - in production would use system calls)
			cpuUsage := w.getCPUUsage()
			cpuSamples = append(cpuSamples, cpuUsage)
		}
	}
}

// getCPUUsage returns current CPU usage for the worker
// Simplified implementation - in production would use system calls
func (w *Worker) getCPUUsage() float64 {
	// This is a placeholder implementation
	// In a real implementation, this would use system calls to get actual CPU usage
	return 0.0
}

// updateResourceStats updates the worker's resource tracking statistics
func (w *Worker) updateResourceStats(memory uint64, cpu float64) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if memory > w.peakMemory {
		w.peakMemory = memory
	}

	// Update average CPU usage
	if w.avgCPU == 0 {
		w.avgCPU = cpu
	} else {
		w.avgCPU = (w.avgCPU + cpu) / 2
	}
}

// GetStats returns worker performance statistics
func (w *Worker) GetStats() map[string]interface{} {
	w.mu.RLock()
	defer w.mu.RUnlock()

	stats := make(map[string]interface{})
	stats["id"] = w.ID
	stats["executions"] = w.executions
	stats["crashes"] = w.crashes
	stats["hangs"] = w.hangs
	stats["start_time"] = w.startTime
	stats["uptime"] = time.Since(w.startTime)
	stats["peak_memory"] = w.peakMemory
	stats["avg_cpu"] = w.avgCPU
	stats["running"] = w.running

	// Calculate execution rate
	uptime := time.Since(w.startTime).Seconds()
	if uptime > 0 {
		stats["executions_per_second"] = float64(w.executions) / uptime
	}

	return stats
}

// Start begins the worker's execution loop
// Continuously processes test cases until stopped
func (w *Worker) Start() error {
	w.mu.Lock()
	if w.running {
		w.mu.Unlock()
		return fmt.Errorf("worker %d is already running", w.ID)
	}
	w.running = true
	w.mu.Unlock()

	w.logger.Infof("Worker %d started", w.ID)
	return nil
}

// Stop gracefully stops the worker
// Cancels the context and waits for cleanup
func (w *Worker) Stop() error {
	w.mu.Lock()
	if !w.running {
		w.mu.Unlock()
		return fmt.Errorf("worker %d is not running", w.ID)
	}
	w.running = false
	w.mu.Unlock()

	w.logger.Infof("Worker %d stopping", w.ID)

	// Cancel context to stop all operations
	w.cancel()

	// Wait for all goroutines to complete
	w.wg.Wait()

	w.logger.Infof("Worker %d stopped", w.ID)
	return nil
}

// IsRunning returns whether the worker is currently running
func (w *Worker) IsRunning() bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.running
}

// GetContext returns the worker's context
// Useful for cancellation and timeout management
func (w *Worker) GetContext() context.Context {
	return w.ctx
}

// GetCancelFunc returns the worker's cancel function
// Useful for stopping the worker from external code
func (w *Worker) GetCancelFunc() context.CancelFunc {
	return w.cancel
}
