/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: metrics.go
Description: Advanced resource monitoring system for the Akaylee Fuzzer. Provides
comprehensive CPU/memory tracking per test case and per worker, real-time metrics
collection, performance profiling, and resource optimization capabilities.
*/

package monitoring

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
)

// ResourceMetrics represents comprehensive resource usage metrics
type ResourceMetrics struct {
	Timestamp     time.Time   `json:"timestamp"`
	CPUUsage      float64     `json:"cpu_usage"`       // CPU usage percentage
	MemoryUsage   uint64      `json:"memory_usage"`    // Memory usage in bytes
	MemoryPeak    uint64      `json:"memory_peak"`     // Peak memory usage
	MemoryRSS     uint64      `json:"memory_rss"`      // Resident set size
	MemoryVMS     uint64      `json:"memory_vms"`      // Virtual memory size
	NetworkBytes  uint64      `json:"network_bytes"`   // Network bytes sent/received
	DiskIO        uint64      `json:"disk_io"`         // Disk I/O operations
	GoRoutines    int         `json:"go_routines"`     // Number of goroutines
	HeapAlloc     uint64      `json:"heap_alloc"`      // Heap allocation
	HeapSys       uint64      `json:"heap_sys"`        // Heap system
	HeapIdle      uint64      `json:"heap_idle"`       // Heap idle
	HeapInuse     uint64      `json:"heap_inuse"`      // Heap in use
	HeapReleased  uint64      `json:"heap_released"`   // Heap released
	HeapObjects   uint64      `json:"heap_objects"`    // Number of heap objects
	StackInuse    uint64      `json:"stack_inuse"`     // Stack in use
	StackSys      uint64      `json:"stack_sys"`       // Stack system
	MSpanInuse    uint64      `json:"mspan_inuse"`     // MSpan in use
	MSpanSys      uint64      `json:"mspan_sys"`       // MSpan system
	MCacheInuse   uint64      `json:"mcache_inuse"`    // MCache in use
	MCacheSys     uint64      `json:"mcache_sys"`      // MCache system
	BuckHashSys   uint64      `json:"buck_hash_sys"`   // Bucket hash system
	GCSys         uint64      `json:"gc_sys"`          // GC system
	OtherSys      uint64      `json:"other_sys"`       // Other system
	NextGC        uint64      `json:"next_gc"`         // Next GC threshold
	LastGC        uint64      `json:"last_gc"`         // Last GC time
	PauseTotalNs  uint64      `json:"pause_total_ns"`  // Total GC pause time
	PauseNs       [256]uint64 `json:"pause_ns"`        // GC pause times
	NumGC         uint32      `json:"num_gc"`          // Number of GCs
	NumForcedGC   uint32      `json:"num_forced_gc"`   // Number of forced GCs
	GCCPUFraction float64     `json:"gc_cpu_fraction"` // GC CPU fraction
}

// TestCaseMetrics represents metrics for a specific test case
type TestCaseMetrics struct {
	TestCaseID    string                 `json:"test_case_id"`
	WorkerID      int                    `json:"worker_id"`
	StartTime     time.Time              `json:"start_time"`
	EndTime       time.Time              `json:"end_time"`
	Duration      time.Duration          `json:"duration"`
	ResourceUsage ResourceMetrics        `json:"resource_usage"`
	Executions    int64                  `json:"executions"`
	Status        string                 `json:"status"`
	Metadata      map[string]interface{} `json:"metadata"`
}

// WorkerMetrics represents metrics for a specific worker
type WorkerMetrics struct {
	WorkerID            int                    `json:"worker_id"`
	StartTime           time.Time              `json:"start_time"`
	LastActivity        time.Time              `json:"last_activity"`
	TotalTests          int64                  `json:"total_tests"`
	TotalCrashes        int64                  `json:"total_crashes"`
	TotalHangs          int64                  `json:"total_hangs"`
	CurrentCPU          float64                `json:"current_cpu"`
	CurrentMemory       uint64                 `json:"current_memory"`
	PeakMemory          uint64                 `json:"peak_memory"`
	AverageCPU          float64                `json:"average_cpu"`
	AverageMemory       uint64                 `json:"average_memory"`
	ExecutionsPerSecond float64                `json:"executions_per_second"`
	ResourceHistory     []ResourceMetrics      `json:"resource_history"`
	TestCaseHistory     []TestCaseMetrics      `json:"test_case_history"`
	Status              string                 `json:"status"`
	Metadata            map[string]interface{} `json:"metadata"`
}

// GlobalMetrics represents global fuzzer metrics
type GlobalMetrics struct {
	StartTime           time.Time              `json:"start_time"`
	Uptime              time.Duration          `json:"uptime"`
	TotalExecutions     int64                  `json:"total_executions"`
	TotalCrashes        int64                  `json:"total_crashes"`
	TotalHangs          int64                  `json:"total_hangs"`
	ActiveWorkers       int                    `json:"active_workers"`
	TotalWorkers        int                    `json:"total_workers"`
	CorpusSize          int                    `json:"corpus_size"`
	CoveragePoints      int                    `json:"coverage_points"`
	ExecutionsPerSecond float64                `json:"executions_per_second"`
	AverageCPU          float64                `json:"average_cpu"`
	AverageMemory       uint64                 `json:"average_memory"`
	PeakMemory          uint64                 `json:"peak_memory"`
	TotalNetworkBytes   uint64                 `json:"total_network_bytes"`
	TotalDiskIO         uint64                 `json:"total_disk_io"`
	WorkerMetrics       map[int]*WorkerMetrics `json:"worker_metrics"`
	ResourceHistory     []ResourceMetrics      `json:"resource_history"`
	PerformanceAlerts   []PerformanceAlert     `json:"performance_alerts"`
	Metadata            map[string]interface{} `json:"metadata"`
}

// PerformanceAlert represents a performance issue alert
type PerformanceAlert struct {
	Timestamp  time.Time `json:"timestamp"`
	Type       string    `json:"type"`     // cpu_high, memory_high, network_high, etc.
	Severity   string    `json:"severity"` // low, medium, high, critical
	Message    string    `json:"message"`
	Value      float64   `json:"value"`
	Threshold  float64   `json:"threshold"`
	WorkerID   int       `json:"worker_id,omitempty"`
	TestCaseID string    `json:"test_case_id,omitempty"`
}

// MetricsCollector provides comprehensive metrics collection
type MetricsCollector struct {
	globalMetrics   *GlobalMetrics
	workerMetrics   map[int]*WorkerMetrics
	testCaseMetrics map[string]*TestCaseMetrics

	// Configuration
	collectionInterval time.Duration
	historySize        int
	alertThresholds    AlertThresholds

	// State
	running bool
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	mu      sync.RWMutex

	// Performance tracking
	lastCollection time.Time
	executionCount int64
	crashCount     int64
	hangCount      int64

	// Logging
	logger *logrus.Logger
}

// AlertThresholds defines thresholds for performance alerts
type AlertThresholds struct {
	CPUHigh        float64 `json:"cpu_high"`         // CPU usage threshold (percentage)
	MemoryHigh     uint64  `json:"memory_high"`      // Memory usage threshold (bytes)
	NetworkHigh    uint64  `json:"network_high"`     // Network usage threshold (bytes/sec)
	DiskIOHigh     uint64  `json:"disk_io_high"`     // Disk I/O threshold (ops/sec)
	GoRoutinesHigh int     `json:"go_routines_high"` // Goroutine count threshold
	HeapHigh       uint64  `json:"heap_high"`        // Heap usage threshold (bytes)
}

// NewMetricsCollector creates a new metrics collector
func NewMetricsCollector(logger *logrus.Logger) *MetricsCollector {
	return &MetricsCollector{
		globalMetrics: &GlobalMetrics{
			StartTime:         time.Now(),
			WorkerMetrics:     make(map[int]*WorkerMetrics),
			ResourceHistory:   make([]ResourceMetrics, 0),
			PerformanceAlerts: make([]PerformanceAlert, 0),
			Metadata:          make(map[string]interface{}),
		},
		workerMetrics:      make(map[int]*WorkerMetrics),
		testCaseMetrics:    make(map[string]*TestCaseMetrics),
		collectionInterval: 1 * time.Second,
		historySize:        1000,
		alertThresholds: AlertThresholds{
			CPUHigh:        80.0,    // 80% CPU usage
			MemoryHigh:     1 << 30, // 1GB memory
			NetworkHigh:    1 << 20, // 1MB/s network
			DiskIOHigh:     1000,    // 1000 ops/sec
			GoRoutinesHigh: 10000,   // 10k goroutines
			HeapHigh:       1 << 29, // 512MB heap
		},
		logger: logger,
	}
}

// Start begins metrics collection
func (mc *MetricsCollector) Start(ctx context.Context) error {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	if mc.running {
		return fmt.Errorf("metrics collector already running")
	}

	mc.ctx, mc.cancel = context.WithCancel(ctx)
	mc.running = true
	mc.lastCollection = time.Now()

	// Start collection goroutine
	mc.wg.Add(1)
	go mc.collectionLoop()

	mc.logger.Info("Metrics collector started")
	return nil
}

// Stop stops metrics collection
func (mc *MetricsCollector) Stop() error {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	if !mc.running {
		return fmt.Errorf("metrics collector not running")
	}

	mc.running = false
	mc.cancel()
	mc.wg.Wait()

	mc.logger.Info("Metrics collector stopped")
	return nil
}

// collectionLoop runs the main metrics collection loop
func (mc *MetricsCollector) collectionLoop() {
	defer mc.wg.Done()

	ticker := time.NewTicker(mc.collectionInterval)
	defer ticker.Stop()

	for {
		select {
		case <-mc.ctx.Done():
			return
		case <-ticker.C:
			mc.collectMetrics()
		}
	}
}

// collectMetrics collects current system metrics
func (mc *MetricsCollector) collectMetrics() {
	metrics := mc.getCurrentResourceMetrics()

	mc.mu.Lock()
	defer mc.mu.Unlock()

	// Update global metrics
	mc.globalMetrics.Uptime = time.Since(mc.globalMetrics.StartTime)
	mc.globalMetrics.TotalExecutions = atomic.LoadInt64(&mc.executionCount)
	mc.globalMetrics.TotalCrashes = atomic.LoadInt64(&mc.crashCount)
	mc.globalMetrics.TotalHangs = atomic.LoadInt64(&mc.hangCount)
	mc.globalMetrics.ActiveWorkers = len(mc.workerMetrics)
	mc.globalMetrics.TotalWorkers = len(mc.workerMetrics)
	mc.globalMetrics.AverageCPU = metrics.CPUUsage
	mc.globalMetrics.AverageMemory = metrics.MemoryUsage
	mc.globalMetrics.PeakMemory = metrics.MemoryPeak

	// Calculate executions per second
	duration := time.Since(mc.lastCollection).Seconds()
	if duration > 0 {
		executions := atomic.LoadInt64(&mc.executionCount)
		mc.globalMetrics.ExecutionsPerSecond = float64(executions) / duration
	}

	// Add to resource history
	mc.addToResourceHistory(metrics)

	// Check for performance alerts
	mc.checkPerformanceAlerts(metrics)

	mc.lastCollection = time.Now()
}

// getCurrentResourceMetrics collects current system resource metrics
func (mc *MetricsCollector) getCurrentResourceMetrics() ResourceMetrics {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	metrics := ResourceMetrics{
		Timestamp:     time.Now(),
		CPUUsage:      mc.getCPUUsage(),
		MemoryUsage:   m.Alloc,
		MemoryPeak:    m.TotalAlloc,
		MemoryRSS:     m.Sys,
		MemoryVMS:     m.Sys,
		NetworkBytes:  mc.getNetworkBytes(),
		DiskIO:        mc.getDiskIO(),
		GoRoutines:    runtime.NumGoroutine(),
		HeapAlloc:     m.HeapAlloc,
		HeapSys:       m.HeapSys,
		HeapIdle:      m.HeapIdle,
		HeapInuse:     m.HeapInuse,
		HeapReleased:  m.HeapReleased,
		HeapObjects:   m.HeapObjects,
		StackInuse:    m.StackInuse,
		StackSys:      m.StackSys,
		MSpanInuse:    m.MSpanInuse,
		MSpanSys:      m.MSpanSys,
		MCacheInuse:   m.MCacheInuse,
		MCacheSys:     m.MCacheSys,
		BuckHashSys:   m.BuckHashSys,
		GCSys:         m.GCSys,
		OtherSys:      m.OtherSys,
		NextGC:        m.NextGC,
		LastGC:        m.LastGC,
		PauseTotalNs:  m.PauseTotalNs,
		PauseNs:       m.PauseNs,
		NumGC:         m.NumGC,
		NumForcedGC:   m.NumForcedGC,
		GCCPUFraction: m.GCCPUFraction,
	}

	return metrics
}

// getCPUUsage gets current CPU usage using /proc/stat
func (mc *MetricsCollector) getCPUUsage() float64 {
	// Read /proc/stat to get CPU usage statistics
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		mc.logger.Warnf("Failed to read /proc/stat: %v", err)
		return 0.0
	}

	lines := strings.Split(string(data), "\n")
	if len(lines) == 0 {
		return 0.0
	}

	// Parse the first line (total CPU usage)
	fields := strings.Fields(lines[0])
	if len(fields) < 5 || fields[0] != "cpu" {
		return 0.0
	}

	// Extract CPU time values
	var total, idle uint64
	for i := 1; i < len(fields); i++ {
		val, err := strconv.ParseUint(fields[i], 10, 64)
		if err != nil {
			continue
		}
		total += val
		if i == 4 { // idle time is the 5th field
			idle = val
		}
	}

	// Calculate CPU usage percentage
	if total == 0 {
		return 0.0
	}

	// Store previous values for delta calculation
	mc.mu.Lock()
	prevTotal, prevIdle := mc.globalMetrics.Metadata["prev_cpu_total"], mc.globalMetrics.Metadata["prev_cpu_idle"]
	mc.globalMetrics.Metadata["prev_cpu_total"] = total
	mc.globalMetrics.Metadata["prev_cpu_idle"] = idle
	mc.mu.Unlock()

	// Calculate delta if we have previous values
	if prevTotal != nil && prevIdle != nil {
		prevTotalVal, ok1 := prevTotal.(uint64)
		prevIdleVal, ok2 := prevIdle.(uint64)
		if ok1 && ok2 {
			totalDelta := total - prevTotalVal
			idleDelta := idle - prevIdleVal
			if totalDelta > 0 {
				usage := 100.0 * (1.0 - float64(idleDelta)/float64(totalDelta))
				return usage
			}
		}
	}

	return 0.0
}

// getNetworkBytes gets current network usage using /proc/net/dev
func (mc *MetricsCollector) getNetworkBytes() uint64 {
	// Read /proc/net/dev to get network interface statistics
	data, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		mc.logger.Warnf("Failed to read /proc/net/dev: %v", err)
		return 0
	}

	lines := strings.Split(string(data), "\n")
	var totalBytes uint64

	for _, line := range lines {
		// Skip header lines
		if strings.Contains(line, "Inter-|") || strings.Contains(line, "face |") || strings.Contains(line, "lo:") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}

		// Parse interface name (remove trailing colon)
		ifaceName := strings.TrimSuffix(fields[0], ":")

		// Skip loopback and virtual interfaces for total bandwidth calculation
		if ifaceName == "lo" || strings.HasPrefix(ifaceName, "docker") ||
			strings.HasPrefix(ifaceName, "veth") || strings.HasPrefix(ifaceName, "br-") {
			continue
		}

		// Parse received and transmitted bytes
		rxBytes, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}
		txBytes, err := strconv.ParseUint(fields[9], 10, 64)
		if err != nil {
			continue
		}

		totalBytes += rxBytes + txBytes
	}

	// Store previous value for rate calculation
	mc.mu.Lock()
	prevBytes := mc.globalMetrics.Metadata["prev_network_bytes"]
	mc.globalMetrics.Metadata["prev_network_bytes"] = totalBytes
	mc.mu.Unlock()

	// Calculate bytes per second if we have previous value
	if prevBytes != nil {
		prevBytesVal, ok := prevBytes.(uint64)
		if ok {
			// Calculate rate based on collection interval
			rate := float64(totalBytes-prevBytesVal) / mc.collectionInterval.Seconds()
			return uint64(rate)
		}
	}

	return totalBytes
}

// getDiskIO gets current disk I/O usage using /proc/diskstats
func (mc *MetricsCollector) getDiskIO() uint64 {
	// Read /proc/diskstats to get disk I/O statistics
	data, err := os.ReadFile("/proc/diskstats")
	if err != nil {
		mc.logger.Warnf("Failed to read /proc/diskstats: %v", err)
		return 0
	}

	lines := strings.Split(string(data), "\n")
	var totalIO uint64

	for _, line := range lines {
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 14 {
			continue
		}

		// Parse disk name
		diskName := fields[2]

		// Skip partitions and virtual devices
		if strings.Contains(diskName, "loop") || strings.Contains(diskName, "ram") ||
			strings.Contains(diskName, "md") || strings.Contains(diskName, "dm-") {
			continue
		}

		// Parse read and write operations
		readOps, err := strconv.ParseUint(fields[3], 10, 64)
		if err != nil {
			continue
		}
		writeOps, err := strconv.ParseUint(fields[7], 10, 64)
		if err != nil {
			continue
		}

		totalIO += readOps + writeOps
	}

	// Store previous value for rate calculation
	mc.mu.Lock()
	prevIO := mc.globalMetrics.Metadata["prev_disk_io"]
	mc.globalMetrics.Metadata["prev_disk_io"] = totalIO
	mc.mu.Unlock()

	// Calculate I/O operations per second if we have previous value
	if prevIO != nil {
		prevIOVal, ok := prevIO.(uint64)
		if ok {
			// Calculate rate based on collection interval
			rate := float64(totalIO-prevIOVal) / mc.collectionInterval.Seconds()
			return uint64(rate)
		}
	}

	return totalIO
}

// addToResourceHistory adds metrics to resource history
func (mc *MetricsCollector) addToResourceHistory(metrics ResourceMetrics) {
	mc.globalMetrics.ResourceHistory = append(mc.globalMetrics.ResourceHistory, metrics)

	// Keep history size manageable
	if len(mc.globalMetrics.ResourceHistory) > mc.historySize {
		mc.globalMetrics.ResourceHistory = mc.globalMetrics.ResourceHistory[1:]
	}
}

// checkPerformanceAlerts checks for performance issues
func (mc *MetricsCollector) checkPerformanceAlerts(metrics ResourceMetrics) {
	// Check CPU usage
	if metrics.CPUUsage > mc.alertThresholds.CPUHigh {
		mc.addAlert(PerformanceAlert{
			Timestamp: time.Now(),
			Type:      "cpu_high",
			Severity:  "high",
			Message:   fmt.Sprintf("High CPU usage: %.2f%%", metrics.CPUUsage),
			Value:     metrics.CPUUsage,
			Threshold: mc.alertThresholds.CPUHigh,
		})
	}

	// Check memory usage
	if metrics.MemoryUsage > mc.alertThresholds.MemoryHigh {
		mc.addAlert(PerformanceAlert{
			Timestamp: time.Now(),
			Type:      "memory_high",
			Severity:  "high",
			Message:   fmt.Sprintf("High memory usage: %d bytes", metrics.MemoryUsage),
			Value:     float64(metrics.MemoryUsage),
			Threshold: float64(mc.alertThresholds.MemoryHigh),
		})
	}

	// Check goroutine count
	if metrics.GoRoutines > mc.alertThresholds.GoRoutinesHigh {
		mc.addAlert(PerformanceAlert{
			Timestamp: time.Now(),
			Type:      "goroutines_high",
			Severity:  "medium",
			Message:   fmt.Sprintf("High goroutine count: %d", metrics.GoRoutines),
			Value:     float64(metrics.GoRoutines),
			Threshold: float64(mc.alertThresholds.GoRoutinesHigh),
		})
	}

	// Check heap usage
	if metrics.HeapAlloc > mc.alertThresholds.HeapHigh {
		mc.addAlert(PerformanceAlert{
			Timestamp: time.Now(),
			Type:      "heap_high",
			Severity:  "high",
			Message:   fmt.Sprintf("High heap usage: %d bytes", metrics.HeapAlloc),
			Value:     float64(metrics.HeapAlloc),
			Threshold: float64(mc.alertThresholds.HeapHigh),
		})
	}
}

// addAlert adds a performance alert
func (mc *MetricsCollector) addAlert(alert PerformanceAlert) {
	mc.globalMetrics.PerformanceAlerts = append(mc.globalMetrics.PerformanceAlerts, alert)
	mc.logger.Warnf("Performance alert: %s - %s", alert.Type, alert.Message)
}

// RecordTestCaseExecution records metrics for a test case execution
func (mc *MetricsCollector) RecordTestCaseExecution(testCaseID string, workerID int, duration time.Duration, status string) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	metrics := TestCaseMetrics{
		TestCaseID:    testCaseID,
		WorkerID:      workerID,
		StartTime:     time.Now().Add(-duration),
		EndTime:       time.Now(),
		Duration:      duration,
		ResourceUsage: mc.getCurrentResourceMetrics(),
		Executions:    1,
		Status:        status,
		Metadata:      make(map[string]interface{}),
	}

	mc.testCaseMetrics[testCaseID] = &metrics

	// Update worker metrics
	if worker, exists := mc.workerMetrics[workerID]; exists {
		worker.TotalTests++
		worker.LastActivity = time.Now()
		worker.TestCaseHistory = append(worker.TestCaseHistory, metrics)

		// Keep history manageable
		if len(worker.TestCaseHistory) > mc.historySize {
			worker.TestCaseHistory = worker.TestCaseHistory[1:]
		}

		switch status {
		case "crash":
			worker.TotalCrashes++
			atomic.AddInt64(&mc.crashCount, 1)
		case "hang":
			worker.TotalHangs++
			atomic.AddInt64(&mc.hangCount, 1)
		}
	}

	atomic.AddInt64(&mc.executionCount, 1)
}

// RegisterWorker registers a worker for monitoring
func (mc *MetricsCollector) RegisterWorker(workerID int) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	mc.workerMetrics[workerID] = &WorkerMetrics{
		WorkerID:        workerID,
		StartTime:       time.Now(),
		LastActivity:    time.Now(),
		ResourceHistory: make([]ResourceMetrics, 0),
		TestCaseHistory: make([]TestCaseMetrics, 0),
		Status:          "active",
		Metadata:        make(map[string]interface{}),
	}

	mc.globalMetrics.WorkerMetrics[workerID] = mc.workerMetrics[workerID]
}

// UnregisterWorker unregisters a worker
func (mc *MetricsCollector) UnregisterWorker(workerID int) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	if worker, exists := mc.workerMetrics[workerID]; exists {
		worker.Status = "stopped"
		worker.LastActivity = time.Now()
	}
}

// GetGlobalMetrics returns current global metrics
func (mc *MetricsCollector) GetGlobalMetrics() *GlobalMetrics {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	// Create a copy to avoid race conditions
	metrics := *mc.globalMetrics
	return &metrics
}

// GetWorkerMetrics returns metrics for a specific worker
func (mc *MetricsCollector) GetWorkerMetrics(workerID int) *WorkerMetrics {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	if worker, exists := mc.workerMetrics[workerID]; exists {
		// Create a copy to avoid race conditions
		workerCopy := *worker
		return &workerCopy
	}

	return nil
}

// GetTestCaseMetrics returns metrics for a specific test case
func (mc *MetricsCollector) GetTestCaseMetrics(testCaseID string) *TestCaseMetrics {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	if metrics, exists := mc.testCaseMetrics[testCaseID]; exists {
		// Create a copy to avoid race conditions
		metricsCopy := *metrics
		return &metricsCopy
	}

	return nil
}

// SetAlertThresholds sets performance alert thresholds
func (mc *MetricsCollector) SetAlertThresholds(thresholds AlertThresholds) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	mc.alertThresholds = thresholds
}

// GetAlertThresholds returns current alert thresholds
func (mc *MetricsCollector) GetAlertThresholds() AlertThresholds {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	return mc.alertThresholds
}
