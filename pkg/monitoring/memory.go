/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: memory.go
Description: Memory leak detection and monitoring system for the Akaylee Fuzzer.
Provides comprehensive memory usage tracking, leak detection algorithms,
memory optimization recommendations, and automatic memory management.
*/

package monitoring

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// MemoryLeakType represents the type of memory leak detected
type MemoryLeakType string

const (
	MemoryLeakTypeGradual   MemoryLeakType = "gradual"   // Gradual memory increase
	MemoryLeakTypeSudden    MemoryLeakType = "sudden"    // Sudden memory spike
	MemoryLeakTypeCyclic    MemoryLeakType = "cyclic"    // Cyclic memory pattern
	MemoryLeakTypeGoroutine MemoryLeakType = "goroutine" // Goroutine leak
	MemoryLeakTypeHeap      MemoryLeakType = "heap"      // Heap memory leak
	MemoryLeakTypeStack     MemoryLeakType = "stack"     // Stack memory leak
)

// MemoryLeakAlert represents a memory leak alert
type MemoryLeakAlert struct {
	ID              string                 `json:"id"`
	Type            MemoryLeakType         `json:"type"`
	Severity        string                 `json:"severity"` // low, medium, high, critical
	Timestamp       time.Time              `json:"timestamp"`
	Message         string                 `json:"message"`
	CurrentUsage    uint64                 `json:"current_usage"`
	PeakUsage       uint64                 `json:"peak_usage"`
	GrowthRate      float64                `json:"growth_rate"` // bytes per second
	Duration        time.Duration          `json:"duration"`
	Confidence      float64                `json:"confidence"` // 0.0 to 1.0
	Evidence        []string               `json:"evidence"`
	Recommendations []string               `json:"recommendations"`
	Metadata        map[string]interface{} `json:"metadata"`
}

// MemorySnapshot represents a memory usage snapshot
type MemorySnapshot struct {
	Timestamp     time.Time `json:"timestamp"`
	HeapAlloc     uint64    `json:"heap_alloc"`
	HeapSys       uint64    `json:"heap_sys"`
	HeapIdle      uint64    `json:"heap_idle"`
	HeapInuse     uint64    `json:"heap_inuse"`
	HeapReleased  uint64    `json:"heap_released"`
	HeapObjects   uint64    `json:"heap_objects"`
	StackInuse    uint64    `json:"stack_inuse"`
	StackSys      uint64    `json:"stack_sys"`
	MSpanInuse    uint64    `json:"mspan_inuse"`
	MSpanSys      uint64    `json:"mspan_sys"`
	MCacheInuse   uint64    `json:"mcache_inuse"`
	MCacheSys     uint64    `json:"mcache_sys"`
	BuckHashSys   uint64    `json:"buck_hash_sys"`
	GCSys         uint64    `json:"gc_sys"`
	OtherSys      uint64    `json:"other_sys"`
	GoRoutines    int       `json:"go_routines"`
	NumGC         uint32    `json:"num_gc"`
	PauseTotalNs  uint64    `json:"pause_total_ns"`
	GCCPUFraction float64   `json:"gc_cpu_fraction"`
}

// MemoryLeakDetector provides memory leak detection capabilities
type MemoryLeakDetector struct {
	config *MemoryLeakConfig
	logger *logrus.Logger

	// State
	running bool
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	mu      sync.RWMutex

	// Memory tracking
	snapshots []*MemorySnapshot
	alerts    []*MemoryLeakAlert
	baseline  *MemorySnapshot

	// Detection algorithms
	detectors map[MemoryLeakType]LeakDetector

	// Performance tracking
	lastSnapshot       time.Time
	collectionInterval time.Duration
}

// MemoryLeakConfig represents memory leak detection configuration
type MemoryLeakConfig struct {
	Enabled             bool          `json:"enabled"`
	CollectionInterval  time.Duration `json:"collection_interval"`
	HistorySize         int           `json:"history_size"`
	DetectionThreshold  float64       `json:"detection_threshold"`  // Growth rate threshold
	AlertThreshold      uint64        `json:"alert_threshold"`      // Memory usage threshold
	ConfidenceThreshold float64       `json:"confidence_threshold"` // Minimum confidence for alerts
	AutoGC              bool          `json:"auto_gc"`              // Automatic garbage collection
	GCThreshold         uint64        `json:"gc_threshold"`         // Memory threshold for auto GC
}

// LeakDetector interface for different leak detection algorithms
type LeakDetector interface {
	Detect(snapshots []*MemorySnapshot) (*MemoryLeakAlert, error)
	Name() string
	Description() string
}

// NewMemoryLeakDetector creates a new memory leak detector
func NewMemoryLeakDetector(config *MemoryLeakConfig, logger *logrus.Logger) *MemoryLeakDetector {
	detector := &MemoryLeakDetector{
		config:             config,
		logger:             logger,
		snapshots:          make([]*MemorySnapshot, 0),
		alerts:             make([]*MemoryLeakAlert, 0),
		detectors:          make(map[MemoryLeakType]LeakDetector),
		collectionInterval: config.CollectionInterval,
	}

	// Register leak detectors
	detector.registerDetectors()

	return detector
}

// registerDetectors registers all leak detection algorithms
func (mld *MemoryLeakDetector) registerDetectors() {
	mld.detectors[MemoryLeakTypeGradual] = &GradualLeakDetector{}
	mld.detectors[MemoryLeakTypeSudden] = &SuddenLeakDetector{}
	mld.detectors[MemoryLeakTypeCyclic] = &CyclicLeakDetector{}
	mld.detectors[MemoryLeakTypeGoroutine] = &GoroutineLeakDetector{}
	mld.detectors[MemoryLeakTypeHeap] = &HeapLeakDetector{}
	mld.detectors[MemoryLeakTypeStack] = &StackLeakDetector{}
}

// Start begins memory leak detection
func (mld *MemoryLeakDetector) Start(ctx context.Context) error {
	mld.mu.Lock()
	defer mld.mu.Unlock()

	if mld.running {
		return fmt.Errorf("memory leak detector already running")
	}

	mld.ctx, mld.cancel = context.WithCancel(ctx)
	mld.running = true
	mld.lastSnapshot = time.Now()

	// Take initial baseline snapshot
	mld.baseline = mld.takeSnapshot()

	// Start collection goroutine
	mld.wg.Add(1)
	go mld.collectionLoop()

	mld.logger.Info("Memory leak detector started")
	return nil
}

// Stop stops memory leak detection
func (mld *MemoryLeakDetector) Stop() error {
	mld.mu.Lock()
	defer mld.mu.Unlock()

	if !mld.running {
		return fmt.Errorf("memory leak detector not running")
	}

	mld.running = false
	mld.cancel()
	mld.wg.Wait()

	mld.logger.Info("Memory leak detector stopped")
	return nil
}

// collectionLoop runs the main memory collection loop
func (mld *MemoryLeakDetector) collectionLoop() {
	defer mld.wg.Done()

	ticker := time.NewTicker(mld.collectionInterval)
	defer ticker.Stop()

	for {
		select {
		case <-mld.ctx.Done():
			return
		case <-ticker.C:
			mld.collectMemoryData()
		}
	}
}

// collectMemoryData collects memory data and runs leak detection
func (mld *MemoryLeakDetector) collectMemoryData() {
	snapshot := mld.takeSnapshot()

	mld.mu.Lock()
	defer mld.mu.Unlock()

	// Add snapshot to history
	mld.snapshots = append(mld.snapshots, snapshot)

	// Keep history size manageable
	if len(mld.snapshots) > mld.config.HistorySize {
		mld.snapshots = mld.snapshots[1:]
	}

	// Run leak detection if we have enough data
	if len(mld.snapshots) >= 10 {
		mld.runLeakDetection()
	}

	// Check for auto GC
	if mld.config.AutoGC && snapshot.HeapAlloc > mld.config.GCThreshold {
		mld.triggerGarbageCollection()
	}

	mld.lastSnapshot = time.Now()
}

// takeSnapshot takes a memory usage snapshot
func (mld *MemoryLeakDetector) takeSnapshot() *MemorySnapshot {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	return &MemorySnapshot{
		Timestamp:     time.Now(),
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
		GoRoutines:    runtime.NumGoroutine(),
		NumGC:         m.NumGC,
		PauseTotalNs:  m.PauseTotalNs,
		GCCPUFraction: m.GCCPUFraction,
	}
}

// runLeakDetection runs all leak detection algorithms
func (mld *MemoryLeakDetector) runLeakDetection() {
	for leakType, detector := range mld.detectors {
		alert, err := detector.Detect(mld.snapshots)
		if err != nil {
			mld.logger.Debugf("Leak detection failed for %s: %v", leakType, err)
			continue
		}

		if alert != nil && alert.Confidence >= mld.config.ConfidenceThreshold {
			alert.ID = fmt.Sprintf("leak_%s_%d", leakType, time.Now().Unix())
			alert.Type = leakType
			alert.Timestamp = time.Now()

			mld.alerts = append(mld.alerts, alert)
			mld.logger.Warnf("Memory leak detected: %s - %s", leakType, alert.Message)
		}
	}
}

// triggerGarbageCollection triggers garbage collection
func (mld *MemoryLeakDetector) triggerGarbageCollection() {
	before := runtime.NumGoroutine()
	runtime.GC()
	after := runtime.NumGoroutine()

	mld.logger.Infof("Auto GC triggered: goroutines %d -> %d", before, after)
}

// GetMemorySnapshots returns memory snapshots
func (mld *MemoryLeakDetector) GetMemorySnapshots() []*MemorySnapshot {
	mld.mu.RLock()
	defer mld.mu.RUnlock()

	// Create a copy to avoid race conditions
	snapshots := make([]*MemorySnapshot, len(mld.snapshots))
	copy(snapshots, mld.snapshots)
	return snapshots
}

// GetMemoryAlerts returns memory leak alerts
func (mld *MemoryLeakDetector) GetMemoryAlerts() []*MemoryLeakAlert {
	mld.mu.RLock()
	defer mld.mu.RUnlock()

	// Create a copy to avoid race conditions
	alerts := make([]*MemoryLeakAlert, len(mld.alerts))
	copy(alerts, mld.alerts)
	return alerts
}

// GetBaseline returns the baseline memory snapshot
func (mld *MemoryLeakDetector) GetBaseline() *MemorySnapshot {
	mld.mu.RLock()
	defer mld.mu.RUnlock()

	if mld.baseline == nil {
		return nil
	}

	// Create a copy to avoid race conditions
	baseline := *mld.baseline
	return &baseline
}

// IsRunning returns whether the detector is running
func (mld *MemoryLeakDetector) IsRunning() bool {
	mld.mu.RLock()
	defer mld.mu.RUnlock()
	return mld.running
}

// GetConfig returns the detector configuration
func (mld *MemoryLeakDetector) GetConfig() *MemoryLeakConfig {
	return mld.config
}

// Leak detector implementations

// GradualLeakDetector detects gradual memory leaks
type GradualLeakDetector struct{}

func (d *GradualLeakDetector) Detect(snapshots []*MemorySnapshot) (*MemoryLeakAlert, error) {
	if len(snapshots) < 10 {
		return nil, fmt.Errorf("insufficient data for gradual leak detection")
	}

	// Calculate growth rate over time
	first := snapshots[0]
	last := snapshots[len(snapshots)-1]

	duration := last.Timestamp.Sub(first.Timestamp).Seconds()
	if duration == 0 {
		return nil, fmt.Errorf("zero duration between snapshots")
	}

	growthRate := float64(last.HeapAlloc-first.HeapAlloc) / duration

	// Check if growth rate exceeds threshold
	if growthRate > 1024*1024 { // 1MB per second
		return &MemoryLeakAlert{
			Severity:     "high",
			Message:      fmt.Sprintf("Gradual memory leak detected: %.2f bytes/sec growth", growthRate),
			CurrentUsage: last.HeapAlloc,
			PeakUsage:    last.HeapAlloc,
			GrowthRate:   growthRate,
			Duration:     last.Timestamp.Sub(first.Timestamp),
			Confidence:   0.8,
			Evidence:     []string{"Consistent memory growth over time", "No corresponding GC activity"},
			Recommendations: []string{
				"Review object lifecycle management",
				"Check for unclosed resources",
				"Implement proper cleanup in defer statements",
				"Use memory profiling to identify allocation sources",
			},
			Metadata: make(map[string]interface{}),
		}, nil
	}

	return nil, nil
}

func (d *GradualLeakDetector) Name() string {
	return "GradualLeakDetector"
}

func (d *GradualLeakDetector) Description() string {
	return "Detects gradual memory leaks by analyzing growth rate over time"
}

// SuddenLeakDetector detects sudden memory spikes
type SuddenLeakDetector struct{}

func (d *SuddenLeakDetector) Detect(snapshots []*MemorySnapshot) (*MemoryLeakAlert, error) {
	if len(snapshots) < 5 {
		return nil, fmt.Errorf("insufficient data for sudden leak detection")
	}

	// Look for sudden spikes in memory usage
	for i := 1; i < len(snapshots); i++ {
		prev := snapshots[i-1]
		curr := snapshots[i]

		increase := curr.HeapAlloc - prev.HeapAlloc
		increasePercent := float64(increase) / float64(prev.HeapAlloc) * 100

		// Detect sudden increase (>50% in one snapshot)
		if increasePercent > 50 && increase > 10*1024*1024 { // 50% and >10MB
			return &MemoryLeakAlert{
				Severity:     "critical",
				Message:      fmt.Sprintf("Sudden memory spike detected: %.1f%% increase (%d bytes)", increasePercent, increase),
				CurrentUsage: curr.HeapAlloc,
				PeakUsage:    curr.HeapAlloc,
				GrowthRate:   float64(increase),
				Duration:     curr.Timestamp.Sub(prev.Timestamp),
				Confidence:   0.9,
				Evidence:     []string{"Sudden memory increase", "Large allocation spike"},
				Recommendations: []string{
					"Investigate recent code changes",
					"Check for large data structure allocations",
					"Review memory-intensive operations",
					"Consider implementing memory limits",
				},
				Metadata: make(map[string]interface{}),
			}, nil
		}
	}

	return nil, nil
}

func (d *SuddenLeakDetector) Name() string {
	return "SuddenLeakDetector"
}

func (d *SuddenLeakDetector) Description() string {
	return "Detects sudden memory spikes and large allocations"
}

// CyclicLeakDetector detects cyclic memory patterns
type CyclicLeakDetector struct{}

func (d *CyclicLeakDetector) Detect(snapshots []*MemorySnapshot) (*MemoryLeakAlert, error) {
	if len(snapshots) < 20 {
		return nil, fmt.Errorf("insufficient data for cyclic leak detection")
	}

	// Look for cyclic patterns in memory usage
	// This is a simplified implementation
	// In production, would use more sophisticated pattern recognition

	var peaks []uint64
	for i := 1; i < len(snapshots)-1; i++ {
		prev := snapshots[i-1].HeapAlloc
		curr := snapshots[i].HeapAlloc
		next := snapshots[i+1].HeapAlloc

		if curr > prev && curr > next {
			peaks = append(peaks, curr)
		}
	}

	// Check if peaks are increasing over time
	if len(peaks) >= 3 {
		increasing := true
		for i := 1; i < len(peaks); i++ {
			if peaks[i] <= peaks[i-1] {
				increasing = false
				break
			}
		}

		if increasing {
			return &MemoryLeakAlert{
				Severity:     "medium",
				Message:      "Cyclic memory pattern detected with increasing peaks",
				CurrentUsage: snapshots[len(snapshots)-1].HeapAlloc,
				PeakUsage:    peaks[len(peaks)-1],
				GrowthRate:   0,
				Duration:     snapshots[len(snapshots)-1].Timestamp.Sub(snapshots[0].Timestamp),
				Confidence:   0.7,
				Evidence:     []string{"Cyclic memory pattern", "Increasing peak values"},
				Recommendations: []string{
					"Review periodic operations",
					"Check for accumulating data structures",
					"Implement proper cleanup in cycles",
					"Consider memory pooling for repeated allocations",
				},
				Metadata: make(map[string]interface{}),
			}, nil
		}
	}

	return nil, nil
}

func (d *CyclicLeakDetector) Name() string {
	return "CyclicLeakDetector"
}

func (d *CyclicLeakDetector) Description() string {
	return "Detects cyclic memory patterns with increasing peaks"
}

// GoroutineLeakDetector detects goroutine leaks
type GoroutineLeakDetector struct{}

func (d *GoroutineLeakDetector) Detect(snapshots []*MemorySnapshot) (*MemoryLeakAlert, error) {
	if len(snapshots) < 5 {
		return nil, fmt.Errorf("insufficient data for goroutine leak detection")
	}

	// Check for increasing goroutine count
	first := snapshots[0]
	last := snapshots[len(snapshots)-1]

	if last.GoRoutines > first.GoRoutines*2 && last.GoRoutines > 1000 {
		return &MemoryLeakAlert{
			Severity:     "high",
			Message:      fmt.Sprintf("Goroutine leak detected: %d -> %d", first.GoRoutines, last.GoRoutines),
			CurrentUsage: last.HeapAlloc,
			PeakUsage:    last.HeapAlloc,
			GrowthRate:   float64(last.GoRoutines - first.GoRoutines),
			Duration:     last.Timestamp.Sub(first.Timestamp),
			Confidence:   0.8,
			Evidence:     []string{"Increasing goroutine count", "No corresponding cleanup"},
			Recommendations: []string{
				"Review goroutine lifecycle management",
				"Ensure all goroutines have proper exit conditions",
				"Use context cancellation for goroutine cleanup",
				"Implement goroutine pools for controlled concurrency",
			},
			Metadata: make(map[string]interface{}),
		}, nil
	}

	return nil, nil
}

func (d *GoroutineLeakDetector) Name() string {
	return "GoroutineLeakDetector"
}

func (d *GoroutineLeakDetector) Description() string {
	return "Detects goroutine leaks by monitoring goroutine count"
}

// HeapLeakDetector detects heap memory leaks
type HeapLeakDetector struct{}

func (d *HeapLeakDetector) Detect(snapshots []*MemorySnapshot) (*MemoryLeakAlert, error) {
	if len(snapshots) < 10 {
		return nil, fmt.Errorf("insufficient data for heap leak detection")
	}

	// Check for increasing heap usage without corresponding GC
	first := snapshots[0]
	last := snapshots[len(snapshots)-1]

	heapGrowth := last.HeapAlloc - first.HeapAlloc
	gcIncrease := last.NumGC - first.NumGC

	if heapGrowth > 100*1024*1024 && gcIncrease < 5 { // 100MB growth with <5 GCs
		return &MemoryLeakAlert{
			Severity:     "high",
			Message:      fmt.Sprintf("Heap memory leak detected: %d bytes growth with %d GCs", heapGrowth, gcIncrease),
			CurrentUsage: last.HeapAlloc,
			PeakUsage:    last.HeapAlloc,
			GrowthRate:   float64(heapGrowth),
			Duration:     last.Timestamp.Sub(first.Timestamp),
			Confidence:   0.9,
			Evidence:     []string{"Large heap growth", "Insufficient garbage collection"},
			Recommendations: []string{
				"Review object allocation patterns",
				"Check for unclosed resources",
				"Implement proper cleanup",
				"Consider manual garbage collection",
			},
			Metadata: make(map[string]interface{}),
		}, nil
	}

	return nil, nil
}

func (d *HeapLeakDetector) Name() string {
	return "HeapLeakDetector"
}

func (d *HeapLeakDetector) Description() string {
	return "Detects heap memory leaks by analyzing heap growth vs GC activity"
}

// StackLeakDetector detects stack memory leaks
type StackLeakDetector struct{}

func (d *StackLeakDetector) Detect(snapshots []*MemorySnapshot) (*MemoryLeakAlert, error) {
	if len(snapshots) < 5 {
		return nil, fmt.Errorf("insufficient data for stack leak detection")
	}

	// Check for increasing stack usage
	first := snapshots[0]
	last := snapshots[len(snapshots)-1]

	stackGrowth := last.StackInuse - first.StackInuse

	if stackGrowth > 10*1024*1024 { // 10MB stack growth
		return &MemoryLeakAlert{
			Severity:     "medium",
			Message:      fmt.Sprintf("Stack memory leak detected: %d bytes growth", stackGrowth),
			CurrentUsage: last.StackInuse,
			PeakUsage:    last.StackInuse,
			GrowthRate:   float64(stackGrowth),
			Duration:     last.Timestamp.Sub(first.Timestamp),
			Confidence:   0.7,
			Evidence:     []string{"Increasing stack usage", "Deep call stacks"},
			Recommendations: []string{
				"Review recursive functions",
				"Check for deep call stacks",
				"Implement proper stack management",
				"Consider iterative alternatives to recursion",
			},
			Metadata: make(map[string]interface{}),
		}, nil
	}

	return nil, nil
}

func (d *StackLeakDetector) Name() string {
	return "StackLeakDetector"
}

func (d *StackLeakDetector) Description() string {
	return "Detects stack memory leaks by monitoring stack usage"
}
