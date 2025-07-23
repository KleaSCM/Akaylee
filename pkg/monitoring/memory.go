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

	// Extract memory usage values for analysis
	var values []uint64
	var timestamps []time.Time
	for _, snapshot := range snapshots {
		values = append(values, snapshot.HeapAlloc)
		timestamps = append(timestamps, snapshot.Timestamp)
	}

	// Perform advanced cyclic pattern analysis
	cycleInfo := d.analyzeCyclicPattern(values, timestamps)
	if cycleInfo == nil {
		return nil, nil
	}

	// Calculate confidence based on pattern strength
	confidence := d.calculateConfidence(cycleInfo, values)

	// Generate evidence and recommendations
	evidence := d.generateEvidence(cycleInfo, values)
	recommendations := d.generateRecommendations(cycleInfo)

	return &MemoryLeakAlert{
		Severity:        d.determineSeverity(cycleInfo, confidence),
		Message:         fmt.Sprintf("Cyclic memory pattern detected: %s", cycleInfo.description),
		CurrentUsage:    values[len(values)-1],
		PeakUsage:       cycleInfo.peakValue,
		GrowthRate:      cycleInfo.growthRate,
		Duration:        timestamps[len(timestamps)-1].Sub(timestamps[0]),
		Confidence:      confidence,
		Evidence:        evidence,
		Recommendations: recommendations,
		Metadata: map[string]interface{}{
			"cycle_length":    cycleInfo.cycleLength,
			"cycle_count":     cycleInfo.cycleCount,
			"peak_count":      cycleInfo.peakCount,
			"growth_rate":     cycleInfo.growthRate,
			"pattern_type":    cycleInfo.patternType,
			"amplitude":       cycleInfo.amplitude,
			"baseline_growth": cycleInfo.baselineGrowth,
		},
	}, nil
}

// cycleInfo holds information about detected cyclic patterns
type cycleInfo struct {
	cycleLength    int     // Length of the cycle in samples
	cycleCount     int     // Number of complete cycles detected
	peakCount      int     // Number of peaks in the pattern
	peakValue      uint64  // Highest peak value
	growthRate     float64 // Overall growth rate (bytes/sec)
	patternType    string  // Type of pattern (linear, exponential, etc.)
	amplitude      uint64  // Amplitude of the cycle
	baselineGrowth float64 // Growth rate of the baseline
	description    string  // Human-readable description
}

// analyzeCyclicPattern performs advanced cyclic pattern analysis
func (d *CyclicLeakDetector) analyzeCyclicPattern(values []uint64, timestamps []time.Time) *cycleInfo {
	// Find peaks in the data
	peaks := d.findPeaks(values)
	if len(peaks) < 3 {
		return nil // Need at least 3 peaks for cyclic pattern
	}

	// Calculate cycle length from peak intervals
	cycleLength := d.calculateCycleLength(peaks, timestamps)
	if cycleLength <= 0 {
		return nil
	}

	// Analyze peak progression
	peakProgression := d.analyzePeakProgression(peaks, values)
	if peakProgression == nil {
		return nil
	}

	// Calculate growth rates
	growthRate := d.calculateGrowthRate(values, timestamps)
	baselineGrowth := d.calculateBaselineGrowth(values, timestamps)

	// Determine pattern type
	patternType := d.determinePatternType(peakProgression, growthRate)

	// Calculate amplitude
	amplitude := d.calculateAmplitude(values, cycleLength)

	// Generate description
	description := d.generateDescription(cycleLength, peakProgression, patternType, growthRate)

	return &cycleInfo{
		cycleLength:    cycleLength,
		cycleCount:     len(peaks) - 1,
		peakCount:      len(peaks),
		peakValue:      values[peaks[len(peaks)-1]],
		growthRate:     growthRate,
		patternType:    patternType,
		amplitude:      amplitude,
		baselineGrowth: baselineGrowth,
		description:    description,
	}
}

// findPeaks finds local maxima in the data
func (d *CyclicLeakDetector) findPeaks(values []uint64) []int {
	var peaks []int

	for i := 1; i < len(values)-1; i++ {
		// Check if current point is a peak
		if values[i] > values[i-1] && values[i] > values[i+1] {
			// Additional check: ensure it's a significant peak
			leftDiff := float64(values[i]-values[i-1]) / float64(values[i-1])
			rightDiff := float64(values[i]-values[i+1]) / float64(values[i+1])

			if leftDiff > 0.05 && rightDiff > 0.05 { // 5% threshold
				peaks = append(peaks, i)
			}
		}
	}

	return peaks
}

// calculateCycleLength calculates the average cycle length from peak intervals
func (d *CyclicLeakDetector) calculateCycleLength(peaks []int, timestamps []time.Time) int {
	if len(peaks) < 2 {
		return 0
	}

	var totalInterval int
	for i := 1; i < len(peaks); i++ {
		interval := peaks[i] - peaks[i-1]
		totalInterval += interval
	}

	return totalInterval / (len(peaks) - 1)
}

// analyzePeakProgression analyzes how peaks change over time
func (d *CyclicLeakDetector) analyzePeakProgression(peaks []int, values []uint64) []uint64 {
	var peakValues []uint64
	for _, peak := range peaks {
		if peak < len(values) {
			peakValues = append(peakValues, values[peak])
		}
	}
	return peakValues
}

// calculateGrowthRate calculates the overall growth rate
func (d *CyclicLeakDetector) calculateGrowthRate(values []uint64, timestamps []time.Time) float64 {
	if len(values) < 2 {
		return 0.0
	}

	duration := timestamps[len(timestamps)-1].Sub(timestamps[0]).Seconds()
	if duration <= 0 {
		return 0.0
	}

	growth := float64(values[len(values)-1] - values[0])
	return growth / duration
}

// calculateBaselineGrowth calculates growth rate of the baseline (minimum values)
func (d *CyclicLeakDetector) calculateBaselineGrowth(values []uint64, timestamps []time.Time) float64 {
	if len(values) < 2 {
		return 0.0
	}

	// Find local minima for baseline
	var minima []uint64
	for i := 1; i < len(values)-1; i++ {
		if values[i] < values[i-1] && values[i] < values[i+1] {
			minima = append(minima, values[i])
		}
	}

	if len(minima) < 2 {
		return 0.0
	}

	duration := timestamps[len(timestamps)-1].Sub(timestamps[0]).Seconds()
	if duration <= 0 {
		return 0.0
	}

	baselineGrowth := float64(minima[len(minima)-1] - minima[0])
	return baselineGrowth / duration
}

// determinePatternType determines the type of cyclic pattern
func (d *CyclicLeakDetector) determinePatternType(peakValues []uint64, growthRate float64) string {
	if len(peakValues) < 3 {
		return "unknown"
	}

	// Check if peaks are increasing
	increasing := true
	for i := 1; i < len(peakValues); i++ {
		if peakValues[i] <= peakValues[i-1] {
			increasing = false
			break
		}
	}

	if !increasing {
		return "stable_cyclic"
	}

	// Calculate peak growth rate
	peakGrowthRate := float64(peakValues[len(peakValues)-1]-peakValues[0]) / float64(len(peakValues)-1)

	if peakGrowthRate > growthRate*2 {
		return "accelerating_cyclic"
	} else if peakGrowthRate > growthRate*0.5 {
		return "linear_cyclic"
	} else {
		return "gradual_cyclic"
	}
}

// calculateAmplitude calculates the amplitude of the cyclic pattern
func (d *CyclicLeakDetector) calculateAmplitude(values []uint64, cycleLength int) uint64 {
	if len(values) < cycleLength*2 {
		return 0
	}

	var totalAmplitude uint64
	count := 0

	for i := cycleLength; i < len(values)-cycleLength; i += cycleLength {
		// Find min and max in this cycle
		min := values[i]
		max := values[i]

		for j := i; j < i+cycleLength && j < len(values); j++ {
			if values[j] < min {
				min = values[j]
			}
			if values[j] > max {
				max = values[j]
			}
		}

		totalAmplitude += max - min
		count++
	}

	if count == 0 {
		return 0
	}

	return totalAmplitude / uint64(count)
}

// generateDescription generates a human-readable description of the pattern
func (d *CyclicLeakDetector) generateDescription(cycleLength int, peakValues []uint64, patternType string, growthRate float64) string {
	cycleCount := len(peakValues) - 1
	avgPeakGrowth := 0.0

	if len(peakValues) > 1 {
		avgPeakGrowth = float64(peakValues[len(peakValues)-1]-peakValues[0]) / float64(len(peakValues)-1)
	}

	description := fmt.Sprintf("%s pattern with %d cycles", patternType, cycleCount)
	description += fmt.Sprintf(", cycle length: %d samples", cycleLength)

	if avgPeakGrowth > 0 {
		description += fmt.Sprintf(", peak growth: %.0f bytes/cycle", avgPeakGrowth)
	}

	if growthRate > 0 {
		description += fmt.Sprintf(", overall growth: %.0f bytes/sec", growthRate)
	}

	return description
}

// calculateConfidence calculates confidence in the detection
func (d *CyclicLeakDetector) calculateConfidence(cycleInfo *cycleInfo, values []uint64) float64 {
	confidence := 0.5 // Base confidence

	// Increase confidence based on cycle count
	if cycleInfo.cycleCount >= 3 {
		confidence += 0.2
	} else if cycleInfo.cycleCount >= 2 {
		confidence += 0.1
	}

	// Increase confidence based on pattern strength
	if cycleInfo.amplitude > 0 {
		amplitudeRatio := float64(cycleInfo.amplitude) / float64(cycleInfo.peakValue)
		if amplitudeRatio > 0.1 {
			confidence += 0.15
		} else if amplitudeRatio > 0.05 {
			confidence += 0.1
		}
	}

	// Increase confidence based on growth rate
	if cycleInfo.growthRate > 0 {
		confidence += 0.1
	}

	// Increase confidence based on pattern type
	switch cycleInfo.patternType {
	case "accelerating_cyclic":
		confidence += 0.1
	case "linear_cyclic":
		confidence += 0.05
	}

	// Cap confidence at 1.0
	if confidence > 1.0 {
		confidence = 1.0
	}

	return confidence
}

// determineSeverity determines the severity of the leak
func (d *CyclicLeakDetector) determineSeverity(cycleInfo *cycleInfo, confidence float64) string {
	if confidence < 0.6 {
		return "low"
	}

	if cycleInfo.growthRate > 1e6 { // > 1MB/sec
		return "critical"
	} else if cycleInfo.growthRate > 1e5 { // > 100KB/sec
		return "high"
	} else if cycleInfo.growthRate > 1e4 { // > 10KB/sec
		return "medium"
	}

	return "low"
}

// generateEvidence generates evidence for the detection
func (d *CyclicLeakDetector) generateEvidence(cycleInfo *cycleInfo, values []uint64) []string {
	evidence := []string{
		fmt.Sprintf("Detected %d complete cycles", cycleInfo.cycleCount),
		fmt.Sprintf("Cycle length: %d samples", cycleInfo.cycleLength),
		fmt.Sprintf("Pattern type: %s", cycleInfo.patternType),
	}

	if cycleInfo.growthRate > 0 {
		evidence = append(evidence, fmt.Sprintf("Overall growth rate: %.0f bytes/sec", cycleInfo.growthRate))
	}

	if cycleInfo.amplitude > 0 {
		evidence = append(evidence, fmt.Sprintf("Cycle amplitude: %d bytes", cycleInfo.amplitude))
	}

	if cycleInfo.baselineGrowth > 0 {
		evidence = append(evidence, fmt.Sprintf("Baseline growth: %.0f bytes/sec", cycleInfo.baselineGrowth))
	}

	return evidence
}

// generateRecommendations generates recommendations for fixing the leak
func (d *CyclicLeakDetector) generateRecommendations(cycleInfo *cycleInfo) []string {
	recommendations := []string{
		"Review periodic operations and their memory usage",
		"Check for accumulating data structures in cycles",
		"Implement proper cleanup in periodic operations",
		"Consider memory pooling for repeated allocations",
	}

	switch cycleInfo.patternType {
	case "accelerating_cyclic":
		recommendations = append(recommendations,
			"Investigate exponential memory growth in cycles",
			"Check for nested loops or recursive operations",
			"Review data structure growth patterns",
		)
	case "linear_cyclic":
		recommendations = append(recommendations,
			"Look for linear memory accumulation in cycles",
			"Check for missing cleanup in loop iterations",
		)
	}

	if cycleInfo.growthRate > 1e5 {
		recommendations = append(recommendations,
			"High growth rate detected - immediate investigation required",
			"Consider implementing memory limits and circuit breakers",
		)
	}

	return recommendations
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
