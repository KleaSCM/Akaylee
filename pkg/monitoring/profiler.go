/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: profiler.go
Description: Performance profiling system for the Akaylee Fuzzer. Provides CPU
profiling, memory profiling, goroutine profiling, and performance optimization
capabilities for identifying bottlenecks and optimizing fuzzer performance.
*/

package monitoring

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"runtime/trace"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// ProfilerType represents the type of profiling
type ProfilerType string

const (
	ProfilerTypeCPU       ProfilerType = "cpu"
	ProfilerTypeMemory    ProfilerType = "memory"
	ProfilerTypeGoroutine ProfilerType = "goroutine"
	ProfilerTypeBlock     ProfilerType = "block"
	ProfilerTypeMutex     ProfilerType = "mutex"
	ProfilerTypeTrace     ProfilerType = "trace"
)

// ProfilerConfig represents profiling configuration
type ProfilerConfig struct {
	Enabled          bool          `json:"enabled"`
	OutputDir        string        `json:"output_dir"`
	Duration         time.Duration `json:"duration"`
	Interval         time.Duration `json:"interval"`
	CPUProfile       bool          `json:"cpu_profile"`
	MemoryProfile    bool          `json:"memory_profile"`
	GoroutineProfile bool          `json:"goroutine_profile"`
	BlockProfile     bool          `json:"block_profile"`
	MutexProfile     bool          `json:"mutex_profile"`
	TraceProfile     bool          `json:"trace_profile"`
	AutoStart        bool          `json:"auto_start"`
	AutoStop         bool          `json:"auto_stop"`
}

// ProfileResult represents profiling results
type ProfileResult struct {
	Type       ProfilerType           `json:"type"`
	StartTime  time.Time              `json:"start_time"`
	EndTime    time.Time              `json:"end_time"`
	Duration   time.Duration          `json:"duration"`
	OutputFile string                 `json:"output_file"`
	Size       int64                  `json:"size"`
	Summary    string                 `json:"summary"`
	Metadata   map[string]interface{} `json:"metadata"`
}

// PerformanceProfile represents a comprehensive performance profile
type PerformanceProfile struct {
	ID              string                          `json:"id"`
	StartTime       time.Time                       `json:"start_time"`
	EndTime         time.Time                       `json:"end_time"`
	Duration        time.Duration                   `json:"duration"`
	Results         map[ProfilerType]*ProfileResult `json:"results"`
	Summary         PerformanceSummary              `json:"summary"`
	Recommendations []string                        `json:"recommendations"`
	Metadata        map[string]interface{}          `json:"metadata"`
}

// PerformanceSummary represents performance analysis summary
type PerformanceSummary struct {
	CPUUsage      float64  `json:"cpu_usage"`
	MemoryUsage   uint64   `json:"memory_usage"`
	MemoryPeak    uint64   `json:"memory_peak"`
	GoRoutines    int      `json:"go_routines"`
	HeapAlloc     uint64   `json:"heap_alloc"`
	HeapSys       uint64   `json:"heap_sys"`
	GCs           uint32   `json:"gcs"`
	GCPauseTime   uint64   `json:"gc_pause_time"`
	Bottlenecks   []string `json:"bottlenecks"`
	Optimizations []string `json:"optimizations"`
}

// Profiler provides comprehensive performance profiling
type Profiler struct {
	config *ProfilerConfig
	logger *logrus.Logger

	// State
	running bool
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	mu      sync.RWMutex

	// Active profiles
	activeProfiles map[ProfilerType]*ProfileResult
	profileHistory []*PerformanceProfile

	// Performance tracking
	startTime time.Time
	metrics   *MetricsCollector
}

// NewProfiler creates a new performance profiler
func NewProfiler(config *ProfilerConfig, logger *logrus.Logger, metrics *MetricsCollector) *Profiler {
	return &Profiler{
		config:         config,
		logger:         logger,
		activeProfiles: make(map[ProfilerType]*ProfileResult),
		profileHistory: make([]*PerformanceProfile, 0),
		metrics:        metrics,
	}
}

// Start begins profiling
func (p *Profiler) Start(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.running {
		return fmt.Errorf("profiler already running")
	}

	p.ctx, p.cancel = context.WithCancel(ctx)
	p.running = true
	p.startTime = time.Now()

	// Create output directory
	if err := os.MkdirAll(p.config.OutputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Start profiling based on configuration
	if p.config.CPUProfile {
		if err := p.startCPUProfile(); err != nil {
			p.logger.Warnf("Failed to start CPU profile: %v", err)
		}
	}

	if p.config.MemoryProfile {
		if err := p.startMemoryProfile(); err != nil {
			p.logger.Warnf("Failed to start memory profile: %v", err)
		}
	}

	if p.config.GoroutineProfile {
		if err := p.startGoroutineProfile(); err != nil {
			p.logger.Warnf("Failed to start goroutine profile: %v", err)
		}
	}

	if p.config.BlockProfile {
		if err := p.startBlockProfile(); err != nil {
			p.logger.Warnf("Failed to start block profile: %v", err)
		}
	}

	if p.config.MutexProfile {
		if err := p.startMutexProfile(); err != nil {
			p.logger.Warnf("Failed to start mutex profile: %v", err)
		}
	}

	if p.config.TraceProfile {
		if err := p.startTraceProfile(); err != nil {
			p.logger.Warnf("Failed to start trace profile: %v", err)
		}
	}

	// Start periodic profiling if configured
	if p.config.Interval > 0 {
		p.wg.Add(1)
		go p.periodicProfiling()
	}

	p.logger.Info("Performance profiler started")
	return nil
}

// Stop stops profiling
func (p *Profiler) Stop() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.running {
		return fmt.Errorf("profiler not running")
	}

	p.running = false
	p.cancel()
	p.wg.Wait()

	// Stop all active profiles
	p.stopAllProfiles()

	// Generate final performance profile
	profile := p.generatePerformanceProfile()
	p.profileHistory = append(p.profileHistory, profile)

	p.logger.Info("Performance profiler stopped")
	return nil
}

// periodicProfiling runs periodic profiling
func (p *Profiler) periodicProfiling() {
	defer p.wg.Done()

	ticker := time.NewTicker(p.config.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
			p.runPeriodicProfile()
		}
	}
}

// runPeriodicProfile runs a periodic profile
func (p *Profiler) runPeriodicProfile() {
	profile := p.generatePerformanceProfile()
	p.profileHistory = append(p.profileHistory, profile)

	// Keep history manageable
	if len(p.profileHistory) > 100 {
		p.profileHistory = p.profileHistory[1:]
	}

	p.logger.Debugf("Periodic profile generated: %s", profile.ID)
}

// startCPUProfile starts CPU profiling
func (p *Profiler) startCPUProfile() error {
	outputFile := filepath.Join(p.config.OutputDir, fmt.Sprintf("cpu_%d.prof", time.Now().Unix()))

	file, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create CPU profile file: %w", err)
	}

	if err := pprof.StartCPUProfile(file); err != nil {
		file.Close()
		return fmt.Errorf("failed to start CPU profile: %w", err)
	}

	result := &ProfileResult{
		Type:       ProfilerTypeCPU,
		StartTime:  time.Now(),
		OutputFile: outputFile,
		Metadata:   make(map[string]interface{}),
	}

	p.activeProfiles[ProfilerTypeCPU] = result
	p.logger.Info("CPU profiling started")
	return nil
}

// startMemoryProfile starts memory profiling
func (p *Profiler) startMemoryProfile() error {
	outputFile := filepath.Join(p.config.OutputDir, fmt.Sprintf("memory_%d.prof", time.Now().Unix()))

	file, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create memory profile file: %w", err)
	}

	// Store file reference for later use
	result := &ProfileResult{
		Type:       ProfilerTypeMemory,
		StartTime:  time.Now(),
		OutputFile: outputFile,
		Metadata:   make(map[string]interface{}),
	}

	// Store file handle in metadata for proper cleanup
	result.Metadata["file_handle"] = file
	p.activeProfiles[ProfilerTypeMemory] = result
	p.logger.Info("Memory profiling started")
	return nil
}

// startGoroutineProfile starts goroutine profiling
func (p *Profiler) startGoroutineProfile() error {
	outputFile := filepath.Join(p.config.OutputDir, fmt.Sprintf("goroutine_%d.prof", time.Now().Unix()))

	file, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create goroutine profile file: %w", err)
	}

	// Store file reference for later use
	result := &ProfileResult{
		Type:       ProfilerTypeGoroutine,
		StartTime:  time.Now(),
		OutputFile: outputFile,
		Metadata:   make(map[string]interface{}),
	}

	// Store file handle in metadata for proper cleanup
	result.Metadata["file_handle"] = file
	p.activeProfiles[ProfilerTypeGoroutine] = result
	p.logger.Info("Goroutine profiling started")
	return nil
}

// startBlockProfile starts block profiling
func (p *Profiler) startBlockProfile() error {
	runtime.SetBlockProfileRate(1)

	outputFile := filepath.Join(p.config.OutputDir, fmt.Sprintf("block_%d.prof", time.Now().Unix()))

	file, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create block profile file: %w", err)
	}

	// Store file reference for later use
	result := &ProfileResult{
		Type:       ProfilerTypeBlock,
		StartTime:  time.Now(),
		OutputFile: outputFile,
		Metadata:   make(map[string]interface{}),
	}

	// Store file handle in metadata for proper cleanup
	result.Metadata["file_handle"] = file
	p.activeProfiles[ProfilerTypeBlock] = result
	p.logger.Info("Block profiling started")
	return nil
}

// startMutexProfile starts mutex profiling
func (p *Profiler) startMutexProfile() error {
	runtime.SetMutexProfileFraction(1)

	outputFile := filepath.Join(p.config.OutputDir, fmt.Sprintf("mutex_%d.prof", time.Now().Unix()))

	file, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create mutex profile file: %w", err)
	}

	// Store file reference for later use
	result := &ProfileResult{
		Type:       ProfilerTypeMutex,
		StartTime:  time.Now(),
		OutputFile: outputFile,
		Metadata:   make(map[string]interface{}),
	}

	// Store file handle in metadata for proper cleanup
	result.Metadata["file_handle"] = file
	p.activeProfiles[ProfilerTypeMutex] = result
	p.logger.Info("Mutex profiling started")
	return nil
}

// startTraceProfile starts trace profiling
func (p *Profiler) startTraceProfile() error {
	outputFile := filepath.Join(p.config.OutputDir, fmt.Sprintf("trace_%d.out", time.Now().Unix()))

	file, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create trace file: %w", err)
	}

	if err := trace.Start(file); err != nil {
		file.Close()
		return fmt.Errorf("failed to start trace: %w", err)
	}

	result := &ProfileResult{
		Type:       ProfilerTypeTrace,
		StartTime:  time.Now(),
		OutputFile: outputFile,
		Metadata:   make(map[string]interface{}),
	}

	p.activeProfiles[ProfilerTypeTrace] = result
	p.logger.Info("Trace profiling started")
	return nil
}

// stopAllProfiles stops all active profiles
func (p *Profiler) stopAllProfiles() {
	// Stop CPU profiling
	if result, exists := p.activeProfiles[ProfilerTypeCPU]; exists {
		pprof.StopCPUProfile()
		result.EndTime = time.Now()
		result.Duration = result.EndTime.Sub(result.StartTime)
		p.logger.Info("CPU profiling stopped")
	}

	// Stop memory profiling
	if result, exists := p.activeProfiles[ProfilerTypeMemory]; exists {
		file, err := os.Create(result.OutputFile)
		if err == nil {
			pprof.WriteHeapProfile(file)
			file.Close()
		}
		result.EndTime = time.Now()
		result.Duration = result.EndTime.Sub(result.StartTime)
		p.logger.Info("Memory profiling stopped")
	}

	// Stop goroutine profiling
	if result, exists := p.activeProfiles[ProfilerTypeGoroutine]; exists {
		file, err := os.Create(result.OutputFile)
		if err == nil {
			pprof.Lookup("goroutine").WriteTo(file, 0)
			file.Close()
		}
		result.EndTime = time.Now()
		result.Duration = result.EndTime.Sub(result.StartTime)
		p.logger.Info("Goroutine profiling stopped")
	}

	// Stop block profiling
	if result, exists := p.activeProfiles[ProfilerTypeBlock]; exists {
		file, err := os.Create(result.OutputFile)
		if err == nil {
			pprof.Lookup("block").WriteTo(file, 0)
			file.Close()
		}
		result.EndTime = time.Now()
		result.Duration = result.EndTime.Sub(result.StartTime)
		runtime.SetBlockProfileRate(0)
		p.logger.Info("Block profiling stopped")
	}

	// Stop mutex profiling
	if result, exists := p.activeProfiles[ProfilerTypeMutex]; exists {
		file, err := os.Create(result.OutputFile)
		if err == nil {
			pprof.Lookup("mutex").WriteTo(file, 0)
			file.Close()
		}
		result.EndTime = time.Now()
		result.Duration = result.EndTime.Sub(result.StartTime)
		runtime.SetMutexProfileFraction(0)
		p.logger.Info("Mutex profiling stopped")
	}

	// Stop trace profiling
	if result, exists := p.activeProfiles[ProfilerTypeTrace]; exists {
		trace.Stop()
		result.EndTime = time.Now()
		result.Duration = result.EndTime.Sub(result.StartTime)
		p.logger.Info("Trace profiling stopped")
	}
}

// generatePerformanceProfile generates a comprehensive performance profile
func (p *Profiler) generatePerformanceProfile() *PerformanceProfile {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	summary := PerformanceSummary{
		CPUUsage:      0.0, // Would be calculated from metrics
		MemoryUsage:   m.Alloc,
		MemoryPeak:    m.TotalAlloc,
		GoRoutines:    runtime.NumGoroutine(),
		HeapAlloc:     m.HeapAlloc,
		HeapSys:       m.HeapSys,
		GCs:           m.NumGC,
		GCPauseTime:   m.PauseTotalNs,
		Bottlenecks:   p.analyzeBottlenecks(m),
		Optimizations: p.generateOptimizations(m),
	}

	profile := &PerformanceProfile{
		ID:        fmt.Sprintf("profile_%d", time.Now().Unix()),
		StartTime: p.startTime,
		EndTime:   time.Now(),
		Duration:  time.Since(p.startTime),
		Results:   make(map[ProfilerType]*ProfileResult),
		Summary:   summary,
		Metadata:  make(map[string]interface{}),
	}

	// Copy active profiles
	for profilerType, result := range p.activeProfiles {
		profile.Results[profilerType] = result
	}

	return profile
}

// analyzeBottlenecks analyzes performance bottlenecks
func (p *Profiler) analyzeBottlenecks(m runtime.MemStats) []string {
	var bottlenecks []string

	// Memory bottlenecks
	if m.HeapAlloc > 1<<30 { // 1GB
		bottlenecks = append(bottlenecks, "High heap allocation (>1GB)")
	}

	if m.NumGC > 100 {
		bottlenecks = append(bottlenecks, "Frequent garbage collection (>100 GCs)")
	}

	if m.PauseTotalNs > 1e9 { // 1 second total pause time
		bottlenecks = append(bottlenecks, "High GC pause time (>1s total)")
	}

	// Goroutine bottlenecks
	if runtime.NumGoroutine() > 10000 {
		bottlenecks = append(bottlenecks, "High goroutine count (>10k)")
	}

	return bottlenecks
}

// generateOptimizations generates optimization recommendations
func (p *Profiler) generateOptimizations(m runtime.MemStats) []string {
	var optimizations []string

	// Memory optimizations
	if m.HeapAlloc > 1<<29 { // 512MB
		optimizations = append(optimizations, "Consider reducing memory allocations")
		optimizations = append(optimizations, "Use object pooling for frequently allocated objects")
	}

	if m.NumGC > 50 {
		optimizations = append(optimizations, "Optimize garbage collection by reducing allocations")
		optimizations = append(optimizations, "Consider using sync.Pool for temporary objects")
	}

	// Goroutine optimizations
	if runtime.NumGoroutine() > 5000 {
		optimizations = append(optimizations, "Limit concurrent goroutines")
		optimizations = append(optimizations, "Use worker pools for controlled concurrency")
	}

	return optimizations
}

// GetProfileHistory returns profiling history
func (p *Profiler) GetProfileHistory() []*PerformanceProfile {
	p.mu.RLock()
	defer p.mu.RUnlock()

	// Create a copy to avoid race conditions
	history := make([]*PerformanceProfile, len(p.profileHistory))
	copy(history, p.profileHistory)
	return history
}

// GetLatestProfile returns the latest performance profile
func (p *Profiler) GetLatestProfile() *PerformanceProfile {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if len(p.profileHistory) == 0 {
		return nil
	}

	// Create a copy to avoid race conditions
	latest := *p.profileHistory[len(p.profileHistory)-1]
	return &latest
}

// IsRunning returns whether the profiler is running
func (p *Profiler) IsRunning() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.running
}

// GetConfig returns the profiler configuration
func (p *Profiler) GetConfig() *ProfilerConfig {
	return p.config
}
