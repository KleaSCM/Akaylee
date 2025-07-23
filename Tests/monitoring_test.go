/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: monitoring_test.go
Description: Comprehensive tests for the monitoring packages including metrics collection,
network monitoring, memory leak detection, and real-time performance monitoring.
*/

package core_test

import (
	"context"
	"testing"
	"time"

	"github.com/kleascm/akaylee-fuzzer/pkg/monitoring"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMetricsCollector tests the metrics collector
func TestMetricsCollector(t *testing.T) {
	runTest(t, "TestMetricsCollector", func(t *testing.T) {
		logger := logrus.New()
		collector := monitoring.NewMetricsCollector(logger)
		require.NotNil(t, collector)

		// Test basic functionality without starting
		// Test getting metrics
		metrics := collector.GetGlobalMetrics()
		assert.NotNil(t, metrics)

		// Test that collector can be created and basic operations work
		assert.NotNil(t, collector)
	})
}

func TestNetworkMonitor(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)

	config := &monitoring.NetworkMonitorConfig{
		Enabled:            true,
		CollectionInterval: 1 * time.Second,
		HistorySize:        100,
		Interfaces:         []string{"lo", "eth0"},
		BandwidthThreshold: 1 << 20, // 1MB/s
		LatencyThreshold:   100 * time.Millisecond,
		ErrorThreshold:     100,
		ConnectionTracking: true,
		LatencyMonitoring:  true,
		AlertThreshold:     0.8,
	}

	monitor := monitoring.NewNetworkMonitor(config, logger)
	require.NotNil(t, monitor)

	// Test start/stop
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := monitor.Start(ctx)
	require.NoError(t, err)
	assert.True(t, monitor.IsRunning())

	// Test interface discovery
	interfaces := monitor.GetNetworkInterfaces()
	assert.NotEmpty(t, interfaces)

	// Test metrics collection
	time.Sleep(2 * time.Second)

	// Test metrics retrieval
	metrics := monitor.GetNetworkMetrics("lo")
	assert.NotNil(t, metrics)

	// Test latency history
	latencyHistory := monitor.GetLatencyHistory("lo")
	assert.NotNil(t, latencyHistory)

	// Test bandwidth history
	bandwidthHistory := monitor.GetBandwidthHistory("lo")
	assert.NotNil(t, bandwidthHistory)

	// Test alerts
	alerts := monitor.GetNetworkAlerts()
	assert.NotNil(t, alerts)

	// Test stop
	err = monitor.Stop()
	require.NoError(t, err)
	assert.False(t, monitor.IsRunning())
}

func TestMemoryLeakDetector(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)

	config := &monitoring.MemoryLeakConfig{
		Enabled:             true,
		CollectionInterval:  1 * time.Second,
		HistorySize:         100,
		DetectionThreshold:  1e6,     // 1MB/sec
		AlertThreshold:      1 << 30, // 1GB
		ConfidenceThreshold: 0.7,
		AutoGC:              false,
		GCThreshold:         1 << 29, // 512MB
	}

	detector := monitoring.NewMemoryLeakDetector(config, logger)
	require.NotNil(t, detector)

	// Test start/stop
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := detector.Start(ctx)
	require.NoError(t, err)
	assert.True(t, detector.IsRunning())

	// Test memory data collection
	time.Sleep(2 * time.Second)

	// Test snapshots
	snapshots := detector.GetMemorySnapshots()
	assert.NotEmpty(t, snapshots)

	// Test alerts
	alerts := detector.GetMemoryAlerts()
	assert.NotNil(t, alerts)

	// Test baseline
	baseline := detector.GetBaseline()
	assert.NotNil(t, baseline)

	// Test stop
	err = detector.Stop()
	require.NoError(t, err)
	assert.False(t, detector.IsRunning())
}

func TestProfiler(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)

	config := &monitoring.ProfilerConfig{
		Enabled:          true,
		Interval:         5 * time.Second,
		CPUProfile:       true,
		MemoryProfile:    true,
		GoroutineProfile: true,
		BlockProfile:     true,
		MutexProfile:     true,
		TraceProfile:     false,
		OutputDir:        "/tmp/profiler",
	}

	metricsCollector := monitoring.NewMetricsCollector(logger)
	profiler := monitoring.NewProfiler(config, logger, metricsCollector)
	require.NotNil(t, profiler)

	// Test start/stop
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := profiler.Start(ctx)
	require.NoError(t, err)
	assert.True(t, profiler.IsRunning())

	// Test profiling
	time.Sleep(6 * time.Second)

	// Test profile history
	history := profiler.GetProfileHistory()
	assert.NotEmpty(t, history)

	// Test latest profile
	latest := profiler.GetLatestProfile()
	assert.NotNil(t, latest)

	// Test stop
	err = profiler.Stop()
	require.NoError(t, err)
	assert.False(t, profiler.IsRunning())
}

func TestRealTimeMonitor(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)

	config := &monitoring.RealTimeMonitorConfig{
		Enabled:            true,
		CollectionInterval: 1 * time.Second,
		HistorySize:        100,
		PatternDetection:   true,
		AlertThreshold:     0.8,
		CPUThreshold:       80.0,
		MemoryThreshold:    1 << 30, // 1GB
		NetworkThreshold:   1 << 20, // 1MB/s
		DiskThreshold:      1000,    // 1000 ops/sec
	}

	monitor := monitoring.NewRealTimeMonitor(config, logger)
	require.NotNil(t, monitor)

	// Test start/stop
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := monitor.Start(ctx)
	require.NoError(t, err)
	assert.True(t, monitor.IsRunning())

	// Let it run for a short time
	time.Sleep(1 * time.Second) // Reduced from 5 seconds to 1 second

	// Stop the monitor
	err = monitor.Stop()
	require.NoError(t, err)
	assert.False(t, monitor.IsRunning())
}

func TestCyclicMemoryLeakDetection(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)

	// Create test snapshots with cyclic pattern
	var snapshots []*monitoring.MemorySnapshot
	baseTime := time.Now()
	baseValue := uint64(1 << 20) // 1MB base

	for i := 0; i < 30; i++ {
		// Create cyclic pattern with increasing peaks
		cycle := i % 10
		peak := uint64(cycle) * (1 << 19)             // 512KB per cycle
		value := baseValue + peak + uint64(i*(1<<18)) // Add some growth

		snapshot := &monitoring.MemorySnapshot{
			Timestamp:  baseTime.Add(time.Duration(i) * time.Second),
			HeapAlloc:  value,
			HeapSys:    value + (1 << 18),
			HeapIdle:   value / 2,
			HeapInuse:  value / 2,
			GoRoutines: 100 + i,
			NumGC:      uint32(i / 5),
		}
		snapshots = append(snapshots, snapshot)
	}

	// Test cyclic leak detector
	detector := &monitoring.CyclicLeakDetector{}
	alert, err := detector.Detect(snapshots)

	require.NoError(t, err)
	assert.NotNil(t, alert)
	assert.Equal(t, "CyclicLeakDetector", detector.Name())
	assert.Contains(t, detector.Description(), "cyclic")

	// Verify alert properties
	assert.Greater(t, alert.Confidence, 0.5)
	assert.NotEmpty(t, alert.Evidence)
	assert.NotEmpty(t, alert.Recommendations)
	assert.Contains(t, alert.Message, "Cyclic memory pattern detected")
}

func TestPerformanceAlertThresholds(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)

	collector := monitoring.NewMetricsCollector(logger)
	require.NotNil(t, collector)

	// Test alert thresholds
	thresholds := monitoring.AlertThresholds{
		CPUHigh:        50.0,    // 50% CPU
		MemoryHigh:     1 << 29, // 512MB
		NetworkHigh:    1 << 19, // 512KB/s
		DiskIOHigh:     500,     // 500 ops/sec
		GoRoutinesHigh: 5000,    // 5k goroutines
		HeapHigh:       1 << 28, // 256MB heap
	}

	collector.SetAlertThresholds(thresholds)
	retrieved := collector.GetAlertThresholds()
	assert.Equal(t, thresholds, retrieved)
}
