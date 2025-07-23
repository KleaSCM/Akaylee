/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: network.go
Description: Network bandwidth monitoring system for the Akaylee Fuzzer. Provides
comprehensive network usage tracking, bandwidth consumption monitoring, connection
analysis, and network performance optimization for API fuzzing and network testing.
*/

package monitoring

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// NetworkMetricType represents the type of network metric
type NetworkMetricType string

const (
	NetworkMetricTypeBytesSent       NetworkMetricType = "bytes_sent"
	NetworkMetricTypeBytesReceived   NetworkMetricType = "bytes_received"
	NetworkMetricTypePacketsSent     NetworkMetricType = "packets_sent"
	NetworkMetricTypePacketsReceived NetworkMetricType = "packets_received"
	NetworkMetricTypeConnections     NetworkMetricType = "connections"
	NetworkMetricTypeLatency         NetworkMetricType = "latency"
	NetworkMetricTypeBandwidth       NetworkMetricType = "bandwidth"
)

// NetworkInterface represents a network interface
type NetworkInterface struct {
	Name        string   `json:"name"`
	Index       int      `json:"index"`
	MTU         int      `json:"mtu"`
	Flags       uint32   `json:"flags"`
	Addresses   []net.IP `json:"addresses"`
	IsUp        bool     `json:"is_up"`
	IsLoopback  bool     `json:"is_loopback"`
	IsMulticast bool     `json:"is_multicast"`
}

// NetworkMetrics represents network usage metrics
type NetworkMetrics struct {
	Timestamp         time.Time     `json:"timestamp"`
	InterfaceName     string        `json:"interface_name"`
	BytesSent         uint64        `json:"bytes_sent"`
	BytesReceived     uint64        `json:"bytes_received"`
	PacketsSent       uint64        `json:"packets_sent"`
	PacketsReceived   uint64        `json:"packets_received"`
	ErrorsIn          uint64        `json:"errors_in"`
	ErrorsOut         uint64        `json:"errors_out"`
	DropsIn           uint64        `json:"drops_in"`
	DropsOut          uint64        `json:"drops_out"`
	BandwidthIn       float64       `json:"bandwidth_in"`    // bytes per second
	BandwidthOut      float64       `json:"bandwidth_out"`   // bytes per second
	PacketRateIn      float64       `json:"packet_rate_in"`  // packets per second
	PacketRateOut     float64       `json:"packet_rate_out"` // packets per second
	ActiveConnections int           `json:"active_connections"`
	Latency           time.Duration `json:"latency"`
	Jitter            time.Duration `json:"jitter"`
}

// NetworkConnection represents a network connection
type NetworkConnection struct {
	LocalAddr     string    `json:"local_addr"`
	RemoteAddr    string    `json:"remote_addr"`
	Protocol      string    `json:"protocol"`
	State         string    `json:"state"`
	PID           int       `json:"pid"`
	Program       string    `json:"program"`
	BytesSent     uint64    `json:"bytes_sent"`
	BytesReceived uint64    `json:"bytes_received"`
	StartTime     time.Time `json:"start_time"`
	LastActivity  time.Time `json:"last_activity"`
}

// NetworkAlert represents a network performance alert
type NetworkAlert struct {
	ID              string                 `json:"id"`
	Type            string                 `json:"type"`     // bandwidth_high, latency_high, errors_high, etc.
	Severity        string                 `json:"severity"` // low, medium, high, critical
	Timestamp       time.Time              `json:"timestamp"`
	Message         string                 `json:"message"`
	Interface       string                 `json:"interface"`
	Value           float64                `json:"value"`
	Threshold       float64                `json:"threshold"`
	Duration        time.Duration          `json:"duration"`
	Confidence      float64                `json:"confidence"`
	Evidence        []string               `json:"evidence"`
	Recommendations []string               `json:"recommendations"`
	Metadata        map[string]interface{} `json:"metadata"`
}

// NetworkMonitor provides network monitoring capabilities
type NetworkMonitor struct {
	config *NetworkMonitorConfig
	logger *logrus.Logger

	// State
	running bool
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	mu      sync.RWMutex

	// Network tracking
	interfaces  map[string]*NetworkInterface
	metrics     map[string][]*NetworkMetrics
	connections map[string]*NetworkConnection
	alerts      []*NetworkAlert

	// Performance tracking
	lastMetrics        map[string]*NetworkMetrics
	collectionInterval time.Duration

	// Bandwidth tracking
	bandwidthHistory map[string][]float64
	latencyHistory   map[string][]time.Duration
}

// NetworkMonitorConfig represents network monitoring configuration
type NetworkMonitorConfig struct {
	Enabled            bool          `json:"enabled"`
	CollectionInterval time.Duration `json:"collection_interval"`
	HistorySize        int           `json:"history_size"`
	Interfaces         []string      `json:"interfaces"`          // Specific interfaces to monitor
	BandwidthThreshold float64       `json:"bandwidth_threshold"` // bytes per second
	LatencyThreshold   time.Duration `json:"latency_threshold"`   // maximum acceptable latency
	ErrorThreshold     uint64        `json:"error_threshold"`     // maximum errors
	ConnectionTracking bool          `json:"connection_tracking"`
	LatencyMonitoring  bool          `json:"latency_monitoring"`
	AlertThreshold     float64       `json:"alert_threshold"`
}

// NewNetworkMonitor creates a new network monitor
func NewNetworkMonitor(config *NetworkMonitorConfig, logger *logrus.Logger) *NetworkMonitor {
	return &NetworkMonitor{
		config:             config,
		logger:             logger,
		interfaces:         make(map[string]*NetworkInterface),
		metrics:            make(map[string][]*NetworkMetrics),
		connections:        make(map[string]*NetworkConnection),
		alerts:             make([]*NetworkAlert, 0),
		lastMetrics:        make(map[string]*NetworkMetrics),
		collectionInterval: config.CollectionInterval,
		bandwidthHistory:   make(map[string][]float64),
		latencyHistory:     make(map[string][]time.Duration),
	}
}

// Start begins network monitoring
func (nm *NetworkMonitor) Start(ctx context.Context) error {
	nm.mu.Lock()
	defer nm.mu.Unlock()

	if nm.running {
		return fmt.Errorf("network monitor already running")
	}

	nm.ctx, nm.cancel = context.WithCancel(ctx)
	nm.running = true

	// Discover network interfaces
	if err := nm.discoverInterfaces(); err != nil {
		return fmt.Errorf("failed to discover interfaces: %w", err)
	}

	// Start collection goroutine
	nm.wg.Add(1)
	go nm.collectionLoop()

	nm.logger.Info("Network monitor started")
	return nil
}

// Stop stops network monitoring
func (nm *NetworkMonitor) Stop() error {
	nm.mu.Lock()
	defer nm.mu.Unlock()

	if !nm.running {
		return fmt.Errorf("network monitor not running")
	}

	nm.running = false
	nm.cancel()
	nm.wg.Wait()

	nm.logger.Info("Network monitor stopped")
	return nil
}

// collectionLoop runs the main network collection loop
func (nm *NetworkMonitor) collectionLoop() {
	defer nm.wg.Done()

	ticker := time.NewTicker(nm.collectionInterval)
	defer ticker.Stop()

	for {
		select {
		case <-nm.ctx.Done():
			return
		case <-ticker.C:
			nm.collectNetworkData()
		}
	}
}

// collectNetworkData collects network data from all interfaces
func (nm *NetworkMonitor) collectNetworkData() {
	nm.mu.Lock()
	defer nm.mu.Unlock()

	for interfaceName := range nm.interfaces {
		metrics, err := nm.getInterfaceMetrics(interfaceName)
		if err != nil {
			nm.logger.Debugf("Failed to get metrics for interface %s: %v", interfaceName, err)
			continue
		}

		// Calculate bandwidth and rates
		if lastMetrics, exists := nm.lastMetrics[interfaceName]; exists {
			nm.calculateRates(metrics, lastMetrics)
		}

		// Add to history
		nm.metrics[interfaceName] = append(nm.metrics[interfaceName], metrics)

		// Keep history size manageable
		if len(nm.metrics[interfaceName]) > nm.config.HistorySize {
			nm.metrics[interfaceName] = nm.metrics[interfaceName][1:]
		}

		// Update last metrics
		nm.lastMetrics[interfaceName] = metrics

		// Check for alerts
		nm.checkNetworkAlerts(metrics)
	}

	// Update connections if tracking is enabled
	if nm.config.ConnectionTracking {
		nm.updateConnections()
	}

	// Update latency if monitoring is enabled
	if nm.config.LatencyMonitoring {
		nm.updateLatency()
	}
}

// discoverInterfaces discovers available network interfaces
func (nm *NetworkMonitor) discoverInterfaces() error {
	interfaces, err := net.Interfaces()
	if err != nil {
		return fmt.Errorf("failed to get interfaces: %w", err)
	}

	for _, iface := range interfaces {
		// Skip loopback and down interfaces unless specifically requested
		if iface.Flags&net.FlagLoopback != 0 && !nm.shouldMonitorInterface(iface.Name) {
			continue
		}
		if iface.Flags&net.FlagUp == 0 && !nm.shouldMonitorInterface(iface.Name) {
			continue
		}

		networkInterface := &NetworkInterface{
			Name:        iface.Name,
			Index:       iface.Index,
			MTU:         iface.MTU,
			Flags:       uint32(iface.Flags),
			Addresses:   make([]net.IP, 0),
			IsUp:        iface.Flags&net.FlagUp != 0,
			IsLoopback:  iface.Flags&net.FlagLoopback != 0,
			IsMulticast: iface.Flags&net.FlagMulticast != 0,
		}

		// Get interface addresses
		addrs, err := iface.Addrs()
		if err == nil {
			for _, addr := range addrs {
				if ipnet, ok := addr.(*net.IPNet); ok {
					networkInterface.Addresses = append(networkInterface.Addresses, ipnet.IP)
				}
			}
		}

		nm.interfaces[iface.Name] = networkInterface
		nm.metrics[iface.Name] = make([]*NetworkMetrics, 0)
		nm.bandwidthHistory[iface.Name] = make([]float64, 0)
		nm.latencyHistory[iface.Name] = make([]time.Duration, 0)
	}

	return nil
}

// shouldMonitorInterface checks if an interface should be monitored
func (nm *NetworkMonitor) shouldMonitorInterface(name string) bool {
	if len(nm.config.Interfaces) == 0 {
		return true // Monitor all interfaces if none specified
	}

	for _, iface := range nm.config.Interfaces {
		if iface == name {
			return true
		}
	}
	return false
}

// getInterfaceMetrics gets metrics for a specific interface
func (nm *NetworkMonitor) getInterfaceMetrics(interfaceName string) (*NetworkMetrics, error) {
	// This is a simplified implementation
	// In production, would read from /proc/net/dev or use system calls

	metrics := &NetworkMetrics{
		Timestamp:         time.Now(),
		InterfaceName:     interfaceName,
		BytesSent:         0,
		BytesReceived:     0,
		PacketsSent:       0,
		PacketsReceived:   0,
		ErrorsIn:          0,
		ErrorsOut:         0,
		DropsIn:           0,
		DropsOut:          0,
		ActiveConnections: 0,
		Latency:           0,
		Jitter:            0,
	}

	// Read from /proc/net/dev if available
	if err := nm.readProcNetDev(interfaceName, metrics); err != nil {
		nm.logger.Debugf("Failed to read /proc/net/dev for %s: %v", interfaceName, err)
	}

	return metrics, nil
}

// readProcNetDev reads network statistics from /proc/net/dev
func (nm *NetworkMonitor) readProcNetDev(interfaceName string, metrics *NetworkMetrics) error {
	data, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return fmt.Errorf("failed to read /proc/net/dev: %w", err)
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 17 {
			continue
		}

		if strings.TrimSuffix(fields[0], ":") == interfaceName {
			// Parse received bytes
			if bytes, err := strconv.ParseUint(fields[1], 10, 64); err == nil {
				metrics.BytesReceived = bytes
			}

			// Parse received packets
			if packets, err := strconv.ParseUint(fields[2], 10, 64); err == nil {
				metrics.PacketsReceived = packets
			}

			// Parse received errors
			if errors, err := strconv.ParseUint(fields[3], 10, 64); err == nil {
				metrics.ErrorsIn = errors
			}

			// Parse received drops
			if drops, err := strconv.ParseUint(fields[4], 10, 64); err == nil {
				metrics.DropsIn = drops
			}

			// Parse sent bytes
			if bytes, err := strconv.ParseUint(fields[9], 10, 64); err == nil {
				metrics.BytesSent = bytes
			}

			// Parse sent packets
			if packets, err := strconv.ParseUint(fields[10], 10, 64); err == nil {
				metrics.PacketsSent = packets
			}

			// Parse sent errors
			if errors, err := strconv.ParseUint(fields[11], 10, 64); err == nil {
				metrics.ErrorsOut = errors
			}

			// Parse sent drops
			if drops, err := strconv.ParseUint(fields[12], 10, 64); err == nil {
				metrics.DropsOut = drops
			}

			break
		}
	}

	return nil
}

// calculateRates calculates bandwidth and packet rates
func (nm *NetworkMonitor) calculateRates(current, last *NetworkMetrics) {
	duration := current.Timestamp.Sub(last.Timestamp).Seconds()
	if duration == 0 {
		return
	}

	// Calculate bandwidth
	bytesInDiff := current.BytesReceived - last.BytesReceived
	bytesOutDiff := current.BytesSent - last.BytesSent

	current.BandwidthIn = float64(bytesInDiff) / duration
	current.BandwidthOut = float64(bytesOutDiff) / duration

	// Calculate packet rates
	packetsInDiff := current.PacketsReceived - last.PacketsReceived
	packetsOutDiff := current.PacketsSent - last.PacketsSent

	current.PacketRateIn = float64(packetsInDiff) / duration
	current.PacketRateOut = float64(packetsOutDiff) / duration

	// Update bandwidth history
	nm.bandwidthHistory[current.InterfaceName] = append(nm.bandwidthHistory[current.InterfaceName], current.BandwidthIn)
	if len(nm.bandwidthHistory[current.InterfaceName]) > nm.config.HistorySize {
		nm.bandwidthHistory[current.InterfaceName] = nm.bandwidthHistory[current.InterfaceName][1:]
	}
}

// checkNetworkAlerts checks for network performance issues
func (nm *NetworkMonitor) checkNetworkAlerts(metrics *NetworkMetrics) {
	// Check bandwidth threshold
	if metrics.BandwidthIn > nm.config.BandwidthThreshold {
		nm.addAlert(&NetworkAlert{
			Type:       "bandwidth_high",
			Severity:   "high",
			Timestamp:  time.Now(),
			Message:    fmt.Sprintf("High bandwidth usage: %.2f bytes/sec", metrics.BandwidthIn),
			Interface:  metrics.InterfaceName,
			Value:      metrics.BandwidthIn,
			Threshold:  nm.config.BandwidthThreshold,
			Confidence: 0.8,
			Evidence:   []string{"Bandwidth exceeds threshold", "High network activity"},
			Recommendations: []string{
				"Review network-intensive operations",
				"Consider bandwidth throttling",
				"Optimize data transfer protocols",
				"Monitor for network congestion",
			},
			Metadata: make(map[string]interface{}),
		})
	}

	// Check error threshold
	if metrics.ErrorsIn > nm.config.ErrorThreshold || metrics.ErrorsOut > nm.config.ErrorThreshold {
		nm.addAlert(&NetworkAlert{
			Type:       "errors_high",
			Severity:   "critical",
			Timestamp:  time.Now(),
			Message:    fmt.Sprintf("High network errors: in=%d, out=%d", metrics.ErrorsIn, metrics.ErrorsOut),
			Interface:  metrics.InterfaceName,
			Value:      float64(metrics.ErrorsIn + metrics.ErrorsOut),
			Threshold:  float64(nm.config.ErrorThreshold),
			Confidence: 0.9,
			Evidence:   []string{"Network errors exceed threshold", "Potential network issues"},
			Recommendations: []string{
				"Check network cable connections",
				"Verify network configuration",
				"Monitor for hardware issues",
				"Consider network diagnostics",
			},
			Metadata: make(map[string]interface{}),
		})
	}

	// Check latency threshold
	if metrics.Latency > nm.config.LatencyThreshold {
		nm.addAlert(&NetworkAlert{
			Type:       "latency_high",
			Severity:   "medium",
			Timestamp:  time.Now(),
			Message:    fmt.Sprintf("High network latency: %v", metrics.Latency),
			Interface:  metrics.InterfaceName,
			Value:      float64(metrics.Latency.Milliseconds()),
			Threshold:  float64(nm.config.LatencyThreshold.Milliseconds()),
			Confidence: 0.7,
			Evidence:   []string{"Latency exceeds threshold", "Network congestion possible"},
			Recommendations: []string{
				"Check network congestion",
				"Review routing configuration",
				"Consider QoS settings",
				"Monitor for bandwidth bottlenecks",
			},
			Metadata: make(map[string]interface{}),
		})
	}
}

// addAlert adds a network alert
func (nm *NetworkMonitor) addAlert(alert *NetworkAlert) {
	alert.ID = fmt.Sprintf("network_%s_%d", alert.Type, time.Now().Unix())
	nm.alerts = append(nm.alerts, alert)
	nm.logger.Warnf("Network alert: %s - %s", alert.Type, alert.Message)
}

// updateConnections updates active network connections
func (nm *NetworkMonitor) updateConnections() {
	// This is a simplified implementation
	// In production, would read from /proc/net/tcp, /proc/net/udp, etc.

	// For now, just count active connections
	activeCount := 0
	for _, conn := range nm.connections {
		if time.Since(conn.LastActivity) < 5*time.Minute {
			activeCount++
		}
	}

	// Update metrics for all interfaces
	for _, metrics := range nm.lastMetrics {
		metrics.ActiveConnections = activeCount
	}
}

// updateLatency updates network latency measurements
func (nm *NetworkMonitor) updateLatency() {
	// This is a simplified implementation
	// In production, would perform actual latency measurements

	for interfaceName := range nm.interfaces {
		// Simulate latency measurement
		latency := time.Duration(10+time.Now().UnixNano()%50) * time.Millisecond

		if metrics, exists := nm.lastMetrics[interfaceName]; exists {
			metrics.Latency = latency

			// Update latency history
			nm.latencyHistory[interfaceName] = append(nm.latencyHistory[interfaceName], latency)
			if len(nm.latencyHistory[interfaceName]) > nm.config.HistorySize {
				nm.latencyHistory[interfaceName] = nm.latencyHistory[interfaceName][1:]
			}

			// Calculate jitter
			if len(nm.latencyHistory[interfaceName]) > 1 {
				nm.calculateJitter(interfaceName)
			}
		}
	}
}

// calculateJitter calculates network jitter
func (nm *NetworkMonitor) calculateJitter(interfaceName string) {
	history := nm.latencyHistory[interfaceName]
	if len(history) < 2 {
		return
	}

	var totalJitter time.Duration
	for i := 1; i < len(history); i++ {
		diff := history[i] - history[i-1]
		if diff < 0 {
			diff = -diff
		}
		totalJitter += diff
	}

	averageJitter := totalJitter / time.Duration(len(history)-1)

	if metrics, exists := nm.lastMetrics[interfaceName]; exists {
		metrics.Jitter = averageJitter
	}
}

// GetNetworkInterfaces returns discovered network interfaces
func (nm *NetworkMonitor) GetNetworkInterfaces() map[string]*NetworkInterface {
	nm.mu.RLock()
	defer nm.mu.RUnlock()

	// Create a copy to avoid race conditions
	interfaces := make(map[string]*NetworkInterface)
	for k, v := range nm.interfaces {
		interfaces[k] = v
	}
	return interfaces
}

// GetNetworkMetrics returns network metrics for an interface
func (nm *NetworkMonitor) GetNetworkMetrics(interfaceName string) []*NetworkMetrics {
	nm.mu.RLock()
	defer nm.mu.RUnlock()

	if metrics, exists := nm.metrics[interfaceName]; exists {
		// Create a copy to avoid race conditions
		metricsCopy := make([]*NetworkMetrics, len(metrics))
		copy(metricsCopy, metrics)
		return metricsCopy
	}
	return nil
}

// GetNetworkAlerts returns network alerts
func (nm *NetworkMonitor) GetNetworkAlerts() []*NetworkAlert {
	nm.mu.RLock()
	defer nm.mu.RUnlock()

	// Create a copy to avoid race conditions
	alerts := make([]*NetworkAlert, len(nm.alerts))
	copy(alerts, nm.alerts)
	return alerts
}

// GetBandwidthHistory returns bandwidth history for an interface
func (nm *NetworkMonitor) GetBandwidthHistory(interfaceName string) []float64 {
	nm.mu.RLock()
	defer nm.mu.RUnlock()

	if history, exists := nm.bandwidthHistory[interfaceName]; exists {
		// Create a copy to avoid race conditions
		historyCopy := make([]float64, len(history))
		copy(historyCopy, history)
		return historyCopy
	}
	return nil
}

// GetLatencyHistory returns latency history for an interface
func (nm *NetworkMonitor) GetLatencyHistory(interfaceName string) []time.Duration {
	nm.mu.RLock()
	defer nm.mu.RUnlock()

	if history, exists := nm.latencyHistory[interfaceName]; exists {
		// Create a copy to avoid race conditions
		historyCopy := make([]time.Duration, len(history))
		copy(historyCopy, history)
		return historyCopy
	}
	return nil
}

// IsRunning returns whether the monitor is running
func (nm *NetworkMonitor) IsRunning() bool {
	nm.mu.RLock()
	defer nm.mu.RUnlock()
	return nm.running
}

// GetConfig returns the monitor configuration
func (nm *NetworkMonitor) GetConfig() *NetworkMonitorConfig {
	return nm.config
}
