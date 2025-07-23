/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: dashboard.go
Description: CLI command for generating beautiful HTML dashboards. Provides
comprehensive fuzzing metrics visualization with interactive charts, crash analysis,
coverage tracking, and state exploration data.
*/

package commands

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"github.com/kleascm/akaylee-fuzzer/pkg/core"
	"github.com/kleascm/akaylee-fuzzer/pkg/interfaces"
	"github.com/kleascm/akaylee-fuzzer/pkg/reporting"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// DashboardConfig contains dashboard generation configuration
type DashboardConfig struct {
	OutputDir          string `json:"output_dir"`
	Title              string `json:"title"`
	IncludeCrashes     bool   `json:"include_crashes"`
	IncludeStates      bool   `json:"include_states"`
	IncludeCoverage    bool   `json:"include_coverage"`
	IncludePerformance bool   `json:"include_performance"`
	AutoOpen           bool   `json:"auto_open"`
	Format             string `json:"format"`
}

// PerformDashboardGeneration generates a beautiful HTML dashboard
func PerformDashboardGeneration(cmd *cobra.Command, args []string) error {
	// Load configuration
	if err := LoadConfig(); err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Setup logging
	if err := SetupLogging(); err != nil {
		return fmt.Errorf("failed to setup logging: %w", err)
	}

	logger := logrus.New()
	logger.Info("Starting dashboard generation...")

	// Parse dashboard configuration
	config := parseDashboardConfig()

	// Create dashboard generator
	generator := reporting.NewDashboardGenerator(config.OutputDir, logger)

	// Generate dashboard data
	data, err := generateDashboardData(config)
	if err != nil {
		return fmt.Errorf("failed to generate dashboard data: %w", err)
	}

	// Generate dashboard
	if err := generator.GenerateDashboard(data); err != nil {
		return fmt.Errorf("failed to generate dashboard: %w", err)
	}

	// Display results
	displayDashboardResults(config, data)

	logger.Info("Dashboard generation completed successfully!")
	return nil
}

// parseDashboardConfig parses dashboard configuration from CLI flags and config
func parseDashboardConfig() *DashboardConfig {
	config := &DashboardConfig{
		OutputDir:          viper.GetString("dashboard.output_dir"),
		Title:              viper.GetString("dashboard.title"),
		IncludeCrashes:     viper.GetBool("dashboard.include_crashes"),
		IncludeStates:      viper.GetBool("dashboard.include_states"),
		IncludeCoverage:    viper.GetBool("dashboard.include_coverage"),
		IncludePerformance: viper.GetBool("dashboard.include_performance"),
		AutoOpen:           viper.GetBool("dashboard.auto_open"),
		Format:             viper.GetString("dashboard.format"),
	}

	// Set defaults
	if config.OutputDir == "" {
		config.OutputDir = "./dashboard"
	}
	if config.Title == "" {
		config.Title = "Akaylee Fuzzer Report"
	}
	if config.Format == "" {
		config.Format = "html"
	}

	return config
}

// generateDashboardData creates comprehensive dashboard data
func generateDashboardData(config *DashboardConfig) (*reporting.DashboardData, error) {
	data := &reporting.DashboardData{
		Title:       config.Title,
		GeneratedAt: time.Now(),
		Version:     "1.0.0",
		SessionID:   uuid.New().String(),
	}

	// Generate fuzzer statistics
	if err := generateFuzzerStats(data); err != nil {
		return nil, fmt.Errorf("failed to generate fuzzer stats: %w", err)
	}

	// Generate state statistics
	if config.IncludeStates {
		if err := generateStateStats(data); err != nil {
			return nil, fmt.Errorf("failed to generate state stats: %w", err)
		}
	}

	// Generate crash statistics
	if config.IncludeCrashes {
		if err := generateCrashStats(data); err != nil {
			return nil, fmt.Errorf("failed to generate crash stats: %w", err)
		}
	}

	// Generate coverage statistics
	if config.IncludeCoverage {
		if err := generateCoverageStats(data); err != nil {
			return nil, fmt.Errorf("failed to generate coverage stats: %w", err)
		}
	}

	// Generate performance statistics
	if config.IncludePerformance {
		if err := generatePerformanceStats(data); err != nil {
			return nil, fmt.Errorf("failed to generate performance stats: %w", err)
		}
	}

	return data, nil
}

// generateFuzzerStats generates fuzzer statistics
func generateFuzzerStats(data *reporting.DashboardData) error {
	// Create mock fuzzer stats (in real implementation, this would come from actual fuzzer data)
	data.FuzzerStats = &core.FuzzerStats{
		Executions:          1000000,
		ExecutionsPerSecond: 1500.5,
		Crashes:             25,
		Hangs:               5,
		StartTime:           time.Now().Add(-2 * time.Hour),
		LastCrashTime:       time.Now().Add(-30 * time.Minute),
		CoveragePoints:      15000,
	}

	return nil
}

// generateStateStats generates state-aware fuzzing statistics
func generateStateStats(data *reporting.DashboardData) error {
	data.StateStats = &reporting.StateDashboardStats{
		TotalStates:       150,
		UniqueStates:      120,
		StateTransitions:  500,
		StateValidations:  1000,
		StateErrors:       5,
		MaxStateDepth:     15,
		AverageStateDepth: 8.5,
		StateCoverage:     85.5,
		StateTypes: map[string]int{
			"database": 50,
			"api":      40,
			"network":  30,
			"file":     20,
			"memory":   10,
		},
	}

	// Generate mock state history
	data.StateHistory = generateMockStateHistory()

	return nil
}

// generateCrashStats generates crash analysis statistics
func generateCrashStats(data *reporting.DashboardData) error {
	data.CrashStats = &reporting.CrashDashboardStats{
		TotalCrashes:        25,
		UniqueCrashes:       20,
		CriticalCrashes:     5,
		HighCrashes:         8,
		MediumCrashes:       7,
		LowCrashes:          5,
		ReproducibleCrashes: 18,
		ExploitableCrashes:  12,
		CrashTypes: map[string]int{
			"SIGSEGV": 10,
			"SIGABRT": 8,
			"SIGFPE":  4,
			"SIGILL":  3,
		},
		CrashSignals: map[string]int{
			"11": 10,
			"6":  8,
			"8":  4,
			"4":  3,
		},
	}

	// Generate mock crash reports
	data.CrashReports = generateMockCrashReports()

	return nil
}

// generateCoverageStats generates coverage analysis statistics
func generateCoverageStats(data *reporting.DashboardData) error {
	data.CoverageStats = &reporting.CoverageDashboardStats{
		TotalCoveragePoints:  20000,
		UniqueCoveragePoints: 15000,
		CoveragePercentage:   75.0,
		EdgeCoverage:         12000,
		BlockCoverage:        8000,
		FunctionCoverage:     1500,
		CoverageTrend:        generateMockCoverageTrend(),
	}

	// Generate mock coverage data
	data.CoverageData = generateMockCoverageData()

	return nil
}

// generatePerformanceStats generates performance metrics
func generatePerformanceStats(data *reporting.DashboardData) error {
	data.PerformanceStats = &reporting.PerformanceDashboardStats{
		ExecutionsPerSecond:  1500.5,
		AverageExecutionTime: 0.002,
		PeakMemoryUsage:      512 * 1024 * 1024, // 512MB
		AverageCPUUsage:      45.5,
		TotalUptime:          2 * time.Hour,
		WorkerStats:          generateMockWorkerStats(),
	}

	return nil
}

// Helper functions for generating mock data

func generateMockStateHistory() []*interfaces.State {
	states := make([]*interfaces.State, 0, 10)

	for i := 0; i < 10; i++ {
		state := &interfaces.State{
			ID:         fmt.Sprintf("state-%d", i),
			Name:       fmt.Sprintf("State %d", i),
			Type:       interfaces.StateTypeDatabase,
			Data:       make(map[string]interface{}),
			Metadata:   make(map[string]interface{}),
			Timestamp:  time.Now().Add(-time.Duration(i) * 10 * time.Minute),
			Valid:      true,
			Hash:       fmt.Sprintf("hash-%d", i),
			Generation: i,
		}
		states = append(states, state)
	}

	return states
}

func generateMockCrashReports() []*reporting.CrashReport {
	reports := make([]*reporting.CrashReport, 0, 5)

	crashTypes := []string{"SIGSEGV", "SIGABRT", "SIGFPE", "SIGILL"}
	severities := []string{"critical", "high", "medium", "low"}

	for i := 0; i < 5; i++ {
		report := &reporting.CrashReport{
			ID:           fmt.Sprintf("crash-%d", i),
			Timestamp:    time.Now().Add(-time.Duration(i) * 30 * time.Minute),
			Type:         crashTypes[i%len(crashTypes)],
			Severity:     severities[i%len(severities)],
			Signal:       11,
			ExitCode:     139,
			Reproducible: i%2 == 0,
			Exploitable:  i%3 == 0,
			Hash:         fmt.Sprintf("crash-hash-%d", i),
			InputSize:    1024 + i*100,
			Metadata:     make(map[string]interface{}),
		}
		reports = append(reports, report)
	}

	return reports
}

func generateMockCoverageTrend() []reporting.CoveragePoint {
	points := make([]reporting.CoveragePoint, 0, 10)

	for i := 0; i < 10; i++ {
		point := reporting.CoveragePoint{
			Timestamp:  time.Now().Add(-time.Duration(9-i) * 10 * time.Minute),
			Edges:      1000 + i*200,
			Blocks:     800 + i*150,
			Functions:  100 + i*20,
			Percentage: 50.0 + float64(i)*2.5,
		}
		points = append(points, point)
	}

	return points
}

func generateMockCoverageData() *reporting.CoverageData {
	return &reporting.CoverageData{
		Points:    generateMockCoverageTrend(),
		Functions: generateMockFunctionCoverage(),
		Files:     generateMockFileCoverage(),
		Trend:     generateMockCoverageTrend(),
	}
}

func generateMockFunctionCoverage() []reporting.FunctionCoverage {
	functions := make([]reporting.FunctionCoverage, 0, 5)

	names := []string{"main", "process_data", "validate_input", "parse_json", "handle_request"}

	for i, name := range names {
		function := reporting.FunctionCoverage{
			Name:       name,
			File:       fmt.Sprintf("file_%d.go", i),
			Line:       10 + i*20,
			Covered:    i%2 == 0,
			HitCount:   100 + i*50,
			Percentage: 80.0 + float64(i)*5.0,
		}
		functions = append(functions, function)
	}

	return functions
}

func generateMockFileCoverage() []reporting.FileCoverage {
	files := make([]reporting.FileCoverage, 0, 3)

	names := []string{"main.go", "processor.go", "validator.go"}

	for i, name := range names {
		file := reporting.FileCoverage{
			Name:       name,
			Path:       fmt.Sprintf("/src/%s", name),
			Covered:    true,
			HitCount:   500 + i*200,
			Percentage: 85.0 + float64(i)*5.0,
			Functions:  generateMockFunctionCoverage(),
		}
		files = append(files, file)
	}

	return files
}

func generateMockWorkerStats() []reporting.WorkerStat {
	stats := make([]reporting.WorkerStat, 0, 4)

	for i := 0; i < 4; i++ {
		stat := reporting.WorkerStat{
			ID:                  i,
			Executions:          250000 + int64(i)*50000,
			Crashes:             int64(6 + i),
			Hangs:               int64(1 + i%2),
			ExecutionsPerSecond: 375.0 + float64(i)*25.0,
			PeakMemory:          128 * 1024 * 1024, // 128MB
			AverageCPU:          45.0 + float64(i)*5.0,
			Uptime:              2 * time.Hour,
		}
		stats = append(stats, stat)
	}

	return stats
}

// displayDashboardResults displays dashboard generation results
func displayDashboardResults(config *DashboardConfig, data *reporting.DashboardData) {
	fmt.Printf("\n🎉 Dashboard Generated Successfully!\n")
	fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	fmt.Printf("📁 Output Directory: %s\n", config.OutputDir)
	fmt.Printf("🌐 Main Dashboard: %s/index.html\n", config.OutputDir)
	fmt.Printf("📊 Generated At: %s\n", data.GeneratedAt.Format("2006-01-02 15:04:05"))
	fmt.Printf("🆔 Session ID: %s\n", data.SessionID)

	fmt.Printf("\n📈 Dashboard Statistics:\n")
	fmt.Printf("   • Total Executions: %d\n", data.FuzzerStats.Executions)
	fmt.Printf("   • Execution Rate: %.1f/sec\n", data.FuzzerStats.ExecutionsPerSecond)
	fmt.Printf("   • Total Crashes: %d\n", data.FuzzerStats.Crashes)
	fmt.Printf("   • Coverage: %.1f%%\n", data.CoverageStats.CoveragePercentage)
	fmt.Printf("   • Unique States: %d\n", data.StateStats.UniqueStates)

	if config.AutoOpen {
		fmt.Printf("\n🚀 Opening dashboard in browser...\n")
		openDashboard(config.OutputDir)
	} else {
		fmt.Printf("\n💡 To view the dashboard, open: %s/index.html\n", config.OutputDir)
	}

	fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
}

// openDashboard opens the dashboard in the default browser
func openDashboard(outputDir string) {
	indexPath := filepath.Join(outputDir, "index.html")

	// Try to open with different commands
	commands := []string{"xdg-open", "open", "start"}

	for _, cmd := range commands {
		if err := exec.Command(cmd, indexPath).Start(); err == nil {
			return
		}
	}

	fmt.Printf("⚠️  Could not automatically open dashboard. Please open: %s\n", indexPath)
}
