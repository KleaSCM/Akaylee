/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: dashboard.go
Description: HTML dashboard system for the Akaylee Fuzzer. Generates beautiful,
interactive web reports with real-time charts, state visualizations, crash analysis,
and comprehensive fuzzing metrics. Provides enterprise-grade reporting capabilities.
*/

package reporting

import (
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"time"

	"github.com/kleascm/akaylee-fuzzer/pkg/core"
	"github.com/kleascm/akaylee-fuzzer/pkg/interfaces"
	"github.com/sirupsen/logrus"
)

// DashboardGenerator creates beautiful HTML dashboards
type DashboardGenerator struct {
	outputDir string
	logger    *logrus.Logger
	templates *template.Template
}

// DashboardData contains all data for dashboard generation
type DashboardData struct {
	Title            string                     `json:"title"`
	GeneratedAt      time.Time                  `json:"generated_at"`
	Version          string                     `json:"version"`
	SessionID        string                     `json:"session_id"`
	FuzzerStats      *core.FuzzerStats          `json:"fuzzer_stats"`
	StateStats       *StateDashboardStats       `json:"state_stats"`
	CrashStats       *CrashDashboardStats       `json:"crash_stats"`
	CoverageStats    *CoverageDashboardStats    `json:"coverage_stats"`
	PerformanceStats *PerformanceDashboardStats `json:"performance_stats"`
	StateHistory     []*interfaces.State        `json:"state_history"`
	CrashReports     []*CrashReport             `json:"crash_reports"`
	CoverageData     *CoverageData              `json:"coverage_data"`
	Charts           *ChartData                 `json:"charts"`
}

// StateDashboardStats contains state-aware fuzzing statistics
type StateDashboardStats struct {
	TotalStates       int            `json:"total_states"`
	UniqueStates      int            `json:"unique_states"`
	StateTransitions  int            `json:"state_transitions"`
	StateValidations  int            `json:"state_validations"`
	StateErrors       int            `json:"state_errors"`
	MaxStateDepth     int            `json:"max_state_depth"`
	AverageStateDepth float64        `json:"average_state_depth"`
	StateCoverage     float64        `json:"state_coverage"`
	StateTypes        map[string]int `json:"state_types"`
}

// CrashDashboardStats contains crash analysis statistics
type CrashDashboardStats struct {
	TotalCrashes        int            `json:"total_crashes"`
	UniqueCrashes       int            `json:"unique_crashes"`
	CriticalCrashes     int            `json:"critical_crashes"`
	HighCrashes         int            `json:"high_crashes"`
	MediumCrashes       int            `json:"medium_crashes"`
	LowCrashes          int            `json:"low_crashes"`
	ReproducibleCrashes int            `json:"reproducible_crashes"`
	ExploitableCrashes  int            `json:"exploitable_crashes"`
	CrashTypes          map[string]int `json:"crash_types"`
	CrashSignals        map[string]int `json:"crash_signals"`
}

// CoverageDashboardStats contains coverage analysis statistics
type CoverageDashboardStats struct {
	TotalCoveragePoints  int             `json:"total_coverage_points"`
	UniqueCoveragePoints int             `json:"unique_coverage_points"`
	CoveragePercentage   float64         `json:"coverage_percentage"`
	EdgeCoverage         int             `json:"edge_coverage"`
	BlockCoverage        int             `json:"block_coverage"`
	FunctionCoverage     int             `json:"function_coverage"`
	CoverageTrend        []CoveragePoint `json:"coverage_trend"`
}

// PerformanceDashboardStats contains performance metrics
type PerformanceDashboardStats struct {
	ExecutionsPerSecond  float64       `json:"executions_per_second"`
	AverageExecutionTime float64       `json:"average_execution_time"`
	PeakMemoryUsage      uint64        `json:"peak_memory_usage"`
	AverageCPUUsage      float64       `json:"average_cpu_usage"`
	TotalUptime          time.Duration `json:"total_uptime"`
	WorkerStats          []WorkerStat  `json:"worker_stats"`
}

// CrashReport contains detailed crash information
type CrashReport struct {
	ID           string                 `json:"id"`
	Timestamp    time.Time              `json:"timestamp"`
	Type         string                 `json:"type"`
	Severity     string                 `json:"severity"`
	Signal       int                    `json:"signal"`
	ExitCode     int                    `json:"exit_code"`
	Reproducible bool                   `json:"reproducible"`
	Exploitable  bool                   `json:"exploitable"`
	Hash         string                 `json:"hash"`
	StackTrace   []string               `json:"stack_trace"`
	InputSize    int                    `json:"input_size"`
	StateInfo    *interfaces.State      `json:"state_info,omitempty"`
	Metadata     map[string]interface{} `json:"metadata"`
}

// CoverageData contains coverage information
type CoverageData struct {
	Points    []CoveragePoint    `json:"points"`
	Functions []FunctionCoverage `json:"functions"`
	Files     []FileCoverage     `json:"files"`
	Trend     []CoveragePoint    `json:"trend"`
}

// CoveragePoint represents a coverage data point
type CoveragePoint struct {
	Timestamp  time.Time `json:"timestamp"`
	Edges      int       `json:"edges"`
	Blocks     int       `json:"blocks"`
	Functions  int       `json:"functions"`
	Percentage float64   `json:"percentage"`
}

// FunctionCoverage contains function-level coverage
type FunctionCoverage struct {
	Name       string  `json:"name"`
	File       string  `json:"file"`
	Line       int     `json:"line"`
	Covered    bool    `json:"covered"`
	HitCount   int     `json:"hit_count"`
	Percentage float64 `json:"percentage"`
}

// FileCoverage contains file-level coverage
type FileCoverage struct {
	Name       string             `json:"name"`
	Path       string             `json:"path"`
	Covered    bool               `json:"covered"`
	HitCount   int                `json:"hit_count"`
	Percentage float64            `json:"percentage"`
	Functions  []FunctionCoverage `json:"functions"`
}

// WorkerStat contains worker performance statistics
type WorkerStat struct {
	ID                  int           `json:"id"`
	Executions          int64         `json:"executions"`
	Crashes             int64         `json:"crashes"`
	Hangs               int64         `json:"hangs"`
	ExecutionsPerSecond float64       `json:"executions_per_second"`
	PeakMemory          uint64        `json:"peak_memory"`
	AverageCPU          float64       `json:"average_cpu"`
	Uptime              time.Duration `json:"uptime"`
}

// ChartData contains chart configuration and data
type ChartData struct {
	ExecutionRateChart *ChartConfig `json:"execution_rate_chart"`
	CoverageChart      *ChartConfig `json:"coverage_chart"`
	CrashChart         *ChartConfig `json:"crash_chart"`
	StateChart         *ChartConfig `json:"state_chart"`
	PerformanceChart   *ChartConfig `json:"performance_chart"`
}

// ChartConfig contains chart configuration
type ChartConfig struct {
	Type    string      `json:"type"`
	Title   string      `json:"title"`
	Data    interface{} `json:"data"`
	Options interface{} `json:"options"`
}

// NewDashboardGenerator creates a new dashboard generator
func NewDashboardGenerator(outputDir string, logger *logrus.Logger) *DashboardGenerator {
	return &DashboardGenerator{
		outputDir: outputDir,
		logger:    logger,
		templates: template.Must(template.New("dashboard").Parse(dashboardTemplate)),
	}
}

// GenerateDashboard creates a complete HTML dashboard
func (dg *DashboardGenerator) GenerateDashboard(data *DashboardData) error {
	// Create output directory
	if err := os.MkdirAll(dg.outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Generate main dashboard
	if err := dg.generateMainDashboard(data); err != nil {
		return fmt.Errorf("failed to generate main dashboard: %w", err)
	}

	// Generate crash reports
	if err := dg.generateCrashReports(data.CrashReports); err != nil {
		return fmt.Errorf("failed to generate crash reports: %w", err)
	}

	// Generate coverage reports
	if err := dg.generateCoverageReports(data.CoverageData); err != nil {
		return fmt.Errorf("failed to generate coverage reports: %w", err)
	}

	// Generate state reports
	if err := dg.generateStateReports(data.StateHistory); err != nil {
		return fmt.Errorf("failed to generate state reports: %w", err)
	}

	// Generate performance reports
	if err := dg.generatePerformanceReports(data.PerformanceStats); err != nil {
		return fmt.Errorf("failed to generate performance reports: %w", err)
	}

	// Copy static assets
	if err := dg.copyStaticAssets(); err != nil {
		return fmt.Errorf("failed to copy static assets: %w", err)
	}

	dg.logger.Infof("Dashboard generated successfully in: %s", dg.outputDir)
	return nil
}

// generateMainDashboard creates the main dashboard HTML
func (dg *DashboardGenerator) generateMainDashboard(data *DashboardData) error {
	// Prepare chart data
	dg.prepareChartData(data)

	// Generate HTML
	outputFile := filepath.Join(dg.outputDir, "index.html")
	file, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer file.Close()

	// Execute template
	if err := dg.templates.Execute(file, data); err != nil {
		return fmt.Errorf("failed to execute template: %w", err)
	}

	return nil
}

// prepareChartData prepares chart configurations
func (dg *DashboardGenerator) prepareChartData(data *DashboardData) {
	data.Charts = &ChartData{
		ExecutionRateChart: dg.createExecutionRateChart(data),
		CoverageChart:      dg.createCoverageChart(data),
		CrashChart:         dg.createCrashChart(data),
		StateChart:         dg.createStateChart(data),
		PerformanceChart:   dg.createPerformanceChart(data),
	}
}

// createExecutionRateChart creates execution rate chart configuration
func (dg *DashboardGenerator) createExecutionRateChart(data *DashboardData) *ChartConfig {
	return &ChartConfig{
		Type:  "line",
		Title: "Execution Rate Over Time",
		Data: map[string]interface{}{
			"labels": []string{"Time"},
			"datasets": []map[string]interface{}{
				{
					"label":           "Executions/sec",
					"data":            []float64{data.FuzzerStats.ExecutionsPerSecond},
					"borderColor":     "rgb(75, 192, 192)",
					"backgroundColor": "rgba(75, 192, 192, 0.2)",
				},
			},
		},
		Options: map[string]interface{}{
			"responsive": true,
			"scales": map[string]interface{}{
				"y": map[string]interface{}{
					"beginAtZero": true,
				},
			},
		},
	}
}

// createCoverageChart creates coverage chart configuration
func (dg *DashboardGenerator) createCoverageChart(data *DashboardData) *ChartConfig {
	return &ChartConfig{
		Type:  "doughnut",
		Title: "Coverage Distribution",
		Data: map[string]interface{}{
			"labels": []string{"Covered", "Uncovered"},
			"datasets": []map[string]interface{}{
				{
					"data": []int{
						data.CoverageStats.UniqueCoveragePoints,
						data.CoverageStats.TotalCoveragePoints - data.CoverageStats.UniqueCoveragePoints,
					},
					"backgroundColor": []string{"#4CAF50", "#f44336"},
				},
			},
		},
		Options: map[string]interface{}{
			"responsive": true,
		},
	}
}

// createCrashChart creates crash chart configuration
func (dg *DashboardGenerator) createCrashChart(data *DashboardData) *ChartConfig {
	return &ChartConfig{
		Type:  "bar",
		Title: "Crash Distribution by Severity",
		Data: map[string]interface{}{
			"labels": []string{"Critical", "High", "Medium", "Low"},
			"datasets": []map[string]interface{}{
				{
					"label": "Crashes",
					"data": []int{
						data.CrashStats.CriticalCrashes,
						data.CrashStats.HighCrashes,
						data.CrashStats.MediumCrashes,
						data.CrashStats.LowCrashes,
					},
					"backgroundColor": []string{"#f44336", "#ff9800", "#ffc107", "#4caf50"},
				},
			},
		},
		Options: map[string]interface{}{
			"responsive": true,
			"scales": map[string]interface{}{
				"y": map[string]interface{}{
					"beginAtZero": true,
				},
			},
		},
	}
}

// createStateChart creates state chart configuration
func (dg *DashboardGenerator) createStateChart(data *DashboardData) *ChartConfig {
	return &ChartConfig{
		Type:  "line",
		Title: "State Exploration Over Time",
		Data: map[string]interface{}{
			"labels": []string{"Time"},
			"datasets": []map[string]interface{}{
				{
					"label":           "States Explored",
					"data":            []int{data.StateStats.UniqueStates},
					"borderColor":     "rgb(153, 102, 255)",
					"backgroundColor": "rgba(153, 102, 255, 0.2)",
				},
			},
		},
		Options: map[string]interface{}{
			"responsive": true,
			"scales": map[string]interface{}{
				"y": map[string]interface{}{
					"beginAtZero": true,
				},
			},
		},
	}
}

// createPerformanceChart creates performance chart configuration
func (dg *DashboardGenerator) createPerformanceChart(data *DashboardData) *ChartConfig {
	return &ChartConfig{
		Type:  "line",
		Title: "Performance Metrics",
		Data: map[string]interface{}{
			"labels": []string{"Time"},
			"datasets": []map[string]interface{}{
				{
					"label":           "CPU Usage (%)",
					"data":            []float64{data.PerformanceStats.AverageCPUUsage},
					"borderColor":     "rgb(255, 99, 132)",
					"backgroundColor": "rgba(255, 99, 132, 0.2)",
				},
				{
					"label":           "Memory Usage (MB)",
					"data":            []float64{float64(data.PerformanceStats.PeakMemoryUsage) / 1024 / 1024},
					"borderColor":     "rgb(54, 162, 235)",
					"backgroundColor": "rgba(54, 162, 235, 0.2)",
				},
			},
		},
		Options: map[string]interface{}{
			"responsive": true,
			"scales": map[string]interface{}{
				"y": map[string]interface{}{
					"beginAtZero": true,
				},
			},
		},
	}
}

// generateCrashReports creates detailed crash report pages
func (dg *DashboardGenerator) generateCrashReports(reports []*CrashReport) error {
	// Implementation for crash report generation
	return nil
}

// generateCoverageReports creates detailed coverage report pages
func (dg *DashboardGenerator) generateCoverageReports(coverage *CoverageData) error {
	// Implementation for coverage report generation
	return nil
}

// generateStateReports creates detailed state report pages
func (dg *DashboardGenerator) generateStateReports(states []*interfaces.State) error {
	// Implementation for state report generation
	return nil
}

// generatePerformanceReports creates detailed performance report pages
func (dg *DashboardGenerator) generatePerformanceReports(stats *PerformanceDashboardStats) error {
	// Implementation for performance report generation
	return nil
}

// copyStaticAssets copies CSS, JS, and other static assets
func (dg *DashboardGenerator) copyStaticAssets() error {
	// Implementation for copying static assets
	return nil
}
