/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: logging_test.go
Description: Comprehensive tests for the logging system. Tests logger creation,
formatting, file output, rotation, and analysis capabilities.
*/

package core_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kleascm/akaylee-fuzzer/pkg/logging"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLoggerCreation tests logger creation with different configurations
func TestLoggerCreation(t *testing.T) {
	// Test with default configuration
	logger, err := logging.NewLogger(nil)
	require.NoError(t, err)
	assert.NotNil(t, logger)
	defer logger.Close()

	// Test with custom configuration
	config := &logging.LoggerConfig{
		Level:     logging.LogLevelDebug,
		Format:    logging.LogFormatJSON,
		OutputDir: "./test_logs",
		MaxFiles:  5,
		MaxSize:   1024 * 1024, // 1MB
		Timestamp: true,
		Caller:    true,
		Colors:    false,
		Compress:  false,
	}

	logger, err = logging.NewLogger(config)
	require.NoError(t, err)
	assert.NotNil(t, logger)
	defer logger.Close()

	// Cleanup test directory
	os.RemoveAll("./test_logs")
}

// TestLogLevels tests different log levels
func TestLogLevels(t *testing.T) {
	logger, err := logging.NewLogger(&logging.LoggerConfig{
		Level:     logging.LogLevelDebug,
		Format:    logging.LogFormatText,
		OutputDir: "./test_logs",
		Timestamp: false,
		Caller:    false,
		Colors:    false,
	})
	require.NoError(t, err)
	defer logger.Close()

	// Test all log levels
	logger.Debug("Debug message", map[string]interface{}{"key": "value"})
	logger.Info("Info message", map[string]interface{}{"key": "value"})
	logger.Warning("Warning message", map[string]interface{}{"key": "value"})
	logger.Error("Error message", map[string]interface{}{"key": "value"})

	// Cleanup
	os.RemoveAll("./test_logs")
}

// TestLogFormats tests different log formats
func TestLogFormats(t *testing.T) {
	formats := []logging.LogFormat{
		logging.LogFormatText,
		logging.LogFormatJSON,
		logging.LogFormatCustom,
	}

	for _, format := range formats {
		t.Run(string(format), func(t *testing.T) {
			logger, err := logging.NewLogger(&logging.LoggerConfig{
				Level:     logging.LogLevelInfo,
				Format:    format,
				OutputDir: "./test_logs",
				Timestamp: true,
				Caller:    true,
				Colors:    false,
			})
			require.NoError(t, err)
			defer logger.Close()

			logger.Info("Test message", map[string]interface{}{
				"test_key": "test_value",
				"number":   42,
			})
		})
	}

	// Cleanup
	os.RemoveAll("./test_logs")
}

// TestFuzzerSpecificLogging tests fuzzer-specific logging methods
func TestFuzzerSpecificLogging(t *testing.T) {
	logger, err := logging.NewLogger(&logging.LoggerConfig{
		Level:     logging.LogLevelDebug,
		Format:    logging.LogFormatText,
		OutputDir: "./test_logs",
		Timestamp: true,
		Caller:    false,
		Colors:    false,
	})
	require.NoError(t, err)
	defer logger.Close()

	// Test execution logging
	logger.LogExecution("test-123", 100*time.Millisecond, "success", map[string]interface{}{
		"memory_usage": 1024,
		"cpu_usage":    50.5,
	})

	// Test crash logging
	logger.LogCrash("test-456", "SIGSEGV", map[string]interface{}{
		"address": "0x12345678",
		"stack":   []string{"func1", "func2"},
	})

	// Test hang logging
	logger.LogHang("test-789", 5*time.Second, map[string]interface{}{
		"last_output": "processing...",
	})

	// Test coverage logging
	logger.LogCoverage("test-abc", 150, 75, map[string]interface{}{
		"new_edges": 10,
	})

	// Test mutation logging
	logger.LogMutation("parent-123", "child-456", "BitFlipMutator", map[string]interface{}{
		"mutation_rate": 0.5,
	})

	// Test stats logging
	logger.LogStats(1000, 5, 2, 150.5, map[string]interface{}{
		"unique_crashes": 3,
	})

	// Cleanup
	os.RemoveAll("./test_logs")
}

// TestLogManager tests log management functionality
func TestLogManager(t *testing.T) {
	logDir := "./test_logs"
	os.MkdirAll(logDir, 0755)
	defer os.RemoveAll(logDir)

	// Create log manager
	manager := logging.NewLogManager(logDir, 3, 1024, false)

	// Create some test log files
	testFiles := []string{
		"akaylee-fuzzer_2024-01-01_10-00-00.log",
		"akaylee-fuzzer_2024-01-01_11-00-00.log",
		"akaylee-fuzzer_2024-01-01_12-00-00.log",
		"akaylee-fuzzer_2024-01-01_13-00-00.log",
	}

	for _, filename := range testFiles {
		filepath := filepath.Join(logDir, filename)
		file, err := os.Create(filepath)
		require.NoError(t, err)
		file.Close()
	}

	// Test cleanup
	err := manager.CleanupOldLogs()
	require.NoError(t, err)

	// Verify cleanup worked
	files, err := filepath.Glob(filepath.Join(logDir, "akaylee-fuzzer_*.log"))
	require.NoError(t, err)
	assert.Len(t, files, 3) // Should keep only 3 files

	// Test log stats
	stats, err := manager.GetLogStats()
	require.NoError(t, err)
	assert.Equal(t, 3, stats.TotalFiles)
}

// TestLogAnalyzer tests log analysis functionality
func TestLogAnalyzer(t *testing.T) {
	logDir := "./test_logs"
	os.MkdirAll(logDir, 0755)
	defer os.RemoveAll(logDir)

	// Create test log file with various entries
	logFile := filepath.Join(logDir, "akaylee-fuzzer_2024-01-01_10-00-00.log")
	file, err := os.Create(logFile)
	require.NoError(t, err)

	// Write test log entries
	testLogs := []string{
		"2024-01-01 10:00:01 INFO Test case executed test_case_id=abc123",
		"2024-01-01 10:00:02 DEBUG Test case mutated parent_id=abc123 child_id=def456",
		"2024-01-01 10:00:03 ERROR Crash detected test_case_id=ghi789 crash_type=SIGSEGV",
		"2024-01-01 10:00:04 WARN Hang detected test_case_id=jkl012 duration=5s",
		"2024-01-01 10:00:05 INFO Coverage updated test_case_id=mno345 edge_count=150",
		"2024-01-01 10:00:06 INFO Statistics update executions=1000 crashes=5",
	}

	for _, logEntry := range testLogs {
		file.WriteString(logEntry + "\n")
	}
	file.Close()

	// Test log analysis
	analyzer := logging.NewLogAnalyzer(logDir)
	analysis, err := analyzer.AnalyzeLogs()
	require.NoError(t, err)

	// Verify analysis results
	assert.Equal(t, 1, analysis.LogFiles)
	assert.Equal(t, int64(6), analysis.TotalLines)
	assert.Equal(t, int64(1), analysis.DebugCount)
	assert.Equal(t, int64(4), analysis.InfoCount)
	assert.Equal(t, int64(1), analysis.WarningCount)
	assert.Equal(t, int64(1), analysis.ErrorCount)
	assert.Equal(t, int64(1), analysis.CrashCount)
	assert.Equal(t, int64(1), analysis.HangCount)
	assert.Equal(t, int64(1), analysis.ExecutionCount)
	assert.Equal(t, int64(1), analysis.MutationCount)
	assert.Equal(t, int64(1), analysis.CoverageCount)

	// Test log summary
	summary := analysis.GetLogSummary()
	assert.Contains(t, summary, "Log Analysis Summary")
	assert.Contains(t, summary, "Files: 1")
	assert.Contains(t, summary, "Total Lines: 6")
}

// TestCustomFormatter tests the custom formatter
func TestCustomFormatter(t *testing.T) {
	formatter := &logging.CustomFormatter{
		Timestamp: true,
		Caller:    true,
		Colors:    false,
	}

	// Create a test log entry
	entry := &logrus.Entry{
		Level:   logrus.InfoLevel,
		Message: "Test message",
		Time:    time.Now(),
		Data: logrus.Fields{
			"key1": "value1",
			"key2": 42,
		},
	}

	// Format the entry
	formatted, err := formatter.Format(entry)
	require.NoError(t, err)
	assert.NotEmpty(t, formatted)

	// Verify formatting
	formattedStr := string(formatted)
	assert.Contains(t, formattedStr, "INFO")
	assert.Contains(t, formattedStr, "Test message")
	assert.Contains(t, formattedStr, "key1=value1")
	assert.Contains(t, formattedStr, "key2=42")
}

// TestFuzzerFormatter tests the fuzzer-specific formatter
func TestFuzzerFormatter(t *testing.T) {
	formatter := &logging.FuzzerFormatter{
		CustomFormatter: logging.CustomFormatter{
			Timestamp: true,
			Caller:    false,
			Colors:    false,
		},
		ShowPerformance: true,
		ShowCoverage:    true,
	}

	// Test with different message types
	testCases := []struct {
		message string
		prefix  string
	}{
		{"Test case executed", "EXEC"},
		{"Crash detected", "CRASH"},
		{"Hang detected", "HANG"},
		{"Coverage updated", "COVERAGE"},
		{"Test case mutated", "MUTATE"},
		{"Statistics update", "STATS"},
		{"Worker started", "WORKER"},
		{"Engine initialized", "ENGINE"},
		{"Random message", ""},
	}

	for _, tc := range testCases {
		t.Run(tc.message, func(t *testing.T) {
			entry := &logrus.Entry{
				Level:   logrus.InfoLevel,
				Message: tc.message,
				Time:    time.Now(),
				Data:    logrus.Fields{},
			}

			formatted, err := formatter.Format(entry)
			require.NoError(t, err)
			formattedStr := string(formatted)

			if tc.prefix != "" {
				assert.Contains(t, formattedStr, "["+tc.prefix+"]")
			} else {
				assert.NotContains(t, formattedStr, "[")
			}
		})
	}
}
