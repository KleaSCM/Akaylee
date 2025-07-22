/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: utils.go
Description: Utility functions for log management in the Akaylee Fuzzer. Provides
log rotation, cleanup, performance monitoring, and log analysis capabilities.
*/

package logging

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// LogManager provides advanced log management capabilities
type LogManager struct {
	logDir   string
	maxFiles int
	maxSize  int64
	compress bool
}

// NewLogManager creates a new log manager
func NewLogManager(logDir string, maxFiles int, maxSize int64, compress bool) *LogManager {
	return &LogManager{
		logDir:   logDir,
		maxFiles: maxFiles,
		maxSize:  maxSize,
		compress: compress,
	}
}

// RotateLogs rotates log files when they exceed size limits
func (lm *LogManager) RotateLogs() error {
	files, err := filepath.Glob(filepath.Join(lm.logDir, "akaylee-fuzzer_*.log"))
	if err != nil {
		return fmt.Errorf("failed to glob log files: %w", err)
	}

	for _, file := range files {
		if err := lm.rotateFile(file); err != nil {
			return fmt.Errorf("failed to rotate file %s: %w", file, err)
		}
	}

	return nil
}

// rotateFile rotates a single log file
func (lm *LogManager) rotateFile(filepath string) error {
	stat, err := os.Stat(filepath)
	if err != nil {
		return err
	}

	if stat.Size() < lm.maxSize {
		return nil
	}

	// Create rotated filename
	timestamp := time.Now().Format("2006-01-02_15-04-05")
	rotatedPath := fmt.Sprintf("%s.%s", filepath, timestamp)

	// Move current file to rotated name
	if err := os.Rename(filepath, rotatedPath); err != nil {
		return err
	}

	// Compress if enabled
	if lm.compress {
		if err := lm.compressFile(rotatedPath); err != nil {
			return err
		}
	}

	return nil
}

// compressFile compresses a log file using gzip
func (lm *LogManager) compressFile(filepath string) error {
	// Open source file
	source, err := os.Open(filepath)
	if err != nil {
		return err
	}
	defer source.Close()

	// Create compressed file
	compressedPath := filepath + ".gz"
	compressed, err := os.Create(compressedPath)
	if err != nil {
		return err
	}
	defer compressed.Close()

	// Create gzip writer
	gzipWriter := gzip.NewWriter(compressed)
	defer gzipWriter.Close()

	// Copy data
	if _, err := io.Copy(gzipWriter, source); err != nil {
		return err
	}

	// Remove original file
	return os.Remove(filepath)
}

// CleanupOldLogs removes old log files based on retention policy
func (lm *LogManager) CleanupOldLogs() error {
	files, err := filepath.Glob(filepath.Join(lm.logDir, "akaylee-fuzzer_*.log*"))
	if err != nil {
		return fmt.Errorf("failed to glob log files: %w", err)
	}

	if len(files) <= lm.maxFiles {
		return nil
	}

	// Sort files by modification time (oldest first)
	sort.Slice(files, func(i, j int) bool {
		statI, _ := os.Stat(files[i])
		statJ, _ := os.Stat(files[j])
		return statI.ModTime().Before(statJ.ModTime())
	})

	// Remove oldest files
	filesToRemove := len(files) - lm.maxFiles
	for i := 0; i < filesToRemove; i++ {
		if err := os.Remove(files[i]); err != nil {
			return fmt.Errorf("failed to remove file %s: %w", files[i], err)
		}
	}

	return nil
}

// GetLogStats returns statistics about log files
func (lm *LogManager) GetLogStats() (*LogStats, error) {
	files, err := filepath.Glob(filepath.Join(lm.logDir, "akaylee-fuzzer_*.log*"))
	if err != nil {
		return nil, fmt.Errorf("failed to glob log files: %w", err)
	}

	stats := &LogStats{
		TotalFiles: len(files),
		TotalSize:  0,
		OldestFile: time.Now(),
		NewestFile: time.Time{},
	}

	for _, file := range files {
		stat, err := os.Stat(file)
		if err != nil {
			continue
		}

		stats.TotalSize += stat.Size()

		if stat.ModTime().Before(stats.OldestFile) {
			stats.OldestFile = stat.ModTime()
		}

		if stat.ModTime().After(stats.NewestFile) {
			stats.NewestFile = stat.ModTime()
		}

		if strings.HasSuffix(file, ".gz") {
			stats.CompressedFiles++
		} else {
			stats.UncompressedFiles++
		}
	}

	return stats, nil
}

// LogStats holds statistics about log files
type LogStats struct {
	TotalFiles        int       `json:"total_files"`
	TotalSize         int64     `json:"total_size"`
	CompressedFiles   int       `json:"compressed_files"`
	UncompressedFiles int       `json:"uncompressed_files"`
	OldestFile        time.Time `json:"oldest_file"`
	NewestFile        time.Time `json:"newest_file"`
}

// LogAnalyzer provides log analysis capabilities
type LogAnalyzer struct {
	logDir string
}

// NewLogAnalyzer creates a new log analyzer
func NewLogAnalyzer(logDir string) *LogAnalyzer {
	return &LogAnalyzer{
		logDir: logDir,
	}
}

// AnalyzeLogs analyzes log files for patterns and statistics
func (la *LogAnalyzer) AnalyzeLogs() (*LogAnalysis, error) {
	files, err := filepath.Glob(filepath.Join(la.logDir, "akaylee-fuzzer_*.log"))
	if err != nil {
		return nil, fmt.Errorf("failed to glob log files: %w", err)
	}

	analysis := &LogAnalysis{
		StartTime: time.Now(),
		LogFiles:  len(files),
	}

	for _, file := range files {
		if err := la.analyzeFile(file, analysis); err != nil {
			return nil, fmt.Errorf("failed to analyze file %s: %w", file, err)
		}
	}

	return analysis, nil
}

// analyzeFile analyzes a single log file
func (la *LogAnalyzer) analyzeFile(filepath string, analysis *LogAnalysis) error {
	file, err := os.Open(filepath)
	if err != nil {
		return err
	}
	defer file.Close()

	// Read file line by line
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		la.analyzeLine(line, analysis)
	}

	return scanner.Err()
}

// analyzeLine analyzes a single log line
func (la *LogAnalyzer) analyzeLine(line string, analysis *LogAnalysis) {
	analysis.TotalLines++

	// Count log levels
	if strings.Contains(line, "DEBUG") {
		analysis.DebugCount++
	} else if strings.Contains(line, "INFO") {
		analysis.InfoCount++
	} else if strings.Contains(line, "WARN") {
		analysis.WarningCount++
	} else if strings.Contains(line, "ERROR") {
		analysis.ErrorCount++
	} else if strings.Contains(line, "FATAL") {
		analysis.FatalCount++
	}

	// Count fuzzer-specific events
	if strings.Contains(line, "Crash detected") {
		analysis.CrashCount++
	} else if strings.Contains(line, "Hang detected") {
		analysis.HangCount++
	} else if strings.Contains(line, "Test case executed") {
		analysis.ExecutionCount++
	} else if strings.Contains(line, "Test case mutated") {
		analysis.MutationCount++
	} else if strings.Contains(line, "Coverage updated") {
		analysis.CoverageCount++
	}
}

// LogAnalysis holds the results of log analysis
type LogAnalysis struct {
	StartTime      time.Time `json:"start_time"`
	LogFiles       int       `json:"log_files"`
	TotalLines     int64     `json:"total_lines"`
	DebugCount     int64     `json:"debug_count"`
	InfoCount      int64     `json:"info_count"`
	WarningCount   int64     `json:"warning_count"`
	ErrorCount     int64     `json:"error_count"`
	FatalCount     int64     `json:"fatal_count"`
	CrashCount     int64     `json:"crash_count"`
	HangCount      int64     `json:"hang_count"`
	ExecutionCount int64     `json:"execution_count"`
	MutationCount  int64     `json:"mutation_count"`
	CoverageCount  int64     `json:"coverage_count"`
}

// GetLogSummary returns a summary of the log analysis
func (la *LogAnalysis) GetLogSummary() string {
	return fmt.Sprintf(
		"Log Analysis Summary:\n"+
			"  Files: %d\n"+
			"  Total Lines: %d\n"+
			"  Debug: %d\n"+
			"  Info: %d\n"+
			"  Warning: %d\n"+
			"  Error: %d\n"+
			"  Fatal: %d\n"+
			"  Crashes: %d\n"+
			"  Hangs: %d\n"+
			"  Executions: %d\n"+
			"  Mutations: %d\n"+
			"  Coverage Updates: %d",
		la.LogFiles, la.TotalLines, la.DebugCount, la.InfoCount,
		la.WarningCount, la.ErrorCount, la.FatalCount, la.CrashCount,
		la.HangCount, la.ExecutionCount, la.MutationCount, la.CoverageCount,
	)
}
