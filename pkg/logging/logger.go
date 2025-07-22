/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: logger.go
Description: Comprehensive logging system for the Akaylee Fuzzer. Provides structured
logging with timestamped files, multiple output formats, and beautiful formatting.
Supports JSON, text, and custom formats with rotation and performance optimization.
*/

package logging

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"time"

	"log/syslog"

	"github.com/sirupsen/logrus"
)

// LogLevel represents the logging level
type LogLevel string

const (
	LogLevelDebug   LogLevel = "debug"
	LogLevelInfo    LogLevel = "info"
	LogLevelWarning LogLevel = "warn"
	LogLevelError   LogLevel = "error"
	LogLevelFatal   LogLevel = "fatal"
)

// LogFormat represents the logging format
type LogFormat string

const (
	LogFormatJSON   LogFormat = "json"
	LogFormatText   LogFormat = "text"
	LogFormatCustom LogFormat = "custom"
)

// LoggerConfig holds the configuration for the logger
// Now includes syslog and journald options
type LoggerConfig struct {
	Level     LogLevel  `json:"level"`
	Format    LogFormat `json:"format"`
	OutputDir string    `json:"output_dir"`
	MaxFiles  int       `json:"max_files"`
	MaxSize   int64     `json:"max_size"` // in bytes
	Timestamp bool      `json:"timestamp"`
	Caller    bool      `json:"caller"`
	Colors    bool      `json:"colors"`
	Compress  bool      `json:"compress"`

	SyslogEnabled   bool   `json:"syslog_enabled"`
	SyslogNetwork   string `json:"syslog_network"`
	SyslogAddress   string `json:"syslog_address"`
	JournaldEnabled bool   `json:"journald_enabled"`
	// GRPCSinkEnabled bool   `json:"grpc_sink_enabled"` // Stub for now
}

// Validate checks the LoggerConfig for invalid or missing values.
// Returns an error if the config is invalid, or nil if valid.
func (c *LoggerConfig) Validate() error {
	if c.OutputDir == "" {
		return fmt.Errorf("output_dir must not be empty")
	}
	if c.MaxFiles <= 0 {
		return fmt.Errorf("max_files must be positive")
	}
	if c.MaxSize <= 0 {
		return fmt.Errorf("max_size must be positive")
	}
	switch c.Format {
	case LogFormatJSON, LogFormatText, LogFormatCustom:
		// ok
	default:
		return fmt.Errorf("unsupported log format: %s", c.Format)
	}
	switch c.Level {
	case LogLevelDebug, LogLevelInfo, LogLevelWarning, LogLevelError, LogLevelFatal:
		// ok
	default:
		return fmt.Errorf("unsupported log level: %s", c.Level)
	}
	return nil
}

type logEntry struct {
	level  logrus.Level
	msg    string
	fields logrus.Fields
}

// Logger provides comprehensive logging functionality
// Now supports async log queue for high performance
type Logger struct {
	config     *LoggerConfig
	logger     *logrus.Logger
	fileHandle *os.File
	startTime  time.Time

	logQueue chan logEntry
	quit     chan struct{}
}

// NewLogger creates a new logger instance
func NewLogger(config *LoggerConfig) (*Logger, error) {
	if config == nil {
		config = &LoggerConfig{
			Level:     LogLevelInfo,
			Format:    LogFormatText,
			OutputDir: "./logs",
			MaxFiles:  10,
			MaxSize:   100 * 1024 * 1024, // 100MB
			Timestamp: true,
			Caller:    true,
			Colors:    true,
			Compress:  false,
		}
	}

	l := &Logger{
		config:    config,
		logger:    logrus.New(),
		startTime: time.Now(),
		logQueue:  make(chan logEntry, 1024),
		quit:      make(chan struct{}),
	}

	if err := l.setup(); err != nil {
		return nil, fmt.Errorf("failed to setup logger: %w", err)
	}

	go l.runLogQueue()

	return l, nil
}

// setup configures the logger with the given configuration
func (l *Logger) setup() error {
	// Set log level
	level, err := logrus.ParseLevel(string(l.config.Level))
	if err != nil {
		level = logrus.InfoLevel
	}
	l.logger.SetLevel(level)

	// Set formatter
	if err := l.setFormatter(); err != nil {
		return err
	}

	// Setup file output
	if err := l.setupFileOutput(); err != nil {
		return err
	}

	// Setup console output
	l.setupConsoleOutput()

	// Setup syslog sink if enabled
	if l.config.SyslogEnabled {
		writer, err := syslog.Dial(l.config.SyslogNetwork, l.config.SyslogAddress, syslog.LOG_INFO|syslog.LOG_USER, "akaylee-fuzzer")
		if err != nil {
			return fmt.Errorf("failed to connect to syslog: %w", err)
		}
		l.logger.SetOutput(io.MultiWriter(l.logger.Out, writer))
	}
	// Setup journald sink if enabled (stub)
	if l.config.JournaldEnabled {
		// TODO: Integrate with go-systemd/journal for journald support
		// For now, just log a warning
		l.logger.Warn("Journald logging enabled, but not implemented yet.")
	}

	return nil
}

// setFormatter configures the log formatter
func (l *Logger) setFormatter() error {
	switch l.config.Format {
	case LogFormatJSON:
		l.logger.SetFormatter(&logrus.JSONFormatter{
			TimestampFormat: time.RFC3339,
			CallerPrettyfier: func(f *runtime.Frame) (string, string) {
				filename := filepath.Base(f.File)
				return "", fmt.Sprintf("%s:%d", filename, f.Line)
			},
		})

	case LogFormatText:
		l.logger.SetFormatter(&logrus.TextFormatter{
			FullTimestamp:   l.config.Timestamp,
			TimestampFormat: time.RFC3339,
			ForceColors:     l.config.Colors,
			DisableColors:   !l.config.Colors,
			CallerPrettyfier: func(f *runtime.Frame) (string, string) {
				filename := filepath.Base(f.File)
				return "", fmt.Sprintf("%s:%d", filename, f.Line)
			},
		})

	case LogFormatCustom:
		l.logger.SetFormatter(&CustomFormatter{
			Timestamp: l.config.Timestamp,
			Caller:    l.config.Caller,
			Colors:    l.config.Colors,
		})

	default:
		return fmt.Errorf("unsupported log format: %s", l.config.Format)
	}

	return nil
}

// setupFileOutput configures file-based logging
func (l *Logger) setupFileOutput() error {
	if l.config.OutputDir == "" {
		return nil
	}

	// Create output directory
	if err := os.MkdirAll(l.config.OutputDir, 0755); err != nil {
		return fmt.Errorf("failed to create log directory: %w", err)
	}

	// Generate filename with timestamp
	timestamp := time.Now().Format("2006-01-02_15-04-05")
	filename := fmt.Sprintf("akaylee-fuzzer_%s.log", timestamp)
	filepath := filepath.Join(l.config.OutputDir, filename)

	// Open log file
	file, err := os.OpenFile(filepath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		return fmt.Errorf("failed to open log file: %w", err)
	}

	l.fileHandle = file

	// Create multi-writer for both file and console
	multiWriter := io.MultiWriter(os.Stdout, file)
	l.logger.SetOutput(multiWriter)

	// Log startup message
	l.logger.WithFields(logrus.Fields{
		"start_time": l.startTime.Format(time.RFC3339),
		"log_file":   filepath,
		"level":      l.config.Level,
		"format":     l.config.Format,
	}).Info("Akaylee Fuzzer logging system initialized")

	return nil
}

// setupConsoleOutput configures console output
func (l *Logger) setupConsoleOutput() {
	// Console output is handled by the multi-writer in setupFileOutput
	// This method can be extended for additional console formatting
}

// rotateLogs rotates log files when they exceed size limits
func (l *Logger) rotateLogs() error {
	if l.fileHandle == nil {
		return nil
	}

	// Check file size
	stat, err := l.fileHandle.Stat()
	if err != nil {
		return err
	}

	if stat.Size() < l.config.MaxSize {
		return nil
	}

	// Close current file
	l.fileHandle.Close()

	// Setup new file
	return l.setupFileOutput()
}

// cleanup removes old log files
func (l *Logger) cleanup() error {
	if l.config.OutputDir == "" {
		return nil
	}

	files, err := filepath.Glob(filepath.Join(l.config.OutputDir, "akaylee-fuzzer_*.log"))
	if err != nil {
		return err
	}

	if len(files) <= l.config.MaxFiles {
		return nil
	}

	// Sort files by modification time (oldest first)
	sort.Slice(files, func(i, j int) bool {
		statI, _ := os.Stat(files[i])
		statJ, _ := os.Stat(files[j])
		return statI.ModTime().Before(statJ.ModTime())
	})

	// Remove oldest files
	filesToRemove := len(files) - l.config.MaxFiles
	for i := 0; i < filesToRemove; i++ {
		os.Remove(files[i])
	}

	return nil
}

// runLogQueue flushes log entries from the queue in a background goroutine
func (l *Logger) runLogQueue() {
	for {
		select {
		case entry := <-l.logQueue:
			l.logger.WithFields(entry.fields).Log(entry.level, entry.msg)
		case <-l.quit:
			return
		}
	}
}

// Fuzzer-specific logging methods

// LogExecution logs test case execution
func (l *Logger) LogExecution(testCaseID string, duration time.Duration, status string, fields map[string]interface{}) {
	if fields == nil {
		fields = make(map[string]interface{})
	}
	fields["test_case_id"] = testCaseID
	fields["duration"] = duration
	fields["status"] = status
	fields["timestamp"] = time.Now()

	l.logger.WithFields(fields).Info("Test case executed")
}

// LogCrash logs a crash detection
func (l *Logger) LogCrash(testCaseID string, crashType string, fields map[string]interface{}) {
	if fields == nil {
		fields = make(map[string]interface{})
	}
	fields["test_case_id"] = testCaseID
	fields["crash_type"] = crashType
	fields["timestamp"] = time.Now()

	l.logger.WithFields(fields).Error("Crash detected")
}

// LogHang logs a hang detection
func (l *Logger) LogHang(testCaseID string, duration time.Duration, fields map[string]interface{}) {
	if fields == nil {
		fields = make(map[string]interface{})
	}
	fields["test_case_id"] = testCaseID
	fields["duration"] = duration
	fields["timestamp"] = time.Now()

	l.logger.WithFields(fields).Warning("Hang detected")
}

// LogCoverage logs coverage information
func (l *Logger) LogCoverage(testCaseID string, edgeCount int, blockCount int, fields map[string]interface{}) {
	if fields == nil {
		fields = make(map[string]interface{})
	}
	fields["test_case_id"] = testCaseID
	fields["edge_count"] = edgeCount
	fields["block_count"] = blockCount
	fields["timestamp"] = time.Now()

	l.logger.WithFields(fields).Info("Coverage updated")
}

// LogMutation logs mutation operations
func (l *Logger) LogMutation(parentID string, childID string, mutator string, fields map[string]interface{}) {
	if fields == nil {
		fields = make(map[string]interface{})
	}
	fields["parent_id"] = parentID
	fields["child_id"] = childID
	fields["mutator"] = mutator
	fields["timestamp"] = time.Now()

	l.logger.WithFields(fields).Debug("Test case mutated")
}

// LogStats logs statistics
func (l *Logger) LogStats(executions int64, crashes int64, hangs int64, execPerSec float64, fields map[string]interface{}) {
	if fields == nil {
		fields = make(map[string]interface{})
	}
	fields["executions"] = executions
	fields["crashes"] = crashes
	fields["hangs"] = hangs
	fields["executions_per_sec"] = execPerSec
	fields["uptime"] = time.Since(l.startTime)
	fields["timestamp"] = time.Now()

	l.logger.WithFields(fields).Info("Statistics update")
}

// Close closes the logger and performs cleanup
func (l *Logger) Close() error {
	close(l.quit)
	if l.fileHandle != nil {
		l.fileHandle.Close()
	}

	if err := l.cleanup(); err != nil {
		return fmt.Errorf("failed to cleanup log files: %w", err)
	}

	return nil
}

// GetLogger returns the underlying logrus logger
func (l *Logger) GetLogger() *logrus.Logger {
	return l.logger
}

// Debug logs a debug message (async)
func (l *Logger) Debug(msg string, fields map[string]interface{}) {
	l.logQueue <- logEntry{level: logrus.DebugLevel, msg: msg, fields: fields}
}

// Info logs an info message (async)
func (l *Logger) Info(msg string, fields map[string]interface{}) {
	l.logQueue <- logEntry{level: logrus.InfoLevel, msg: msg, fields: fields}
}

// Warning logs a warning message (async)
func (l *Logger) Warning(msg string, fields map[string]interface{}) {
	l.logQueue <- logEntry{level: logrus.WarnLevel, msg: msg, fields: fields}
}

// Error logs an error message (async)
func (l *Logger) Error(msg string, fields map[string]interface{}) {
	l.logQueue <- logEntry{level: logrus.ErrorLevel, msg: msg, fields: fields}
}

// Fatal logs a fatal message and exits (async)
func (l *Logger) Fatal(msg string, fields map[string]interface{}) {
	l.logQueue <- logEntry{level: logrus.FatalLevel, msg: msg, fields: fields}
}
