/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: formatter.go
Description: Custom log formatter for the Akaylee Fuzzer. Provides beautiful,
structured logging output with colors, enhanced formatting, and fuzzer-specific
information display.
*/

package logging

import (
	"fmt"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// CustomFormatter provides beautiful, structured logging output
type CustomFormatter struct {
	Timestamp bool
	Caller    bool
	Colors    bool
}

// Format formats a log entry with beautiful output
func (f *CustomFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	var output strings.Builder

	// Add timestamp
	if f.Timestamp {
		timestamp := entry.Time.Format("2006-01-02 15:04:05.000")
		if f.Colors {
			output.WriteString(fmt.Sprintf("\033[36m%s\033[0m ", timestamp)) // Cyan
		} else {
			output.WriteString(fmt.Sprintf("%s ", timestamp))
		}
	}

	// Add log level with color
	level := strings.ToUpper(entry.Level.String())
	if f.Colors {
		levelColor := f.getLevelColor(entry.Level)
		output.WriteString(fmt.Sprintf("\033[%dm%s\033[0m ", levelColor, level))
	} else {
		output.WriteString(fmt.Sprintf("%s ", level))
	}

	// Add caller information
	if f.Caller && entry.HasCaller() {
		caller := fmt.Sprintf("%s:%d", entry.Caller.File, entry.Caller.Line)
		if f.Colors {
			output.WriteString(fmt.Sprintf("\033[33m[%s]\033[0m ", caller)) // Yellow
		} else {
			output.WriteString(fmt.Sprintf("[%s] ", caller))
		}
	}

	// Add message
	output.WriteString(entry.Message)

	// Add structured fields
	if len(entry.Data) > 0 {
		output.WriteString(" ")
		output.WriteString(f.formatFields(entry.Data))
	}

	output.WriteString("\n")
	return []byte(output.String()), nil
}

// getLevelColor returns the ANSI color code for a log level
func (f *CustomFormatter) getLevelColor(level logrus.Level) int {
	switch level {
	case logrus.DebugLevel:
		return 37 // White
	case logrus.InfoLevel:
		return 32 // Green
	case logrus.WarnLevel:
		return 33 // Yellow
	case logrus.ErrorLevel:
		return 31 // Red
	case logrus.FatalLevel:
		return 35 // Magenta
	case logrus.PanicLevel:
		return 35 // Magenta
	default:
		return 37 // White
	}
}

// formatFields formats structured fields in a readable way
func (f *CustomFormatter) formatFields(fields logrus.Fields) string {
	var parts []string

	for key, value := range fields {
		formattedValue := f.formatValue(value)
		if f.Colors {
			parts = append(parts, fmt.Sprintf("\033[34m%s\033[0m=\033[32m%s\033[0m", key, formattedValue)) // Blue key, Green value
		} else {
			parts = append(parts, fmt.Sprintf("%s=%s", key, formattedValue))
		}
	}

	return strings.Join(parts, " ")
}

// formatValue formats a field value appropriately
func (f *CustomFormatter) formatValue(value interface{}) string {
	switch v := value.(type) {
	case time.Duration:
		return v.String()
	case time.Time:
		return v.Format("15:04:05.000")
	case string:
		if len(v) > 50 {
			return fmt.Sprintf("%s...", v[:50])
		}
		return v
	case []byte:
		if len(v) > 20 {
			return fmt.Sprintf("[%d bytes]", len(v))
		}
		return fmt.Sprintf("%x", v)
	default:
		return fmt.Sprintf("%v", v)
	}
}

// FuzzerFormatter provides specialized formatting for fuzzer-specific logs
type FuzzerFormatter struct {
	CustomFormatter
	ShowPerformance bool
	ShowCoverage    bool
}

// Format formats fuzzer-specific log entries with enhanced information
func (f *FuzzerFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	var output strings.Builder

	// Add timestamp
	if f.Timestamp {
		timestamp := entry.Time.Format("2006-01-02 15:04:05.000")
		if f.Colors {
			output.WriteString(fmt.Sprintf("\033[36m%s\033[0m ", timestamp))
		} else {
			output.WriteString(fmt.Sprintf("%s ", timestamp))
		}
	}

	// Add log level
	level := strings.ToUpper(entry.Level.String())
	if f.Colors {
		levelColor := f.getLevelColor(entry.Level)
		output.WriteString(fmt.Sprintf("\033[%dm%s\033[0m ", levelColor, level))
	} else {
		output.WriteString(fmt.Sprintf("%s ", level))
	}

	// Add fuzzer-specific prefix based on message
	prefix := f.getFuzzerPrefix(entry.Message)
	if prefix != "" {
		if f.Colors {
			output.WriteString(fmt.Sprintf("\033[35m[%s]\033[0m ", prefix)) // Magenta
		} else {
			output.WriteString(fmt.Sprintf("[%s] ", prefix))
		}
	}

	// Add caller information
	if f.Caller && entry.HasCaller() {
		caller := fmt.Sprintf("%s:%d", entry.Caller.File, entry.Caller.Line)
		if f.Colors {
			output.WriteString(fmt.Sprintf("\033[33m[%s]\033[0m ", caller))
		} else {
			output.WriteString(fmt.Sprintf("[%s] ", caller))
		}
	}

	// Add message
	output.WriteString(entry.Message)

	// Add structured fields with fuzzer-specific formatting
	if len(entry.Data) > 0 {
		output.WriteString(" ")
		output.WriteString(f.formatFuzzerFields(entry.Data))
	}

	output.WriteString("\n")
	return []byte(output.String()), nil
}

// getFuzzerPrefix returns a prefix based on the log message
func (f *FuzzerFormatter) getFuzzerPrefix(message string) string {
	switch {
	case strings.Contains(message, "Test case executed"):
		return "EXEC"
	case strings.Contains(message, "Crash detected"):
		return "CRASH"
	case strings.Contains(message, "Hang detected"):
		return "HANG"
	case strings.Contains(message, "Coverage updated"):
		return "COVERAGE"
	case strings.Contains(message, "Test case mutated"):
		return "MUTATE"
	case strings.Contains(message, "Statistics update"):
		return "STATS"
	case strings.Contains(message, "Worker"):
		return "WORKER"
	case strings.Contains(message, "Engine"):
		return "ENGINE"
	default:
		return ""
	}
}

// formatFuzzerFields formats fuzzer-specific fields with enhanced display
func (f *FuzzerFormatter) formatFuzzerFields(fields logrus.Fields) string {
	var parts []string

	for key, value := range fields {
		formattedValue := f.formatFuzzerValue(key, value)
		if f.Colors {
			parts = append(parts, fmt.Sprintf("\033[34m%s\033[0m=\033[32m%s\033[0m", key, formattedValue))
		} else {
			parts = append(parts, fmt.Sprintf("%s=%s", key, formattedValue))
		}
	}

	return strings.Join(parts, " ")
}

// formatFuzzerValue formats fuzzer-specific field values
func (f *FuzzerFormatter) formatFuzzerValue(key string, value interface{}) string {
	switch key {
	case "duration":
		if d, ok := value.(time.Duration); ok {
			return d.String()
		}
	case "executions_per_sec":
		if f, ok := value.(float64); ok {
			return fmt.Sprintf("%.2f/sec", f)
		}
	case "edge_count", "block_count":
		if i, ok := value.(int); ok {
			return fmt.Sprintf("%d", i)
		}
	case "test_case_id":
		if s, ok := value.(string); ok {
			if len(s) > 8 {
				return s[:8] + "..."
			}
			return s
		}
	case "uptime":
		if d, ok := value.(time.Duration); ok {
			return d.String()
		}
	case "timestamp":
		if t, ok := value.(time.Time); ok {
			return t.Format("15:04:05.000")
		}
	}

	return f.formatValue(value)
}
