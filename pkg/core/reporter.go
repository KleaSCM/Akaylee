/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: reporter.go
Description: Reporter interface and implementations for Akaylee Fuzzer telemetry and live reporting.
 Supports logging, Prometheus, and future integrations for real-time fuzzing metrics and events.
*/

package core

import (
	"github.com/sirupsen/logrus"
)

// Reporter defines the interface for telemetry and reporting hooks.
// Allows the fuzzer to notify listeners of execution and corpus events.
type Reporter interface {
	// OnTestCaseExecuted is called after a test case is executed.
	OnTestCaseExecuted(result *ExecutionResult)
	// OnTestCaseAdded is called when a new test case is added to the corpus.
	OnTestCaseAdded(tc *TestCase)
}

// LoggerReporter logs execution and corpus events using the standard logger.
type LoggerReporter struct {
	logger *logrus.Logger // Use logrus.Logger for demonstration
}

// NewLoggerReporter creates a new LoggerReporter.
func NewLoggerReporter(logger *logrus.Logger) *LoggerReporter {
	return &LoggerReporter{logger: logger}
}

// OnTestCaseExecuted logs execution results.
func (r *LoggerReporter) OnTestCaseExecuted(result *ExecutionResult) {
	switch result.Status {
	case StatusCrash:
		r.logger.WithFields(logrus.Fields{"testcase": result.TestCaseID}).Warn("Crash detected")
	case StatusHang:
		r.logger.WithFields(logrus.Fields{"testcase": result.TestCaseID}).Warn("Hang detected")
	default:
		r.logger.WithFields(logrus.Fields{"testcase": result.TestCaseID}).Info("Test case executed")
	}
}

// OnTestCaseAdded logs new test case addition.
func (r *LoggerReporter) OnTestCaseAdded(tc *TestCase) {
	r.logger.WithFields(logrus.Fields{"id": tc.ID, "priority": tc.Priority}).Info("Test case added to corpus")
}

// PrometheusReporter is a stub for Prometheus metrics export.
type PrometheusReporter struct {
	// TODO: Add Prometheus metrics fields
}

// NewPrometheusReporter creates a new PrometheusReporter.
func NewPrometheusReporter() *PrometheusReporter {
	return &PrometheusReporter{}
}

// OnTestCaseExecuted (stub).
func (r *PrometheusReporter) OnTestCaseExecuted(result *ExecutionResult) {
	// TODO: Export metrics to Prometheus
}

// OnTestCaseAdded (stub).
func (r *PrometheusReporter) OnTestCaseAdded(tc *TestCase) {
	// TODO: Export metrics to Prometheus
}
