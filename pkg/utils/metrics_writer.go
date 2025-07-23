/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: metrics_writer.go
Description: Utility for writing test results to the metrics directory.
Handles timestamped, versioned, and type-specific subdirectory naming.
Ensures directories exist and writes JSON files for easy analysis.
*/

package utils

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// WriteMetricsResult writes a result to the metrics directory with timestamp, type, and version
func WriteMetricsResult(testType string, version string, result interface{}) (string, error) {
	// Ensure metrics directory and subdirectory exist
	metricsDir := filepath.Join("metrics", testType)
	if err := os.MkdirAll(metricsDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create metrics directory: %w", err)
	}

	// Generate filename: 2024-06-11_01-30-00_core_v1.0.0.json
	timestamp := time.Now().Format("2006-01-02_15-04-05")
	filename := fmt.Sprintf("%s_%s_v%s.json", timestamp, testType, version)
	filePath := filepath.Join(metricsDir, filename)

	// Marshal result to JSON
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal result: %w", err)
	}

	// Write to file
	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return "", fmt.Errorf("failed to write metrics file: %w", err)
	}

	return filePath, nil
}
