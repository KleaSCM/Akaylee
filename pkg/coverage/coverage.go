/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: coverage.go
Description: Provides interfaces and implementations for collecting code coverage during fuzzing. Includes a modular CoverageCollector interface and a GoCoverageCollector for Go source targets. Designed for easy extension to other target types (native, API, etc).
*/

package coverage

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// CoverageInfo holds coverage data for a single fuzz run
// (can be extended for more detail)
type CoverageInfo struct {
	CoveredBlocks map[string]bool // e.g., file:line or block IDs
	RawProfile    string          // raw coverage profile data (optional)
}

// CoverageCollector is the interface for all coverage collectors
type CoverageCollector interface {
	// Prepare the target for coverage collection (e.g., build with coverage flags)
	Prepare(targetPath string, args []string) error
	// Collect coverage after a fuzz run
	Collect(runOutput []byte, runErr error) (*CoverageInfo, error)
	// Cleanup any temp files or state
	Cleanup() error
}

// GoCoverageCollector implements CoverageCollector for Go source targets
type GoCoverageCollector struct {
	TargetPath string
	Args       []string
	ProfileDir string // where to store coverage profiles
}

// Prepare builds the target with coverage instrumentation
func (g *GoCoverageCollector) Prepare(targetPath string, args []string) error {
	g.TargetPath = targetPath
	g.Args = args
	g.ProfileDir = "./coverage_profiles"
	if err := os.MkdirAll(g.ProfileDir, 0755); err != nil {
		return fmt.Errorf("failed to create coverage profile dir: %w", err)
	}
	// For Go, we may not need to rebuild, but could add build hooks here
	return nil
}

// Collect parses the coverage profile after a fuzz run
func (g *GoCoverageCollector) Collect(runOutput []byte, runErr error) (*CoverageInfo, error) {
	// Assume the target writes a coverage profile to a known location
	profilePath := filepath.Join(g.ProfileDir, "fuzz.coverprofile")
	if _, err := os.Stat(profilePath); err != nil {
		return nil, fmt.Errorf("coverage profile not found: %w", err)
	}
	// Parse the profile
	data, err := os.ReadFile(profilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read coverage profile: %w", err)
	}
	info := &CoverageInfo{
		CoveredBlocks: make(map[string]bool),
		RawProfile:    string(data),
	}
	// Parse Go coverprofile format
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "mode:") {
			continue // skip header
		}
		// Format: filename:startLine.startCol,endLine.endCol numStatements count
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		filename := fields[0]
		block := fields[1]
		count := fields[2]
		if count == "0" {
			continue // not covered
		}
		// Use filename:block as the key
		info.CoveredBlocks[filename+":"+block] = true
	}
	return info, nil
}

// Cleanup removes any temp files
func (g *GoCoverageCollector) Cleanup() error {
	// Optionally remove coverage profiles
	return nil
}
