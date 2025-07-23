/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: app_analyzer.go
Description: AndroidAppAnalyzer. Implements AppAnalyzer interface for APK/manifest
analysis and runtime inspection using aapt, dumpsys, ps, and logcat. Robust output parsing and error handling.
*/

package mobile

import (
	"bufio"
	"bytes"
	"encoding/xml"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

// AndroidAppAnalyzer implements AppAnalyzer for Android APKs and running apps
type AndroidAppAnalyzer struct{}

func NewAndroidAppAnalyzer() *AndroidAppAnalyzer {
	return &AndroidAppAnalyzer{}
}

func (a *AndroidAppAnalyzer) AnalyzeApp(appPath string) (*AppAnalysis, error) {
	// Use aapt to dump badging info
	cmd := exec.Command("aapt", "dump", "badging", appPath)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("aapt failed: %v", err)
	}
	analysis := &AppAnalysis{
		Metadata: make(map[string]interface{}),
	}
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "package: ") {
			fields := strings.Fields(line)
			for _, f := range fields {
				if strings.HasPrefix(f, "name=") {
					analysis.PackageName = strings.Trim(f[5:], "'\"")
				}
				if strings.HasPrefix(f, "versionName=") {
					analysis.Version = strings.Trim(f[12:], "'\"")
				}
			}
		}
		if strings.HasPrefix(line, "uses-permission: ") {
			perm := strings.TrimPrefix(line, "uses-permission: ")
			perm = strings.Trim(perm, "'\"")
			analysis.Permissions = append(analysis.Permissions, perm)
		}
		if strings.HasPrefix(line, "launchable-activity: ") {
			fields := strings.Fields(line)
			for _, f := range fields {
				if strings.HasPrefix(f, "name=") {
					analysis.Activities = append(analysis.Activities, strings.Trim(f[5:], "'\""))
				}
			}
		}
		if strings.HasPrefix(line, "application-label:") {
			analysis.Metadata["label"] = strings.TrimPrefix(line, "application-label:")
		}
	}
	return analysis, nil
}

func (a *AndroidAppAnalyzer) AnalyzeManifest(manifestPath string) (*ManifestAnalysis, error) {
	// Parse AndroidManifest.xml (assume already extracted)
	data, err := exec.Command("cat", manifestPath).Output()
	if err != nil {
		return nil, fmt.Errorf("failed to read manifest: %v", err)
	}
	var manifest struct {
		XMLName     xml.Name `xml:"manifest"`
		Package     string   `xml:"package,attr"`
		Permissions []struct {
			Name string `xml:"name,attr"`
		} `xml:"uses-permission"`
		Activities []struct {
			Name string `xml:"name,attr"`
		} `xml:"application>activity"`
	}
	if err := xml.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("xml unmarshal failed: %v", err)
	}
	analysis := &ManifestAnalysis{
		PackageName: manifest.Package,
		Metadata:    make(map[string]interface{}),
	}
	for _, p := range manifest.Permissions {
		analysis.Permissions = append(analysis.Permissions, p.Name)
	}
	for _, a := range manifest.Activities {
		analysis.Activities = append(analysis.Activities, a.Name)
	}
	return analysis, nil
}

func (a *AndroidAppAnalyzer) AnalyzeRunningApp(packageName string) (*AppRuntimeAnalysis, error) {
	// Use dumpsys and ps to get process/thread info
	cmd := exec.Command("adb", "shell", "ps")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("ps failed: %v", err)
	}
	var processes []string
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, packageName) {
			processes = append(processes, line)
		}
	}
	// Get logs
	cmd = exec.Command("adb", "logcat", "-d", "|", "grep", packageName)
	logsOutput, _ := cmd.Output()
	var logs []string
	scanLogs := bufio.NewScanner(bytes.NewReader(logsOutput))
	for scanLogs.Scan() {
		logs = append(logs, scanLogs.Text())
	}
	// Use dumpsys meminfo for memory
	cmd = exec.Command("adb", "shell", "dumpsys", "meminfo", packageName)
	memOutput, _ := cmd.Output()
	memUsage := parseMemUsage(string(memOutput))
	// Use dumpsys cpuinfo for CPU
	cmd = exec.Command("adb", "shell", "dumpsys", "cpuinfo")
	cpuOutput, _ := cmd.Output()
	cpuUsage := parseCPUUsage(string(cpuOutput), packageName)
	return &AppRuntimeAnalysis{
		PackageName: packageName,
		Processes:   processes,
		MemoryUsage: memUsage,
		CPUUsage:    cpuUsage,
		Logs:        logs,
		Metadata:    make(map[string]interface{}),
	}, nil
}

func (a *AndroidAppAnalyzer) Name() string { return "AndroidAppAnalyzer" }
func (a *AndroidAppAnalyzer) Description() string {
	return "Analyzes Android APKs, manifests, and running apps for structure and vulnerabilities"
}

// Helpers
func parseMemUsage(output string) uint64 {
	re := regexp.MustCompile(`TOTAL\s+(\d+)`)
	match := re.FindStringSubmatch(output)
	if len(match) == 2 {
		return parseUint(match[1])
	}
	return 0
}

func parseCPUUsage(output, packageName string) float64 {
	re := regexp.MustCompile(packageName + `\s+(\d+\.\d+)\%`)
	match := re.FindStringSubmatch(output)
	if len(match) == 2 {
		return parseFloat(match[1])
	}
	return 0.0
}

func parseUint(s string) uint64 {
	var v uint64
	fmt.Sscanf(s, "%d", &v)
	return v
}

func parseFloat(s string) float64 {
	var v float64
	fmt.Sscanf(s, "%f", &v)
	return v
}
