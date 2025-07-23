/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: crash_reporter.go
Description: Production-level AndroidCrashReporter. Implements CrashReporter interface for collecting
and reporting Android crashes, ANRs, and security issues by parsing adb logcat output with regex-based
detection. Robust, production-level crash triage and reporting.
*/

package mobile

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// AndroidCrashReporter implements CrashReporter for Android
type AndroidCrashReporter struct{}

func NewAndroidCrashReporter() *AndroidCrashReporter {
	return &AndroidCrashReporter{}
}

func (r *AndroidCrashReporter) CollectCrashes(packageName string) ([]*CrashReport, error) {
	cmd := exec.Command("adb", "logcat", "-d")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("logcat failed: %v", err)
	}
	crashRegex := regexp.MustCompile(`FATAL EXCEPTION|ANR in|SecurityException|Process \d+ terminated|java\.lang\.[A-Za-z]+Exception`)
	timeRegex := regexp.MustCompile(`^(\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})`)
	var reports []*CrashReport
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	var current *CrashReport
	for scanner.Scan() {
		line := scanner.Text()
		if crashRegex.MatchString(line) && strings.Contains(line, packageName) {
			if current != nil {
				reports = append(reports, current)
			}
			current = &CrashReport{
				PackageName: packageName,
				Type:        "crash",
				Logs:        []string{line},
				Metadata:    make(map[string]interface{}),
			}
			if m := timeRegex.FindStringSubmatch(line); len(m) == 2 {
				if t, err := time.Parse("01-02 15:04:05.000", m[1]); err == nil {
					current.Timestamp = t
				}
			}
			current.Message = line
		} else if current != nil {
			current.Logs = append(current.Logs, line)
			if strings.Contains(line, "at ") {
				current.StackTrace += line + "\n"
			}
		}
	}
	if current != nil {
		reports = append(reports, current)
	}
	return reports, nil
}

func (r *AndroidCrashReporter) ReportCrash(crash *CrashReport) error {
	// Output crash report to file (timestamped)
	filename := fmt.Sprintf("crash_%s_%d.txt", crash.PackageName, time.Now().UnixNano())
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()
	fmt.Fprintf(f, "Crash Report for %s\n", crash.PackageName)
	fmt.Fprintf(f, "Timestamp: %v\n", crash.Timestamp)
	fmt.Fprintf(f, "Type: %s\n", crash.Type)
	fmt.Fprintf(f, "Message: %s\n", crash.Message)
	fmt.Fprintf(f, "StackTrace:\n%s\n", crash.StackTrace)
	fmt.Fprintf(f, "Logs:\n")
	for _, l := range crash.Logs {
		fmt.Fprintln(f, l)
	}
	return nil
}

func (r *AndroidCrashReporter) Name() string { return "AndroidCrashReporter" }
func (r *AndroidCrashReporter) Description() string {
	return "Collects and reports Android crashes, ANRs, and security issues by parsing logcat output."
}
