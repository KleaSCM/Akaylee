/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: analyzer.go
Description: Production-level WebAnalyzer implementation. Detects XSS, DOM changes, JS errors,
and HTTP errors. Designed for extensibility and integration with web fuzzing engine.
*/

package web

import (
	"strings"
)

type SimpleWebAnalyzer struct {
	lastDOM string
}

func NewSimpleWebAnalyzer() *SimpleWebAnalyzer {
	return &SimpleWebAnalyzer{}
}

func (a *SimpleWebAnalyzer) AnalyzeResponse(dom string, logs []string, network []string) ([]string, error) {
	var bugs []string
	// XSS detection: look for <script>alert or known payloads
	if strings.Contains(dom, "<script>alert") {
		bugs = append(bugs, "Potential XSS: <script>alert found in DOM")
	}
	if strings.Contains(dom, "onerror=alert") {
		bugs = append(bugs, "Potential XSS: onerror=alert found in DOM")
	}
	// DOM diff detection
	if a.lastDOM != "" && dom != a.lastDOM {
		bugs = append(bugs, "DOM changed after mutation (possible bug or injection)")
	}
	a.lastDOM = dom
	// JS error detection
	for _, log := range logs {
		if strings.Contains(strings.ToLower(log), "error") {
			bugs = append(bugs, "JS error: "+log)
		}
	}
	// HTTP/network error detection
	for _, netlog := range network {
		if strings.Contains(strings.ToLower(netlog), "error") {
			bugs = append(bugs, "Network error: "+netlog)
		}
	}
	return bugs, nil
}

func (a *SimpleWebAnalyzer) Name() string { return "SimpleWebAnalyzer" }
func (a *SimpleWebAnalyzer) Description() string {
	return "Detects XSS, DOM changes, JS errors, and HTTP errors"
}
