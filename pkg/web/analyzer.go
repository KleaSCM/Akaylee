/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: analyzer.go
Description: AdvancedWebAnalyzer implementation. Provides deep XSS/injection detection, DOM diffing,
JS/console/network/HTTP analysis, and bug prioritization for production-level web fuzzing.
*/

package web

import (
	"regexp"
	"strings"
)

type AdvancedWebAnalyzer struct {
	lastDOM     string
	lastScripts map[string]struct{}
}

func NewAdvancedWebAnalyzer() *AdvancedWebAnalyzer {
	return &AdvancedWebAnalyzer{
		lastScripts: make(map[string]struct{}),
	}
}

func (a *AdvancedWebAnalyzer) AnalyzeResponse(dom string, logs []string, network []string) ([]string, error) {
	var bugs []string
	// --- XSS/Injection Detection ---
	if strings.Contains(dom, "<script>alert") || strings.Contains(dom, "onerror=alert") {
		bugs = append(bugs, "Potential XSS: <script>alert or onerror=alert found in DOM")
	}
	if strings.Contains(dom, "<svg/onload=") {
		bugs = append(bugs, "Potential XSS: <svg/onload found in DOM")
	}
	if strings.Contains(dom, "javascript:alert") {
		bugs = append(bugs, "Potential XSS: javascript:alert found in DOM")
	}
	if strings.Contains(dom, "file:///etc/passwd") || strings.Contains(dom, "../../etc/passwd") {
		bugs = append(bugs, "Potential Path Traversal/SSRF: suspicious file path in DOM")
	}
	// Error-based injection detection
	errPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)syntax error`),
		regexp.MustCompile(`(?i)sql syntax`),
		regexp.MustCompile(`(?i)unexpected token`),
		regexp.MustCompile(`(?i)exception`),
		regexp.MustCompile(`(?i)stack trace`),
	}
	for _, pat := range errPatterns {
		if pat.MatchString(dom) {
			bugs = append(bugs, "Potential Injection/Error: "+pat.String())
		}
	}
	// --- DOM Diffing ---
	if a.lastDOM != "" && dom != a.lastDOM {
		if domDiff(a.lastDOM, dom) {
			bugs = append(bugs, "DOM structure changed: possible injection or mutation")
		}
	}
	// Track scripts for stored/DOM-based XSS
	scripts := extractScripts(dom)
	for s := range scripts {
		if _, seen := a.lastScripts[s]; !seen {
			bugs = append(bugs, "New script tag detected: possible stored/DOM XSS")
		}
	}
	a.lastDOM = dom
	a.lastScripts = scripts
	// --- JS/Console Analysis ---
	for _, log := range logs {
		if strings.Contains(strings.ToLower(log), "error") {
			bugs = append(bugs, "JS error: "+log)
		}
		if strings.Contains(strings.ToLower(log), "csp") && strings.Contains(strings.ToLower(log), "bypass") {
			bugs = append(bugs, "Potential CSP bypass: "+log)
		}
		if strings.Contains(strings.ToLower(log), "eval") || strings.Contains(strings.ToLower(log), "function(") {
			bugs = append(bugs, "Suspicious JS usage: "+log)
		}
	}
	// --- Network/HTTP Analysis ---
	for _, netlog := range network {
		if strings.Contains(strings.ToLower(netlog), "error") {
			bugs = append(bugs, "Network error: "+netlog)
		}
		if strings.Contains(strings.ToLower(netlog), "302") || strings.Contains(strings.ToLower(netlog), "redirect") {
			bugs = append(bugs, "HTTP redirect detected: check for open redirect or auth bypass")
		}
		if strings.Contains(strings.ToLower(netlog), "401") || strings.Contains(strings.ToLower(netlog), "403") {
			bugs = append(bugs, "HTTP auth error: possible auth/csrf/session issue")
		}
	}
	// --- Heuristics for prioritization ---
	if len(bugs) > 0 {
		for i, bug := range bugs {
			if strings.Contains(strings.ToLower(bug), "xss") {
				bugs[i] = "[HIGH] " + bug
			} else if strings.Contains(strings.ToLower(bug), "error") {
				bugs[i] = "[MEDIUM] " + bug
			} else {
				bugs[i] = "[INFO] " + bug
			}
		}
	}
	return bugs, nil
}

func (a *AdvancedWebAnalyzer) Name() string { return "AdvancedWebAnalyzer" }
func (a *AdvancedWebAnalyzer) Description() string {
	return "Deep XSS/injection, DOM/JS/network/HTTP analysis, bug prioritization"
}

// domDiff: simple structural diff (can be replaced with a real diff lib)
func domDiff(oldDOM, newDOM string) bool {
	return len(oldDOM) != len(newDOM) || oldDOM != newDOM
}

func extractScripts(dom string) map[string]struct{} {
	scripts := make(map[string]struct{})
	for _, line := range strings.Split(dom, "<script") {
		if strings.Contains(line, ">") {
			parts := strings.SplitN(line, ">", 2)
			if len(parts) > 1 {
				content := strings.SplitN(parts[1], "</script>", 2)[0]
				if content != "" {
					scripts[content] = struct{}{}
				}
			}
		}
	}
	return scripts
}
