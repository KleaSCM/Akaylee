/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: analyzer.go
Description: Uses goquery for real DOM parsing and diffing,
correlates JS/console/network events for deep bug detection, and applies advanced heuristics for bug prioritization.
*/

package web

import (
	"fmt"
	"strings"

	"github.com/PuerkitoBio/goquery"
)

type AdvancedWebAnalyzer struct {
	lastDOM     string
	lastScripts map[string]struct{}
	lastDoc     *goquery.Document
}

func NewAdvancedWebAnalyzer() *AdvancedWebAnalyzer {
	return &AdvancedWebAnalyzer{
		lastScripts: make(map[string]struct{}),
	}
}

// AnalyzeResponse uses goquery for DOM parsing/diffing and correlates JS/console/network events
func (a *AdvancedWebAnalyzer) AnalyzeResponse(dom string, logs []string, network []string) ([]string, error) {
	var bugs []string
	// --- Parse DOM with goquery ---
	d, err := goquery.NewDocumentFromReader(strings.NewReader(dom))
	if err != nil {
		return []string{fmt.Sprintf("[ERROR] Failed to parse DOM: %v", err)}, nil
	}

	// --- XSS/Injection Detection ---
	d.Find("script").Each(func(i int, s *goquery.Selection) {
		code := s.Text()
		if strings.Contains(code, "alert") {
			bugs = append(bugs, "Potential XSS: <script>alert found in DOM")
		}
		if _, seen := a.lastScripts[code]; !seen && code != "" {
			bugs = append(bugs, "New script tag detected: possible stored/DOM XSS")
		}
	})
	d.Find("img,svg,iframe").Each(func(i int, s *goquery.Selection) {
		for _, attr := range []string{"onerror", "onload"} {
			if v, exists := s.Attr(attr); exists && strings.Contains(v, "alert") {
				bugs = append(bugs, fmt.Sprintf("Potential XSS: %s=%q found", attr, v))
			}
		}
	})
	d.Find("a,form,input").Each(func(i int, s *goquery.Selection) {
		for _, attr := range []string{"href", "action", "value"} {
			if v, exists := s.Attr(attr); exists && (strings.Contains(v, "javascript:alert") || strings.Contains(v, "file:///etc/passwd") || strings.Contains(v, "../../etc/passwd")) {
				bugs = append(bugs, fmt.Sprintf("Potential Injection/Traversal: %s=%q", attr, v))
			}
		}
	})

	// --- DOM Diffing (structural/semantic) ---
	if a.lastDoc != nil {
		if domStructuralDiff(a.lastDoc, d) {
			bugs = append(bugs, "DOM structure changed: possible injection or mutation")
		}
	}
	a.lastDoc = d

	// Track scripts for stored/DOM-based XSS
	a.lastScripts = extractScriptsGoquery(d)

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
	return "Deep XSS/injection, DOM/JS/network/HTTP analysis, bug prioritization using real DOM parsing"
}

// domStructuralDiff: basic structural diff using goquery (can be replaced with a real diff lib)
func domStructuralDiff(oldDoc, newDoc *goquery.Document) bool {
	return oldDoc.Find("*").Length() != newDoc.Find("*").Length()
}

func extractScriptsGoquery(doc *goquery.Document) map[string]struct{} {
	scripts := make(map[string]struct{})
	doc.Find("script").Each(func(i int, s *goquery.Selection) {
		code := s.Text()
		if code != "" {
			scripts[code] = struct{}{}
		}
	})
	return scripts
}
