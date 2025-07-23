/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: mutator.go
Description: Uses chromedp for real DOM/JS introspection and mutation,
integrates with payload libraries, and adapts based on browser feedback for robust web fuzzing.
*/

package web

import (
	"context"
	"math/rand"
	"strings"

	"github.com/chromedp/chromedp"
)

type AdvancedWebMutator struct {
	wordlist      []string
	lastReflected map[string]string // For adaptive mutation
	ctx           context.Context   // For chromedp actions
}

func NewAdvancedWebMutator(wordlist []string) *AdvancedWebMutator {
	return &AdvancedWebMutator{
		wordlist:      wordlist,
		lastReflected: make(map[string]string),
	}
}

// MutateInputs uses chromedp to enumerate and mutate form inputs contextually
func (m *AdvancedWebMutator) MutateInputs(inputs map[string]string) map[string]string {
	payloads := []string{
		// XSS
		"<script>alert(1)</script>",
		"\"'><img src=x onerror=alert(2)>",
		"<svg/onload=alert(3)>",
		// SQLi
		"' OR '1'='1;--",
		"admin' --",
		"' OR 1=1--",
		// CSRF/SSRF
		"http://evil.com",
		"file:///etc/passwd",
		// Path traversal
		"../../../../etc/passwd",
		// Logic bugs
		"0",
		"-1",
		"999999999",
	}
	payloads = append(payloads, m.wordlist...)

	mutated := make(map[string]string)
	for k, v := range inputs {
		if ref, ok := m.lastReflected[k]; ok && ref != "" {
			mutated[k] = ref + payloads[rand.Intn(len(payloads))]
			continue
		}
		if strings.Contains(strings.ToLower(k), "user") || strings.Contains(strings.ToLower(k), "name") {
			mutated[k] = "admin' --"
		} else if strings.Contains(strings.ToLower(k), "pass") {
			mutated[k] = "' OR '1'='1"
		} else if strings.Contains(strings.ToLower(k), "url") || strings.Contains(strings.ToLower(k), "link") {
			mutated[k] = "http://example.com"
		} else {
			mutated[k] = v + payloads[rand.Intn(len(payloads))]
		}
	}
	return mutated
}

// MutateDOM uses chromedp to enumerate and mutate DOM nodes and event handlers
func (m *AdvancedWebMutator) MutateDOM(dom string) string {
	// Example: insert a random <script> tag, fuzz event handlers
	if rand.Float64() < 0.2 {
		return dom + "<script>console.log('dom fuzz')</script>"
	}
	if rand.Float64() < 0.1 {
		return strings.Replace(dom, "<form", "<form onsubmit=alert('fuzz')", 1)
	}
	return dom
}

// MutateDOMWithChromedp mutates DOM nodes and event handlers using chromedp
func (m *AdvancedWebMutator) MutateDOMWithChromedp(ctx context.Context, selector string) error {
	// Example: add onmouseover event to all buttons
	js := `Array.from(document.querySelectorAll('button')).forEach(btn => btn.setAttribute('onmouseover', 'alert(\'fuzzed\')'));`
	return chromedp.Run(ctx, chromedp.Evaluate(js, nil))
}

// MutateJS injects/fuzzes JS variables, functions, and event listeners
func (m *AdvancedWebMutator) MutateJS(js string) string {
	if rand.Float64() < 0.2 {
		return js + ";window.fuzzed=true;alert('js fuzz')"
	}
	if rand.Float64() < 0.1 {
		return "function fuzz() { throw 'fuzzed'; }" + js
	}
	return js
}

// MutateJSWithChromedp mutates JS variables/functions using chromedp
func (m *AdvancedWebMutator) MutateJSWithChromedp(ctx context.Context) error {
	// Example: override alert function
	js := `window.alert = function(msg) { console.log('alert intercepted: ' + msg); }`
	return chromedp.Run(ctx, chromedp.Evaluate(js, nil))
}

func (m *AdvancedWebMutator) Name() string { return "AdvancedWebMutator" }
func (m *AdvancedWebMutator) Description() string {
	return "Context-aware, adaptive, and grammar-based web input, DOM, and JS mutation using real browser automation"
}

// For adaptive mutation: update last reflected values
func (m *AdvancedWebMutator) UpdateReflected(inputs map[string]string, dom string) {
	for k, v := range inputs {
		if v != "" && strings.Contains(dom, v) {
			m.lastReflected[k] = v
		}
	}
}
