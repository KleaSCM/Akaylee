/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: fuzzer.go
Description: Production-level WebFuzzer implementation. Orchestrates crawling, mutation, and analysis
using the controller, mutator, and analyzer. Designed for extensibility and integration with the core engine.
*/

package web

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"time"
)

type BasicWebFuzzer struct {
	target     *WebTarget
	controller BrowserController
	mutator    WebMutator
	analyzer   WebAnalyzer
	running    int32
	lastStatus string
}

func NewBasicWebFuzzer() *BasicWebFuzzer {
	return &BasicWebFuzzer{}
}

func (w *BasicWebFuzzer) Configure(target *WebTarget, controller BrowserController, mutator WebMutator, analyzer WebAnalyzer) error {
	w.target = target
	w.controller = controller
	w.mutator = mutator
	w.analyzer = analyzer
	return nil
}

func (w *BasicWebFuzzer) Start(ctx context.Context) error {
	if !atomic.CompareAndSwapInt32(&w.running, 0, 1) {
		return fmt.Errorf("WebFuzzer already running")
	}
	go w.fuzzLoop(ctx)
	return nil
}

func (w *BasicWebFuzzer) Stop() error {
	atomic.StoreInt32(&w.running, 0)
	if w.controller != nil {
		w.controller.Stop()
	}
	return nil
}

func (w *BasicWebFuzzer) Status() string {
	return w.lastStatus
}

func (w *BasicWebFuzzer) fuzzLoop(ctx context.Context) {
	defer atomic.StoreInt32(&w.running, 0)
	if err := w.controller.Start(ctx); err != nil {
		w.lastStatus = "Failed to start browser: " + err.Error()
		return
	}
	defer w.controller.Stop()

	url := w.target.URL
	for atomic.LoadInt32(&w.running) == 1 {
		select {
		case <-ctx.Done():
			w.lastStatus = "Stopped by context"
			return
		default:
		}

		// Navigate to target
		if err := w.controller.Navigate(url); err != nil {
			w.lastStatus = "Navigation error: " + err.Error()
			time.Sleep(2 * time.Second)
			continue
		}

		// Get DOM
		dom, err := w.controller.GetDOM()
		if err != nil {
			w.lastStatus = "DOM error: " + err.Error()
			time.Sleep(2 * time.Second)
			continue
		}

		// Mutate DOM (optional)
		mutatedDOM := w.mutator.MutateDOM(dom)
		if mutatedDOM != dom {
			w.controller.ExecuteJS(fmt.Sprintf(`document.documentElement.innerHTML = %q;`, mutatedDOM))
		}

		// Find forms and mutate inputs (simple: look for <input name=...>)
		// In production, use chromedp to enumerate forms/inputs
		inputs := extractInputsFromDOM(dom)
		mutatedInputs := w.mutator.MutateInputs(inputs)
		if len(mutatedInputs) > 0 {
			w.controller.FillForm("form", mutatedInputs)
			w.controller.Click("form [type=submit],form button")
		}

		// JS mutation (optional)
		w.mutator.MutateJS("")

		// Wait for page to update
		time.Sleep(1 * time.Second)

		// Analyze response
		newDOM, _ := w.controller.GetDOM()
		logs, _ := w.controller.GetConsoleLogs()
		network, _ := w.controller.GetNetworkLogs()
		bugs, _ := w.analyzer.AnalyzeResponse(newDOM, logs, network)
		if len(bugs) > 0 {
			w.lastStatus = fmt.Sprintf("Bugs found: %s", strings.Join(bugs, "; "))
			fmt.Printf("[webfuzz] Bugs found: %s\n", strings.Join(bugs, "; "))
		} else {
			w.lastStatus = "No bugs found"
		}

		// Sleep before next iteration
		time.Sleep(2 * time.Second)
	}
}

// extractInputsFromDOM is a simple parser for <input name=... value=...>
// In production, use chromedp to enumerate inputs
func extractInputsFromDOM(dom string) map[string]string {
	inputs := make(map[string]string)
	for _, line := range strings.Split(dom, "<input") {
		if strings.Contains(line, "name=") {
			name := extractAttr(line, "name")
			value := extractAttr(line, "value")
			if name != "" {
				inputs[name] = value
			}
		}
	}
	return inputs
}

func extractAttr(s, attr string) string {
	idx := strings.Index(s, attr+"=")
	if idx == -1 {
		return ""
	}
	s = s[idx+len(attr)+1:]
	if len(s) == 0 {
		return ""
	}
	quote := s[0]
	s = s[1:]
	end := strings.IndexRune(s, rune(quote))
	if end == -1 {
		return ""
	}
	return s[:end]
}
