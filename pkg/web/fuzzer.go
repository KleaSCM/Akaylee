/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: fuzzer.go
Description: Provides full crawling, session handling, coverage tracking,
parallelism, and stateful corpus management for  web application fuzzing.
*/

package web

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type FuzzedState struct {
	URL      string
	DOMHash  string
	Inputs   map[string]string
	Response string
}

type AdvancedWebFuzzer struct {
	target     *WebTarget
	controller BrowserController
	mutator    WebMutator
	analyzer   WebAnalyzer

	// State
	running     int32
	lastStatus  string
	visitedURLs map[string]struct{}
	visitedDOMs map[string]struct{}
	queue       []string
	queueMu     sync.Mutex
	corpus      []*FuzzedState
	corpusMu    sync.Mutex
	MaxContexts int // Exported for CLI/config integration
}

func NewAdvancedWebFuzzer() *AdvancedWebFuzzer {
	return &AdvancedWebFuzzer{
		visitedURLs: make(map[string]struct{}),
		visitedDOMs: make(map[string]struct{}),
		queue:       []string{},
		MaxContexts: 2, // Parallel browser contexts
	}
}

func (w *AdvancedWebFuzzer) Configure(target *WebTarget, controller BrowserController, mutator WebMutator, analyzer WebAnalyzer) error {
	w.target = target
	w.controller = controller
	w.mutator = mutator
	w.analyzer = analyzer
	w.queue = append(w.queue, target.URL)
	return nil
}

func (w *AdvancedWebFuzzer) Start(ctx context.Context) error {
	if !atomic.CompareAndSwapInt32(&w.running, 0, 1) {
		return fmt.Errorf("WebFuzzer already running")
	}
	var wg sync.WaitGroup
	for i := 0; i < w.MaxContexts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w.fuzzLoop(ctx)
		}()
	}
	go func() { wg.Wait(); atomic.StoreInt32(&w.running, 0) }()
	return nil
}

func (w *AdvancedWebFuzzer) Stop() error {
	atomic.StoreInt32(&w.running, 0)
	if w.controller != nil {
		w.controller.Stop()
	}
	return nil
}

func (w *AdvancedWebFuzzer) Status() string {
	return w.lastStatus
}

func (w *AdvancedWebFuzzer) fuzzLoop(ctx context.Context) {
	if err := w.controller.Start(ctx); err != nil {
		w.lastStatus = "Failed to start browser: " + err.Error()
		return
	}
	defer w.controller.Stop()

	for atomic.LoadInt32(&w.running) == 1 {
		url := w.dequeueURL()
		if url == "" {
			time.Sleep(1 * time.Second)
			continue
		}
		if !w.inScope(url) {
			continue
		}
		if w.isVisitedURL(url) {
			continue
		}
		w.markVisitedURL(url)

		// Handle login/session if needed
		if w.target.AuthType != "" && w.target.LoginScript != "" {
			w.controller.ExecuteJS(w.target.LoginScript)
		}

		// Navigate to target
		if err := w.controller.Navigate(url); err != nil {
			w.lastStatus = "Navigation error: " + err.Error()
			continue
		}

		// Get DOM
		dom, err := w.controller.GetDOM()
		if err != nil {
			w.lastStatus = "DOM error: " + err.Error()
			continue
		}
		domHash := hashString(dom)
		if w.isVisitedDOM(domHash) {
			continue
		}
		w.markVisitedDOM(domHash)

		// Extract and enqueue links
		links := extractLinksFromDOM(dom)
		for _, link := range links {
			if w.inScope(link) && !w.isVisitedURL(link) {
				w.enqueueURL(link)
			}
		}

		// Extract and enqueue forms/buttons
		forms := extractFormsFromDOM(dom)
		for _, form := range forms {
			if !w.isVisitedURL(url + form) {
				w.enqueueURL(url + form)
			}
		}

		// Mutate DOM
		mutatedDOM := w.mutator.MutateDOM(dom)
		if mutatedDOM != dom {
			w.controller.ExecuteJS(fmt.Sprintf(`document.documentElement.innerHTML = %q;`, mutatedDOM))
		}

		// Mutate and submit forms
		inputs := extractInputsFromDOM(dom)
		mutatedInputs := w.mutator.MutateInputs(inputs)
		if len(mutatedInputs) > 0 {
			w.controller.FillForm("form", mutatedInputs)
			w.controller.Click("form [type=submit],form button")
		}

		// JS mutation
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
			w.saveCorpus(url, domHash, mutatedInputs, newDOM)
		} else {
			w.lastStatus = "No bugs found"
		}
	}
}

// --- Queue and Coverage Management ---
func (w *AdvancedWebFuzzer) enqueueURL(url string) {
	w.queueMu.Lock()
	w.queue = append(w.queue, url)
	w.queueMu.Unlock()
}

func (w *AdvancedWebFuzzer) dequeueURL() string {
	w.queueMu.Lock()
	defer w.queueMu.Unlock()
	if len(w.queue) == 0 {
		return ""
	}
	url := w.queue[0]
	w.queue = w.queue[1:]
	return url
}

func (w *AdvancedWebFuzzer) isVisitedURL(url string) bool {
	w.queueMu.Lock()
	defer w.queueMu.Unlock()
	_, ok := w.visitedURLs[url]
	return ok
}

func (w *AdvancedWebFuzzer) markVisitedURL(url string) {
	w.queueMu.Lock()
	w.visitedURLs[url] = struct{}{}
	w.queueMu.Unlock()
}

func (w *AdvancedWebFuzzer) isVisitedDOM(hash string) bool {
	w.queueMu.Lock()
	defer w.queueMu.Unlock()
	_, ok := w.visitedDOMs[hash]
	return ok
}

func (w *AdvancedWebFuzzer) markVisitedDOM(hash string) {
	w.queueMu.Lock()
	w.visitedDOMs[hash] = struct{}{}
	w.queueMu.Unlock()
}

func (w *AdvancedWebFuzzer) inScope(url string) bool {
	if len(w.target.Scope) == 0 {
		return true
	}
	for _, scope := range w.target.Scope {
		if strings.Contains(url, scope) {
			return true
		}
	}
	return false
}

func (w *AdvancedWebFuzzer) saveCorpus(url, domHash string, inputs map[string]string, response string) {
	w.corpusMu.Lock()
	w.corpus = append(w.corpus, &FuzzedState{
		URL:      url,
		DOMHash:  domHash,
		Inputs:   inputs,
		Response: response,
	})
	w.corpusMu.Unlock()
}

// --- DOM Extraction Helpers ---
func extractLinksFromDOM(dom string) []string {
	var links []string
	for _, line := range strings.Split(dom, "<a ") {
		if strings.Contains(line, "href=") {
			href := extractAttr(line, "href")
			if href != "" && !strings.HasPrefix(href, "#") && !strings.HasPrefix(href, "javascript:") {
				links = append(links, href)
			}
		}
	}
	return links
}

func extractFormsFromDOM(dom string) []string {
	var forms []string
	for _, line := range strings.Split(dom, "<form") {
		if strings.Contains(line, "action=") {
			action := extractAttr(line, "action")
			if action != "" {
				forms = append(forms, action)
			}
		}
	}
	return forms
}

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

func hashString(s string) string {
	// Simple hash for DOM deduplication
	var h uint64
	for i := 0; i < len(s); i++ {
		h = h*31 + uint64(s[i])
	}
	return fmt.Sprintf("%x", h)
}
