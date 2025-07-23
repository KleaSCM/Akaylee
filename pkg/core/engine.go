/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: engine.go
Description: Minimal modular engine implementation for the Akaylee Fuzzer. Implements the FuzzerEngine interface using the core types (corpus, worker, queue, etc). Provides Initialize, Start, Stop, and GetStats methods for integration with the main fuzzer entrypoint. Modular, extensible, and ready for further expansion.
*/

package core

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/kleascm/akaylee-fuzzer/pkg/logging"
)

// Engine is a minimal implementation of the FuzzerEngine interface
// Wires up the corpus, queue, and a single worker for now
// Modular and ready for further expansion
type Engine struct {
	config        *FuzzerConfig
	corpus        *Corpus
	queue         *PriorityQueue
	worker        *Worker
	stats         *FuzzerStats
	stopCh        chan struct{}
	wg            sync.WaitGroup
	started       bool
	reportOnce    sync.Once
	reportResults *[]map[string]interface{}
	mutator       Mutator
	logger        *logging.Logger
}

// NewEngine creates a new modular engine instance
func NewEngine() *Engine {
	return &Engine{
		stopCh: make(chan struct{}),
		stats:  &FuzzerStats{StartTime: time.Now()},
	}
}

// Initialize sets up the engine with the given configuration
func (e *Engine) Initialize(config *FuzzerConfig, mutator Mutator, logger *logging.Logger) error {
	e.config = config
	e.corpus = NewCorpus(config.MaxCorpusSize)
	e.queue = NewPriorityQueue()
	e.mutator = mutator
	e.logger = logger
	// For now, create a dummy worker (no executor/analyzer yet)
	e.worker = nil // Will be set in Start when executor/analyzer are available
	return nil
}

func (e *Engine) writeReports() {
	if e.reportResults == nil {
		fmt.Printf("[Engine] writeReports() called but reportResults is nil!\n")
		return
	}
	results := *e.reportResults
	fmt.Printf("[Engine] writeReports() called (guaranteed once). Results: %d\n", len(results))
	timestamp := time.Now().Format("2006-01-02_15-04-05")
	os.MkdirAll(e.config.OutputDir, 0755)
	jsonPath := filepath.Join(e.config.OutputDir, fmt.Sprintf("modular_fuzz_report_%s.json", timestamp))
	fmt.Printf("[Engine] Attempting to write JSON report: %s\n", jsonPath)
	jsonData, _ := json.MarshalIndent(results, "", "  ")
	err := os.WriteFile(jsonPath, jsonData, 0644)
	if err != nil {
		fmt.Printf("[Engine] Error writing JSON report: %v\n", err)
	} else {
		fmt.Printf("[Engine] JSON report written: %s\n", jsonPath)
	}
	htmlPath := filepath.Join(e.config.OutputDir, fmt.Sprintf("modular_fuzz_report_%s.html", timestamp))
	fmt.Printf("[Engine] Attempting to write HTML report: %s\n", htmlPath)
	f, err := os.Create(htmlPath)
	if err != nil {
		fmt.Printf("[Engine] Error creating HTML report: %v\n", err)
	} else {
		defer f.Close()
		f.WriteString("<html><head><title>Akaylee Modular Fuzz Report</title><style>body{font-family:sans-serif;}table{border-collapse:collapse;}th,td{border:1px solid #ccc;padding:4px;}th{background:#eee;}tr.crash{background:#fdd;}tr.ok{background:#dfd;}</style></head><body>")
		f.WriteString("<h1>Akaylee Modular Fuzz Report</h1><table><tr><th>Test Case</th><th>Status</th><th>Duration</th><th>Error</th><th>Output</th></tr>")
		for _, r := range results {
			rowClass := r["status"].(string)
			f.WriteString(fmt.Sprintf("<tr class='%s'><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td><pre>%s</pre></td></tr>", rowClass, r["test_case"], r["status"], r["duration"], r["error"], htmlEscape(r["output"].(string))))
		}
		f.WriteString("</table></body></html>")
		fmt.Printf("[Engine] HTML report written: %s\n", htmlPath)
	}
}

// Start begins the fuzzing process (now with real execution loop)
func (e *Engine) Start() error {
	if e.started {
		return fmt.Errorf("engine already started")
	}
	e.started = true
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		var results []map[string]interface{}
		e.reportResults = &results
		defer func() {
			e.reportOnce.Do(func() {
				fmt.Printf("[Engine] writeReports() called from goroutine defer\n")
				e.writeReports()
			})
		}()
		files, _ := ioutil.ReadDir(e.config.CorpusDir)
		for _, file := range files {
			if file.IsDir() {
				continue
			}
			path := e.config.CorpusDir + "/" + file.Name()
			data, err := ioutil.ReadFile(path)
			if err != nil {
				continue
			}
			// Mutate the test case before execution
			orig := &TestCase{
				ID:         file.Name(),
				Data:       data,
				ParentID:   "",
				Generation: 0,
				CreatedAt:  time.Now(),
				Priority:   100,
				Metadata:   make(map[string]interface{}),
			}
			mutated := orig
			if e.mutator != nil {
				m, err := e.mutator.Mutate(orig)
				if err == nil && m != nil {
					fmt.Printf("[Engine] Mutated test case %s using %s\n", orig.ID, e.mutator.Name())
					if e.logger != nil {
						e.logger.LogMutation(orig.ID, m.ID, e.mutator.Name(), nil)
					}
					mutated = m
				} else {
					fmt.Printf("[Engine] Mutation failed for %s: %v\n", orig.ID, err)
				}
			}
			cmd := exec.Command(e.config.Target, "--fuzz")
			cmd.Stdin = bytes.NewReader(mutated.Data)
			start := time.Now()
			out, err := cmd.CombinedOutput()
			dur := time.Since(start)
			status := "ok"
			if err != nil {
				status = "crash"
				e.stats.Crashes++
				if e.logger != nil {
					e.logger.LogCrash(mutated.ID, "process error", map[string]interface{}{
						"error": fmt.Sprintf("%v", err),
					})
				}
			}
			e.stats.Executions++
			if e.logger != nil {
				e.logger.LogExecution(mutated.ID, dur, status, map[string]interface{}{
					"output": string(out),
					"error":  fmt.Sprintf("%v", err),
				})
			}
			fmt.Printf("[Engine] Test: %s | Status: %s | Duration: %s\nOutput: %s\n", mutated.ID, status, dur, string(out))
			results = append(results, map[string]interface{}{
				"test_case": mutated.ID,
				"status":    status,
				"duration":  dur.String(),
				"output":    string(out),
				"error":     fmt.Sprintf("%v", err),
			})
			time.Sleep(100 * time.Millisecond)
			select {
			case <-e.stopCh:
				return
			default:
			}
		}
		// At the end of the goroutine, log stats
		if e.logger != nil {
			e.logger.LogStats(e.stats.Executions, e.stats.Crashes, 0, float64(e.stats.Executions)/float64(time.Since(e.stats.StartTime).Seconds()), nil)
		}
	}()
	return nil
}

// Stop gracefully stops the engine
func (e *Engine) Stop() error {
	if !e.started {
		return fmt.Errorf("engine not started")
	}
	close(e.stopCh)
	e.wg.Wait()
	e.reportOnce.Do(func() {
		fmt.Printf("[Engine] writeReports() called from Stop()\n")
		e.writeReports()
	})
	e.started = false
	return nil
}

// GetStats returns the current fuzzer statistics
func (e *Engine) GetStats() *FuzzerStats {
	return e.stats
}

func htmlEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	s = strings.ReplaceAll(s, "'", "&#39;")
	return s
}
