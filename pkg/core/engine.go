/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: engine.go
Description: Minimal modular engine implementation for the Akaylee Fuzzer. Implements the FuzzerEngine interface using the core types (corpus, worker, queue, etc). Provides Initialize, Start, Stop, and GetStats methods for integration with the main fuzzer entrypoint. Modular, extensible, and ready for further expansion.
*/

package core

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
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
	workers       []*Worker
	stats         *FuzzerStats
	stopCh        chan struct{}
	wg            sync.WaitGroup
	started       bool
	reportOnce    sync.Once
	reportResults *[]map[string]interface{}
	mutator       Mutator
	logger        *logging.Logger
	executor      Executor
	analyzer      Analyzer
}

// NewEngine creates a new modular engine instance
func NewEngine() *Engine {
	return &Engine{
		stopCh: make(chan struct{}),
		stats:  &FuzzerStats{StartTime: time.Now()},
	}
}

// Initialize sets up the engine with the given configuration
func (e *Engine) Initialize(config *FuzzerConfig, mutator Mutator, logger *logging.Logger, executor Executor, analyzer Analyzer) error {
	e.config = config
	e.corpus = NewCorpus(config.MaxCorpusSize)
	e.queue = NewPriorityQueue()
	e.mutator = mutator
	e.logger = logger
	e.executor = executor
	e.analyzer = analyzer
	e.worker = nil // Will be set in Start
	if e.executor != nil {
		if err := e.executor.Initialize(config); err != nil {
			return fmt.Errorf("executor initialization failed: %w", err)
		}
	}
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
		total := len(results)
		crashes := 0
		hangs := 0
		for _, r := range results {
			if r["status"] == "crash" {
				crashes++
			}
			if r["status"] == "hang" {
				hangs++
			}
		}
		f.WriteString(`<html><head><title>Akaylee Modular Fuzz Report</title><style>
body{font-family:sans-serif;background:#fafbfc;}
table{border-collapse:collapse;width:100%;margin-top:1em;}
th,td{border:1px solid #ccc;padding:6px 8px;}
th{background:#eee;position:sticky;top:0;z-index:2;}
tr:nth-child(even){background:#f6f8fa;}
tr:nth-child(odd){background:#fff;}
tr.crash{background:#ffeaea;}
tr.hang{background:#fffbe6;}
tr.ok{background:#eaffea;}
.mono{font-family:monospace;font-size:0.95em;white-space:pre-wrap;word-break:break-all;}
.summary{margin-top:1em;margin-bottom:1em;padding:1em;background:#e0e7ff;border-radius:8px;}
@media (max-width: 800px) { th,td{font-size:0.95em;padding:4px;} }
</style></head><body>`)
		f.WriteString(`<h1>Akaylee Modular Fuzz Report</h1>`)
		f.WriteString(fmt.Sprintf(`<div class='summary'><b>Total:</b> %d &nbsp; <b>Crashes:</b> %d &nbsp; <b>Hangs:</b> %d</div>`, total, crashes, hangs))
		f.WriteString(`<table><tr><th>Test Case</th><th>Status</th><th>Duration</th><th>Error</th><th>Output</th></tr>`)
		for _, r := range results {
			rowClass := r["status"].(string)
			errStr := r["error"].(string)
			if errStr == "<nil>" || errStr == "" {
				errStr = "—"
			}
			outputStr := htmlEscape(r["output"].(string))
			if len(outputStr) > 120 {
				outputStr = fmt.Sprintf(`<details><summary>Show (%d chars)</summary><div class='mono'>%s</div></details>`, len(r["output"].(string)), outputStr)
			} else {
				outputStr = fmt.Sprintf(`<div class='mono'>%s</div>`, outputStr)
			}
			errHtml := htmlEscape(errStr)
			if len(errStr) > 80 {
				errHtml = fmt.Sprintf(`<details><summary>Show (%d chars)</summary><div class='mono'>%s</div></details>`, len(errStr), errHtml)
			} else {
				errHtml = fmt.Sprintf(`<div class='mono'>%s</div>`, errHtml)
			}
			f.WriteString(fmt.Sprintf(`<tr class='%s'><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>`, rowClass, r["test_case"], r["status"], r["duration"], errHtml, outputStr))
		}
		f.WriteString(`</table></body></html>`)
		fmt.Printf("[Engine] HTML report written: %s\n", htmlPath)
	}
}

// Start begins the fuzzing process (now with real execution loop)
func (e *Engine) Start() error {
	if e.started {
		return fmt.Errorf("engine already started")
	}
	e.started = true
	workerCount := e.config.Workers
	if workerCount <= 0 {
		workerCount = 1
	}
	e.workers = make([]*Worker, workerCount)
	// Load corpus into queue
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
		orig := &TestCase{
			ID:         file.Name(),
			Data:       data,
			ParentID:   "",
			Generation: 0,
			CreatedAt:  time.Now(),
			Priority:   100,
			Metadata:   make(map[string]interface{}),
		}
		e.queue.Put(orig)
	}
	var resultsMu sync.Mutex
	var results []map[string]interface{}
	e.reportResults = &results
	e.stopCh = make(chan struct{})
	e.wg.Add(workerCount)
	for i := 0; i < workerCount; i++ {
		go func(workerID int) {
			defer e.wg.Done()
			for {
				select {
				case <-e.stopCh:
					return
				default:
				}
				tc := e.queue.Get()
				if tc == nil {
					time.Sleep(50 * time.Millisecond)
					continue
				}
				mutated := tc
				if e.mutator != nil {
					m, err := e.mutator.Mutate(tc)
					if err == nil && m != nil {
						if e.logger != nil {
							e.logger.LogMutation(tc.ID, m.ID, e.mutator.Name(), nil)
						}
						mutated = m
						// Re-queue mutated test case for further mutation, up to generation 5
						if mutated.Generation < 5 {
							e.queue.Put(mutated)
						}
					}
				}
				// Use modular executor and analyzer
				var execResult *ExecutionResult
				var err error
				if e.executor != nil {
					execResult, err = e.executor.Execute(mutated)
				} else {
					err = fmt.Errorf("no executor configured")
				}
				dur := time.Duration(0)
				status := "ok"
				out := []byte{}
				if execResult != nil {
					dur = execResult.Duration
					out = execResult.Output
				}
				if err != nil {
					status = "crash"
					if e.logger != nil {
						e.logger.LogCrash(mutated.ID, "process error", map[string]interface{}{
							"error": fmt.Sprintf("%v", err),
						})
					}
				}
				if e.logger != nil {
					e.logger.LogExecution(mutated.ID, dur, status, map[string]interface{}{
						"output": string(out),
						"error":  fmt.Sprintf("%v", err),
					})
				}
				// Analyze result if analyzer is present
				if e.analyzer != nil && execResult != nil {
					_ = e.analyzer.Analyze(execResult)
					// Optionally: detect crash/hang, update stats
				}
				resultsMu.Lock()
				results = append(results, map[string]interface{}{
					"test_case": mutated.ID,
					"status":    status,
					"duration":  dur.String(),
					"output":    string(out),
					"error":     fmt.Sprintf("%v", err),
				})
				resultsMu.Unlock()
				e.stats.Executions++
				if status == "crash" {
					e.stats.Crashes++
				}
			}
		}(i)
	}
	go func() {
		e.wg.Wait()
		e.reportOnce.Do(func() {
			e.writeReports()
		})
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
