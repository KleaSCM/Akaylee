/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: engine_minimal.go
Description: Minimal, clean fuzzer engine core for Akaylee. Loads test cases, executes them, records results, writes a report, and shuts down cleanly. No deadlocks, no stuck workers, just results.
*/

package core

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/kleascm/akaylee-fuzzer/pkg/interfaces"
)

type MinimalEngine struct {
	config   *interfaces.FuzzerConfig
	executor interfaces.Executor
	results  []*interfaces.ExecutionResult
	mu       sync.Mutex
	ctx      context.Context
	cancel   context.CancelFunc
}

func NewMinimalEngine(config *interfaces.FuzzerConfig, executor interfaces.Executor) *MinimalEngine {
	ctx, cancel := context.WithCancel(context.Background())
	return &MinimalEngine{
		config:   config,
		executor: executor,
		results:  []*interfaces.ExecutionResult{},
		ctx:      ctx,
		cancel:   cancel,
	}
}

func (e *MinimalEngine) Run() error {
	fmt.Println("[MINIMAL] Starting minimal engine...")
	// Load test cases
	testCases, err := loadTestCases(e.config.CorpusDir)
	if err != nil {
		return fmt.Errorf("failed to load test cases: %w", err)
	}
	fmt.Printf("[MINIMAL] Loaded %d test cases\n", len(testCases))

	// Handle interrupt
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		fmt.Println("[MINIMAL] Received interrupt, shutting down...")
		e.cancel()
	}()

	// Execute test cases
	maxExec := e.config.MaxCorpusSize
	if maxExec <= 0 || maxExec > len(testCases) {
		maxExec = len(testCases)
	}
	for i, tc := range testCases[:maxExec] {
		select {
		case <-e.ctx.Done():
			fmt.Println("[MINIMAL] Shutdown requested, stopping execution loop.")
			break
		default:
		}
		fmt.Printf("[MINIMAL] Executing test case %d/%d: %s\n", i+1, maxExec, tc.ID)
		res, err := e.executor.Execute(tc)
		if err != nil {
			fmt.Printf("[MINIMAL] Error executing test case %s: %v\n", tc.ID, err)
		}
		e.mu.Lock()
		e.results = append(e.results, res)
		e.mu.Unlock()
	}

	// Write report
	return e.writeReport()
}

func (e *MinimalEngine) writeReport() error {
	fmt.Println("[MINIMAL] Writing report...")
	os.MkdirAll("./fuzz_output", 0755)
	reportFile := fmt.Sprintf("./fuzz_output/minimal_report_%s.json", time.Now().Format("2006-01-02_15-04-05"))
	report := map[string]interface{}{
		"executions": len(e.results),
		"results":    e.results,
	}
	f, err := os.Create(reportFile)
	if err != nil {
		return fmt.Errorf("failed to create report file: %w", err)
	}
	defer f.Close()
	if err := json.NewEncoder(f).Encode(report); err != nil {
		return fmt.Errorf("failed to write report: %w", err)
	}
	fmt.Printf("[MINIMAL] Report written: %s\n", reportFile)
	return nil
}

func loadTestCases(dir string) ([]*interfaces.TestCase, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*"))
	if err != nil {
		return nil, err
	}
	var cases []*interfaces.TestCase
	for _, file := range files {
		if info, err := os.Stat(file); err == nil && !info.IsDir() {
			data, err := os.ReadFile(file)
			if err != nil {
				continue
			}
			cases = append(cases, &interfaces.TestCase{
				ID:   filepath.Base(file),
				Data: data,
			})
		}
	}
	return cases, nil
}
