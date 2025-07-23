/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: Akaylee.go
Description: Entry point for the Akaylee Fuzzer. Now uses the modular engine from pkg/core. No more standalone logic—just modular, extensible fuzzing!
*/

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"github.com/kleascm/akaylee-fuzzer/pkg/analysis"
	"github.com/kleascm/akaylee-fuzzer/pkg/core"
	"github.com/kleascm/akaylee-fuzzer/pkg/execution"
	"github.com/kleascm/akaylee-fuzzer/pkg/interfaces"
	"github.com/kleascm/akaylee-fuzzer/pkg/logging"
	"github.com/kleascm/akaylee-fuzzer/pkg/strategies"
)

// AdapterAPIExecutor wraps HTTPAPIExecutor to implement interfaces.Executor
// for the core engine.
type AdapterAPIExecutor struct {
	httpExec *execution.HTTPAPIExecutor
}

func NewAdapterAPIExecutor(httpExec *execution.HTTPAPIExecutor) *AdapterAPIExecutor {
	return &AdapterAPIExecutor{httpExec: httpExec}
}

func (a *AdapterAPIExecutor) Initialize(config *interfaces.FuzzerConfig) error {
	return nil // Already initialized
}

func (a *AdapterAPIExecutor) Execute(testCase *interfaces.TestCase) (*interfaces.ExecutionResult, error) {
	// Convert testCase.Data to APIRequest
	var req interfaces.APIRequest
	err := json.Unmarshal(testCase.Data, &req)
	if err != nil {
		return &interfaces.ExecutionResult{
			TestCaseID: testCase.ID,
			Status:     interfaces.StatusError,
			Error:      []byte("invalid APIRequest JSON"),
		}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	apiResult, err := a.httpExec.ExecuteAPIRequest(ctx, &req)
	if err != nil {
		return &interfaces.ExecutionResult{
			TestCaseID: testCase.ID,
			Status:     interfaces.StatusError,
			Error:      []byte(err.Error()),
		}, err
	}
	return apiResult.ExecutionResult, nil
}

func (a *AdapterAPIExecutor) Cleanup() error { return nil }
func (a *AdapterAPIExecutor) Reset() error   { return nil }

// Helper to convert interfaces.FuzzerConfig to core.FuzzerConfig
func toCoreFuzzerConfig(cfg *interfaces.FuzzerConfig) *core.FuzzerConfig {
	if cfg == nil {
		return nil
	}
	return &core.FuzzerConfig{
		Target:        cfg.Target,
		CorpusDir:     cfg.CorpusDir,
		OutputDir:     cfg.OutputDir,
		CrashDir:      cfg.CrashDir,
		Workers:       cfg.Workers,
		Timeout:       cfg.Timeout,
		MemoryLimit:   cfg.MemoryLimit,
		MaxCorpusSize: cfg.MaxCorpusSize,
		MutationRate:  cfg.MutationRate,
		MaxMutations:  cfg.MaxMutations,
		Strategy:      cfg.Strategy,
		CoverageType:  cfg.CoverageType,
		SchedulerType: cfg.SchedulerType,
		SessionID:     cfg.SessionID,
	}
}

func main() {
	fmt.Println("[Akaylee] Starting modular engine...")

	// Try to load API fuzz config if present
	apiConfigPath := "api_fuzz_config.json"
	if _, err := os.Stat(apiConfigPath); err == nil {
		fmt.Println("[Akaylee] Detected api_fuzz_config.json, running in API fuzzing mode!")
		apiConfigData, err := ioutil.ReadFile(apiConfigPath)
		if err != nil {
			panic(err)
		}
		var apiConfig map[string]interface{}
		if err := json.Unmarshal(apiConfigData, &apiConfig); err != nil {
			panic(err)
		}
		// Build APIFuzzerConfig
		apiFuzzerConfig := &interfaces.APIFuzzerConfig{
			FuzzerConfig: &interfaces.FuzzerConfig{
				CorpusDir: apiConfig["corpus_dir"].(string),
				OutputDir: apiConfig["output_dir"].(string),
				Workers:   int(apiConfig["workers"].(float64)),
			},
			ConcurrentRequests: int(apiConfig["concurrent_requests"].(float64)),
			RequestTimeout:     5 * time.Second,
			FollowRedirects:    apiConfig["follow_redirects"].(bool),
			VerifySSL:          apiConfig["verify_ssl"].(bool),
			UserAgent:          apiConfig["user_agent"].(string),
		}
		// Parse targets
		targets := apiConfig["targets"].([]interface{})
		for _, t := range targets {
			tmap := t.(map[string]interface{})
			target := &interfaces.APITarget{
				ID:      tmap["id"].(string),
				Name:    tmap["name"].(string),
				Type:    interfaces.APITargetType(tmap["type"].(string)),
				URL:     tmap["url"].(string),
				Method:  interfaces.HTTPMethod(tmap["method"].(string)),
				Headers: map[string]string{"Content-Type": "application/json"},
				Body:    []byte(tmap["body"].(string)),
				Timeout: 5 * time.Second,
			}
			apiFuzzerConfig.Targets = append(apiFuzzerConfig.Targets, target)
		}
		// Use API mutator
		loggerConfig := &logging.LoggerConfig{
			Level:     logging.LogLevelDebug,
			Format:    logging.LogFormatCustom,
			OutputDir: "./logs",
			MaxFiles:  10,
			MaxSize:   10 * 1024 * 1024,
			Timestamp: true,
			Caller:    false,
			Colors:    true,
			Compress:  false,
			Target:    apiFuzzerConfig.Targets[0].URL,
		}
		logger, err := logging.NewLogger(loggerConfig)
		if err != nil {
			panic(err)
		}
		defer logger.Close()
		apiMutator := strategies.NewAPIMutator(0.05, logger.GetLogger())
		mutator := core.NewAdapterMutator(apiMutator)
		httpExec := execution.NewHTTPAPIExecutor(apiFuzzerConfig, logger.GetLogger())
		executor := core.NewAdapterExecutor(NewAdapterAPIExecutor(httpExec))
		analyzer := core.NewAdapterAnalyzer(analysis.NewCoverageAnalyzer())
		engine := core.NewEngine()
		if err := engine.Initialize(toCoreFuzzerConfig(apiFuzzerConfig.FuzzerConfig), mutator, logger, executor, analyzer); err != nil {
			panic(err)
		}
		if err := engine.Start(); err != nil {
			panic(err)
		}
		time.Sleep(5 * time.Second)
		fmt.Println("[Akaylee] Stopping modular engine...")
		if err := engine.Stop(); err != nil {
			panic(err)
		}
		fmt.Printf("[Akaylee] Final stats: Executions=%d, Crashes=%d\n", engine.GetStats().Executions, engine.GetStats().Crashes)
		return
	}

	config := &core.FuzzerConfig{
		Target:        "TARGET/vulnscan",
		CorpusDir:     "TARGET/corpus/split",
		OutputDir:     "fuzz_output",
		MaxCorpusSize: 1000,
		Workers:       4,
	}
	// Create a BitFlipMutator with 1% mutation rate
	bitFlip := strategies.NewBitFlipMutator(0.01)
	mutator := core.NewAdapterMutator(bitFlip)
	// Create a logger
	loggerConfig := &logging.LoggerConfig{
		Level:     logging.LogLevelDebug,
		Format:    logging.LogFormatCustom,
		OutputDir: "./logs",
		MaxFiles:  10,
		MaxSize:   10 * 1024 * 1024, // 10MB
		Timestamp: true,
		Caller:    false,
		Colors:    true,
		Compress:  false,
		Target:    config.Target,
	}
	logger, err := logging.NewLogger(loggerConfig)
	if err != nil {
		panic(err)
	}
	defer logger.Close()
	// Create modular executor and analyzer
	executor := core.NewAdapterExecutor(execution.NewProcessExecutor())
	analyzer := core.NewAdapterAnalyzer(analysis.NewCoverageAnalyzer())
	engine := core.NewEngine()
	if err := engine.Initialize(config, mutator, logger, executor, analyzer); err != nil {
		panic(err)
	}
	if err := engine.Start(); err != nil {
		panic(err)
	}
	time.Sleep(5 * time.Second)
	fmt.Println("[Akaylee] Stopping modular engine...")
	if err := engine.Stop(); err != nil {
		panic(err)
	}
	fmt.Printf("[Akaylee] Final stats: Executions=%d, Crashes=%d\n", engine.GetStats().Executions, engine.GetStats().Crashes)
}
