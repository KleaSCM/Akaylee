/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: Akaylee.go
Description: Entry point for the Akaylee Fuzzer. Now uses the modular engine from pkg/core. No more standalone logic—just modular, extensible fuzzing!
*/

package main

import (
	"fmt"
	"time"

	"github.com/kleascm/akaylee-fuzzer/pkg/core"
)

func main() {
	config := &core.FuzzerConfig{
		Target:        "TARGET/vulnscan",
		CorpusDir:     "TARGET/corpus/split",
		OutputDir:     "./fuzz_output",
		CrashDir:      "./crashes",
		Workers:       1,
		Timeout:       5 * time.Second,
		MemoryLimit:   256 * 1024 * 1024, // 256MB
		MaxCorpusSize: 10000,
		MutationRate:  0.01,
		MaxMutations:  5,
		Strategy:      "mutation",
		CoverageType:  "edge",
		SchedulerType: "priority",
		SessionID:     "standalone-test",
	}
	engine := core.NewEngine()
	if err := engine.Initialize(config); err != nil {
		panic(err)
	}
	fmt.Println("[Akaylee] Starting modular engine...")
	if err := engine.Start(); err != nil {
		panic(err)
	}
	// Let it run for 5 seconds as a demo
	time.Sleep(5 * time.Second)
	fmt.Println("[Akaylee] Stopping modular engine...")
	if err := engine.Stop(); err != nil {
		panic(err)
	}
	stats := engine.GetStats()
	fmt.Printf("[Akaylee] Final stats: Executions=%d, Crashes=%d\n", stats.Executions, stats.Crashes)
}
