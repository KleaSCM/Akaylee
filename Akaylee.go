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
	"github.com/kleascm/akaylee-fuzzer/pkg/logging"
	"github.com/kleascm/akaylee-fuzzer/pkg/strategies"
)

func main() {
	fmt.Println("[Akaylee] Starting modular engine...")
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
	engine := core.NewEngine()
	if err := engine.Initialize(config, mutator, logger); err != nil {
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
