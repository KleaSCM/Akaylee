/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: expansion.go
Description: Core logic for seed corpus auto-expansion. Defines the ExpansionSource interface,
connectors for real-world data, and the ExpansionManager for orchestrating expansion events.
Provides , extensible architecture for integrating new data sources.
*/

package expansion

import (
	"context"
	"time"
)

// ExpansionSource defines an interface for real-world data connectors
// Each source can fetch new seeds for the corpus
// Example sources: public datasets, web APIs, repo mining, etc.
type ExpansionSource interface {
	Name() string
	Description() string
	FetchSeeds(ctx context.Context) ([][]byte, error)
}

// ExpansionManager orchestrates all expansion sources and manages deduplication
// Periodically fetches new seeds and integrates them into the corpus
// Provides logging, metrics, and error handling for all expansion events
type ExpansionManager struct {
	sources   []ExpansionSource
	interval  time.Duration
	lastRun   time.Time
	metrics   *ExpansionMetrics
	callbacks []func([][]byte)
	ctx       context.Context
	cancel    context.CancelFunc
	running   bool
}

// ExpansionMetrics tracks expansion events and statistics
type ExpansionMetrics struct {
	TotalSeedsFetched int
	TotalRuns         int
	Errors            int
	LastError         string
	LastRun           time.Time
}

// NewExpansionManager creates a new ExpansionManager with the given sources and interval
func NewExpansionManager(sources []ExpansionSource, interval time.Duration) *ExpansionManager {
	ctx, cancel := context.WithCancel(context.Background())
	return &ExpansionManager{
		sources:  sources,
		interval: interval,
		metrics:  &ExpansionMetrics{},
		ctx:      ctx,
		cancel:   cancel,
	}
}

// Start begins periodic expansion
func (em *ExpansionManager) Start() {
	em.running = true
	go em.run()
}

// Stop halts expansion
func (em *ExpansionManager) Stop() {
	em.running = false
	em.cancel()
}

// RegisterCallback allows the engine to receive new seeds as they are fetched
func (em *ExpansionManager) RegisterCallback(cb func([][]byte)) {
	em.callbacks = append(em.callbacks, cb)
}

// run is the main expansion loop
func (em *ExpansionManager) run() {
	ticker := time.NewTicker(em.interval)
	defer ticker.Stop()
	for {
		select {
		case <-em.ctx.Done():
			return
		case <-ticker.C:
			em.performExpansion()
		}
	}
}

// performExpansion fetches seeds from all sources and invokes callbacks
func (em *ExpansionManager) performExpansion() {
	em.metrics.TotalRuns++
	em.metrics.LastRun = time.Now()
	var allSeeds [][]byte
	for _, src := range em.sources {
		seeds, err := src.FetchSeeds(em.ctx)
		if err != nil {
			em.metrics.Errors++
			em.metrics.LastError = err.Error()
			continue
		}
		allSeeds = append(allSeeds, seeds...)
	}
	em.metrics.TotalSeedsFetched += len(allSeeds)
	for _, cb := range em.callbacks {
		cb(allSeeds)
	}
}
