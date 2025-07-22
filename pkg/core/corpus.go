/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: corpus.go
Description: Corpus management system for the Akaylee Fuzzer. Provides efficient storage
and retrieval of test cases with intelligent cleanup algorithms and coverage-based
prioritization. Implements thread-safe operations for concurrent access.
*/

package core

import (
	"math/rand"
	"sync"
	"time"
)

// Corpus manages the collection of test cases
// Provides efficient storage, retrieval, and cleanup operations
type Corpus struct {
	testCases map[string]*TestCase // Map of test case ID to test case
	mu        sync.RWMutex         // Read-write mutex for thread safety

	// Statistics
	size       int
	maxSize    int
	generation int
}

// NewCorpus creates a new corpus instance
// Initializes the internal data structures for test case management
func NewCorpus() *Corpus {
	return &Corpus{
		testCases: make(map[string]*TestCase),
		maxSize:   10000, // Default maximum size
	}
}

// Add adds a test case to the corpus
// Returns error if test case already exists or corpus is full
func (c *Corpus) Add(testCase *TestCase) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if test case already exists
	if _, exists := c.testCases[testCase.ID]; exists {
		return nil // Already exists, no error
	}

	// Check if corpus is full
	if c.size >= c.maxSize {
		// Perform cleanup to make room
		c.cleanupInternal()
	}

	// Add test case
	c.testCases[testCase.ID] = testCase
	c.size++

	return nil
}

// Get retrieves a test case by ID
// Returns nil if test case doesn't exist
func (c *Corpus) Get(id string) *TestCase {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.testCases[id]
}

// GetRandom returns a random selection of test cases
// Useful for mutation and sampling operations
func (c *Corpus) GetRandom(count int) []*TestCase {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if count <= 0 || c.size == 0 {
		return nil
	}

	// Convert map to slice for random selection
	testCases := make([]*TestCase, 0, c.size)
	for _, tc := range c.testCases {
		testCases = append(testCases, tc)
	}

	// Shuffle and return requested count
	rand.Seed(time.Now().UnixNano())
	rand.Shuffle(len(testCases), func(i, j int) {
		testCases[i], testCases[j] = testCases[j], testCases[i]
	})

	if count > len(testCases) {
		count = len(testCases)
	}

	return testCases[:count]
}

// GetByPriority returns test cases sorted by priority
// Higher priority test cases are returned first
func (c *Corpus) GetByPriority(count int) []*TestCase {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if count <= 0 || c.size == 0 {
		return nil
	}

	// Convert map to slice and sort by priority
	testCases := make([]*TestCase, 0, c.size)
	for _, tc := range c.testCases {
		testCases = append(testCases, tc)
	}

	// Sort by priority (descending)
	for i := 0; i < len(testCases)-1; i++ {
		for j := i + 1; j < len(testCases); j++ {
			if testCases[i].Priority < testCases[j].Priority {
				testCases[i], testCases[j] = testCases[j], testCases[i]
			}
		}
	}

	if count > len(testCases) {
		count = len(testCases)
	}

	return testCases[:count]
}

// Remove removes a test case from the corpus
// Returns true if test case was found and removed
func (c *Corpus) Remove(id string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, exists := c.testCases[id]; exists {
		delete(c.testCases, id)
		c.size--
		return true
	}

	return false
}

// Size returns the current number of test cases in the corpus
func (c *Corpus) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.size
}

// SetMaxSize sets the maximum size of the corpus
// Triggers cleanup if current size exceeds new maximum
func (c *Corpus) SetMaxSize(maxSize int) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.maxSize = maxSize

	// Cleanup if necessary
	if c.size > maxSize {
		c.cleanupInternal()
	}
}

// Cleanup removes old or uninteresting test cases
// Maintains corpus size within configured limits
func (c *Corpus) Cleanup(targetSize int) int {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.size <= targetSize {
		return 0
	}

	return c.cleanupInternal()
}

// cleanupInternal performs the actual cleanup operation
// Removes test cases with low priority and high execution count
func (c *Corpus) cleanupInternal() int {
	if c.size <= c.maxSize {
		return 0
	}

	// Convert to slice for sorting
	testCases := make([]*TestCase, 0, c.size)
	for _, tc := range c.testCases {
		testCases = append(testCases, tc)
	}

	// Sort by priority and execution count
	// Lower priority and higher execution count = higher removal priority
	for i := 0; i < len(testCases)-1; i++ {
		for j := i + 1; j < len(testCases); j++ {
			scoreI := c.calculateRemovalScore(testCases[i])
			scoreJ := c.calculateRemovalScore(testCases[j])
			if scoreI < scoreJ {
				testCases[i], testCases[j] = testCases[j], testCases[i]
			}
		}
	}

	// Remove test cases from the end (lowest priority)
	toRemove := c.size - c.maxSize
	if toRemove > len(testCases) {
		toRemove = len(testCases)
	}

	removed := 0
	for i := len(testCases) - toRemove; i < len(testCases); i++ {
		delete(c.testCases, testCases[i].ID)
		removed++
	}

	c.size -= removed
	return removed
}

// calculateRemovalScore calculates a score for test case removal
// Higher scores indicate test cases that should be kept
func (c *Corpus) calculateRemovalScore(testCase *TestCase) int {
	score := testCase.Priority

	// Penalize test cases with high execution count
	score -= int(testCase.Executions) * 5

	// Bonus for test cases with good coverage
	if testCase.Coverage != nil {
		score += testCase.Coverage.EdgeCount * 10
	}

	// Bonus for test cases that found crashes
	if testCase.Metadata != nil {
		if _, hasCrash := testCase.Metadata["found_crash"]; hasCrash {
			score += 1000
		}
	}

	// Bonus for seed test cases
	if testCase.Generation == 0 {
		score += 500
	}

	return score
}

// GetAll returns all test cases in the corpus
// Useful for corpus analysis and statistics
func (c *Corpus) GetAll() []*TestCase {
	c.mu.RLock()
	defer c.mu.RUnlock()

	testCases := make([]*TestCase, 0, c.size)
	for _, tc := range c.testCases {
		testCases = append(testCases, tc)
	}

	return testCases
}

// GetStats returns corpus statistics
// Provides information about corpus composition and performance
func (c *Corpus) GetStats() map[string]interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()

	stats := make(map[string]interface{})
	stats["size"] = c.size
	stats["max_size"] = c.maxSize

	// Calculate generation distribution
	generationCount := make(map[int]int)
	totalCoverage := 0
	totalExecutions := int64(0)

	for _, tc := range c.testCases {
		generationCount[tc.Generation]++
		totalExecutions += tc.Executions

		if tc.Coverage != nil {
			totalCoverage += tc.Coverage.EdgeCount
		}
	}

	stats["generation_distribution"] = generationCount
	stats["total_executions"] = totalExecutions
	stats["total_coverage"] = totalCoverage

	if c.size > 0 {
		stats["avg_executions"] = float64(totalExecutions) / float64(c.size)
		stats["avg_coverage"] = float64(totalCoverage) / float64(c.size)
	}

	return stats
}
