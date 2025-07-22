/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: scheduler.go
Description: Scheduler interface and implementations for pluggable test case scheduling in the Akaylee Fuzzer. Includes PriorityScheduler and a stub for CoverageGuidedScheduler.
*/

package core

// Scheduler defines the interface for pluggable test case scheduling.
// Allows the fuzzer engine to use different scheduling strategies.
type Scheduler interface {
	// Next returns the next test case to execute, or nil if empty.
	Next() *TestCase
	// Push adds a test case to the scheduler.
	Push(tc *TestCase)
	// Size returns the number of test cases in the scheduler.
	Size() int
	// IsEmpty returns true if the scheduler is empty.
	IsEmpty() bool
}

// PriorityScheduler implements Scheduler using a PriorityQueue.
type PriorityScheduler struct {
	queue *PriorityQueue
}

// NewPriorityScheduler creates a new PriorityScheduler instance.
func NewPriorityScheduler() *PriorityScheduler {
	return &PriorityScheduler{
		queue: NewPriorityQueue(),
	}
}

// Next returns the next test case (highest priority) or nil if empty.
func (s *PriorityScheduler) Next() *TestCase {
	return s.queue.Get()
}

// Push adds a test case to the scheduler.
func (s *PriorityScheduler) Push(tc *TestCase) {
	s.queue.Put(tc)
}

// Size returns the number of test cases in the scheduler.
func (s *PriorityScheduler) Size() int {
	return s.queue.Size()
}

// IsEmpty returns true if the scheduler is empty.
func (s *PriorityScheduler) IsEmpty() bool {
	return s.queue.IsEmpty()
}

// CoverageGuidedScheduler is a stub for future coverage-based scheduling.
type CoverageGuidedScheduler struct {
	// TODO: Implement coverage-guided scheduling logic
}

// NewCoverageGuidedScheduler creates a new CoverageGuidedScheduler instance.
func NewCoverageGuidedScheduler() *CoverageGuidedScheduler {
	return &CoverageGuidedScheduler{}
}

// Next returns the next test case (stub).
func (s *CoverageGuidedScheduler) Next() *TestCase {
	return nil // Not implemented yet
}

// Push adds a test case to the scheduler (stub).
func (s *CoverageGuidedScheduler) Push(tc *TestCase) {
	// Not implemented yet
}

// Size returns the number of test cases (stub).
func (s *CoverageGuidedScheduler) Size() int {
	return 0 // Not implemented yet
}

// IsEmpty returns true if the scheduler is empty (stub).
func (s *CoverageGuidedScheduler) IsEmpty() bool {
	return true // Not implemented yet
}
