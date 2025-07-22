/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: queue.go
Description: Priority queue implementation for test case scheduling in the Akaylee Fuzzer.
Provides efficient insertion, removal, and priority-based ordering for optimal fuzzing
performance. Uses a binary heap data structure for O(log n) operations.
*/

package core

import (
	"sync"
	"time"
)

// PriorityQueue implements a thread-safe priority queue for test cases
// Uses a binary heap for efficient priority-based operations
type PriorityQueue struct {
	heap []*TestCase  // Binary heap array
	mu   sync.RWMutex // Thread safety
	size int          // Current number of elements

	// Performance tracking
	insertions int64
	removals   int64
	lastAccess time.Time
}

// NewPriorityQueue creates a new priority queue instance
// Initializes the internal heap data structure
func NewPriorityQueue() *PriorityQueue {
	return &PriorityQueue{
		heap: make([]*TestCase, 0, 1000), // Pre-allocate capacity
	}
}

// Put adds a test case to the priority queue
// Maintains heap property for efficient priority-based retrieval
func (pq *PriorityQueue) Put(testCase *TestCase) {
	pq.mu.Lock()
	defer pq.mu.Unlock()

	// Add to end of heap
	pq.heap = append(pq.heap, testCase)
	pq.size++
	pq.insertions++
	pq.lastAccess = time.Now()

	// Bubble up to maintain heap property
	pq.bubbleUp(pq.size - 1)
}

// Get removes and returns the highest priority test case
// Returns nil if queue is empty
func (pq *PriorityQueue) Get() *TestCase {
	pq.mu.Lock()
	defer pq.mu.Unlock()

	if pq.size == 0 {
		return nil
	}

	// Get root element (highest priority)
	root := pq.heap[0]
	pq.removals++
	pq.lastAccess = time.Now()

	// Move last element to root
	pq.heap[0] = pq.heap[pq.size-1]
	pq.heap = pq.heap[:pq.size-1]
	pq.size--

	// Bubble down to maintain heap property
	if pq.size > 0 {
		pq.bubbleDown(0)
	}

	return root
}

// Peek returns the highest priority test case without removing it
// Returns nil if queue is empty
func (pq *PriorityQueue) Peek() *TestCase {
	pq.mu.RLock()
	defer pq.mu.RUnlock()

	if pq.size == 0 {
		return nil
	}

	return pq.heap[0]
}

// Size returns the current number of test cases in the queue
func (pq *PriorityQueue) Size() int {
	pq.mu.RLock()
	defer pq.mu.RUnlock()
	return pq.size
}

// IsEmpty returns true if the queue is empty
func (pq *PriorityQueue) IsEmpty() bool {
	return pq.Size() == 0
}

// Clear removes all test cases from the queue
func (pq *PriorityQueue) Clear() {
	pq.mu.Lock()
	defer pq.mu.Unlock()

	pq.heap = pq.heap[:0]
	pq.size = 0
}

// GetStats returns queue performance statistics
func (pq *PriorityQueue) GetStats() map[string]interface{} {
	pq.mu.RLock()
	defer pq.mu.RUnlock()

	stats := make(map[string]interface{})
	stats["size"] = pq.size
	stats["capacity"] = cap(pq.heap)
	stats["insertions"] = pq.insertions
	stats["removals"] = pq.removals
	stats["last_access"] = pq.lastAccess

	// Calculate priority distribution
	if pq.size > 0 {
		priorityCount := make(map[int]int)
		for _, tc := range pq.heap {
			priorityCount[tc.Priority]++
		}
		stats["priority_distribution"] = priorityCount

		// Find min/max priorities
		minPriority := pq.heap[0].Priority
		maxPriority := pq.heap[0].Priority
		for _, tc := range pq.heap {
			if tc.Priority < minPriority {
				minPriority = tc.Priority
			}
			if tc.Priority > maxPriority {
				maxPriority = tc.Priority
			}
		}
		stats["min_priority"] = minPriority
		stats["max_priority"] = maxPriority
	}

	return stats
}

// bubbleUp moves an element up the heap to maintain heap property
// Used after insertion to restore heap order
func (pq *PriorityQueue) bubbleUp(index int) {
	for index > 0 {
		parent := (index - 1) / 2

		// If current element has higher priority than parent, swap
		if pq.heap[index].Priority > pq.heap[parent].Priority {
			pq.heap[index], pq.heap[parent] = pq.heap[parent], pq.heap[index]
			index = parent
		} else {
			break
		}
	}
}

// bubbleDown moves an element down the heap to maintain heap property
// Used after removal to restore heap order
func (pq *PriorityQueue) bubbleDown(index int) {
	for {
		left := 2*index + 1
		right := 2*index + 2
		largest := index

		// Find the largest among current node and its children
		if left < pq.size && pq.heap[left].Priority > pq.heap[largest].Priority {
			largest = left
		}

		if right < pq.size && pq.heap[right].Priority > pq.heap[largest].Priority {
			largest = right
		}

		// If largest is not the current node, swap and continue
		if largest != index {
			pq.heap[index], pq.heap[largest] = pq.heap[largest], pq.heap[index]
			index = largest
		} else {
			break
		}
	}
}

// UpdatePriority updates the priority of a test case and reorders the heap
// Useful for dynamic priority adjustments based on execution results
func (pq *PriorityQueue) UpdatePriority(testCaseID string, newPriority int) bool {
	pq.mu.Lock()
	defer pq.mu.Unlock()

	// Find the test case in the heap
	for i, tc := range pq.heap {
		if tc.ID == testCaseID {
			oldPriority := tc.Priority
			tc.Priority = newPriority

			// Reorder heap based on priority change
			if newPriority > oldPriority {
				pq.bubbleUp(i)
			} else if newPriority < oldPriority {
				pq.bubbleDown(i)
			}

			return true
		}
	}

	return false
}

// Remove removes a specific test case from the queue
// Returns true if the test case was found and removed
func (pq *PriorityQueue) Remove(testCaseID string) bool {
	pq.mu.Lock()
	defer pq.mu.Unlock()

	// Find the test case in the heap
	for i, tc := range pq.heap {
		if tc.ID == testCaseID {
			// Move last element to this position
			pq.heap[i] = pq.heap[pq.size-1]
			pq.heap = pq.heap[:pq.size-1]
			pq.size--
			pq.removals++

			// Reorder heap if necessary
			if i < pq.size {
				pq.bubbleDown(i)
			}

			return true
		}
	}

	return false
}

// GetBatch returns multiple test cases with the highest priorities
// Useful for batch processing operations
func (pq *PriorityQueue) GetBatch(count int) []*TestCase {
	pq.mu.Lock()
	defer pq.mu.Unlock()

	if count <= 0 || pq.size == 0 {
		return nil
	}

	if count > pq.size {
		count = pq.size
	}

	result := make([]*TestCase, count)
	for i := 0; i < count; i++ {
		result[i] = pq.heap[0]

		// Remove root and reorder
		pq.heap[0] = pq.heap[pq.size-1]
		pq.heap = pq.heap[:pq.size-1]
		pq.size--

		if pq.size > 0 {
			pq.bubbleDown(0)
		}
	}

	pq.removals += int64(count)
	pq.lastAccess = time.Now()

	return result
}

// ValidateHeap checks if the heap property is maintained
// Useful for debugging and testing
func (pq *PriorityQueue) ValidateHeap() bool {
	pq.mu.RLock()
	defer pq.mu.RUnlock()

	for i := 0; i < pq.size; i++ {
		left := 2*i + 1
		right := 2*i + 2

		if left < pq.size && pq.heap[i].Priority < pq.heap[left].Priority {
			return false
		}

		if right < pq.size && pq.heap[i].Priority < pq.heap[right].Priority {
			return false
		}
	}

	return true
}
