/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: event_mutator.go
Description:  AndroidEventMutator. Implements EventMutator interface for generating
and mutating Android UI events (tap, swipe, input) with real selectors and values. Provides diverse,
context-aware event mutations for comprehensive fuzzing.
*/

package mobile

import (
	"math/rand"
	"strconv"
	"time"
)

// AndroidEventMutator implements EventMutator for Android
type AndroidEventMutator struct{}

func NewAndroidEventMutator() *AndroidEventMutator {
	return &AndroidEventMutator{}
}

func (m *AndroidEventMutator) MutateEvent(event *UIEvent) *UIEvent {
	rand.Seed(time.Now().UnixNano())
	mutated := *event // Copy
	eventTypes := []string{"tap", "swipe", "input"}
	if rand.Float64() < 0.7 {
		mutated.Type = eventTypes[rand.Intn(len(eventTypes))]
	}
	// Randomly mutate selector (coordinates for tap/swipe)
	if mutated.Type == "tap" || mutated.Type == "swipe" {
		x := rand.Intn(1080)
		y := rand.Intn(1920)
		mutated.Selector = strconv.Itoa(x) + "," + strconv.Itoa(y)
	}
	// Randomly mutate value for input
	if mutated.Type == "input" {
		vals := []string{"hello", "test", "1234", "!@#", "foo", "bar", ""}
		mutated.Value = vals[rand.Intn(len(vals))]
	}
	mutated.Timestamp = time.Now()
	return &mutated
}

func (m *AndroidEventMutator) Name() string { return "AndroidEventMutator" }
func (m *AndroidEventMutator) Description() string {
	return "Generates and mutates Android UI events (tap, swipe, input) for event fuzzing."
}
