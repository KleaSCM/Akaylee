/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: intent_mutator.go
Description: AndroidIntentMutator. Implements IntentMutator interface for generating
and mutating Android intents with real actions, data URIs, and extras. Provides diverse, context-aware
intent mutations for comprehensive fuzzing.
*/

package mobile

import (
	"math/rand"
	"time"
)

// AndroidIntentMutator implements IntentMutator for Android
type AndroidIntentMutator struct{}

func NewAndroidIntentMutator() *AndroidIntentMutator {
	return &AndroidIntentMutator{}
}

func (m *AndroidIntentMutator) MutateIntent(intent *Intent) *Intent {
	rand.Seed(time.Now().UnixNano())
	mutated := *intent // Copy
	// Randomly mutate action
	actions := []string{
		"android.intent.action.VIEW",
		"android.intent.action.EDIT",
		"android.intent.action.SEND",
		"android.intent.action.DIAL",
		"android.intent.action.PICK",
		"android.intent.action.MAIN",
		"android.intent.action.CALL",
		"android.intent.action.DELETE",
		"android.intent.action.INSERT",
	}
	if rand.Float64() < 0.5 {
		mutated.Action = actions[rand.Intn(len(actions))]
	}
	// Randomly mutate data URI
	dataURIs := []string{
		"content://contacts/people/1",
		"tel:1234567890",
		"geo:37.7749,-122.4194",
		"mailto:test@example.com",
		"http://example.com",
		"file:///sdcard/test.txt",
	}
	if rand.Float64() < 0.5 {
		mutated.Data = dataURIs[rand.Intn(len(dataURIs))]
	}
	// Randomly mutate extras
	if mutated.Extras == nil {
		mutated.Extras = make(map[string]string)
	}
	extraKeys := []string{"foo", "bar", "baz", "user", "token", "id", "flag"}
	extraVals := []string{"1", "true", "test", "abc123", "", "null", "42"}
	if rand.Float64() < 0.7 {
		k := extraKeys[rand.Intn(len(extraKeys))]
		v := extraVals[rand.Intn(len(extraVals))]
		mutated.Extras[k] = v
	}
	// Randomly mutate package
	if rand.Float64() < 0.3 {
		mutated.Package = "com.android.settings/.Settings"
	}
	return &mutated
}

func (m *AndroidIntentMutator) Name() string { return "AndroidIntentMutator" }
func (m *AndroidIntentMutator) Description() string {
	return "Generates and mutates Android intents with real actions, data URIs, and extras for intent fuzzing."
}
