/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: mutator.go
Description: Production-level WebMutator implementation. Mutates form inputs, DOM, and JS for XSS,
logic bugs, and randomization. Designed for extensibility and integration with web fuzzing engine.
*/

package web

import (
	"math/rand"
	"time"
)

type SimpleWebMutator struct{}

func NewSimpleWebMutator() *SimpleWebMutator {
	return &SimpleWebMutator{}
}

func (m *SimpleWebMutator) MutateInputs(inputs map[string]string) map[string]string {
	xssPayloads := []string{
		"<script>alert(1)</script>",
		"\"'><img src=x onerror=alert(2)>",
		"<svg/onload=alert(3)>",
		"<iframe src=javascript:alert(4)>",
	}
	mutated := make(map[string]string)
	for k, v := range inputs {
		if rand.Float64() < 0.3 {
			mutated[k] = xssPayloads[rand.Intn(len(xssPayloads))]
		} else if rand.Float64() < 0.2 {
			mutated[k] = v + "' OR '1'='1"
		} else {
			mutated[k] = v + randomString(3)
		}
	}
	return mutated
}

func (m *SimpleWebMutator) MutateDOM(dom string) string {
	// Insert a random <script> tag for XSS
	if rand.Float64() < 0.2 {
		return dom + "<script>alert('dom')</script>"
	}
	return dom
}

func (m *SimpleWebMutator) MutateJS(js string) string {
	// Insert a random alert or logic bug
	if rand.Float64() < 0.2 {
		return js + ";alert('js')"
	}
	return js
}

func (m *SimpleWebMutator) Name() string { return "SimpleWebMutator" }
func (m *SimpleWebMutator) Description() string {
	return "Mutates web inputs, DOM, and JS for XSS and logic bugs"
}

func randomString(n int) string {
	rand.Seed(time.Now().UnixNano())
	letters := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}
