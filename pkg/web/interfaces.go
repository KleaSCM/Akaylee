/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: interfaces.go
Description: Core interfaces for web application fuzzing. Defines WebFuzzer, BrowserController,
WebTarget, WebMutator, and WebAnalyzer for modular, production-level browser automation and web fuzzing.
*/

package web

import (
	"context"
)

// WebTarget describes a web application target for fuzzing
// Includes URL, scope, authentication, and session info
type WebTarget struct {
	URL         string
	Scope       []string          // Allowed domains/paths
	AuthType    string            // e.g. "basic", "form", "oauth"
	AuthConfig  map[string]string // Credentials, tokens, etc.
	Cookies     map[string]string
	Headers     map[string]string
	LoginScript string // Optional JS for login
	StartPage   string // Optional start page
}

// BrowserController abstracts browser automation (headless Chrome, Firefox, etc.)
type BrowserController interface {
	Start(ctx context.Context) error
	Stop() error
	Navigate(url string) error
	SetCookies(cookies map[string]string) error
	SetHeaders(headers map[string]string) error
	ExecuteJS(js string) (interface{}, error)
	FillForm(selector string, values map[string]string) error
	Click(selector string) error
	GetDOM() (string, error)
	Screenshot(path string) error
	GetConsoleLogs() ([]string, error)
	GetNetworkLogs() ([]string, error)
}

// WebMutator generates and mutates web inputs (forms, params, DOM, JS)
type WebMutator interface {
	MutateInputs(inputs map[string]string) map[string]string
	MutateDOM(dom string) string
	MutateJS(js string) string
	Name() string
	Description() string
}

// WebAnalyzer analyzes web responses, DOM, and JS for bugs
// Detects XSS, CSP bypass, JS errors, HTTP errors, etc.
type WebAnalyzer interface {
	AnalyzeResponse(dom string, logs []string, network []string) ([]string, error) // Returns bug descriptions
	Name() string
	Description() string
}

// WebFuzzer orchestrates the web fuzzing process
type WebFuzzer interface {
	Configure(target *WebTarget, controller BrowserController, mutator WebMutator, analyzer WebAnalyzer) error
	Start(ctx context.Context) error
	Stop() error
	Status() string
}
