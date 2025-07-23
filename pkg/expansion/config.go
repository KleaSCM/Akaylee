/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: config.go
Description: Configuration structures and helpers for seed corpus auto-expansion. Supports
CLI/config integration for enabling/disabling expansion, setting sources, and scheduling frequency.
*/

package expansion

import "time"

// ExpansionConfig holds configuration for auto-expansion
// Can be loaded from CLI flags, config files, or environment variables
type ExpansionConfig struct {
	Enabled        bool     `json:"enabled"`
	Interval       string   `json:"interval"`        // e.g. "1h", "10m"
	DatasetSources []string `json:"dataset_sources"` // URLs or file paths
	DatasetFormats []string `json:"dataset_formats"` // e.g. "json", "csv", "txt", "bin"
	APISources     []string `json:"api_sources"`     // API endpoint URLs
	APIFormats     []string `json:"api_formats"`     // e.g. "json", "csv", "txt"
	APIMethods     []string `json:"api_methods"`     // e.g. "GET", "POST"
	APIHeaders     []string `json:"api_headers"`     // e.g. "Authorization: Bearer ..."
	APIBodies      []string `json:"api_bodies"`      // POST bodies (optional)
	Timeout        string   `json:"timeout"`         // e.g. "10s"
}

// DefaultExpansionConfig returns a sensible default config
func DefaultExpansionConfig() *ExpansionConfig {
	return &ExpansionConfig{
		Enabled:        false,
		Interval:       "1h",
		DatasetSources: []string{},
		DatasetFormats: []string{},
		APISources:     []string{},
		APIFormats:     []string{},
		APIMethods:     []string{},
		APIHeaders:     []string{},
		APIBodies:      []string{},
		Timeout:        "10s",
	}
}

// ParseInterval parses the interval string into a time.Duration
func (c *ExpansionConfig) ParseInterval() time.Duration {
	d, err := time.ParseDuration(c.Interval)
	if err != nil {
		return time.Hour
	}
	return d
}

// ParseTimeout parses the timeout string into a time.Duration
func (c *ExpansionConfig) ParseTimeout() time.Duration {
	d, err := time.ParseDuration(c.Timeout)
	if err != nil {
		return 10 * time.Second
	}
	return d
}
