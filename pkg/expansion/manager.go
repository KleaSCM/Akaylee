/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: manager.go
Description: Helper to build an ExpansionManager from ExpansionConfig. Parses config,
creates sources, and wires everything up for integration with the core engine.
*/

package expansion

import (
	"fmt"
)

// BuildManagerFromConfig creates an ExpansionManager from ExpansionConfig
func BuildManagerFromConfig(cfg *ExpansionConfig) (*ExpansionManager, error) {
	if !cfg.Enabled {
		return nil, nil
	}

	var sources []ExpansionSource
	// Add dataset sources
	for i, url := range cfg.DatasetSources {
		format := "json"
		if i < len(cfg.DatasetFormats) {
			format = cfg.DatasetFormats[i]
		}
		ds := NewDatasetSource(
			fmt.Sprintf("DatasetSource-%d", i+1),
			fmt.Sprintf("Auto-expanded dataset from %s", url),
			url,
			format,
			cfg.ParseTimeout(),
		)
		sources = append(sources, ds)
	}
	// Add API sources
	for i, url := range cfg.APISources {
		format := "json"
		if i < len(cfg.APIFormats) {
			format = cfg.APIFormats[i]
		}
		method := "GET"
		if i < len(cfg.APIMethods) {
			method = cfg.APIMethods[i]
		}
		headers := map[string]string{}
		if i < len(cfg.APIHeaders) && cfg.APIHeaders[i] != "" {
			// Parse header as "Key: Value"
			parts := []rune(cfg.APIHeaders[i])
			if idx := stringIndexRune(parts, ':'); idx > 0 {
				key := string(parts[:idx])
				val := string(parts[idx+1:])
				headers[key] = val
			}
		}
		var body []byte
		if i < len(cfg.APIBodies) {
			body = []byte(cfg.APIBodies[i])
		}
		api := NewWebAPISource(
			fmt.Sprintf("WebAPISource-%d", i+1),
			fmt.Sprintf("Auto-expanded API from %s", url),
			url,
			format,
			method,
			headers,
			body,
			cfg.ParseTimeout(),
		)
		sources = append(sources, api)
	}

	if len(sources) == 0 {
		return nil, fmt.Errorf("no expansion sources configured")
	}

	return NewExpansionManager(sources, cfg.ParseInterval()), nil
}

// stringIndexRune finds the index of a rune in a slice
func stringIndexRune(s []rune, r rune) int {
	for i, v := range s {
		if v == r {
			return i
		}
	}
	return -1
}
