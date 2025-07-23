/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: webapi_source.go
Description: ExpansionSource implementation for web API endpoints. Supports GET/POST,
JSON/CSV/TXT, authentication, and deduplication. Provides robust error handling and
production-level comments for extensibility.
*/

package expansion

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"sync"
	"time"
)

// WebAPISource fetches seeds from a web API endpoint (GET/POST, JSON/CSV/TXT)
type WebAPISource struct {
	NameStr        string
	DescriptionStr string
	URL            string
	Format         string // "json", "csv", "txt"
	Method         string // "GET" or "POST"
	Headers        map[string]string
	Body           []byte
	Timeout        time.Duration
	DedupSet       map[string]struct{}
	Mu             sync.Mutex
}

// NewWebAPISource creates a new WebAPISource
func NewWebAPISource(name, desc, url, format, method string, headers map[string]string, body []byte, timeout time.Duration) *WebAPISource {
	return &WebAPISource{
		NameStr:        name,
		DescriptionStr: desc,
		URL:            url,
		Format:         format,
		Method:         method,
		Headers:        headers,
		Body:           body,
		Timeout:        timeout,
		DedupSet:       make(map[string]struct{}),
	}
}

func (ws *WebAPISource) Name() string        { return ws.NameStr }
func (ws *WebAPISource) Description() string { return ws.DescriptionStr }

// FetchSeeds calls the API and parses the response, returning unique seeds
func (ws *WebAPISource) FetchSeeds(ctx context.Context) ([][]byte, error) {
	client := &http.Client{Timeout: ws.Timeout}
	var req *http.Request
	var err error

	if ws.Method == "POST" {
		req, err = http.NewRequestWithContext(ctx, "POST", ws.URL, bytes.NewReader(ws.Body))
	} else {
		req, err = http.NewRequestWithContext(ctx, "GET", ws.URL, nil)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	for k, v := range ws.Headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to call API: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read API response: %w", err)
	}

	var seeds [][]byte
	switch ws.Format {
	case "json":
		var items []json.RawMessage
		if err := json.Unmarshal(data, &items); err == nil {
			for _, item := range items {
				if ws.isUnique(item) {
					seeds = append(seeds, item)
				}
			}
		} else {
			// Try as object
			var obj map[string]interface{}
			if err := json.Unmarshal(data, &obj); err == nil {
				b, _ := json.Marshal(obj)
				if ws.isUnique(b) {
					seeds = append(seeds, b)
				}
			}
		}
	case "csv":
		csvReader := csv.NewReader(strings.NewReader(string(data)))
		records, err := csvReader.ReadAll()
		if err != nil {
			return nil, fmt.Errorf("failed to read CSV: %w", err)
		}
		for _, rec := range records {
			b := []byte(strings.Join(rec, ","))
			if ws.isUnique(b) {
				seeds = append(seeds, b)
			}
		}
	case "txt":
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			b := []byte(line)
			if len(b) > 0 && ws.isUnique(b) {
				seeds = append(seeds, b)
			}
		}
	default:
		return nil, fmt.Errorf("unsupported API format: %s", ws.Format)
	}

	return seeds, nil
}

// isUnique checks if the seed is new (deduplication by SHA256)
func (ws *WebAPISource) isUnique(seed []byte) bool {
	ws.Mu.Lock()
	defer ws.Mu.Unlock()
	hash := fmt.Sprintf("%x", sha256.Sum256(seed))
	if _, exists := ws.DedupSet[hash]; exists {
		return false
	}
	ws.DedupSet[hash] = struct{}{}
	return true
}
