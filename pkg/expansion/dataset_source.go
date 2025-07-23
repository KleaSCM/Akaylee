/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: dataset_source.go
Description: ExpansionSource implementation for public datasets. Supports HTTP, HTTPS, FTP,
and local files. Handles deduplication, error handling, and logging for robust seed expansion.
*/

package expansion

import (
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// DatasetSource fetches seeds from a public dataset (HTTP, HTTPS, FTP, or local file)
type DatasetSource struct {
	NameStr        string
	DescriptionStr string
	URL            string
	Format         string // "json", "csv", "txt", "bin"
	Timeout        time.Duration
	DedupSet       map[string]struct{}
	Mu             sync.Mutex
}

// NewDatasetSource creates a new DatasetSource
func NewDatasetSource(name, desc, url, format string, timeout time.Duration) *DatasetSource {
	return &DatasetSource{
		NameStr:        name,
		DescriptionStr: desc,
		URL:            url,
		Format:         format,
		Timeout:        timeout,
		DedupSet:       make(map[string]struct{}),
	}
}

func (ds *DatasetSource) Name() string        { return ds.NameStr }
func (ds *DatasetSource) Description() string { return ds.DescriptionStr }

// FetchSeeds downloads and parses the dataset, returning unique seeds
func (ds *DatasetSource) FetchSeeds(ctx context.Context) ([][]byte, error) {
	var reader io.Reader
	var closer io.Closer

	if strings.HasPrefix(ds.URL, "http://") || strings.HasPrefix(ds.URL, "https://") {
		client := &http.Client{Timeout: ds.Timeout}
		resp, err := client.Get(ds.URL)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch dataset: %w", err)
		}
		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("dataset returned status %d", resp.StatusCode)
		}
		reader = resp.Body
		closer = resp.Body
	} else if strings.HasPrefix(ds.URL, "ftp://") {
		// FTP support can be added here (stub for now)
		return nil, fmt.Errorf("FTP not yet supported: %s", ds.URL)
	} else {
		file, err := os.Open(ds.URL)
		if err != nil {
			return nil, fmt.Errorf("failed to open dataset file: %w", err)
		}
		reader = file
		closer = file
	}
	if closer != nil {
		defer closer.Close()
	}

	// Parse based on format
	var seeds [][]byte
	switch ds.Format {
	case "json":
		data, err := ioutil.ReadAll(reader)
		if err != nil {
			return nil, fmt.Errorf("failed to read JSON: %w", err)
		}
		var items []json.RawMessage
		if err := json.Unmarshal(data, &items); err == nil {
			for _, item := range items {
				if ds.isUnique(item) {
					seeds = append(seeds, item)
				}
			}
		} else {
			// Try as object
			var obj map[string]interface{}
			if err := json.Unmarshal(data, &obj); err == nil {
				b, _ := json.Marshal(obj)
				if ds.isUnique(b) {
					seeds = append(seeds, b)
				}
			}
		}
	case "csv":
		csvReader := csv.NewReader(reader)
		records, err := csvReader.ReadAll()
		if err != nil {
			return nil, fmt.Errorf("failed to read CSV: %w", err)
		}
		for _, rec := range records {
			b := []byte(strings.Join(rec, ","))
			if ds.isUnique(b) {
				seeds = append(seeds, b)
			}
		}
	case "txt":
		data, err := ioutil.ReadAll(reader)
		if err != nil {
			return nil, fmt.Errorf("failed to read TXT: %w", err)
		}
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			b := []byte(line)
			if len(b) > 0 && ds.isUnique(b) {
				seeds = append(seeds, b)
			}
		}
	case "bin":
		data, err := ioutil.ReadAll(reader)
		if err != nil {
			return nil, fmt.Errorf("failed to read BIN: %w", err)
		}
		if ds.isUnique(data) {
			seeds = append(seeds, data)
		}
	default:
		return nil, fmt.Errorf("unsupported dataset format: %s", ds.Format)
	}

	return seeds, nil
}

// isUnique checks if the seed is new (deduplication by SHA256)
func (ds *DatasetSource) isUnique(seed []byte) bool {
	ds.Mu.Lock()
	defer ds.Mu.Unlock()
	hash := fmt.Sprintf("%x", sha256.Sum256(seed))
	if _, exists := ds.DedupSet[hash]; exists {
		return false
	}
	ds.DedupSet[hash] = struct{}{}
	return true
}
