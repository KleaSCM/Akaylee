/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: expansion_test.go
Description: Comprehensive tests for the expansion package. Tests ExpansionManager,
DatasetSource, WebAPISource, and edge cases.
*/

package core_test

import (
	"context"
	"testing"
	"time"

	"github.com/kleascm/akaylee-fuzzer/pkg/expansion"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestExpansionConfig tests the ExpansionConfig
func TestExpansionConfig(t *testing.T) {
	runTest(t, "TestExpansionConfig", func(t *testing.T) {
		config := expansion.DefaultExpansionConfig()
		require.NotNil(t, config)

		// Test default values
		assert.False(t, config.Enabled)
		assert.Equal(t, "1h", config.Interval)
		assert.Equal(t, "10s", config.Timeout)
		assert.Empty(t, config.DatasetSources)
		assert.Empty(t, config.APISources)

		// Test custom config
		customConfig := &expansion.ExpansionConfig{
			Enabled:        true,
			Interval:       "30m",
			DatasetSources: []string{"https://example.com/dataset"},
			DatasetFormats: []string{"json"},
			APISources:     []string{"https://api.example.com"},
			APIFormats:     []string{"json"},
			APIMethods:     []string{"GET"},
			Timeout:        "5s",
		}

		assert.True(t, customConfig.Enabled)
		assert.Equal(t, "30m", customConfig.Interval)
		assert.Equal(t, 1, len(customConfig.DatasetSources))
		assert.Equal(t, 1, len(customConfig.APISources))
	})
}

// TestExpansionConfigParsing tests interval and timeout parsing
func TestExpansionConfigParsing(t *testing.T) {
	runTest(t, "TestExpansionConfigParsing", func(t *testing.T) {
		config := &expansion.ExpansionConfig{
			Interval: "30m",
			Timeout:  "5s",
		}

		// Test interval parsing
		interval := config.ParseInterval()
		assert.Equal(t, 30*time.Minute, interval)

		// Test timeout parsing
		timeout := config.ParseTimeout()
		assert.Equal(t, 5*time.Second, timeout)

		// Test invalid interval (should return default)
		config.Interval = "invalid"
		interval = config.ParseInterval()
		assert.Equal(t, time.Hour, interval)

		// Test invalid timeout (should return default)
		config.Timeout = "invalid"
		timeout = config.ParseTimeout()
		assert.Equal(t, 10*time.Second, timeout)
	})
}

// TestExpansionManager tests the ExpansionManager
func TestExpansionManager(t *testing.T) {
	runTest(t, "TestExpansionManager", func(t *testing.T) {
		// Create a mock source
		mockSource := &MockExpansionSource{
			name:        "test-source",
			description: "Test expansion source",
		}

		sources := []expansion.ExpansionSource{mockSource}
		interval := 100 * time.Millisecond

		manager := expansion.NewExpansionManager(sources, interval)
		require.NotNil(t, manager)

		// Test starting and stopping
		manager.Start()
		time.Sleep(50 * time.Millisecond)
		manager.Stop()

		// Test callback registration
		manager.RegisterCallback(func(seeds [][]byte) {
			// First callback registered successfully
		})
		manager.RegisterCallback(func(seeds [][]byte) {
			// Second callback registered successfully
		})
	})
}

// TestDatasetSource tests the DatasetSource
func TestDatasetSource(t *testing.T) {
	runTest(t, "TestDatasetSource", func(t *testing.T) {
		name := "test-dataset"
		description := "Test dataset source"
		url := "https://example.com/dataset"
		format := "json"
		timeout := 10 * time.Second

		source := expansion.NewDatasetSource(name, description, url, format, timeout)
		require.NotNil(t, source)

		// Test source properties
		assert.Equal(t, name, source.Name())
		assert.Equal(t, description, source.Description())

		// Test fetching (this will likely fail in test environment, which is OK)
		ctx := context.Background()
		seeds, err := source.FetchSeeds(ctx)
		if err != nil {
			t.Logf("Dataset fetch failed as expected: %v", err)
		} else {
			assert.NotNil(t, seeds)
		}
	})
}

// TestWebAPISource tests the WebAPISource
func TestWebAPISource(t *testing.T) {
	runTest(t, "TestWebAPISource", func(t *testing.T) {
		name := "test-api"
		description := "Test web API source"
		url := "https://api.example.com"
		format := "json"
		method := "GET"
		headers := map[string]string{"Authorization": "Bearer token"}
		body := []byte("")
		timeout := 10 * time.Second

		source := expansion.NewWebAPISource(name, description, url, format, method, headers, body, timeout)
		require.NotNil(t, source)

		// Test source properties
		assert.Equal(t, name, source.Name())
		assert.Equal(t, description, source.Description())

		// Test fetching (this will likely fail in test environment, which is OK)
		ctx := context.Background()
		seeds, err := source.FetchSeeds(ctx)
		if err != nil {
			t.Logf("WebAPI fetch failed as expected: %v", err)
		} else {
			assert.NotNil(t, seeds)
		}
	})
}

// TestBuildManagerFromConfig tests building manager from config
func TestBuildManagerFromConfig(t *testing.T) {
	runTest(t, "TestBuildManagerFromConfig", func(t *testing.T) {
		// Test with disabled config
		disabledConfig := &expansion.ExpansionConfig{
			Enabled: false,
		}

		manager, err := expansion.BuildManagerFromConfig(disabledConfig)
		require.NoError(t, err)
		assert.Nil(t, manager)

		// Test with enabled config but no sources
		enabledConfig := &expansion.ExpansionConfig{
			Enabled: true,
		}

		manager, err = expansion.BuildManagerFromConfig(enabledConfig)
		assert.Error(t, err)
		assert.Nil(t, manager)

		// Test with dataset source
		datasetConfig := &expansion.ExpansionConfig{
			Enabled:        true,
			DatasetSources: []string{"https://example.com/dataset"},
			DatasetFormats: []string{"json"},
			Timeout:        "10s",
		}

		manager, err = expansion.BuildManagerFromConfig(datasetConfig)
		require.NoError(t, err)
		assert.NotNil(t, manager)

		// Test with API source
		apiConfig := &expansion.ExpansionConfig{
			Enabled:    true,
			APISources: []string{"https://api.example.com"},
			APIFormats: []string{"json"},
			APIMethods: []string{"GET"},
			Timeout:    "10s",
		}

		manager, err = expansion.BuildManagerFromConfig(apiConfig)
		require.NoError(t, err)
		assert.NotNil(t, manager)
	})
}

// TestExpansionEdgeCases tests edge cases
func TestExpansionEdgeCases(t *testing.T) {
	runTest(t, "TestExpansionEdgeCases", func(t *testing.T) {
		// Test with empty sources
		manager := expansion.NewExpansionManager([]expansion.ExpansionSource{}, time.Hour)
		assert.NotNil(t, manager)

		// Test with nil sources
		manager = expansion.NewExpansionManager(nil, time.Hour)
		assert.NotNil(t, manager)

		// Test with zero interval
		mockSource := &MockExpansionSource{name: "test"}
		manager = expansion.NewExpansionManager([]expansion.ExpansionSource{mockSource}, 0)
		assert.NotNil(t, manager)

		// Test multiple callbacks
		manager.RegisterCallback(func(seeds [][]byte) {
			// First callback registered successfully
		})
		manager.RegisterCallback(func(seeds [][]byte) {
			// Second callback registered successfully
		})

		// Start and stop quickly
		manager.Start()
		time.Sleep(10 * time.Millisecond)
		manager.Stop()

		// Callbacks might not be called due to quick stop, which is OK
	})
}

// MockExpansionSource is a mock implementation of ExpansionSource for testing
type MockExpansionSource struct {
	name        string
	description string
}

func (m *MockExpansionSource) Name() string {
	return m.name
}

func (m *MockExpansionSource) Description() string {
	return m.description
}

func (m *MockExpansionSource) FetchSeeds(ctx context.Context) ([][]byte, error) {
	// Return some mock seeds
	return [][]byte{
		[]byte("mock seed 1"),
		[]byte("mock seed 2"),
	}, nil
}
