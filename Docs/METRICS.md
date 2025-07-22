# Akaylee Fuzzer Metrics System

## Overview

The Akaylee Fuzzer automatically writes test results and metrics to the `metrics/` directory. Each result is timestamped, versioned, and organized by test type for easy analysis and reproducibility.

## Directory Structure

```
metrics/
├── core/
│   ├── 2024-06-11_01-30-00_core_v1.0.0.json
│   └── ...
├── mutators/
│   ├── 2024-06-11_01-31-00_mutators_v1.0.0.json
│   └── ...
├── analysis/
│   ├── 2024-06-11_01-32-00_analysis_v1.0.0.json
│   └── ...
└── ...
```

- **metrics/**: Root directory for all metrics and test results.
- **<type>/**: Subdirectory for each test or metrics type (e.g., `core`, `mutators`, `analysis`).
- **<timestamp>_<type>_v<version>.json**: Timestamped, versioned JSON file for each result.

## File Naming Convention

- **Format:** `YYYY-MM-DD_HH-MM-SS_<type>_v<version>.json`
- **Example:** `2024-06-11_01-30-00_core_v1.0.0.json`

## How Results Are Written

The utility function `WriteMetricsResult` in `pkg/utils/metrics_writer.go` handles writing results:

```go
// WriteMetricsResult writes a result to the metrics directory with timestamp, type, and version
func WriteMetricsResult(testType string, version string, result interface{}) (string, error)
```

- **testType**: The type/category of the test (e.g., `core`, `mutators`, `analysis`).
- **version**: The version string (e.g., `1.0.0`).
- **result**: The result data (any Go struct, will be marshaled to JSON).

The function ensures the correct subdirectory exists, then writes a pretty-printed JSON file with the correct name.

## Example Usage

```go
import "github.com/kleascm/akaylee-fuzzer/pkg/utils"

result := map[string]interface{}{
    "test": "bitflip",
    "success": true,
    "coverage": 123,
}

filePath, err := utils.WriteMetricsResult("mutators", "1.0.0", result)
if err != nil {
    panic(err)
}
fmt.Println("Metrics written to:", filePath)
```

## Best Practices

- **Always use the correct test type** for organization.
- **Version your results** to track changes over time.
- **Use structured data** (structs or maps) for easy analysis.
- **Automate metrics writing** in your test harnesses and CI.

## Why This Rocks

- **Easy to find results** by type, time, and version.
- **Perfect for regression analysis** and reproducibility.
- **Ready for data science**: All results are JSON, easy to load in Python, R, or Jupyter.
- **No more lost results**: Everything is timestamped and organized!

---

*Metrics are the heart of scientific fuzzing. With this system, you’ll always know exactly what your fuzzer is doing, when, and how well it’s performing!* 💖 