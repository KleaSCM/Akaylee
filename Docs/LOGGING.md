# Akaylee Fuzzer Logging System

## Overview

The Akaylee Fuzzer features a **beautiful, comprehensive logging system** designed for production environments. Our logging system provides **timestamped files**, **multiple output formats**, **automatic rotation**, and **fuzzer-specific logging methods** to give you complete visibility into the fuzzing process.

## Features

### ✨ **Beautiful Output**
- **Colored log levels** for easy identification
- **Structured fields** with key-value pairs
- **Timestamp formatting** with millisecond precision
- **Caller information** for debugging
- **Fuzzer-specific prefixes** (EXEC, CRASH, HANG, etc.)

### 📁 **Timestamped Files**
- **Automatic file naming** with timestamps: `akaylee-fuzzer_2024-01-15_14-30-25.log`
- **Organized log directory** structure
- **Multiple log formats** support (Text, JSON, Custom)

### 🔄 **Automatic Management**
- **Log rotation** when files exceed size limits
- **Automatic cleanup** of old log files
- **Compression** of rotated logs (optional)
- **Configurable retention** policies

### 🎯 **Fuzzer-Specific Logging**
- **Execution tracking** with performance metrics
- **Crash detection** with detailed information
- **Hang detection** with resource usage
- **Coverage updates** with edge/block counts
- **Mutation tracking** with strategy information
- **Statistics reporting** with real-time metrics

## Configuration

### Command Line Options

```bash
# Basic logging options
--log-level=info                    # Log level (debug, info, warn, error)
--log-dir=./logs                    # Log output directory
--log-format=custom                 # Log format (text, json, custom)

# Advanced logging options
--log-max-files=10                  # Maximum log files to keep
--log-max-size=100MB               # Maximum log file size
--log-compress=false               # Compress rotated logs
```

### Environment Variables

```bash
export AKAYLEE_LOG_LEVEL=debug
export AKAYLEE_LOG_DIR=./logs
export AKAYLEE_LOG_FORMAT=custom
export AKAYLEE_LOG_MAX_FILES=10
export AKAYLEE_LOG_MAX_SIZE=104857600
export AKAYLEE_LOG_COMPRESS=false
```

### Configuration File

```yaml
# akaylee-fuzzer.yaml
log_level: "info"
log_dir: "./logs"
log_format: "custom"
log_max_files: 10
log_max_size: 104857600  # 100MB
log_compress: false
```

## Log Formats

### 1. Custom Format (Default)

Our **beautiful custom format** provides the best readability with colors and structured information:

```
2024-01-15 14:30:25.123 INFO [ENGINE] Starting Akaylee Fuzzer target=/bin/echo workers=4 corpus_dir=./corpus strategy=mutation
2024-01-15 14:30:25.456 INFO [EXEC] Test case executed test_case_id=abc123 duration=15.2ms status=success memory_usage=1024 cpu_usage=25.5
2024-01-15 14:30:25.789 ERROR [CRASH] Crash detected test_case_id=def456 crash_type=SIGSEGV address=0x12345678 stack=["func1", "func2"]
2024-01-15 14:30:26.012 WARN [HANG] Hang detected test_case_id=ghi789 duration=5.2s last_output="processing..."
2024-01-15 14:30:26.345 INFO [COVERAGE] Coverage updated test_case_id=jkl012 edge_count=150 block_count=75 new_edges=10
2024-01-15 14:30:26.678 DEBUG [MUTATE] Test case mutated parent_id=abc123 child_id=def456 mutator=BitFlipMutator mutation_rate=0.5
2024-01-15 14:30:27.001 INFO [STATS] Statistics update executions=1000 crashes=5 hangs=2 executions_per_sec=150.5/sec uptime=1m30s unique_crashes=3 coverage_edges=500 coverage_blocks=250
```

### 2. JSON Format

Perfect for **log aggregation** and **machine processing**:

```json
{
  "level": "info",
  "msg": "Test case executed",
  "time": "2024-01-15T14:30:25.456Z",
  "test_case_id": "abc123",
  "duration": "15.2ms",
  "status": "success",
  "memory_usage": 1024,
  "cpu_usage": 25.5,
  "timestamp": "2024-01-15T14:30:25.456Z"
}
```

### 3. Text Format

**Simple text format** for basic logging needs:

```
time="2024-01-15T14:30:25.456Z" level=info msg="Test case executed" test_case_id=abc123 duration=15.2ms status=success
```

## Fuzzer-Specific Logging Methods

### Execution Logging

```go
logger.LogExecution("test-123", 100*time.Millisecond, "success", map[string]interface{}{
    "memory_usage": 1024,
    "cpu_usage":    50.5,
    "exit_code":    0,
    "signal":       0,
})
```

### Crash Logging

```go
logger.LogCrash("test-456", "SIGSEGV", map[string]interface{}{
    "address":      "0x12345678",
    "stack_trace":  []string{"func1", "func2", "func3"},
    "registers":    map[string]uint64{"rax": 0x1234, "rbx": 0x5678},
    "reproducible": true,
})
```

### Hang Logging

```go
logger.LogHang("test-789", 5*time.Second, map[string]interface{}{
    "last_output":  "processing...",
    "peak_memory":  2048,
    "avg_cpu":      75.0,
    "io_read":      1024,
    "io_write":     512,
})
```

### Coverage Logging

```go
logger.LogCoverage("test-abc", 150, 75, map[string]interface{}{
    "new_edges":    10,
    "new_blocks":   5,
    "new_functions": 2,
    "coverage_hash": 12345,
})
```

### Mutation Logging

```go
logger.LogMutation("parent-123", "child-456", "BitFlipMutator", map[string]interface{}{
    "mutation_rate": 0.5,
    "data_size":     1024,
    "generation":    5,
})
```

### Statistics Logging

```go
logger.LogStats(1000, 5, 2, 150.5, map[string]interface{}{
    "unique_crashes":  3,
    "coverage_edges":  500,
    "coverage_blocks": 250,
    "corpus_size":     100,
})
```

## Log Management

### Automatic Rotation

Log files are automatically rotated when they exceed the configured size limit:

```bash
# Original log file
akaylee-fuzzer_2024-01-15_14-30-25.log

# Rotated log file (when size limit exceeded)
akaylee-fuzzer_2024-01-15_14-30-25.log.2024-01-15_15-45-30

# Compressed log file (if compression enabled)
akaylee-fuzzer_2024-01-15_14-30-25.log.2024-01-15_15-45-30.gz
```

### Cleanup Policy

The system automatically maintains the configured number of log files:

```go
// Keep only the 10 most recent log files
logManager := logging.NewLogManager("./logs", 10, 100*1024*1024, false)
err := logManager.CleanupOldLogs()
```

### Log Analysis

Analyze your logs for patterns and statistics:

```go
analyzer := logging.NewLogAnalyzer("./logs")
analysis, err := analyzer.AnalyzeLogs()

fmt.Println(analysis.GetLogSummary())
// Output:
// Log Analysis Summary:
//   Files: 5
//   Total Lines: 15000
//   Debug: 2000
//   Info: 10000
//   Warning: 2000
//   Error: 1000
//   Crashes: 50
//   Hangs: 25
//   Executions: 10000
//   Mutations: 5000
//   Coverage Updates: 2000
```

## Performance Considerations

### Efficient Logging

- **Structured logging** reduces string formatting overhead
- **Buffered output** for high-performance scenarios
- **Conditional logging** based on log levels
- **Async logging** for non-blocking operations

### Storage Optimization

- **Automatic compression** of old logs
- **Configurable retention** policies
- **Size-based rotation** to prevent disk space issues
- **Efficient file handling** with proper cleanup

## Integration Examples

### With External Log Aggregators

```bash
# Send logs to ELK Stack
akaylee-fuzzer fuzz --target=./target --corpus=./corpus --log-format=json | logstash

# Send logs to Splunk
akaylee-fuzzer fuzz --target=./target --corpus=./corpus --log-format=json | splunk

# Send logs to Fluentd
akaylee-fuzzer fuzz --target=./target --corpus=./corpus --log-format=json | fluentd
```

### With Monitoring Systems

```bash
# Monitor log files for alerts
tail -f logs/akaylee-fuzzer_*.log | grep "ERROR.*Crash detected" | alert-script

# Parse statistics for dashboards
grep "Statistics update" logs/akaylee-fuzzer_*.log | parse-stats.py
```

## Best Practices

### 1. **Use Appropriate Log Levels**
- `DEBUG`: Detailed debugging information
- `INFO`: General operational information
- `WARN`: Warning conditions
- `ERROR`: Error conditions that need attention

### 2. **Include Relevant Context**
```go
logger.LogExecution(testCaseID, duration, status, map[string]interface{}{
    "memory_usage": memoryUsage,
    "cpu_usage":    cpuUsage,
    "exit_code":    exitCode,
    "signal":       signal,
    "data_size":    len(testCase.Data),
    "generation":   testCase.Generation,
})
```

### 3. **Configure Appropriate Retention**
```bash
# For development: Keep more logs
--log-max-files=50 --log-max-size=50MB

# For production: Keep fewer logs
--log-max-files=10 --log-max-size=100MB

# For long-running fuzzing: Enable compression
--log-compress=true --log-max-files=20
```

### 4. **Monitor Log Performance**
- Watch log file sizes and rotation frequency
- Monitor disk space usage
- Check log analysis for patterns
- Use log aggregation for distributed fuzzing

## Troubleshooting

### Common Issues

1. **Log files not created**
   - Check directory permissions
   - Verify log directory exists
   - Check disk space

2. **Performance issues**
   - Reduce log level for high-frequency operations
   - Use JSON format for better performance
   - Enable log compression

3. **Missing log entries**
   - Check log level configuration
   - Verify log rotation settings
   - Check for log file corruption

### Debug Commands

```bash
# Check log directory structure
ls -la logs/

# Monitor log file growth
watch -n 1 'ls -lh logs/'

# Analyze log patterns
grep "ERROR" logs/akaylee-fuzzer_*.log | wc -l

# Check log rotation
find logs/ -name "*.log*" -exec ls -lh {} \;
```

## Conclusion

The Akaylee Fuzzer logging system provides **comprehensive visibility** into the fuzzing process with **beautiful, structured output** and **automatic management**. Whether you're debugging issues, monitoring performance, or analyzing results, our logging system gives you the information you need to make your fuzzing campaigns successful! ✨💕 