# Akaylee

<p align="center">
  <img src="https://img.shields.io/badge/Go-1.21+-00ADD8?style=for-the-badge&logo=go&logoColor=white" />
  <img src="https://img.shields.io/badge/Security-Fuzzer-DC143C?style=for-the-badge" />
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" />
</p>

<p align="center">
  <img src="https://img.shields.io/badge/chromedp-333?style=flat-square" />
  <img src="https://img.shields.io/badge/Cobra-888?style=flat-square" />
  <img src="https://img.shields.io/badge/ADB-3DDC84?style=flat-square&logo=android&logoColor=white" />
  <img src="https://img.shields.io/badge/logrus-333?style=flat-square" />
</p>

A modular security fuzzing engine written in Go, designed for comprehensive vulnerability discovery across binaries, HTTP APIs, web applications, and Android mobile apps.

## Overview

Akaylee is a multi-target security fuzzer that combines coverage-guided fuzzing with intelligent mutation strategies. Unlike traditional fuzzers that focus on a single target type, Akaylee provides unified fuzzing capabilities for:

- **Binary targets** — Traditional executable fuzzing with crash detection
- **HTTP/REST APIs** — Endpoint fuzzing with injection payload generation
- **Web applications** — Headless browser automation via chromedp
- **Android apps** — Mobile fuzzing via ADB with intent/event injection

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Akaylee Engine                          │
├─────────────────────────────────────────────────────────────────┤
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────────┐ │
│  │  Corpus  │  │  Queue   │  │ Scheduler│  │     Workers      │ │
│  │ Manager  │─▶│ Priority │─▶│  (Smart) │─▶│ (Parallel Pool)  │ │
│  └──────────┘  └──────────┘  └──────────┘  └──────────────────┘ │
├─────────────────────────────────────────────────────────────────┤
│                         Mutators                                │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌──────────────┐  │
│  │  Bit-Flip  │ │  Grammar   │ │    API     │ │ State-Aware  │  │
│  │  Mutator   │ │  Mutator   │ │  Mutator   │ │   Mutator    │  │
│  └────────────┘ └────────────┘ └────────────┘ └──────────────┘  │
├─────────────────────────────────────────────────────────────────┤
│                         Executors                               │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌──────────────┐  │
│  │   Binary   │ │    API     │ │    Web     │ │   Mobile     │  │
│  │  Executor  │ │  Executor  │ │ (chromedp) │ │    (ADB)     │  │
│  └────────────┘ └────────────┘ └────────────┘ └──────────────┘  │
├─────────────────────────────────────────────────────────────────┤
│                       Analysis & Reporting                      │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌──────────────┐  │
│  │  Coverage  │ │   Crash    │ │   State    │ │   Reports    │  │
│  │  Tracking  │ │  Analysis  │ │  Manager   │ │  (HTML/JSON) │  │
│  └────────────┘ └────────────┘ └────────────┘ └──────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

## Features

### Mutation Strategies

| Strategy | Description |
|----------|-------------|
| **Bit-Flip** | Random bit-level mutations for binary fuzzing |
| **Grammar-Aware** | Structure-preserving mutations using formal grammars |
| **API Mutator** | Injection payloads for SQL, XSS, command injection, path traversal |
| **State-Aware** | Respects application state for stateful target fuzzing |
| **Composite** | Combines multiple strategies with configurable weights |

### Security Payload Generation

The API mutator includes curated payloads for:

- **SQL Injection** — Union-based, error-based, blind injection variants
- **Cross-Site Scripting (XSS)** — Script injection, event handlers, polyglots
- **Command Injection** — Shell metacharacters, command chaining
- **Path Traversal** — Directory escape sequences, null byte injection
- **Authentication Bypass** — Header manipulation, JWT tampering
- **NoSQL Injection** — MongoDB/CouchDB specific payloads
- **Rate Limit Bypass** — Header spoofing techniques

### Web Fuzzing (chromedp)

Headless Chrome automation with:

- Cookie and header manipulation
- Form filling and submission
- JavaScript execution in page context
- Console log and network event collection
- Screenshot capture for crash reproduction
- DOM inspection and mutation

### Mobile Fuzzing (ADB)

Android device/emulator automation with:

- App install, launch, and lifecycle management
- Intent injection with action/data/extras
- UI event injection (tap, input, swipe)
- Logcat collection for crash detection
- Screenshot capture for reproduction
- Device info and property retrieval

### State Management

For stateful targets (databases, APIs, sessions):

- State capture and snapshot creation
- State restoration for reproducible testing
- Transition graph exploration
- State validation and recovery

## Installation

```bash
git clone https://github.com/KleaSCM/Akaylee.git
cd Akaylee
go mod download
go build -o akaylee ./Akaylee.go
```

### Dependencies

- **Go 1.21+**
- **chromedp** — For web application fuzzing
- **ADB** — For Android mobile fuzzing (optional)

## Usage

### Binary Fuzzing

```bash
./akaylee fuzz \
  --target ./vulnerable-binary \
  --corpus ./seeds \
  --workers 8 \
  --timeout 30s
```

### API Fuzzing

```bash
./akaylee fuzz \
  --mode api \
  --target http://localhost:8080/api \
  --endpoints ./openapi.json \
  --mutations sql,xss,auth-bypass
```

### Web Application Fuzzing

```bash
./akaylee fuzz \
  --mode web \
  --target http://localhost:3000 \
  --headless \
  --screenshot-on-crash
```

### Android Fuzzing

```bash
./akaylee fuzz \
  --mode mobile \
  --device emulator-5554 \
  --app ./target.apk \
  --intents ./intent-seeds.json
```

## Project Structure

```
Akaylee/
├── Akaylee.go              # Main entry point
├── cmd/                    # CLI commands (Cobra)
├── pkg/
│   ├── core/              # Engine, corpus, queue, workers
│   ├── strategies/        # Mutation strategies
│   │   ├── mutators.go        # Bit-flip, byte substitution
│   │   ├── api_mutator.go     # Injection payloads
│   │   ├── grammar_mutator.go # Grammar-based generation
│   │   └── state_aware_mutator.go
│   ├── execution/         # Target execution
│   │   ├── executor.go        # Binary execution
│   │   ├── api_executor.go    # HTTP API execution
│   │   ├── state_manager.go   # State capture/restore
│   │   └── state_validators.go
│   ├── web/               # Web fuzzing
│   │   ├── chromedp_controller.go
│   │   ├── fuzzer.go
│   │   └── analyzer.go
│   ├── mobile/            # Android fuzzing
│   │   ├── adb_controller.go
│   │   ├── app_analyzer.go
│   │   ├── fuzzer.go
│   │   └── intent_mutator.go
│   ├── analysis/          # Coverage and crash analysis
│   ├── coverage/          # Bitmap coverage tracking
│   ├── inference/         # Input format inference
│   ├── monitoring/        # Real-time statistics
│   └── reporting/         # HTML/JSON reports
└── Docs/                  # Documentation
```

## Configuration

Configuration via YAML file or command-line flags:

```yaml
target:
  path: ./target-binary
  mode: binary  # binary, api, web, mobile

corpus:
  input_dir: ./seeds
  output_dir: ./corpus

execution:
  workers: 8
  timeout: 30s
  max_crashes: 100

mutations:
  strategies:
    - bit-flip
    - grammar
  rate: 0.1

coverage:
  enabled: true
  bitmap_size: 65536

reporting:
  format: html
  output: ./reports
```

## Performance

- **Zero-copy mutations** — Minimizes allocations for high throughput
- **Bitmap coverage** — Efficient edge tracking with minimal overhead
- **Priority queue** — Favors high-coverage inputs
- **Parallel workers** — Scales with available CPU cores

## Documentation

Detailed documentation is available in the [`Docs/`](./Docs) directory:

| Document | Description |
|----------|-------------|
| [ARCHITECTURE.md](./Docs/ARCHITECTURE.md) | System architecture, component design, and extensibility points |
| [LOGGING.md](./Docs/LOGGING.md) | Structured logging configuration and output formats |
| [METRICS.md](./Docs/METRICS.md) | Performance metrics and monitoring |

## Demo

Example targets and usage demos are available in the [`demo/`](./demo) directory:

- **grammar_demo.go** — Grammar-based fuzzing demonstration
- **target.go** — Example vulnerable target for testing
- **CORPUS.md** — Corpus management documentation

## Testing

Run the test suite:

```bash
go test ./Tests/...
```

Test coverage includes:

- Crash triage and deduplication
- Grammar inference and mutation
- Logging and metrics collection
- Mutator correctness and performance
- Monitoring and statistics

## License

MIT License — see LICENSE file for details.

## Contact

For questions and support: <KleaSCM@gmail.com>
