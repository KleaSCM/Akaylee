# Akaylee

A modular security fuzzing engine designed for comprehensive vulnerability discovery across binaries, HTTP APIs, web applications, and Android mobile apps.

## Key Features

- **Multi-Target Fuzzing**: Unified engine supporting binary, API, web, and mobile targets.
- **Coverage-Guided Mutations**: Prioritizes inputs that discover new code paths.
- **State-Aware Execution**: Captures and restores application state for stateful targets.
- **Headless Browser Automation**: Full chromedp integration for dynamic web testing.
- **Android ADB Control**: Intent injection, UI events, and logcat collection.

## 🛠️ Technology Stack

### Languages

- Go 1.21+
- Shell/Bash

### Frameworks & Libraries

- chromedp (Headless Chrome)
- Cobra (CLI)
- logrus (Structured Logging)
- UUID (Test Case Identification)

### Databases & Storage

- JSON (Configuration)
- Binary Flatfiles (Corpus)
- In-Memory Maps (Coverage Bitmaps)

### Tools & Platforms

- ADB (Android Debug Bridge)
- Linux (Primary Target)
- Docker (Optional Containerization)

## 🎯 Problem Statement

Existing fuzzers like AFL and libFuzzer are excellent for binary targets, but modern applications span multiple surfaces — REST APIs, web frontends, and mobile apps. We needed a unified fuzzing engine that could test all these targets with consistent mutation strategies and coverage tracking.

### Challenges Faced

- Maintaining state consistency across web sessions (cookies, CSRF tokens).
- Generating semantically valid injection payloads that bypass input validation.
- Correlating crashes in headless browsers with reproducible test cases.
- Managing Android device lifecycle during long fuzzing sessions.

### Project Goals

- Support 4+ target types (binary, API, web, mobile) from a single engine.
- Implement 9+ injection payload categories (SQL, XSS, command, auth bypass, etc.).
- Achieve deterministic crash reproduction for all target types.
- Provide real-time statistics and HTML/JSON reporting.

## 🏗️ Architecture

### System Overview

The engine follows a modular, interface-driven architecture. Core abstractions (Mutator, Executor, Analyzer) allow swapping implementations without modifying the engine. The worker pool pattern enables parallel fuzzing with configurable concurrency.

### Core Components

- **Engine**: Central orchestrator managing corpus, queue, and workers.
- **Corpus Manager**: Prioritized test case storage with intelligent cleanup.
- **Priority Queue**: Binary heap scheduling based on coverage and crash potential.
- **Worker Pool**: Parallel execution with resource monitoring.

### Design Patterns

- Interface-Based Dependency Injection
- Worker Pool Pattern
- Strategy Pattern (Mutators)
- Observer Pattern (Event Listeners)

## 📊 Performance Metrics

### Key Metrics

**Executions/Second**: ~500-2000 (target dependent)
**Corpus Efficiency**: 15-30% interesting rate (coverage-guided)
**Memory Overhead**: ~50-200MB per worker

### Benchmarks

- API Mutation: 10,000 requests/second (localhost)
- Binary Execution: 500-2000 exec/s (with coverage)
- Web Navigation: 5-20 pages/second (with screenshots)

## 📥 Installation

### 1. Clone the repository

```bash
git clone https://github.com/KleaSCM/Akaylee.git
cd Akaylee
```

### 2. Build with Go

```bash
go mod download
go build -o akaylee ./Akaylee.go
```

### 3. Optional: Install for mobile fuzzing

```bash
# Ensure ADB is installed
sudo apt install adb
adb devices  # Verify device connected
```

## 🚀 Usage

### Binary Fuzzing

```bash
./akaylee fuzz --target ./vulnerable-binary --corpus ./seeds --workers 8
```

### API Fuzzing

```bash
./akaylee fuzz --mode api --target http://localhost:8080/api --mutations sql,xss
```

### Web Application Fuzzing

```bash
./akaylee fuzz --mode web --target http://localhost:3000 --headless
```

### Android Mobile Fuzzing

```bash
./akaylee fuzz --mode mobile --device emulator-5554 --app ./target.apk
```

## 💻 Code Snippets

### Injection Payload Generation

```go
// APIMutator generates security payloads for comprehensive API testing
func (m *APIMutator) GenerateInjectionPayloads() []string {
    payloads := []string{}
    payloads = append(payloads, m.payloadGenerator.sqlInjectionPayloads...)
    payloads = append(payloads, m.payloadGenerator.xssPayloads...)
    payloads = append(payloads, m.payloadGenerator.commandInjectionPayloads...)
    payloads = append(payloads, m.payloadGenerator.authBypassPayloads...)
    return payloads
}
```

**Explanation**: The API mutator aggregates payloads from multiple categories, allowing comprehensive security testing with a single fuzzing run.

### Headless Browser Event Collection

```go
// Attach listeners for console, JS errors, and network events
chromedp.ListenTarget(c.ctx, func(ev interface{}) {
    switch e := ev.(type) {
    case *network.EventRequestWillBeSent:
        c.netlogs = append(c.netlogs, fmt.Sprintf("[REQ] %s %s", e.Request.Method, e.Request.URL))
    case *runtime.EventExceptionThrown:
        c.logs = append(c.logs, fmt.Sprintf("[exception] %s", e.ExceptionDetails.Error()))
    }
})
```

**Explanation**: Real-time collection of network requests and JavaScript exceptions enables correlation between fuzzed inputs and application errors.

## 💭 Commentary

### Motivation

I wanted a fuzzer that could follow me across different project types — whether I'm testing a Go API, a React frontend, or an Android app. Switching between AFL, Burp, and manual ADB scripting was exhausting.

### Design Decisions

- **Interface-Driven**: Every major component implements an interface, making testing and extension trivial.
- **Go over Rust**: Faster iteration speed, excellent concurrency primitives, and chromedp availability.
- **Modular Executors**: Each target type (binary, API, web, mobile) has its own executor implementation.

### Lessons Learned

- State management is the hardest part of web fuzzing — cookies, CSRF, and session tokens need careful handling.
- Coverage-guided fuzzing dramatically reduces time-to-crash compared to random mutation.
- Having a unified reporting format across all target types makes analysis much easier.

### Future Plans

- 💡 Add GraphQL mutation support with schema inference
- 🚀 Implement distributed fuzzing across multiple nodes
- 🎮 Add iOS support via libimobiledevice
- 🧠 Integrate ML-based mutation scheduling

## 📫 Contact

- **Email**: <KleaSCM@gmail.com>
- **GitHub**: [github.com/KleaSCM](https://github.com/KleaSCM)
