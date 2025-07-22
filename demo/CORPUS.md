# Akaylee Fuzzer Demo

This demo shows how to use the Akaylee Fuzzer with a simple Go target and real code coverage feedback.

## 1. Build the Target

```
cd demo
# Build the target binary
go build -o target target.go
```

## 2. Prepare a Seed Corpus

Create a directory with at least one input file:

```
mkdir -p corpus
# Add a simple seed file
printf 'AAAA' > corpus/seed1
```

## 3. Run the Fuzzer (from project root)

```
./akaylee-fuzzer fuzz \
  --target=./demo/target \
  --corpus=./demo/corpus \
  --output=./demo/output \
  --coverage-guided
```

- The fuzzer will generate inputs, run them against the target, and collect real Go code coverage.
- Crashes, hangs, and coverage-increasing inputs will be reported and saved.
- Metrics and logs will show coverage progress and findings.

## 4. Check Results

- Crashes: `./demo/output/crashes/`
- Metrics: `./metrics/core/`
- Logs: `./logs/`

## 5. Target Details

- The target panics on input `CRSH`.
- It prints messages for inputs starting with `ABC` or `0xFF 0x00`.

---

Happy fuzzing! 💖 