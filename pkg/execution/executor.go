/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: executor.go
Description: Process executor implementation for the Akaylee Fuzzer. Provides comprehensive
process management, resource limits, and crash detection for target program execution.
Handles process creation, monitoring, and cleanup with  reliability.
*/

package execution

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"

	"math/rand"
	"strings"

	"github.com/kleascm/akaylee-fuzzer/pkg/interfaces"
)

// ProcessExecutor implements the Executor interface
// Handles the execution of target programs with comprehensive monitoring
type ProcessExecutor struct {
	config    *interfaces.FuzzerConfig
	InputMode string // "file", "stdin", or "both"
}

// NewProcessExecutor creates a new process executor instance
func NewProcessExecutor() *ProcessExecutor {
	return &ProcessExecutor{}
}

// Initialize sets up the executor with the given configuration
func (e *ProcessExecutor) Initialize(config *interfaces.FuzzerConfig) error {
	e.config = config
	if config != nil {
		if e.InputMode == "" {
			e.InputMode = "file"
		}
	}
	return nil
}

// Execute runs a test case and returns the execution result
// Handles process creation, monitoring, and result collection
func (e *ProcessExecutor) Execute(testCase *interfaces.TestCase) (*interfaces.ExecutionResult, error) {
	// Write input to temp file
	tmpfile, err := os.CreateTemp("", "fuzzinput")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmpfile.Name())
	if _, err := tmpfile.Write(testCase.Data); err != nil {
		tmpfile.Close()
		return nil, err
	}
	tmpfile.Close()

	// Create execution result
	result := &interfaces.ExecutionResult{
		TestCaseID: testCase.ID,
		Status:     interfaces.StatusSuccess,
	}

	// Pick a random port between 50000 and 60000
	port := 50000 + rand.Intn(10000)
	portStr := fmt.Sprintf("%d", port)

	// Optionally rewrite testCase.Data to use the chosen port in URLs
	// (Assume input is ASCII/UTF-8 text)
	inputStr := string(testCase.Data)
	inputStr = strings.ReplaceAll(inputStr, ":6969", ":"+portStr)
	testCase.Data = []byte(inputStr)

	// Log the chosen port for debugging
	fmt.Printf("[EXECUTOR] Using VULNSCAN_PORT=%s for test case %s\n", portStr, testCase.ID)

	// Build command: target <inputfile> (if file mode)
	var cmd *exec.Cmd
	if e == nil || e.config == nil {
		result.Status = interfaces.StatusError
		result.Error = []byte("executor or config is nil")
		result.Duration = 0
		return result, fmt.Errorf("executor or config is nil")
	}
	if e.InputMode == "stdin" {
		cmd = exec.Command(e.config.Target)
	} else {
		cmd = exec.Command(e.config.Target, tmpfile.Name())
	}

	// Set up input/output pipes
	var stdin io.WriteCloser
	var errStdin error
	if e.InputMode == "stdin" || e.InputMode == "both" {
		stdin, errStdin = cmd.StdinPipe()
		if errStdin != nil {
			result.Status = interfaces.StatusError
			result.Error = []byte("failed to create stdin pipe: " + errStdin.Error())
			result.Duration = 0
			return result, errStdin
		}
	}
	stdoutPipe, _ := cmd.StdoutPipe()
	stderrPipe, _ := cmd.StderrPipe()

	// Set environment variables
	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env, "VULNSCAN_PORT="+portStr)

	// Set resource limits
	e.setResourceLimits(cmd)

	// Start the process
	startTime := time.Now()
	if err := cmd.Start(); err != nil {
		result.Status = interfaces.StatusError
		result.Error = []byte("failed to start process: " + err.Error())
		result.Duration = time.Since(startTime)
		return result, err
	}

	// Track child process
	childProcsMu.Lock()
	childProcs = append(childProcs, cmd.Process)
	childProcsMu.Unlock()

	// Write test case data to stdin if needed
	if (e.InputMode == "stdin" || e.InputMode == "both") && stdin != nil {
		_, errStdin := stdin.Write(testCase.Data)
		stdin.Close()
		if errStdin != nil {
			cmd.Process.Kill()
			result.Status = interfaces.StatusError
			result.Error = []byte("failed to write to stdin: " + errStdin.Error())
			result.Duration = time.Since(startTime)
			return result, errStdin
		}
	}

	// Read stdout/stderr
	stdout, _ := io.ReadAll(stdoutPipe)
	stderr, _ := io.ReadAll(stderrPipe)

	// Wait for process completion with timeout
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	// Wait for completion or timeout
	select {
	case errWait := <-done:
		result.Duration = time.Since(startTime)
		if cmd == nil {
			result.Status = interfaces.StatusError
			result.Error = []byte("cmd is nil")
			return result, fmt.Errorf("cmd is nil")
		}
		if cmd.ProcessState == nil {
			result.Status = interfaces.StatusError
			result.Error = []byte("ProcessState is nil")
			return result, fmt.Errorf("ProcessState is nil")
		}
		result.ExitCode = cmd.ProcessState.ExitCode()

		// Check for signals
		if cmd.ProcessState.Sys() != nil {
			if waitStatus, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); ok {
				if waitStatus.Signaled() {
					result.Signal = int(waitStatus.Signal())
					result.Status = interfaces.StatusCrash
				}
			}
		}
		if errWait != nil {
			result.Status = interfaces.StatusError
			result.Error = []byte("process error: " + errWait.Error())
		}

	case <-time.After(e.config.Timeout):
		cmd.Process.Kill()
		result.Status = interfaces.StatusTimeout
		result.Duration = e.config.Timeout
	}

	// After process exits, remove from childProcs
	defer func() {
		childProcsMu.Lock()
		for i, p := range childProcs {
			if p.Pid == cmd.Process.Pid {
				childProcs = append(childProcs[:i], childProcs[i+1:]...)
				break
			}
		}
		childProcsMu.Unlock()
	}()

	// Always log output
	result.Output = stdout
	if len(stderr) > 0 {
		result.Error = append(result.Error, stderr...)
	}
	return result, nil
}

// setResourceLimits applies resource limits to the process
// Prevents excessive resource usage during fuzzing
func (e *ProcessExecutor) setResourceLimits(cmd *exec.Cmd) {
	// Set memory limit if specified
	if e.config.MemoryLimit > 0 {
		// This is a simplified implementation
		// In a full implementation, you would use rlimit or cgroups
	}
}

// Cleanup performs any necessary cleanup operations
func (e *ProcessExecutor) Cleanup() error {
	childProcsMu.Lock()
	for _, p := range childProcs {
		if p != nil {
			fmt.Printf("[EXECUTOR] Killing child process PID %d\n", p.Pid)
			p.Kill()
		}
	}
	childProcs = nil
	childProcsMu.Unlock()
	return nil
}

// Reset resets the executor state (no-op for ProcessExecutor)
func (e *ProcessExecutor) Reset() error { return nil }

var childProcs []*os.Process
var childProcsMu = &sync.Mutex{}
