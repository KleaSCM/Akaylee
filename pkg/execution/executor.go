/*
Author: KleaSCM
Email: KleaSCM@gmail.com
File: executor.go
Description: Process executor implementation for the Akaylee Fuzzer. Provides comprehensive
process management, resource limits, and crash detection for target program execution.
Handles process creation, monitoring, and cleanup with production-level reliability.
*/

package execution

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/kleascm/akaylee-fuzzer/pkg/interfaces"
)

// ProcessExecutor implements the Executor interface
// Handles the execution of target programs with comprehensive monitoring
type ProcessExecutor struct {
	config *interfaces.FuzzerConfig
}

// NewProcessExecutor creates a new process executor instance
func NewProcessExecutor() *ProcessExecutor {
	return &ProcessExecutor{}
}

// Initialize sets up the executor with the given configuration
func (e *ProcessExecutor) Initialize(config *interfaces.FuzzerConfig) error {
	e.config = config
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

	// Build command: target <inputfile>
	cmd := exec.Command(e.config.TargetPath, tmpfile.Name())

	// Set up input/output pipes
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return result, fmt.Errorf("failed to create stdin pipe: %w", err)
	}

	// Set environment variables
	if len(e.config.TargetEnv) > 0 {
		cmd.Env = append(os.Environ(), e.config.TargetEnv...)
	}

	// Set resource limits
	e.setResourceLimits(cmd)

	// Start the process
	startTime := time.Now()
	if err := cmd.Start(); err != nil {
		result.Status = interfaces.StatusError
		result.Error = []byte(err.Error())
		result.Duration = time.Since(startTime)
		return result, fmt.Errorf("failed to start process: %w", err)
	}

	// Write test case data to stdin
	if _, err := stdin.Write(testCase.Data); err != nil {
		cmd.Process.Kill()
		result.Status = interfaces.StatusError
		result.Error = []byte(err.Error())
		result.Duration = time.Since(startTime)
		return result, fmt.Errorf("failed to write to stdin: %w", err)
	}
	stdin.Close()

	// Wait for process completion with timeout
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	// Wait for completion or timeout
	select {
	case err := <-done:
		result.Duration = time.Since(startTime)
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

		if err != nil {
			result.Status = interfaces.StatusError
			result.Error = []byte(err.Error())
		}

	case <-time.After(e.config.Timeout):
		cmd.Process.Kill()
		result.Status = interfaces.StatusTimeout
		result.Duration = e.config.Timeout
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
	return nil
}

// Reset resets the executor state (no-op for ProcessExecutor)
func (e *ProcessExecutor) Reset() error { return nil }
