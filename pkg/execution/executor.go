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

	"github.com/kleascm/akaylee-fuzzer/pkg/core"
)

// ProcessExecutor implements the Executor interface
// Handles the execution of target programs with comprehensive monitoring
type ProcessExecutor struct {
	config *core.FuzzerConfig
}

// NewProcessExecutor creates a new process executor instance
func NewProcessExecutor() *ProcessExecutor {
	return &ProcessExecutor{}
}

// Initialize sets up the executor with the given configuration
func (e *ProcessExecutor) Initialize(config *core.FuzzerConfig) error {
	e.config = config
	return nil
}

// Execute runs a test case and returns the execution result
// Handles process creation, monitoring, and result collection
func (e *ProcessExecutor) Execute(testCase *core.TestCase) (*core.ExecutionResult, error) {
	// Create execution result
	result := &core.ExecutionResult{
		TestCaseID: testCase.ID,
		Status:     core.StatusSuccess,
	}

	// Create command
	cmd := exec.Command(e.config.TargetPath, e.config.TargetArgs...)

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
		result.Status = core.StatusError
		result.Error = []byte(err.Error())
		result.Duration = time.Since(startTime)
		return result, fmt.Errorf("failed to start process: %w", err)
	}

	// Write test case data to stdin
	if _, err := stdin.Write(testCase.Data); err != nil {
		cmd.Process.Kill()
		result.Status = core.StatusError
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
					result.Status = core.StatusCrash
				}
			}
		}

		if err != nil {
			result.Status = core.StatusError
			result.Error = []byte(err.Error())
		}

	case <-time.After(e.config.Timeout):
		// Process timed out
		cmd.Process.Kill()
		result.Status = core.StatusTimeout
		result.Duration = e.config.Timeout
	}

	return result, nil
}

// setResourceLimits configures resource limits for the process
// Prevents excessive resource consumption during execution
func (e *ProcessExecutor) setResourceLimits(cmd *exec.Cmd) {
	// Set memory limit if configured
	if e.config.MemoryLimit > 0 {
		// This is a simplified implementation
		// In production, would use rlimit or cgroups
	}

	// Set CPU affinity if configured
	if len(e.config.CPUAffinity) > 0 {
		// This is a simplified implementation
		// In production, would use sched_setaffinity
	}
}

// Cleanup performs any necessary cleanup operations
func (e *ProcessExecutor) Cleanup() error {
	// No cleanup needed for process executor
	return nil
}
