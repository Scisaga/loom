package enrollssh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"time"
)

// Invocation is a direct process invocation. Program and Args are never
// interpreted by a shell. Stdin holds one of this package's fixed scripts.
type Invocation struct {
	Program     string
	Args        []string
	Stdin       []byte
	StdoutLimit int
	StderrLimit int
}

// Result is bounded command output. A Runner must set a Truncated field when
// it discards bytes, even if the command itself exits successfully.
type Result struct {
	Stdout          []byte
	Stderr          []byte
	StdoutTruncated bool
	StderrTruncated bool
}

// Runner permits deterministic tests without weakening the production argv
// boundary.
type Runner interface {
	Run(context.Context, Invocation) (Result, error)
}

// RunnerFunc adapts a function to Runner.
type RunnerFunc func(context.Context, Invocation) (Result, error)

func (f RunnerFunc) Run(ctx context.Context, in Invocation) (Result, error) {
	return f(ctx, in)
}

// ExecRunner runs commands directly through os/exec.
type ExecRunner struct {
	WaitDelay time.Duration
}

func (r ExecRunner) Run(ctx context.Context, in Invocation) (Result, error) {
	if in.Program == "" {
		return Result{}, errors.New("command program is empty")
	}
	if in.StdoutLimit <= 0 || in.StderrLimit <= 0 {
		return Result{}, errors.New("command output limits must be positive")
	}
	cmd := exec.CommandContext(ctx, in.Program, in.Args...)
	cmd.Stdin = bytes.NewReader(in.Stdin)
	wait := r.WaitDelay
	if wait <= 0 {
		wait = 2 * time.Second
	}
	cmd.WaitDelay = wait
	stdout := cappedBuffer{limit: in.StdoutLimit}
	stderr := cappedBuffer{limit: in.StderrLimit}
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	result := Result{
		Stdout:          stdout.Bytes(),
		Stderr:          stderr.Bytes(),
		StdoutTruncated: stdout.truncated,
		StderrTruncated: stderr.truncated,
	}
	if ctx.Err() != nil {
		return result, ctx.Err()
	}
	if err != nil {
		return result, err
	}
	if stdout.truncated || stderr.truncated {
		return result, fmt.Errorf("command output exceeded its configured limit")
	}
	return result, nil
}

type cappedBuffer struct {
	buffer    bytes.Buffer
	limit     int
	truncated bool
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	remaining := b.limit - b.buffer.Len()
	if remaining <= 0 {
		b.truncated = true
		return n, nil
	}
	if len(p) > remaining {
		_, _ = b.buffer.Write(p[:remaining])
		b.truncated = true
		return n, nil
	}
	_, _ = b.buffer.Write(p)
	return n, nil
}

func (b *cappedBuffer) Bytes() []byte { return b.buffer.Bytes() }

func runnerOrDefault(r Runner) Runner {
	if r != nil {
		return r
	}
	return ExecRunner{}
}

func commandError(operation string, ctx context.Context, result Result, err error) error {
	if result.StdoutTruncated || result.StderrTruncated {
		return fmt.Errorf("%s output exceeded the configured limit", operation)
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("%s timed out: %w", operation, context.DeadlineExceeded)
	}
	if errors.Is(ctx.Err(), context.Canceled) || errors.Is(err, context.Canceled) {
		return fmt.Errorf("%s canceled: %w", operation, context.Canceled)
	}
	if err == nil {
		return nil
	}
	stderr := string(bytes.TrimSpace(result.Stderr))
	if stderr == "" {
		return fmt.Errorf("%s failed: %w", operation, err)
	}
	return fmt.Errorf("%s failed: %w (stderr: %s)", operation, err, stderr)
}
