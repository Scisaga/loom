package clientruntime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	SingBoxCheckTimeout = 20 * time.Second
	maxExecutableSize   = 64 << 20
	maxPreflightConfig  = 16 << 20
	maxCheckOutput      = 64 << 10
)

// RunSingBoxCheck executes only the upstream syntax/feature validator. It does
// not invoke `run`, create a TUN adapter, or alter routes. Child output is
// deliberately discarded because a diagnostic may echo hydrated secrets.
func RunSingBoxCheck(ctx context.Context, executable string, config []byte, runtimeDir string) (retErr error) {
	if ctx == nil {
		return errors.New("sing-box check context is nil")
	}
	if err := validateExecutable(executable); err != nil {
		return err
	}
	if runtimeDir == "" || !filepath.IsAbs(runtimeDir) || filepath.Clean(runtimeDir) != runtimeDir {
		return fmt.Errorf("sing-box preflight directory must be absolute and clean: %q", runtimeDir)
	}
	if len(config) == 0 || len(config) > maxPreflightConfig {
		return errors.New("sing-box preflight config has invalid size")
	}
	if err := os.MkdirAll(runtimeDir, 0o700); err != nil {
		return err
	}
	file, err := os.CreateTemp(runtimeDir, ".sing-box-check-*.json")
	if err != nil {
		return err
	}
	configPath := file.Name()
	defer func() {
		_ = file.Close()
		if err := os.Remove(configPath); err != nil && !errors.Is(err, os.ErrNotExist) && retErr == nil {
			retErr = fmt.Errorf("remove plaintext sing-box preflight config: %w", err)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		return err
	}
	if _, err := file.Write(config); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}

	checkContext, cancel := context.WithTimeout(ctx, SingBoxCheckTimeout)
	defer cancel()
	command := exec.CommandContext(checkContext, executable, "check", "-c", configPath)
	command.Dir = filepath.Dir(executable)
	command.Env = checkEnvironment()
	output := &discardLimitedWriter{limit: maxCheckOutput}
	command.Stdout, command.Stderr = output, output
	configureCheckCommand(command)
	if err := command.Run(); err != nil {
		if errors.Is(checkContext.Err(), context.DeadlineExceeded) {
			return errors.New("sing-box check timed out")
		}
		return fmt.Errorf("sing-box check failed (diagnostic output suppressed, %d bytes): %w", output.total, err)
	}
	return nil
}

// PreflightWindowsCandidate applies Loom's stricter managed shape checks before
// invoking the pinned upstream executable.
func PreflightWindowsCandidate(ctx context.Context, executable string, config []byte, runtimeDir string) error {
	if err := ValidateWindowsSingBox(config); err != nil {
		return fmt.Errorf("Windows sing-box structural preflight: %w", err)
	}
	return RunSingBoxCheck(ctx, executable, config, runtimeDir)
}

// PreflightWindowsRuntime validates the exact derived profile before invoking
// the pinned upstream syntax and feature checker.
func PreflightWindowsRuntime(ctx context.Context, executable string, config []byte, runtimeDir string,
	profile WindowsRuntimeProfile, caPath string) error {
	if err := ValidateWindowsRuntimeConfig(config, profile, caPath); err != nil {
		return fmt.Errorf("Windows sing-box structural preflight: %w", err)
	}
	return RunSingBoxCheck(ctx, executable, config, runtimeDir)
}

func validateExecutable(name string) error {
	if name == "" || !filepath.IsAbs(name) || filepath.Clean(name) != name {
		return fmt.Errorf("sing-box executable path must be absolute and clean: %q", name)
	}
	info, err := os.Lstat(name)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > maxExecutableSize {
		return errors.New("sing-box executable is not a bounded regular file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o111 == 0 {
		return errors.New("sing-box executable does not have an executable mode")
	}
	return nil
}

func checkEnvironment() []string {
	allowed := []string{"SystemRoot", "WINDIR", "PATH", "TEMP", "TMP", "TMPDIR"}
	environment := make([]string, 0, len(allowed))
	for _, name := range allowed {
		if value := os.Getenv(name); value != "" && !strings.ContainsRune(value, 0) {
			environment = append(environment, name+"="+value)
		}
	}
	return environment
}

type discardLimitedWriter struct {
	limit int
	total int
}

func (writer *discardLimitedWriter) Write(body []byte) (int, error) {
	written := len(body)
	if writer.total < writer.limit {
		remaining := writer.limit - writer.total
		if written > remaining {
			writer.total = writer.limit
		} else {
			writer.total += written
		}
	}
	return written, nil
}
