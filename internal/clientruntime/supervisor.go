package clientruntime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const supervisorStopTimeout = 10 * time.Second

// RunWindowsDataPlane is the single process-lifecycle boundary for sing-box.
// Callers must pass a path returned by clientcomponent.LoadWindows. The
// function preflights first, keeps hydrated configuration only for the child
// lifetime, and kills the process (and on Windows its Job Object) on shutdown.
func RunWindowsDataPlane(ctx context.Context, executable string, config []byte, runtimeDir string) (retErr error) {
	return RunWindowsDataPlaneProfile(ctx, executable, config, runtimeDir, WindowsInstalledProfile, WindowsInstalledCAPath)
}

// RunWindowsDataPlaneProfile is the process-lifecycle boundary for one exact
// derived Windows capture profile.
func RunWindowsDataPlaneProfile(ctx context.Context, executable string, config []byte, runtimeDir string,
	profile WindowsRuntimeProfile, caPath string) (retErr error) {
	return RunWindowsDataPlaneProfileStarted(ctx, executable, config, runtimeDir, profile, caPath, nil)
}

// §16.1：只有进程已创建且已受 Job Object 监督，宿主才可以开始启动稳定窗口。
func RunWindowsDataPlaneProfileStarted(ctx context.Context, executable string, config []byte, runtimeDir string,
	profile WindowsRuntimeProfile, caPath string, started func()) (retErr error) {
	if ctx == nil {
		return errors.New("sing-box supervisor context is nil")
	}
	if err := PreflightWindowsRuntime(ctx, executable, config, runtimeDir, profile, caPath); err != nil {
		return err
	}
	if err := validateExecutable(executable); err != nil {
		return err
	}
	if err := cleanStaleRuntimeConfigs(runtimeDir); err != nil {
		return err
	}
	file, err := os.CreateTemp(runtimeDir, ".sing-box-active-*.json")
	if err != nil {
		return err
	}
	configPath := file.Name()
	defer func() {
		_ = file.Close()
		if err := os.Remove(configPath); err != nil && !errors.Is(err, os.ErrNotExist) && retErr == nil {
			retErr = fmt.Errorf("remove plaintext sing-box runtime config: %w", err)
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

	command := exec.Command(executable, "run", "-c", configPath)
	command.Dir = filepath.Dir(executable)
	command.Env = checkEnvironment()
	output := &discardLimitedWriter{limit: maxCheckOutput}
	command.Stdout, command.Stderr = output, output
	configureRunCommand(command)
	if err := command.Start(); err != nil {
		return fmt.Errorf("start sing-box: %w", err)
	}
	guard, err := attachChildGuard(command.Process)
	if err != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		return fmt.Errorf("attach sing-box process supervisor: %w", err)
	}
	defer guard.Close()
	if started != nil {
		started()
	}
	waited := make(chan error, 1)
	go func() { waited <- command.Wait() }()
	select {
	case err := <-waited:
		if err == nil {
			return errors.New("sing-box exited unexpectedly without an error")
		}
		return fmt.Errorf("sing-box exited unexpectedly (diagnostic output suppressed, %d bytes): %w", output.total, err)
	case <-ctx.Done():
		if err := guard.Terminate(); err != nil {
			_ = command.Process.Kill()
		}
		timer := time.NewTimer(supervisorStopTimeout)
		defer timer.Stop()
		select {
		case <-waited:
			return nil
		case <-timer.C:
			_ = command.Process.Kill()
			<-waited
			return errors.New("sing-box did not stop within the supervisor timeout")
		}
	}
}

// A hard process termination cannot run the normal plaintext-config defer.
// Data-plane ownership is serialized by the caller, so files found before a
// new child starts are stale and must not survive another launch.
func cleanStaleRuntimeConfigs(runtimeDir string) error {
	entries, err := os.ReadDir(runtimeDir)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(runtimeDir, 0o700); err != nil {
			return fmt.Errorf("create sing-box runtime directory: %w", err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("read sing-box runtime directory: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), ".sing-box-active-") || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(runtimeDir, entry.Name())
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refuse unsafe stale sing-box runtime path %s", path)
		}
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("remove stale sing-box runtime config: %w", err)
		}
	}
	return nil
}
