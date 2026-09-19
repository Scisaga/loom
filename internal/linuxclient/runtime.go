package linuxclient

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"time"

	"loom/internal/control"
	"loom/internal/deviceclient"
)

type Options struct {
	DeviceState string
	LocalState  string
	Status      string
	Config      string
	SingBox     string
	Log         io.Writer
	Now         func() time.Time
	Generation  func() (string, error)
	Probe       Probe
}

func (options *Options) defaults() {
	if options.Log == nil {
		options.Log = io.Discard
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.Generation == nil {
		options.Generation = NetworkGeneration
	}
	if options.Probe == nil {
		options.Probe = BusinessProbe
	}
}

func runtimeView(store *deviceclient.Store) (*control.DeviceViewEnvelope, error) {
	lkg := store.LKG()
	if lkg == nil || lkg.View.Platform != "linux" || lkg.View.Runtime == nil {
		return nil, errors.New("Linux device has no certified runtime profile")
	}
	if err := lkg.View.Runtime.Validate(lkg.View.Routes); err != nil {
		return nil, fmt.Errorf("certified runtime profile: %w", err)
	}
	return lkg, nil
}

func writeConfig(path, config string) error {
	return atomicJSONBytes(path, []byte(config))
}

func atomicJSONBytes(path string, body []byte) (retErr error) {
	if len(body) == 0 {
		return errors.New("runtime config is empty")
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	file, err := os.CreateTemp(directory, ".runtime-config-*")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer func() {
		_ = file.Close()
		if retErr != nil {
			_ = os.Remove(temporary)
		}
	}()
	if err = file.Chmod(0o600); err == nil {
		_, err = file.Write(body)
	}
	if err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(temporary, path)
}

func checkRuntime(singBox, config string) error {
	command := exec.Command(singBox, "check", "-c", config)
	if output, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("sing-box preflight failed: %w: %s", err, string(output))
	}
	return nil
}

func Preflight(deviceState, singBox string) error {
	store, err := deviceclient.Load(deviceState)
	if err != nil {
		return err
	}
	lkg, err := runtimeView(store)
	if err != nil {
		return err
	}
	directory, err := os.MkdirTemp("", "loom-linux-preflight-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(directory)
	path := filepath.Join(directory, "config.json")
	if err := writeConfig(path, lkg.View.Runtime.Config); err != nil {
		return err
	}
	return checkRuntime(singBox, path)
}

func trySync(store *deviceclient.Store, log io.Writer) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := deviceclient.Sync(ctx, store); err != nil {
		fmt.Fprintf(log, "control sync unavailable; continuing from certified LKG: %v\n", err)
	}
}

func reportSelection(ctx context.Context, store *deviceclient.Store, activation Activation, now time.Time) error {
	selected := ""
	if len(activation.Selections) > 0 {
		selected = activation.Selections[0].CandidateID
	}
	report := control.DeviceReport{Selection: selected, ReportedAt: now.UTC().Truncate(time.Second).Format(time.RFC3339),
		Observations: append([]control.Observation(nil), activation.State.Observations...)}
	sort.Slice(report.Observations, func(i, j int) bool { return report.Observations[i].CandidateID < report.Observations[j].CandidateID })
	return deviceclient.Report(ctx, store, report)
}

func stopProcess(command *exec.Cmd, done <-chan error) error {
	if command.Process != nil {
		_ = command.Process.Signal(os.Interrupt)
	}
	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	select {
	case err := <-done:
		return err
	case <-timer.C:
		if command.Process != nil {
			_ = command.Process.Kill()
		}
		return <-done
	}
}

// Run owns the real sing-box child for the lifetime of the formal Linux
// service. A failed control sync does not prevent certified LKG recovery.
func Run(ctx context.Context, options Options) error {
	options.defaults()
	if err := os.Remove(options.Status); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove stale runtime status: %w", err)
	}
	store, err := deviceclient.Load(options.DeviceState)
	if err != nil {
		return err
	}
	if store.LKG() != nil {
		trySync(store, options.Log)
		store, err = deviceclient.Load(options.DeviceState)
		if err != nil {
			return err
		}
	}
	lkg, err := runtimeView(store)
	if err != nil {
		return err
	}
	if err := writeConfig(options.Config, lkg.View.Runtime.Config); err != nil {
		return err
	}
	if err := checkRuntime(options.SingBox, options.Config); err != nil {
		return err
	}
	command := exec.Command(options.SingBox, "run", "-c", options.Config)
	command.Stdout, command.Stderr = options.Log, options.Log
	if err := command.Start(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	stopped := false
	defer func() {
		if !stopped {
			_ = stopProcess(command, done)
		}
	}()
	selector, err := NewHTTPSelector(lkg.View.Runtime.Config)
	if err != nil {
		return err
	}
	scopes, _, err := scopesFor(lkg.View.Routes)
	if err != nil {
		return err
	}
	if err := waitSelector(ctx, selector, scopes); err != nil {
		return err
	}
	generation, err := options.Generation()
	if err != nil {
		return err
	}
	local, err := LoadLocalState(options.LocalState, generation)
	if err != nil {
		return err
	}
	activation, activateErr := Activate(ctx, selector, lkg.View.Routes, local, options.Probe, options.Now)
	if activation.State.Schema == 0 {
		return activateErr
	}
	saved, err := SaveObservations(options.LocalState, activation.State)
	if err != nil {
		return err
	}
	activation.State = saved
	reported := false
	reportContext, cancel := context.WithTimeout(ctx, 20*time.Second)
	if err := reportSelection(reportContext, store, activation, options.Now()); err != nil {
		fmt.Fprintf(options.Log, "private report unavailable; data plane remains on certified LKG: %v\n", err)
	} else {
		reported = true
	}
	cancel()
	status := Status{Schema: 1, DeviceID: lkg.View.DeviceID, Head: control.HeadID(lkg.Head), Floor: lkg.Head.Index,
		Preference: activation.State.Preference, NetworkGeneration: activation.State.NetworkGeneration,
		Selections: activation.Selections, Observations: activation.State.Observations, Runtime: "running", Reported: reported}
	if err := WriteStatus(options.Status, status); err != nil {
		return err
	}
	if activateErr != nil {
		fmt.Fprintf(options.Log, "all currently eligible candidates are unavailable: %v\n", activateErr)
	}
	select {
	case <-ctx.Done():
		stopped = true
		_ = stopProcess(command, done)
		return nil
	case err := <-done:
		stopped = true
		if err == nil {
			return errors.New("sing-box exited unexpectedly")
		}
		return fmt.Errorf("sing-box exited: %w", err)
	}
}
