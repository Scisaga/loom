package clientdist

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"loom/internal/control"
)

const updateUnit = "/etc/systemd/system/loom-client-update.service"
const updateTimer = "/etc/systemd/system/loom-client-update.timer"

// This source coordinate is the independently reviewed original projection
// for the explicit one-operation migration. It is never a runtime fallback.
const originalUpdateProjectionCommit = "03d3f7f1cfe00e709237ed3c187e7ae2f0ba08b4"

// UpdateUnits are disposable execution projections of the same local inputs.
// They do not contain an expected release or accepted generation.
func UpdateUnits(state, resources, capture string) ([]byte, []byte, error) {
	service, timer, err := originalUpdateUnits(state, resources, capture)
	if err != nil {
		return nil, nil, err
	}
	// Fixed buffers bound the application heap. The cgroup includes children
	// and charged disk cache; its hard boundary remains independent of Go GC.
	service = bytes.Replace(service, []byte("Type=oneshot\n"), []byte("Type=oneshot\nEnvironment=GOMEMLIMIT=64MiB\nMemoryAccounting=yes\nMemoryHigh=128M\nMemoryMax=256M\nMemorySwapMax=0\nOOMPolicy=stop\n"), 1)
	return service, timer, nil
}

func originalUpdateUnits(state, resources, capture string) ([]byte, []byte, error) {
	if !installPath(state) || resources != "" && !installPath(resources) || capture != "mixed" && capture != "tun" {
		return nil, nil, errors.New("invalid update unit inputs")
	}
	args := " -capture " + capture + " -state " + unitArgument(state)
	if resources != "" {
		args += " -resource-inputs " + unitArgument(resources)
	}
	service := []byte("[Unit]\nDescription=Loom exact signed-package update\nAfter=network-online.target loom-client.service\n\n[Service]\nType=oneshot\nExecStart=" + unitArgument(filepath.Join(installRoot, "current", "loom")) + " client update" + args + "\nTimeoutStartSec=11min\nRestart=no\nKillMode=control-group\nUMask=0077\nNoNewPrivileges=yes\nPrivateTmp=yes\nProtectHome=yes\n")
	timer := []byte("[Unit]\nDescription=Check the accepted Loom component expectation\n\n[Timer]\nOnActiveSec=2min\nOnUnitActiveSec=5min\nUnit=loom-client-update.service\n\n[Install]\nWantedBy=timers.target\n")
	return service, timer, nil
}

// UpdateUnitMigration is protected, explicit operation evidence. It cannot
// accept a package, advance a floor or become persistent runtime authority.
type UpdateUnitMigration struct {
	Schema         int    `json:"schema"`
	ManifestDigest string `json:"manifest_digest"`
	CurrentPath    string `json:"current_path"`
	LoomSHA256     string `json:"loom_sha256"`
	LoomCommit     string `json:"loom_commit"`
	State          string `json:"state"`
	ResourceInputs string `json:"resource_inputs"`
	Capture        string `json:"capture"`
	ServiceDigest  string `json:"service_digest"`
	TimerDigest    string `json:"timer_digest"`
}

func (value UpdateUnitMigration) Validate() error {
	if value.Schema != 3 || control.ValidateDigest(value.ManifestDigest) != nil || control.ValidateDigest(value.ServiceDigest) != nil || control.ValidateDigest(value.TimerDigest) != nil || !lowerHex(value.LoomSHA256, 64) || value.LoomCommit != originalUpdateProjectionCommit || !installPath(value.CurrentPath) || filepath.Dir(value.CurrentPath) != filepath.Join(installRoot, "releases") || !lowerHex(filepath.Base(value.CurrentPath), 64) {
		return errors.New("update unit migration coordinates are invalid")
	}
	_, _, err := originalUpdateUnits(value.State, value.ResourceInputs, value.Capture)
	return err
}

func readUpdateUnitMigration(path string) (UpdateUnitMigration, error) {
	var value UpdateUnitMigration
	body, err := installedFile(path, 16<<10, 0600)
	if err == nil {
		err = control.DecodeCanonical(body, &value, control.ContractDecodeLimits{MaxBytes: 16 << 10, MaxDepth: 4, MaxItems: 64})
	}
	if err == nil {
		err = value.Validate()
	}
	return value, err
}

func migrationUpdateUnits(value UpdateUnitMigration, options InstallOptions, currentPath string, current *Manifest) ([]byte, []byte, error) {
	if value.Validate() != nil || current == nil || current.Loom.Commit != originalUpdateProjectionCommit || current.Loom.Dirty || currentPath != value.CurrentPath || value.ManifestDigest != "sha256:"+filepath.Base(currentPath) || current.Loom.SHA256 != value.LoomSHA256 || current.Loom.Commit != value.LoomCommit || options.State != value.State || options.ResourceInputs != value.ResourceInputs || options.Capture != value.Capture {
		return nil, nil, errors.New("approved current package or update projection inputs changed")
	}
	service, timer, err := originalUpdateUnits(value.State, value.ResourceInputs, value.Capture)
	if err != nil || control.ReleaseDigest(service) != value.ServiceDigest || control.ReleaseDigest(timer) != value.TimerDigest {
		return nil, nil, errors.New("approved original update units differ from their exact source projection")
	}
	return service, timer, nil
}

type checkedUpdateUnit struct {
	body, next []byte
	entry      os.FileInfo
}

type checkedUpdateUnits map[string]checkedUpdateUnit

func updateUnitOwnership(ctx context.Context, path string, missing bool) error {
	for property, wanted := range map[string]string{"FragmentPath": path, "DropInPaths": ""} {
		body, err := exec.CommandContext(ctx, "systemctl", "show", filepath.Base(path), "--property="+property, "--value").Output()
		actual := strings.TrimSpace(string(body))
		if err != nil || actual != wanted && !(missing && property == "FragmentPath" && actual == "") {
			return errors.New("existing update entry has unmanaged ownership or drop-ins")
		}
	}
	return nil
}

func checkUpdateUnits(ctx context.Context, options InstallOptions, currentPath string, current *Manifest) (checkedUpdateUnits, error) {
	service, timer, err := UpdateUnits(options.State, options.ResourceInputs, options.Capture)
	if err != nil {
		return nil, err
	}
	wanted := map[string][]byte{updateUnit: service, updateTimer: timer}
	allowed := wanted
	if options.UpdateUnitMigration != "" {
		value, err := readUpdateUnitMigration(options.UpdateUnitMigration)
		if err != nil {
			return nil, err
		}
		priorService, priorTimer, err := migrationUpdateUnits(value, options, currentPath, current)
		if err != nil {
			return nil, err
		}
		if err := verifyInstalledProgram(ctx, currentPath, current.Loom); err != nil {
			return nil, errors.New("approved current executable changed before update unit migration")
		}
		for _, path := range []string{updateUnit, updateTimer} {
			state, err := exec.CommandContext(ctx, "systemctl", "show", filepath.Base(path), "--property=ActiveState", "--value").Output()
			if err != nil || strings.TrimSpace(string(state)) != "inactive" && strings.TrimSpace(string(state)) != "failed" {
				return nil, errors.New("original updater and timer must be inactive before their explicit unit migration")
			}
		}
		allowed = map[string][]byte{updateUnit: priorService, updateTimer: priorTimer}
	}
	checked := checkedUpdateUnits{}
	for _, path := range []string{updateUnit, updateTimer} {
		entry, statErr := os.Lstat(path)
		body, err := installedFile(path, 64<<10, 0644)
		missing := errors.Is(err, os.ErrNotExist) && errors.Is(statErr, os.ErrNotExist)
		if options.UpdateUnitMigration != "" && missing || !missing && (err != nil || statErr != nil || !bytes.Equal(body, allowed[path]) && !bytes.Equal(body, wanted[path])) {
			return nil, errors.New("existing update entry differs from this installation's owned projection")
		}
		if err := updateUnitOwnership(ctx, path, missing); err != nil {
			return nil, err
		}
		checked[path] = checkedUpdateUnit{body: body, next: wanted[path], entry: entry}
	}
	return checked, nil
}

func compareUpdateUnit(path string, checked checkedUpdateUnit) error {
	entry, err := os.Lstat(path)
	if checked.entry == nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return errors.New("absent update entry was replaced during installation")
	}
	body, readErr := installedFile(path, 64<<10, 0644)
	if err != nil || readErr != nil || !os.SameFile(entry, checked.entry) || !bytes.Equal(body, checked.body) {
		return errors.New("owned update entry changed during installation")
	}
	return nil
}

func installUpdateUnits(ctx context.Context, options InstallOptions, checked checkedUpdateUnits) error {
	if options.AcceptCurrent != "" {
		return nil
	} // The original baseline program predates this CLI.
	for _, path := range []string{updateUnit, updateTimer} {
		value, ok := checked[path]
		if !ok {
			return errors.New("update unit installation lacks its ownership comparison")
		}
		if err := compareUpdateUnit(path, value); err != nil {
			return err
		}
		if err := updateUnitOwnership(ctx, path, value.entry == nil); err != nil {
			return err
		}
	}
	for _, path := range []string{updateUnit, updateTimer} {
		if err := compareUpdateUnit(path, checked[path]); err != nil {
			return err
		}
		if err := installFile(path, checked[path].next, 0644); err != nil {
			return err
		}
	}
	if err := installCommand(ctx, nil, options.Log, "systemctl", "daemon-reload"); err != nil {
		return err
	}
	return installCommand(ctx, nil, options.Log, "systemctl", "enable", "--now", "loom-client-update.timer")
}
