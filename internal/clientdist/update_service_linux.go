package clientdist

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const updateUnit = "/etc/systemd/system/loom-client-update.service"
const updateTimer = "/etc/systemd/system/loom-client-update.timer"

// UpdateUnits are disposable execution projections of the same local inputs.
// They do not contain an expected release or accepted generation.
func UpdateUnits(state, resources, capture string) ([]byte, []byte, error) {
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

func checkUpdateUnits(ctx context.Context, options InstallOptions) error {
	service, timer, err := UpdateUnits(options.State, options.ResourceInputs, options.Capture)
	if err != nil {
		return err
	}
	for path, expected := range map[string][]byte{updateUnit: service, updateTimer: timer} {
		body, err := installedFile(path, 64<<10, 0644)
		missing := errors.Is(err, os.ErrNotExist)
		if !missing && (err != nil || !bytes.Equal(body, expected)) {
			return errors.New("existing update entry differs from this installation's owned projection")
		}
		for property, wanted := range map[string]string{"FragmentPath": path, "DropInPaths": ""} {
			body, err := exec.CommandContext(ctx, "systemctl", "show", filepath.Base(path), "--property="+property, "--value").Output()
			actual := strings.TrimSpace(string(body))
			if err != nil || actual != wanted && !(missing && property == "FragmentPath" && actual == "") {
				return errors.New("existing update entry has unmanaged ownership or drop-ins")
			}
		}
	}
	return nil
}

func installUpdateUnits(ctx context.Context, options InstallOptions) error {
	if options.AcceptCurrent != "" {
		return nil
	} // The original baseline program predates this CLI.
	service, timer, err := UpdateUnits(options.State, options.ResourceInputs, options.Capture)
	if err != nil {
		return err
	}
	if err := installFile(updateUnit, service, 0644); err != nil {
		return err
	}
	if err := installFile(updateTimer, timer, 0644); err != nil {
		return err
	}
	if err := installCommand(ctx, nil, options.Log, "systemctl", "daemon-reload"); err != nil {
		return err
	}
	return installCommand(ctx, nil, options.Log, "systemctl", "enable", "--now", "loom-client-update.timer")
}
