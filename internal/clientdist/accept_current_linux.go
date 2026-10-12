package clientdist

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"loom/internal/control"
	"loom/internal/deviceclient"
)

const priorReleaseFloor = "/var/lib/loom/release-floor.json"

func advanceInstallationPackage(options InstallOptions, currentPath string, current *Manifest, next VerifiedDirectory) error {
	if options.AcceptCurrent != "" {
		return nil
	} // acceptCurrentPackage has already pinned this exact original manifest.
	return advancePackage(currentPath, current, next)
}

// CurrentAcceptance is a one-operation input for an explicitly approved
// existing program. It is never written as installation or Device authority.
type CurrentAcceptance struct {
	Schema          int    `json:"schema"`
	FloorDigest     string `json:"floor_digest"`
	ManifestDigest  string `json:"manifest_digest"`
	NetworkID       string `json:"network_id"`
	GenesisDigest   string `json:"genesis_digest"`
	DeviceID        string `json:"device_id"`
	DevicePublicKey string `json:"device_public_key"`
	UnitDigest      string `json:"unit_digest"`
	CurrentPath     string `json:"current_path"`
}

func (value CurrentAcceptance) Validate() error {
	if value.Schema != 3 || control.ValidateDigest(value.FloorDigest) != nil || control.ValidateDigest(value.ManifestDigest) != nil || control.ValidateDigest(value.GenesisDigest) != nil || control.ValidateDigest(value.UnitDigest) != nil || control.ValidateID(value.NetworkID) != nil || control.ValidateID(value.DeviceID) != nil || control.ValidatePublicKey(value.DevicePublicKey) != nil || !installPath(value.CurrentPath) || filepath.Dir(value.CurrentPath) != filepath.Join(installRoot, "releases") || control.ValidateDigest("sha256:"+filepath.Base(value.CurrentPath)) != nil {
		return errors.New("current acceptance coordinates are invalid")
	}
	return nil
}

func readCurrentAcceptance(path string) (CurrentAcceptance, error) {
	var value CurrentAcceptance
	body, err := installedFile(path, 16<<10, 0o600)
	if err == nil {
		err = control.DecodeCanonical(body, &value, control.ContractDecodeLimits{MaxBytes: 16 << 10, MaxDepth: 4, MaxItems: 64})
	}
	return value, err
}

func currentAcceptanceMatches(value CurrentAcceptance, candidate VerifiedDirectory, identity control.DeviceIdentityReadback, floor, unit []byte) error {
	if value.Validate() != nil || value.ManifestDigest != "sha256:"+candidate.ID || control.ReleaseDigest(floor) != value.FloorDigest || control.ReleaseDigest(unit) != value.UnitDigest || identity.NetworkID != value.NetworkID || identity.GenesisDigest != value.GenesisDigest || identity.DeviceID != value.DeviceID || identity.DevicePublicKey != value.DevicePublicKey || !identity.Joined || identity.Platform != "linux" {
		return errors.New("approved current package, original floor, unit or Device binding changed")
	}
	return nil
}

func acceptCurrentPackage(ctx context.Context, options InstallOptions, candidate VerifiedDirectory, currentPath string, current *Manifest) (string, *Manifest, error) {
	value, err := readCurrentAcceptance(options.AcceptCurrent)
	if err != nil {
		return "", nil, err
	}
	store, err := deviceclient.Load(options.State)
	if err != nil {
		return "", nil, err
	}
	if store.LKG() == nil {
		return "", nil, errors.New("approved current program must retain a joined Device")
	}
	identity, err := store.IdentityReadback()
	if err != nil {
		return "", nil, err
	}
	floor, err := installedFile(priorReleaseFloor, 64<<10, 0o600)
	if err != nil {
		return "", nil, err
	}
	unit, err := installedFile(installUnit, 64<<10, 0o644)
	if err != nil {
		return "", nil, err
	}
	// Recover the sole pre-accept interruption between a durable derived unit
	// and the current rename. Only the exact candidate unit while stopped is
	// admitted; the operator's original unit pin remains unchanged on disk.
	if current == nil && control.ReleaseDigest(unit) != value.UnitDigest {
		derived, projectionErr := ServiceUnit(filepath.Join(installRoot, "releases", candidate.ID), options.State, options.ResourceInputs, options.Capture, needsManagementTUN(store.LKG().View))
		state, stateErr := systemdProperty(ctx, "ActiveState")
		if projectionErr == nil && stateErr == nil && (state == "inactive" || state == "failed") && bytes.Equal(unit, derived) {
			value.UnitDigest = control.ReleaseDigest(unit)
		}
	}
	if current != nil {
		// A retry cannot confer a second baseline. Only the already accepted
		// exact package may finish its interrupted normal installation.
		if currentPath != filepath.Join(installRoot, "releases", candidate.ID) || value.ManifestDigest != "sha256:"+candidate.ID {
			return "", nil, errors.New("one-time acceptance cannot replace an existing accepted package")
		}
		value.UnitDigest = control.ReleaseDigest(unit)
		if err := currentAcceptanceMatches(value, candidate, identity, floor, unit); err != nil {
			return "", nil, err
		}
		return currentPath, current, nil
	}
	if err := currentAcceptanceMatches(value, candidate, identity, floor, unit); err != nil {
		return "", nil, err
	}
	if err := checkDirectory(value.CurrentPath, 0o755, false); err != nil {
		return "", nil, err
	}
	info, err := os.Lstat(filepath.Join(installRoot, "current"))
	if err != nil {
		return "", nil, err
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	target, linkErr := os.Readlink(filepath.Join(installRoot, "current"))
	if !ok || owner.Uid != 0 || linkErr != nil || target != value.CurrentPath {
		return "", nil, errors.New("approved original current link changed")
	}
	entries, err := os.ReadDir(value.CurrentPath)
	if err != nil || len(entries) != 2 || entries[0].Name() != "loom" || entries[1].Name() != "sing-box" || filepath.Base(value.CurrentPath) != candidate.Manifest.Loom.SHA256 {
		return "", nil, errors.New("existing program directory is not the approved two-file layout")
	}
	for _, component := range []Component{candidate.Manifest.Loom, candidate.Manifest.SingBox} {
		body, err := installedFile(filepath.Join(value.CurrentPath, component.Path), maxArchiveBytes, 0o755)
		if err != nil || len(body) != component.Size || sha256Hex(body) != component.SHA256 {
			return "", nil, errors.New("existing executable differs from independently signed original")
		}
	}
	if err := checkAcceptanceExecution(ctx, value.CurrentPath, options); err != nil {
		return "", nil, err
	}
	manifest := candidate.Manifest
	return value.CurrentPath, &manifest, nil
}

func checkAcceptanceExecution(ctx context.Context, currentPath string, options InstallOptions) error {
	for property, wanted := range map[string]string{"FragmentPath": installUnit, "DropInPaths": ""} {
		got, err := systemdProperty(ctx, property)
		if err != nil || got != wanted {
			return errors.New("original service ownership differs from the approved input")
		}
	}
	state, err := systemdProperty(ctx, "ActiveState")
	if err != nil {
		return err
	}
	if state == "inactive" || state == "failed" {
		return nil
	}
	pid, err := systemdProperty(ctx, "MainPID")
	id, parseErr := strconv.Atoi(pid)
	actual, readErr := os.Readlink(filepath.Join("/proc", pid, "exe"))
	if state != "active" || err != nil || parseErr != nil || id <= 0 || readErr != nil || actual != filepath.Join(currentPath, "loom") {
		return errors.New("original service is not executing the approved program")
	}
	body, err := os.ReadFile(filepath.Join("/proc", pid, "cmdline"))
	if err != nil {
		return err
	}
	args := strings.Split(strings.TrimSuffix(string(body), "\x00"), "\x00")
	if len(args) < 3 || args[1] != "client" || args[2] != "run" {
		return errors.New("original process is not the client runtime")
	}
	return checkAcceptanceArguments(args[3:], currentPath, options)
}

// The approved installed programs use these existing CLI defaults. Missing
// flags are their actual execution inputs, not absent identity or new defaults.
func checkAcceptanceArguments(args []string, currentPath string, options InstallOptions) error {
	fs := flag.NewFlagSet("approved client run", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	state := fs.String("state", defaultInstallState, "")
	local := fs.String("runtime-state", "/var/lib/loom-device/runtime.json", "")
	status := fs.String("status", "/run/loom-client/status.json", "")
	config := fs.String("runtime-config", "/run/loom-client/config.json", "")
	plane := fs.String("sing-box", filepath.Join(installRoot, "current", "sing-box"), "")
	capture := fs.String("capture", "mixed", "")
	resources := fs.String("resource-inputs", "", "")
	wg := fs.String("wireguard-private-key", "/etc/wireguard/node.key", "")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		return errors.New("original runtime arguments cannot be verified")
	}
	if *state != options.State || *local != filepath.Join(filepath.Dir(options.State), "runtime.json") || *status != "/run/loom-client/status.json" || *config != "/run/loom-client/config.json" || *plane != filepath.Join(currentPath, "sing-box") && *plane != filepath.Join(installRoot, "current", "sing-box") || *capture != options.Capture || *resources != options.ResourceInputs || *wg != "/etc/wireguard/node.key" {
		return errors.New("requested runtime inputs differ from the running original")
	}
	return nil
}

func checkAcceptanceUnit(options InstallOptions, body []byte, currentPath string, current *Manifest) bool {
	if options.AcceptCurrent == "" || current == nil || filepath.Base(currentPath) != current.Loom.SHA256 {
		return false
	}
	value, err := readCurrentAcceptance(options.AcceptCurrent)
	return err == nil && value.CurrentPath == currentPath && bytes.Equal([]byte(value.UnitDigest), []byte(control.ReleaseDigest(body)))
}
