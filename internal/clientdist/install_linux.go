package clientdist

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"loom/internal/control"
	"loom/internal/deviceclient"
	"loom/internal/linuxclient"
)

const installRoot = "/usr/local/lib/loom-client"
const installTrust = "/etc/loom/trust/platform.pub"
const installUnit = "/etc/systemd/system/loom-client.service"

// InstallOptions are explicit local operation inputs. The signed manifest and
// deviceclient store remain the only package and Device authorities.
type InstallOptions struct {
	PackageRoot, PublicKey, State, ResourceInputs, Capture, InviteFile string
	InviteStdin                                                        bool
	Upgrade, NoEnroll, Inspect                                         bool
	Input                                                              io.Reader
	Log                                                                io.Writer
}

func (o InstallOptions) validate() error {
	modes := 0
	for _, selected := range []bool{o.InviteFile != "", o.InviteStdin, o.Upgrade, o.NoEnroll, o.Inspect} {
		if selected {
			modes++
		}
	}
	if modes != 1 {
		return errors.New("install requires exactly one invitation source, upgrade, no-enroll, or inspect")
	}
	if !installPath(o.PackageRoot) || !installPath(o.State) || o.ResourceInputs != "" && !installPath(o.ResourceInputs) {
		return errors.New("installation paths must be absolute canonical paths")
	}
	if !o.NoEnroll && o.Capture != "mixed" && o.Capture != "tun" {
		return errors.New("activation requires explicit --capture mixed or --capture tun")
	}
	if o.NoEnroll && (o.Capture != "" || o.ResourceInputs != "") {
		return errors.New("no-enroll cannot request runtime activation inputs")
	}
	return nil
}

func protectedDirectory(path string, mode os.FileMode) error {
	return checkDirectory(path, mode, true)
}

func checkDirectory(path string, mode os.FileMode, create bool) error {
	if !installPath(path) {
		return errors.New("invalid protected directory")
	}
	current := "/"
	for _, part := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if create && errors.Is(err, os.ErrNotExist) {
			permissions := os.FileMode(0o755)
			if current == path {
				permissions = mode
			}
			if err = os.Mkdir(current, permissions); err != nil {
				return err
			}
			if err = os.Chmod(current, permissions); err != nil {
				return err
			}
			info, err = os.Lstat(current)
		}
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 || stat.Uid != 0 {
			return errors.New("installation directory is not protected and root-owned")
		}
	}
	return nil
}

func installedFile(path string, limit int64, mode os.FileMode) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || stat.Nlink != 1 || !info.Mode().IsRegular() || info.Mode().Perm() != mode {
		return nil, errors.New("installed file ownership, mode or type differs")
	}
	return readRegularBounded(path, limit)
}

func syncDirectory(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func installFile(path string, body []byte, mode os.FileMode) error {
	directory := filepath.Dir(path)
	file, err := os.CreateTemp(directory, ".loom-install-*")
	if err != nil {
		return err
	}
	name := file.Name()
	defer os.Remove(name)
	if err = file.Chmod(mode); err == nil {
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
	if err = os.Rename(name, path); err != nil {
		return err
	}
	if err = syncDirectory(directory); err != nil {
		return err
	}
	got, err := installedFile(path, int64(len(body)), mode)
	if err != nil || !bytes.Equal(got, body) {
		return errors.New("installed file readback differs")
	}
	return nil
}

func packageFileMode(name string) os.FileMode {
	if name == "loom" || name == "sing-box" || name == "install.sh" {
		return 0o755
	}
	return 0o644
}

func verifyInstalledPayload(directory string, candidate VerifiedDirectory) error {
	count := 0
	err := filepath.WalkDir(directory, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == directory {
			return nil
		}
		name, err := filepath.Rel(directory, path)
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if name == "systemd" || name == "source" || name == "licenses" {
				return protectedDirectory(path, 0o755)
			}
			return errors.New("unexpected directory in installed release")
		}
		expected, ok := candidate.Files[name]
		if !ok {
			return errors.New("unexpected file in installed release")
		}
		got, err := installedFile(path, maxArchiveBytes, packageFileMode(name))
		if err != nil || !bytes.Equal(got, expected) {
			return errors.New("existing release payload differs from the verified package")
		}
		count++
		return nil
	})
	if err != nil {
		return err
	}
	if count != len(candidate.Files) {
		return errors.New("installed release is incomplete")
	}
	return nil
}

func cachePackage(candidate VerifiedDirectory) (string, error) {
	root := filepath.Join(installRoot, "releases")
	if err := protectedDirectory(root, 0o755); err != nil {
		return "", err
	}
	destination := filepath.Join(root, candidate.ID)
	if _, err := os.Lstat(destination); err == nil {
		if err = protectedDirectory(destination, 0o755); err != nil {
			return "", err
		}
		return destination, verifyInstalledPayload(destination, candidate)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	temporary, err := os.MkdirTemp(root, ".staging-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(temporary)
	if err = os.Chmod(temporary, 0o755); err != nil {
		return "", err
	}
	for _, name := range slices.Sorted(maps.Keys(candidate.Files)) {
		path := filepath.Join(temporary, name)
		if err = protectedDirectory(filepath.Dir(path), 0o755); err != nil {
			return "", err
		}
		if err = installFile(path, candidate.Files[name], packageFileMode(name)); err != nil {
			return "", err
		}
	}
	if err = os.Rename(temporary, destination); err != nil {
		return "", err
	}
	if err = syncDirectory(root); err != nil {
		return "", err
	}
	return destination, verifyInstalledPayload(destination, candidate)
}

func readInstallKey(path string) (ed25519.PublicKey, []byte, error) {
	body, err := readRegularBounded(path, 4096)
	if err != nil {
		return nil, nil, err
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(body)))
	if err != nil || len(key) != ed25519.PublicKeySize {
		return nil, nil, errors.New("invalid separately trusted installation key")
	}
	canonical := []byte(base64.StdEncoding.EncodeToString(key) + "\n")
	return ed25519.PublicKey(key), canonical, nil
}

func acceptedPackage(public ed25519.PublicKey) (string, *Manifest, error) {
	pointer := filepath.Join(installRoot, "current")
	info, err := os.Lstat(pointer)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil, nil
	}
	if err != nil {
		return "", nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || info.Mode()&os.ModeSymlink == 0 || stat.Uid != 0 {
		return "", nil, errors.New("current package pointer is not a root-owned symlink")
	}
	path, err := os.Readlink(pointer)
	if err != nil {
		return "", nil, err
	}
	if filepath.Dir(path) != filepath.Join(installRoot, "releases") || !lowerHex(filepath.Base(path), 64) {
		return "", nil, errors.New("current package pointer is not a canonical release path")
	}
	if err = checkDirectory(path, 0o755, false); err != nil {
		return "", nil, err
	}
	body, err := installedFile(filepath.Join(path, "manifest.json"), 64<<10, 0o644)
	if err != nil {
		return "", nil, err
	}
	signature, err := installedFile(filepath.Join(path, "manifest.sig"), ed25519.SignatureSize, 0o644)
	if err != nil {
		return "", nil, err
	}
	manifest, err := verifyManifest(body, signature, public)
	if err != nil {
		return "", nil, err
	}
	if sha256Hex(body) != filepath.Base(path) {
		return "", nil, errors.New("current signed manifest differs from its content ID")
	}
	return path, &manifest, nil
}

func advancePackage(currentPath string, current *Manifest, next VerifiedDirectory) error {
	if current == nil {
		return nil
	}
	if current.Arch != next.Manifest.Arch || next.Manifest.Generation < current.Generation || next.Manifest.Generation == current.Generation && filepath.Base(currentPath) != next.ID {
		return errors.New("package generation would roll back or equivocate")
	}
	return nil
}

func installCommand(ctx context.Context, input io.Reader, log io.Writer, program string, args ...string) error {
	command := exec.CommandContext(ctx, program, args...)
	command.Stdin = input
	command.Stdout = log
	command.Stderr = log
	if err := command.Run(); err != nil {
		return fmt.Errorf("installation command %s failed: %w", filepath.Base(program), err)
	}
	return nil
}

func systemdProperty(ctx context.Context, property string) (string, error) {
	body, err := exec.CommandContext(ctx, "systemctl", "show", "loom-client.service", "--property="+property, "--value").Output()
	return strings.TrimSpace(string(body)), err
}

func replaceInstallLink(path, target string) error {
	directory := filepath.Dir(path)
	temporary, err := os.MkdirTemp(directory, ".link-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(temporary)
	source := filepath.Join(temporary, "link")
	if err = os.Symlink(target, source); err != nil {
		return err
	}
	if err = os.Rename(source, path); err != nil {
		return err
	}
	return syncDirectory(directory)
}

// Install performs one forward operation. A failure after current advances
// disables execution and retains that signed generation and Device state.
func Install(ctx context.Context, options InstallOptions) (resultErr error) {
	if options.State == "" {
		options.State = defaultInstallState
	}
	if options.Log == nil {
		options.Log = io.Discard
	}
	if err := options.validate(); err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return errors.New("installation requires root")
	}
	if options.Inspect {
		value, err := InspectInstallation(ctx, options)
		if err != nil {
			return err
		}
		body, err := control.CanonicalEncode(value)
		if err != nil {
			return err
		}
		_, err = options.Log.Write(append(body, '\n'))
		return err
	}
	if err := protectedDirectory("/run/loom-install", 0o700); err != nil {
		return err
	}
	lock, err := os.OpenFile("/run/loom-install/lock", os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	defer lock.Close()
	stat, err := lock.Stat()
	if err != nil {
		return err
	}
	owner, ok := stat.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != 0 || owner.Nlink != 1 || !stat.Mode().IsRegular() || stat.Mode().Perm() != 0o600 {
		return errors.New("installation lock is not protected")
	}
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return errors.New("another Linux installation is running")
	}
	keyPath := options.PublicKey
	if keyPath == "" {
		keyPath = installTrust
	}
	public, keyBody, err := readInstallKey(keyPath)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(installTrust); err == nil {
		body, err := installedFile(installTrust, 4096, 0o644)
		if err != nil || !bytes.Equal(body, keyBody) {
			return errors.New("existing platform trust cannot be replaced")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	candidate, err := VerifyDirectory(options.PackageRoot, public)
	if err != nil {
		return err
	}
	if candidate.Manifest.Arch != runtime.GOARCH {
		return errors.New("package architecture differs from the installation host")
	}
	var currentPath string
	var current *Manifest
	if !options.NoEnroll {
		currentPath, current, err = acceptedPackage(public)
		if err != nil {
			return fmt.Errorf("existing deployment needs a verified forward cutover: %w", err)
		}
		if err = advancePackage(currentPath, current, candidate); err != nil {
			return err
		}
	}
	if err = protectedDirectory(filepath.Dir(installTrust), 0o755); err != nil {
		return err
	}
	if err = installFile(installTrust, keyBody, 0o644); err != nil {
		return err
	}
	release, err := cachePackage(candidate)
	if err != nil {
		return err
	}
	if options.NoEnroll {
		fmt.Fprintln(options.Log, "Verified release cached; no Device, current pointer or service was changed.")
		return nil
	}
	unit, previousUnit, err := installationInputs(ctx, options, release, currentPath, current)
	if err != nil {
		return err
	}
	if current != nil {
		if err = installCommand(ctx, nil, options.Log, "systemctl", "disable", "--now", "loom-client.service"); err != nil {
			return err
		}
		if err = installCommand(ctx, nil, options.Log, filepath.Join(currentPath, "loom"), "client", "cleanup"); err != nil {
			return fmt.Errorf("previous generation cleanup was not successful: %w", err)
		}
	}
	if err = protectedDirectory(filepath.Dir(options.State), 0o700); err != nil {
		return err
	}
	binary := filepath.Join(release, "loom")
	if !options.Upgrade {
		args := []string{"client", "enroll", "-state", options.State, "-wait", "5m"}
		var input io.Reader
		if options.InviteStdin {
			args = append(args, "-stdin")
			input = options.Input
		} else {
			args = append(args, "-invite-file", options.InviteFile)
		}
		if err = installCommand(ctx, input, options.Log, binary, args...); err != nil {
			return err
		}
	}
	store, err := deviceclient.Load(options.State)
	if err != nil {
		return err
	}
	lkg := store.LKG()
	if lkg == nil {
		return errors.New("enrollment has not completed; activation withheld")
	}
	unit, err = ServiceUnit(release, options.State, options.ResourceInputs, options.Capture, needsManagementTUN(lkg.View))
	if err != nil {
		return err
	}
	args := []string{"client", "preflight", "-state", options.State, "-sing-box", filepath.Join(release, "sing-box"), "-capture", options.Capture}
	if options.ResourceInputs != "" {
		args = append(args, "-resource-inputs", options.ResourceInputs)
	}
	if err = installCommand(ctx, nil, options.Log, binary, args...); err != nil {
		return err
	}
	if err = protectedDirectory(filepath.Dir(installUnit), 0o755); err != nil {
		return err
	}
	if err = installFile(installUnit, unit, 0o644); err != nil {
		return err
	}
	succeeded := false
	defer func() {
		if !succeeded {
			cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			stopErr := installCommand(cleanup, nil, options.Log, "systemctl", "disable", "--now", "loom-client.service")
			state, stateErr := systemdProperty(cleanup, "ActiveState")
			enabled, _ := exec.CommandContext(cleanup, "systemctl", "is-enabled", "loom-client.service").Output()
			if stopErr != nil || stateErr != nil || state != "inactive" && state != "failed" || strings.TrimSpace(string(enabled)) != "disabled" {
				resultErr = errors.Join(resultErr, errors.New("failed activation could not confirm disabled, inactive execution; inspect systemd before retry"), stopErr, stateErr)
			} else {
				fmt.Fprintln(options.Log, "Activation failed; execution is disabled and inactive, and the accepted package, Device and floor are retained.")
			}
		}
	}()
	if err = replaceInstallLink(filepath.Join(installRoot, "current"), release); err != nil {
		// Rename may have committed even if directory fsync failed. Never undo
		// an accepted pointer; restore only the prior unit when it did not.
		if target, readErr := os.Readlink(filepath.Join(installRoot, "current")); readErr == nil && target != release {
			if len(previousUnit) > 0 {
				_ = installFile(installUnit, previousUnit, 0o644)
			}
		}
		return err
	}
	for _, args := range [][]string{{"daemon-reload"}, {"enable", "loom-client.service"}, {"restart", "loom-client.service"}} {
		if err = installCommand(ctx, nil, options.Log, "systemctl", args...); err != nil {
			return err
		}
	}
	deadline := time.NewTimer(45 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		state, stateErr := systemdProperty(ctx, "ActiveState")
		pid, pidErr := systemdProperty(ctx, "MainPID")
		id, _ := strconv.Atoi(pid)
		actual, readErr := os.Readlink(fmt.Sprintf("/proc/%d/exe", id))
		status, statusErr := linuxclient.ReadStatus("/run/loom-client/status.json")
		currentStore, loadErr := deviceclient.Load(options.State)
		if stateErr == nil && pidErr == nil && readErr == nil && state == "active" && actual == binary && statusErr == nil && loadErr == nil && currentStore.LKG() != nil && status.DeviceID == lkg.View.DeviceID && status.ViewDigest == currentStore.LKG().ViewDigest {
			idle := currentStore.LKG().View.RuntimeProfile == nil && len(currentStore.LKG().View.InboundCredentials) == 0
			if status.Runtime == "running" || idle && status.Runtime == "stopped" {
				break
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return errors.New("exact service process and current authenticated runtime were not read back")
		case <-ticker.C:
		}
	}
	if err = protectedDirectory("/usr/local/bin", 0o755); err != nil {
		return err
	}
	if err = replaceInstallLink("/usr/local/bin/loom", filepath.Join(installRoot, "current", "loom")); err != nil {
		return err
	}
	succeeded = true
	if current != nil && currentPath != release {
		if err = removeReplacedPrograms(currentPath, *current); err != nil {
			return fmt.Errorf("new runtime is active; replaced program cleanup remains incomplete: %w", err)
		}
	}
	if err = removeSupersededPrograms(public, candidate.Manifest, release); err != nil {
		return fmt.Errorf("new runtime is active; replaced program cleanup remains incomplete: %w", err)
	}
	fmt.Fprintln(options.Log, "Exact Linux runtime installed and read back; inspect client status and the private signed report for business results.")
	return nil
}

// A unit is a projection of signed package bytes and explicit local inputs.
// A candidate projection is also accepted while inactive after an interrupted
// install between the unit write and current rename.
func checkManagedUnit(ctx context.Context, body, candidate []byte, currentPath string, current *Manifest, options InstallOptions) error {
	fragment, err := systemdProperty(ctx, "FragmentPath")
	if err != nil || fragment != "" && fragment != installUnit {
		return errors.New("service is loaded from an unmanaged path")
	}
	dropins, err := systemdProperty(ctx, "DropInPaths")
	if err != nil || dropins != "" {
		return errors.New("service has unmanaged drop-ins")
	}
	state, err := systemdProperty(ctx, "ActiveState")
	if err != nil {
		return err
	}
	inactive := state == "inactive" || state == "failed"
	if len(body) == 0 {
		if fragment != "" || !inactive {
			return errors.New("service has no managed unit file")
		}
		return nil
	}
	if bytes.Equal(body, candidate) && inactive {
		return nil
	}
	if current == nil {
		return errors.New("existing unit has no accepted package; verified forward cutover is required")
	}
	var template []byte
	for _, file := range current.Files {
		if file.Path != "systemd/loom-client.service" {
			continue
		}
		template, err = installedFile(filepath.Join(currentPath, file.Path), int64(file.Size), 0o644)
		if err != nil || sha256Hex(template) != file.SHA256 {
			return errors.New("accepted service template changed")
		}
	}
	matched := false
	for _, capture := range []string{"mixed", "tun"} {
		for _, management := range []bool{false, true} {
			expected, projectionErr := serviceUnit(string(template), currentPath, options.State, options.ResourceInputs, capture, management)
			matched = matched || projectionErr == nil && len(template) != 0 && bytes.Equal(body, expected)
		}
	}
	if !matched {
		return errors.New("existing runtime unit differs from the requested managed installation")
	}
	if !inactive {
		pid, err := systemdProperty(ctx, "MainPID")
		id, _ := strconv.Atoi(pid)
		actual, readErr := os.Readlink(fmt.Sprintf("/proc/%d/exe", id))
		if err != nil || readErr != nil || actual != filepath.Join(currentPath, "loom") {
			return errors.New("running service does not match the accepted executable")
		}
	}
	return nil
}

func removeReplacedPrograms(directory string, previous Manifest) error {
	for _, component := range []Component{previous.Loom, previous.SingBox} {
		path := filepath.Join(directory, component.Path)
		body, err := installedFile(path, maxArchiveBytes, 0o755)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil || sha256Hex(body) != component.SHA256 {
			return errors.New("replaced executable ownership or bytes differ; retained for inspection")
		}
		if err = os.Remove(path); err != nil {
			return err
		}
	}
	return syncDirectory(directory)
}

// Retry after an accepted but failed activation has no previous-pointer store.
// Signed manifests already identify older packages in our protected content
// directory. Only their exact owned executables are retired; newer caches,
// unknown entries and original signed evidence are untouched.
func removeSupersededPrograms(public ed25519.PublicKey, current Manifest, release string) error {
	root := filepath.Join(installRoot, "releases")
	entries, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		path := filepath.Join(root, entry.Name())
		if path == release || !lowerHex(entry.Name(), 64) || !entry.IsDir() {
			continue
		}
		if err := checkDirectory(path, 0o755, false); err != nil {
			continue
		}
		body, err := installedFile(filepath.Join(path, "manifest.json"), 64<<10, 0o644)
		if err != nil || sha256Hex(body) != entry.Name() {
			continue
		}
		signature, err := installedFile(filepath.Join(path, "manifest.sig"), ed25519.SignatureSize, 0o644)
		if err != nil {
			continue
		}
		manifest, err := verifyManifest(body, signature, public)
		if err != nil || manifest.Arch != current.Arch || manifest.Generation >= current.Generation {
			continue
		}
		if err := removeReplacedPrograms(path, manifest); err != nil {
			return err
		}
	}
	return nil
}

// installationInputs is shared by read-only inspection and locked installation.
// It checks the original unit and exact executables without writing or running
// them, including when an interrupted first installation has no current link.
func installationInputs(ctx context.Context, options InstallOptions, release, currentPath string, current *Manifest) ([]byte, []byte, error) {
	for _, path := range []string{"/var/lib/loom/release-floor.json", "/var/lib/loom-device/migration-overlay.json", "/var/lib/loom/client-v2", "/etc/loom/agent/v2", "/etc/loom/sing-box/v2", "/etc/systemd/system/loom-client.service.d/00-host-network-quarantine.conf"} {
		if _, err := os.Lstat(path); err == nil {
			return nil, nil, errors.New("protected prior deployment needs a verified forward cutover")
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, nil, err
		}
	}
	for _, unit := range []string{"loom-client-v2.service", "loom-client-v2-agent.service", "loom-client-v2-sing-box.service", "loom-client-v2-report.service"} {
		body, err := exec.CommandContext(ctx, "systemctl", "show", unit, "--property=LoadState", "--value").Output()
		if err != nil || strings.TrimSpace(string(body)) != "not-found" {
			return nil, nil, errors.New("prior runtime entry remains; verified cutover must remove it")
		}
	}
	management := false
	if store, err := deviceclient.Load(options.State); err == nil && store.LKG() != nil {
		management = needsManagementTUN(store.LKG().View)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, nil, err
	}
	unit, err := ServiceUnit(release, options.State, options.ResourceInputs, options.Capture, management)
	if err != nil {
		return nil, nil, err
	}
	previousUnit, err := installedFile(installUnit, 64<<10, 0o644)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, nil, err
	}
	if err = checkManagedUnit(ctx, previousUnit, unit, currentPath, current, options); err != nil {
		return nil, nil, err
	}
	if info, err := os.Lstat("/usr/local/bin/loom"); err == nil {
		target, linkErr := os.Readlink("/usr/local/bin/loom")
		owner, ok := info.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != 0 || linkErr != nil || target != filepath.Join(installRoot, "current", "loom") {
			return nil, nil, errors.New("existing CLI entry needs an explicit verified cutover")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, nil, err
	}
	if current != nil {
		for _, component := range []Component{current.Loom, current.SingBox} {
			body, err := installedFile(filepath.Join(currentPath, component.Path), maxArchiveBytes, 0o755)
			if err != nil || sha256Hex(body) != component.SHA256 {
				return nil, nil, errors.New("accepted executable changed; refusing to execute its cleanup")
			}
		}
	}
	return unit, previousUnit, nil
}
