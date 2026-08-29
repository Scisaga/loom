package enrollssh

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// PreflightScript is the complete, fixed remote discovery program. No
// operator-provided value is formatted into it.
const PreflightScript = `set -eu
set -f

hostname_value=$(hostname -s)
uname_value=$(uname -srmo 2>/dev/null || uname -a)

kernel_wireguard=0
if [ -d /sys/module/wireguard ] || grep -qw wireguard /proc/modules 2>/dev/null || { command -v modprobe >/dev/null 2>&1 && modprobe -n wireguard >/dev/null 2>&1; }; then
    kernel_wireguard=1
fi

wg_command=0
if [ -x /usr/bin/wg ]; then
    wg_command=1
fi

privilege=unavailable
if [ "$(id -u)" = 0 ]; then
    privilege=root
elif command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then
    privilege=sudo-nopasswd
fi

ssh_server=
if [ -n "${SSH_CONNECTION:-}" ]; then
    set -- $SSH_CONNECTION
    if [ "$#" = 4 ]; then
        ssh_server=$3
    fi
fi

printf '%s\n' 'LOOM_PREFLIGHT_V1'
printf 'hostname=%s\n' "$hostname_value"
printf 'uname=%s\n' "$uname_value"
printf 'kernel_wireguard=%s\n' "$kernel_wireguard"
printf 'wg_command=%s\n' "$wg_command"
printf 'privilege=%s\n' "$privilege"
printf 'ssh_server=%s\n' "$ssh_server"
`

// InstallWireGuardToolsScript is the fixed, idempotent package bootstrap used
// only after an authenticated preflight proves both kernel support and root or
// passwordless-sudo authority. It never upgrades an already present wg binary.
const InstallWireGuardToolsScript = `set -eu
set -f

installed=0
if [ ! -x /usr/bin/wg ]; then
    if [ "$(id -u)" = 0 ]; then
        privilege=root
    elif command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then
        privilege=sudo-nopasswd
    else
        echo 'root or passwordless sudo is required to install wireguard-tools' >&2
        exit 43
    fi

    run_privileged() {
        if [ "$privilege" = root ]; then
            "$@"
        else
            sudo -n "$@"
        fi
    }

    if command -v apt-get >/dev/null 2>&1; then
        run_privileged env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=60 -o Acquire::Retries=2 update >/dev/null
        run_privileged env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=60 -y --no-install-recommends install wireguard-tools >/dev/null
    elif command -v dnf >/dev/null 2>&1; then
        run_privileged dnf -y install wireguard-tools >/dev/null
    elif command -v yum >/dev/null 2>&1; then
        run_privileged yum -y install wireguard-tools >/dev/null
    elif command -v apk >/dev/null 2>&1; then
        run_privileged apk add --no-cache wireguard-tools >/dev/null
    elif command -v zypper >/dev/null 2>&1; then
        run_privileged zypper --non-interactive install wireguard-tools >/dev/null
    else
        echo 'no supported package manager found (apt-get, dnf, yum, apk or zypper)' >&2
        exit 44
    fi
    [ -x /usr/bin/wg ] || { echo 'wireguard-tools installation completed without providing /usr/bin/wg' >&2; exit 45; }
    installed=1
fi

printf '%s\n' 'LOOM_WG_TOOLS_V1'
printf 'installed=%s\n' "$installed"
`

// PrepareWGScript is a fixed privileged program. It reuses an existing
// regular key or publishes a newly generated key through a same-filesystem
// hard link. Hostname, the actual SSH server address and the WG public key are
// returned by this one SSH session; node.key never leaves the host.
const PrepareWGScript = `set -eu
hostname_value=$(hostname -s)
ssh_server=
if [ -n "${SSH_CONNECTION:-}" ]; then
    set -- $SSH_CONNECTION
    if [ "$#" = 4 ]; then
        ssh_server=$3
    fi
fi
if [ "$(id -u)" = 0 ]; then
    set -- /bin/sh
else
    command -v sudo >/dev/null 2>&1 || { echo 'passwordless sudo is required' >&2; exit 39; }
    set -- sudo -n /bin/sh
fi
public_key=$("$@" -s -- <<'LOOM_WG_PRIVILEGED'
set -eu
umask 077

directory=/etc/wireguard
key=$directory/node.key

if [ -L "$directory" ]; then
    echo 'wireguard directory must not be a symlink' >&2
    exit 40
fi
install -d -m 700 "$directory"
if [ -L "$key" ] || { [ -e "$key" ] && [ ! -f "$key" ]; }; then
    echo 'node WireGuard key must be a regular file' >&2
    exit 41
fi

if [ ! -e "$key" ]; then
    temporary=$(mktemp "$directory/.node.key.XXXXXX")
    trap 'rm -f "$temporary"' EXIT HUP INT TERM
    /usr/bin/wg genkey >"$temporary"
    chmod 600 "$temporary"
    if ! ln "$temporary" "$key" 2>/dev/null; then
        if [ -L "$key" ] || [ ! -f "$key" ]; then
            echo 'could not publish node WireGuard key safely' >&2
            exit 42
        fi
    fi
    rm -f "$temporary"
    trap - EXIT HUP INT TERM
fi

chmod 600 "$key"
/usr/bin/wg pubkey <"$key"
LOOM_WG_PRIVILEGED
)
printf '%s\n' 'LOOM_WG_PREPARE_V1'
printf 'hostname=%s\n' "$hostname_value"
printf 'ssh_server=%s\n' "$ssh_server"
printf 'public_key=%s\n' "$public_key"
`

// Privilege is the fixed preflight privilege classification.
type Privilege string

const (
	PrivilegeRoot        Privilege = "root"
	PrivilegeSudo        Privilege = "sudo-nopasswd"
	PrivilegeUnavailable Privilege = "unavailable"
)

// PreflightResult contains only observations made through the authenticated
// SSH session. ObservedSSHServerAddress is a candidate for later control-plane
// endpoint discovery; it is not evidence that an address is public or that UDP
// is reachable.
type PreflightResult struct {
	Hostname                 string
	Uname                    string
	KernelWireGuard          bool
	WGCommand                bool
	Privilege                Privilege
	ObservedSSHServerAddress string
}

type PrepareWGResult struct {
	Hostname                 string
	ObservedSSHServerAddress string
	PublicKey                string
}

// Client runs fixed remote programs using one specified identity and one
// package-owned known_hosts file.
type Client struct {
	Runner         Runner
	PrivateKeyPath string
	KnownHostsPath string
	Timeout        time.Duration
	InstallTimeout time.Duration
	ConnectTimeout time.Duration
	OutputLimit    int
}

// Preflight discovers identity and capabilities without changing the remote
// host.
func (c Client) Preflight(ctx context.Context, connection Connection) (PreflightResult, error) {
	result, err := c.runScript(ctx, connection, "SSH preflight", PreflightScript)
	if err != nil {
		return PreflightResult{}, err
	}
	parsed, err := parsePreflight(result.Stdout)
	if err != nil {
		return PreflightResult{}, fmt.Errorf("invalid SSH preflight output: %w", err)
	}
	return parsed, nil
}

// EnsureWireGuardTools installs the distribution package only when wg is
// absent. The caller must first establish authenticated host identity and
// preflight privilege; the script repeats that privilege check fail-closed.
func (c Client) EnsureWireGuardTools(ctx context.Context, connection Connection) (bool, error) {
	result, err := c.runScriptWithTimeout(ctx, connection, "install remote wireguard-tools", InstallWireGuardToolsScript, c.InstallTimeout, defaultInstallTimeout)
	if err != nil {
		return false, err
	}
	installed, err := parseWireGuardToolsInstall(result.Stdout)
	if err != nil {
		return false, fmt.Errorf("invalid wireguard-tools installation output: %w", err)
	}
	return installed, nil
}

// PrepareWG idempotently creates /etc/wireguard/node.key through sudo and
// returns only its public WireGuard key.
func (c Client) PrepareWG(ctx context.Context, connection Connection) (PrepareWGResult, error) {
	result, err := c.runScript(ctx, connection, "prepare remote WireGuard identity", PrepareWGScript)
	if err != nil {
		return PrepareWGResult{}, err
	}
	prepared, err := parsePrepareWG(result.Stdout)
	if err != nil {
		return PrepareWGResult{}, fmt.Errorf("invalid remote WireGuard output: %w", err)
	}
	return prepared, nil
}

func parsePrepareWG(output []byte) (PrepareWGResult, error) {
	lines := strings.Split(strings.TrimSuffix(string(output), "\n"), "\n")
	if len(lines) != 4 || lines[0] != "LOOM_WG_PREPARE_V1" {
		return PrepareWGResult{}, errors.New("expected LOOM_WG_PREPARE_V1 and exactly three fields")
	}
	values := map[string]string{}
	for _, line := range lines[1:] {
		key, value, ok := strings.Cut(line, "=")
		if !ok || (key != "hostname" && key != "ssh_server" && key != "public_key") {
			return PrepareWGResult{}, fmt.Errorf("unexpected field %q", line)
		}
		if _, duplicate := values[key]; duplicate {
			return PrepareWGResult{}, fmt.Errorf("duplicate field %q", key)
		}
		values[key] = value
	}
	if err := validateObservedHostname(values["hostname"]); err != nil {
		return PrepareWGResult{}, fmt.Errorf("invalid hostname: %w", err)
	}
	if net.ParseIP(values["ssh_server"]) == nil {
		return PrepareWGResult{}, errors.New("ssh_server is not an IP address from SSH_CONNECTION")
	}
	if err := validateWGPublicKey(values["public_key"]); err != nil {
		return PrepareWGResult{}, err
	}
	return PrepareWGResult{
		Hostname: values["hostname"], ObservedSSHServerAddress: values["ssh_server"],
		PublicKey: values["public_key"],
	}, nil
}

func parseWireGuardToolsInstall(output []byte) (bool, error) {
	lines := strings.Split(strings.TrimSuffix(string(output), "\n"), "\n")
	if len(lines) != 2 || lines[0] != "LOOM_WG_TOOLS_V1" {
		return false, errors.New("expected LOOM_WG_TOOLS_V1 and exactly one field")
	}
	key, value, ok := strings.Cut(lines[1], "=")
	if !ok || key != "installed" {
		return false, fmt.Errorf("unexpected field %q", lines[1])
	}
	return parseScriptBool(value)
}

func (c Client) runScript(ctx context.Context, connection Connection, operation, script string) (Result, error) {
	return c.runScriptWithTimeout(ctx, connection, operation, script, c.Timeout, defaultSSHTimeout)
}

func (c Client) runScriptWithTimeout(ctx context.Context, connection Connection, operation, script string, configuredTimeout, fallbackTimeout time.Duration) (Result, error) {
	if err := connection.Validate(); err != nil {
		return Result{}, err
	}
	if err := validateSecureInputFile(c.PrivateKeyPath, "SSH private key"); err != nil {
		return Result{}, err
	}
	snapshot, err := readKnownHosts(c.KnownHostsPath)
	if err != nil {
		return Result{}, err
	}
	if !snapshot.exists {
		return Result{}, errors.New("control known_hosts does not exist")
	}
	timeoutDuration, err := timeout(configuredTimeout, fallbackTimeout)
	if err != nil {
		return Result{}, fmt.Errorf("invalid SSH timeout: %w", err)
	}
	connectSeconds, err := connectTimeoutSeconds(c.ConnectTimeout)
	if err != nil {
		return Result{}, err
	}
	limit, err := outputLimit(c.OutputLimit)
	if err != nil {
		return Result{}, fmt.Errorf("invalid SSH output limit: %w", err)
	}
	sshCtx, cancel := context.WithTimeout(ctx, timeoutDuration)
	defer cancel()
	args := []string{
		"-F", "/dev/null",
		"-o", "BatchMode=yes",
		"-o", "IdentitiesOnly=yes",
		"-o", "StrictHostKeyChecking=yes",
		"-o", "HostKeyAlgorithms=ssh-ed25519",
		"-o", "GlobalKnownHostsFile=/dev/null",
		"-o", "UserKnownHostsFile=" + c.KnownHostsPath,
		"-o", "UpdateHostKeys=no",
		"-o", "ClearAllForwardings=yes",
		"-o", "RequestTTY=no",
		"-o", "ConnectTimeout=" + strconv.Itoa(connectSeconds),
		"-i", c.PrivateKeyPath,
		"-p", strconv.Itoa(connection.Port),
		"--", connection.destination(),
		"/bin/sh", "-s", "--",
	}
	invocation := Invocation{
		Program:     "ssh",
		Args:        args,
		Stdin:       []byte(script),
		StdoutLimit: limit,
		StderrLimit: limit,
	}
	result, runErr := runnerOrDefault(c.Runner).Run(sshCtx, invocation)
	if err := commandError(operation, sshCtx, result, runErr); err != nil {
		return Result{}, err
	}
	return result, nil
}

func validateSecureInputFile(path, label string) error {
	if err := validateLocalPath(path, label); err != nil {
		return err
	}
	if err := validateSecureParentPath(path, label, false); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect %s: %w", label, err)
	}
	if err := validateSecureFileMetadata(info, label); err != nil {
		return err
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("open %s without following symlinks: %w", label, err)
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return fmt.Errorf("inspect open %s: %w", label, err)
	}
	if !os.SameFile(info, opened) {
		return fmt.Errorf("%s changed while opening", label)
	}
	return validateSecureFileMetadata(opened, label)
}

func validateSecureFileMetadata(info os.FileInfo, label string) error {
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s must be a regular file; symlinks are not accepted", label)
	}
	uid, err := unixFileOwner(info)
	if err != nil {
		return fmt.Errorf("inspect %s owner: %w", label, err)
	}
	if uid != uint32(os.Geteuid()) {
		return fmt.Errorf("%s owner is uid %d, require current euid %d", label, uid, os.Geteuid())
	}
	if info.Mode().Perm() != 0o600 {
		return fmt.Errorf("%s permissions are %04o, require exactly 0600", label, info.Mode().Perm())
	}
	return nil
}

type secureParentDirectory struct {
	path string
	mode os.FileMode
	uid  uint32
}

// validateSecureParentPath checks every existing path component without
// following symlinks. Shared sticky ancestors such as /tmp are accepted only
// when their immediate child is an owner-controlled, non-writable directory;
// the shared directory itself is never accepted as the direct parent.
func validateSecureParentPath(path, label string, create bool) error {
	if filepath.Clean(path) != path {
		return fmt.Errorf("%s path must be clean", label)
	}
	parent := filepath.Dir(path)
	paths := secureParentPaths(parent)
	directories := make([]secureParentDirectory, 0, len(paths))
	missing := false
	for _, current := range paths {
		var info os.FileInfo
		if !missing {
			var err error
			info, err = os.Lstat(current)
			if errors.Is(err, os.ErrNotExist) {
				missing = true
			} else if err != nil {
				return fmt.Errorf("inspect %s parent %q: %w", label, current, err)
			}
		}
		if missing {
			if create {
				if err := os.Mkdir(current, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
					return fmt.Errorf("create %s parent %q: %w", label, current, err)
				}
				var err error
				info, err = os.Lstat(current)
				if err != nil {
					return fmt.Errorf("inspect created %s parent %q: %w", label, current, err)
				}
				missing = false
			} else {
				directories = append(directories, secureParentDirectory{path: current, mode: 0o700 | os.ModeDir, uid: uint32(os.Geteuid())})
				continue
			}
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s parent %q must be a directory and not a symlink", label, current)
		}
		uid, err := unixFileOwner(info)
		if err != nil {
			return fmt.Errorf("inspect %s parent owner %q: %w", label, current, err)
		}
		directories = append(directories, secureParentDirectory{path: current, mode: info.Mode(), uid: uid})
	}
	for i, directory := range directories {
		if directory.mode.Perm()&0o022 == 0 {
			continue
		}
		if directory.mode&os.ModeSticky == 0 || i+1 >= len(directories) {
			return fmt.Errorf("%s parent %q is group/world writable", label, directory.path)
		}
		child := directories[i+1]
		if child.mode.Perm()&0o022 != 0 || (child.uid != uint32(os.Geteuid()) && child.uid != 0) {
			return fmt.Errorf("%s parent %q is not protected beneath sticky directory %q", label, child.path, directory.path)
		}
	}
	return nil
}

func ensureSecureParentDirectory(path, label string) error {
	if err := validateLocalPath(path, label); err != nil {
		return err
	}
	return validateSecureParentPath(path, label, true)
}

func secureParentPaths(parent string) []string {
	if parent == string(filepath.Separator) {
		return []string{parent}
	}
	parts := strings.Split(strings.TrimPrefix(parent, string(filepath.Separator)), string(filepath.Separator))
	paths := make([]string, 0, len(parts)+1)
	current := string(filepath.Separator)
	paths = append(paths, current)
	for _, part := range parts {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		paths = append(paths, current)
	}
	return paths
}

func unixFileOwner(info os.FileInfo) (uint32, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, errors.New("filesystem did not expose Unix ownership")
	}
	return stat.Uid, nil
}

func parsePreflight(output []byte) (PreflightResult, error) {
	if len(output) == 0 {
		return PreflightResult{}, errors.New("empty output")
	}
	lines := strings.Split(strings.TrimSuffix(string(output), "\n"), "\n")
	if len(lines) == 0 || lines[0] != "LOOM_PREFLIGHT_V1" {
		return PreflightResult{}, errors.New("missing LOOM_PREFLIGHT_V1 header")
	}
	values := make(map[string]string, 6)
	allowed := map[string]bool{
		"hostname": true, "uname": true, "kernel_wireguard": true,
		"wg_command": true, "privilege": true, "ssh_server": true,
	}
	for _, line := range lines[1:] {
		key, value, ok := strings.Cut(line, "=")
		if !ok || !allowed[key] {
			return PreflightResult{}, fmt.Errorf("unexpected field %q", line)
		}
		if _, duplicate := values[key]; duplicate {
			return PreflightResult{}, fmt.Errorf("duplicate field %q", key)
		}
		if strings.ContainsAny(value, "\x00\r") {
			return PreflightResult{}, fmt.Errorf("field %q contains control bytes", key)
		}
		values[key] = value
	}
	for key := range allowed {
		if _, ok := values[key]; !ok {
			return PreflightResult{}, fmt.Errorf("missing field %q", key)
		}
	}
	if err := validateObservedHostname(values["hostname"]); err != nil {
		return PreflightResult{}, fmt.Errorf("invalid hostname: %w", err)
	}
	if values["uname"] == "" || len(values["uname"]) > 512 || strings.TrimSpace(values["uname"]) != values["uname"] {
		return PreflightResult{}, errors.New("invalid uname value")
	}
	kernel, err := parseScriptBool(values["kernel_wireguard"])
	if err != nil {
		return PreflightResult{}, fmt.Errorf("invalid kernel_wireguard: %w", err)
	}
	wg, err := parseScriptBool(values["wg_command"])
	if err != nil {
		return PreflightResult{}, fmt.Errorf("invalid wg_command: %w", err)
	}
	privilege := Privilege(values["privilege"])
	if privilege != PrivilegeRoot && privilege != PrivilegeSudo && privilege != PrivilegeUnavailable {
		return PreflightResult{}, fmt.Errorf("invalid privilege %q", privilege)
	}
	server := values["ssh_server"]
	if net.ParseIP(server) == nil {
		return PreflightResult{}, errors.New("ssh_server is not an IP address from SSH_CONNECTION")
	}
	return PreflightResult{
		Hostname:                 values["hostname"],
		Uname:                    values["uname"],
		KernelWireGuard:          kernel,
		WGCommand:                wg,
		Privilege:                privilege,
		ObservedSSHServerAddress: server,
	}, nil
}

func parseScriptBool(s string) (bool, error) {
	switch s {
	case "0":
		return false, nil
	case "1":
		return true, nil
	default:
		return false, fmt.Errorf("expected 0 or 1, got %q", s)
	}
}

func validateObservedHostname(hostname string) error {
	if hostname == "" || len(hostname) > 63 || strings.TrimSpace(hostname) != hostname {
		return errors.New("hostname must contain 1-63 bytes without surrounding whitespace")
	}
	for i, r := range hostname {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_') {
			return errors.New("hostname contains characters unsafe for a node identifier")
		}
		if i == 0 && r == '-' {
			return errors.New("hostname cannot start with '-'")
		}
	}
	return nil
}
