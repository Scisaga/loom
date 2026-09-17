package report

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"loom/internal/clientdist"
	"loom/internal/clientregistry"
	"loom/internal/clientrelease"
	"loom/internal/model"
	"loom/internal/version"
	"loom/internal/webui"
)

// verifiedClientPackageCache retains only bytes that already passed the full
// package verification. The build script publishes every file by atomic rename,
// so an identity change on any member invalidates the cached generation.
type verifiedClientPackageCache struct {
	mu        sync.Mutex
	paths     []string
	state     []os.FileInfo
	published clientdist.Published
	verifyErr error
	ready     bool
	verify    func() (clientdist.Published, error)
}

func (c *verifiedClientPackageCache) load() (clientdist.Published, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	state, err := clientPackageFileState(c.paths)
	if err != nil {
		return clientdist.Published{}, err
	}
	if c.ready && sameClientPackageFileState(c.state, state) {
		return c.published, c.verifyErr
	}
	published, verifyErr := c.verify()
	after, err := clientPackageFileState(c.paths)
	if err != nil {
		return clientdist.Published{}, err
	}
	if !sameClientPackageFileState(state, after) {
		return clientdist.Published{}, errors.New("Linux client package changed during verification")
	}
	c.state, c.published, c.verifyErr, c.ready = after, published, verifyErr, true
	return c.published, c.verifyErr
}

func clientPackageFileState(paths []string) ([]os.FileInfo, error) {
	state := make([]os.FileInfo, 0, len(paths))
	for _, path := range paths {
		info, err := os.Lstat(path)
		if err != nil {
			return nil, err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || !ok || stat.Nlink != 1 {
			return nil, fmt.Errorf("Linux client package member %s is not a single-link regular file", path)
		}
		state = append(state, info)
	}
	return state, nil
}

func sameClientPackageFileState(a, b []os.FileInfo) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !os.SameFile(a[i], b[i]) || a[i].Size() != b[i].Size() ||
			a[i].Mode() != b[i].Mode() || !a[i].ModTime().Equal(b[i].ModTime()) {
			return false
		}
	}
	return true
}

func newClientControlDeps(c *Control, _ ...func()) *webui.ClientControlDeps {
	if c == nil || strings.TrimSpace(c.ClientRegistryPath) == "" {
		return nil
	}
	store := clientregistry.Store{Path: c.ClientRegistryPath}
	platformPublicKeyPath := "/etc/loom/trust/platform.pub"
	packageCache := verifiedClientPackageCache{
		paths: []string{
			c.ClientLinuxPackagePath,
			c.ClientLinuxPackagePath + ".sha256",
			c.ClientLinuxPackagePath + ".sig",
			platformPublicKeyPath,
		},
		verify: func() (clientdist.Published, error) {
			return clientdist.VerifyFiles(c.ClientLinuxPackagePath, platformPublicKeyPath)
		},
	}
	loadPublishedLinuxPackage := packageCache.load
	loadLinuxPackage := func() (webui.LinuxClientPackageView, []byte, error) {
		published, err := loadPublishedLinuxPackage()
		if err != nil {
			return webui.LinuxClientPackageView{}, nil, err
		}
		view := webui.LinuxClientPackageView{
			Filename: filepath.Base(c.ClientLinuxPackagePath), URL: "/devices/download/linux-amd64",
			SHA256: published.SHA256, Version: version.Short(published.Manifest.Loom.Commit),
			Arch: published.Manifest.OS + "/" + published.Manifest.Arch, Size: published.Size,
		}
		if base, err := validClientPublicBaseURL(c.ClientPublicBaseURL); err == nil {
			view.PublicURL = base + view.Filename
			view.InstallerURL = base + "install.sh"
		}
		return view, published.Archive, nil
	}
	releaseKey, _ := clientrelease.PublicKey(platformPublicKeyPath)
	deps := &webui.ClientControlDeps{
		Releases: &clientrelease.Store{Root: filepath.Join(filepath.Dir(c.ClientLinuxPackagePath), "releases"), Key: releaseKey},
		LinuxPackage: func() (webui.LinuxClientPackageView, error) {
			view, _, err := loadLinuxPackage()
			return view, err
		},
		DownloadLinuxPackage: loadLinuxPackage,
		PublicLinuxArtifact: func(name string) (webui.PublicDeviceArtifact, error) {
			published, err := loadPublishedLinuxPackage()
			if err != nil {
				return webui.PublicDeviceArtifact{}, err
			}
			archiveName := filepath.Base(c.ClientLinuxPackagePath)
			artifact := webui.PublicDeviceArtifact{Filename: name}
			switch name {
			case archiveName:
				artifact.ContentType, artifact.Body = "application/gzip", published.Archive
			case archiveName + ".sha256":
				artifact.ContentType, artifact.Body = "text/plain; charset=utf-8", published.Checksum
			case archiveName + ".sig":
				artifact.ContentType, artifact.Body = "application/json; charset=utf-8", published.Signature
			case "platform-signing.pub":
				artifact.ContentType, artifact.Body = "text/plain; charset=utf-8", published.PublicKey
			default:
				return webui.PublicDeviceArtifact{}, fmt.Errorf("public Device artifact %q is not published", name)
			}
			return artifact, nil
		},
		LinuxInstallScript: func() ([]byte, error) {
			view, _, err := loadLinuxPackage()
			if err != nil {
				return nil, err
			}
			if view.PublicURL == "" {
				return nil, fmt.Errorf("client_public_base_url is not configured")
			}
			return linuxPublicInstallScript(view), nil
		},
		EnrollmentOptions: func() (webui.DeviceEnrollmentOptions, error) {
			return deviceEnrollmentOptions(c)
		},
		List: func() (webui.ClientInventory, error) {
			clients, invites, err := store.List()
			if err != nil {
				return webui.ClientInventory{}, err
			}
			inventory := webui.ClientInventory{Clients: make([]webui.ClientView, 0, len(clients))}
			now := time.Now().UTC()
			seen := make(map[string]bool, len(clients))
			for _, client := range clients {
				dataPlaneStatus, configState := "pending", "pending"
				if client.Status == "revoked" {
					dataPlaneStatus, configState = "not applicable", "not applicable"
				}
				seen[client.ID] = true
				inventory.Clients = append(inventory.Clients, webui.ClientView{
					ID: client.ID, Name: client.Name, Platform: client.Platform,
					IdentitySource: client.IdentitySource,
					ReplacedBy:     client.ReplacedBy, Replaces: client.Replaces,
					Status: client.Status, KeyFingerprint: client.KeyFingerprint,
					CreatedAt: client.CreatedAt, EnrolledAt: client.EnrolledAt,
					DataPlaneStatus: dataPlaneStatus, ConfigState: configState,
					Membership:        registryMembership(client.Status),
					Responsibilities:  append([]string(nil), client.Responsibilities...),
					DestinationGrants: append([]string(nil), client.DestinationGrants...),
					Direction:         client.Direction,
				})
			}
			for _, invite := range invites {
				if invite.ConsumedAt != "" {
					continue
				}
				expires, err := time.Parse(time.RFC3339, invite.ExpiresAt)
				if err == nil && now.Before(expires) {
					inventory.ActiveInvites++
				}
			}

			// SSOT currently owns responsibilities, grants and generated network
			// intent. Merge every declared machine, not only access nodes, so the
			// product presents one Device inventory while identity/intent storage is
			// migrated behind this projection.
			ssot, _, err := loadValidatedSSOTSnapshot(c.SSOTPath)
			if err != nil {
				return webui.ClientInventory{}, fmt.Errorf("read SSOT device inventory: %w", err)
			}
			controlID, _ := controlNodeID(c)
			for i := range ssot.Nodes {
				node := &ssot.Nodes[i]
				if seen[node.ID] {
					for i := range inventory.Clients {
						if inventory.Clients[i].ID == node.ID {
							applyDeviceDeclaration(&inventory.Clients[i], ssot, node, controlID, false)
						}
					}
					continue
				}
				name := strings.TrimSpace(node.Name)
				if name == "" {
					name = node.ID
				}
				device := webui.ClientView{ID: node.ID, Name: name, Status: "managed"}
				applyDeviceDeclaration(&device, ssot, node, controlID, true)
				inventory.Clients = append(inventory.Clients, device)
			}
			return inventory, nil
		},
	}
	// Pay the full verification cost during control-plane startup instead of on
	// the first operator request. A missing package is non-fatal and remains a
	// cached unavailable state until one of its atomic files changes.
	_, _ = packageCache.load()
	return deps
}

func registryMembership(status string) string {
	switch status {
	case "ready", "managed", "online", "stale", "problem", "decommissioned":
		return "active"
	case "provisioning":
		return "joining"
	case "revoked":
		return "revoked"
	default:
		return "identity only"
	}
}

func applyDeviceDeclaration(device *webui.ClientView, ssot *model.SSOT, node *model.Node, controlID string, legacy bool) {
	if device == nil || node == nil {
		return
	}
	device.Legacy = legacy
	device.Membership = "active"
	if node.Paused {
		device.Membership = "paused"
	}
	if node.Decommission {
		device.Membership = "decommissioned"
	}
	device.DataPlaneStatus = "declared"
	device.ConfigState = "managed by SSOT"
	device.Responsibilities = nil
	device.DestinationGrants = nil
	if node.Access != nil {
		device.Platform = string(node.Access.Platform)
		device.Responsibilities = append(device.Responsibilities, "use_loom")
	}
	if node.Server != nil {
		device.Responsibilities = append(device.Responsibilities, "forward")
		device.PublicEndpoint = node.PublicEndpoint
		device.InboundPort = node.Server.InboundPort
		device.Direction = string(node.Server.Direction)
		device.EgressCapable = node.Server.EgressCapable
		if node.Server.EgressCapable {
			device.Responsibilities = append(device.Responsibilities, "internet_egress")
		}
	}
	if node.ID == controlID {
		device.Responsibilities = append(device.Responsibilities, "control")
	}
	if node.Access == nil || ssot == nil {
		return
	}
	credentials := ssot.CredentialByID()
	seen := map[string]bool{}
	for _, credentialID := range node.Access.Credentials {
		credential := credentials[credentialID]
		if credential == nil || credential.Declaration == "" || seen[credential.Declaration] {
			continue
		}
		seen[credential.Declaration] = true
		device.DestinationGrants = append(device.DestinationGrants, credential.Declaration)
	}
}

func deviceEnrollmentOptions(c *Control) (webui.DeviceEnrollmentOptions, error) {
	if c == nil {
		return webui.DeviceEnrollmentOptions{}, fmt.Errorf("control configuration is unavailable")
	}
	ssot, _, err := loadValidatedSSOTSnapshot(c.SSOTPath)
	if err != nil {
		return webui.DeviceEnrollmentOptions{}, fmt.Errorf("read Device enrollment options: %w", err)
	}
	options := webui.DeviceEnrollmentOptions{}
	for _, declaration := range ssot.Declarations {
		if !declaration.AddressFromRequest() {
			continue
		}
		name := strings.TrimSpace(declaration.Name)
		if name == "" {
			name = declaration.ID
		}
		options.DestinationGrants = append(options.DestinationGrants, webui.DeviceDestinationOption{ID: declaration.ID, Name: name})
	}
	return options, nil
}

func validClientPublicBaseURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	parsed, err := url.ParseRequestURI(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("client_public_base_url must be an absolute HTTPS URL without credentials, query, or fragment")
	}
	return strings.TrimRight(parsed.String(), "/") + "/", nil
}

func controlNodeID(c *Control) (string, error) {
	id := strings.TrimSpace(c.Node)
	if !model.ValidNodeID(id) {
		return "", fmt.Errorf("report node %q does not identify the control Device", c.Node)
	}
	return id, nil
}

func linuxPublicInstallScript(view webui.LinuxClientPackageView) []byte {
	archiveURL := shellSingleQuote(view.PublicURL)
	checksumURL := shellSingleQuote(view.PublicURL + ".sha256")
	return []byte(`#!/bin/sh
set -eu
[ "$(id -u)" -eq 0 ] || { echo "run as root: curl -fsSL INSTALL_URL | sudo sh" >&2; exit 1; }
command -v sha256sum >/dev/null 2>&1 || { echo "sha256sum is required" >&2; exit 1; }
command -v tar >/dev/null 2>&1 || { echo "tar is required" >&2; exit 1; }
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
fetch() {
    source=$1
    target=$2
    if command -v curl >/dev/null 2>&1; then
        curl -fL --proto '=https' --tlsv1.2 --retry 2 -o "$target" "$source"
    elif command -v wget >/dev/null 2>&1; then
        wget --https-only -O "$target" "$source"
    else
        echo "curl or wget is required" >&2
        exit 1
    fi
}
archive_url=` + archiveURL + `
checksum_url=` + checksumURL + `
archive=` + shellSingleQuote(view.Filename) + `
fetch "$archive_url" "$tmp/$archive"
fetch "$checksum_url" "$tmp/$archive.sha256"
(cd "$tmp" && sha256sum -c "$archive.sha256")
tar -xzf "$tmp/$archive" -C "$tmp"
"$tmp/loom-client-linux-amd64/install.sh" --no-enroll
echo "Loom installed. Complete enrollment with: sudo /usr/local/bin/loom client enroll -stdin"
`)
}

func shellSingleQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}
