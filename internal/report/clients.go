package report

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"loom/internal/clientdist"
	"loom/internal/clientregistry"
	"loom/internal/model"
	"loom/internal/version"
	"loom/internal/webui"
)

type clientInvitePayload struct {
	Schema    int    `json:"schema"`
	Endpoint  string `json:"endpoint"`
	Token     string `json:"token"`
	ExpiresAt string `json:"expires_at"`
}

type clientProvisionFunc func(client clientregistry.Client, csrPEM string) (*webui.ClientBootstrap, error)

func newClientControlDeps(c *Control, provision clientProvisionFunc) *webui.ClientControlDeps {
	if c == nil || strings.TrimSpace(c.ClientRegistryPath) == "" {
		return nil
	}
	store := clientregistry.Store{Path: c.ClientRegistryPath}
	loadPublishedLinuxPackage := func() (clientdist.Published, error) {
		return clientdist.VerifyFiles(c.ClientLinuxPackagePath, "/etc/loom/trust/platform.pub")
	}
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
	inviteURI := func(token, expires string) (string, error) {
		endpoint, err := validClientEnrollmentURL(c.ClientEnrollmentURL)
		if err != nil {
			return "", err
		}
		body, err := json.Marshal(clientInvitePayload{
			Schema: 1, Endpoint: endpoint, Token: token, ExpiresAt: expires,
		})
		if err != nil {
			return "", err
		}
		// Fragment material is never sent as an HTTP request target. The client
		// decodes it locally and sends the bearer token only in the claim POST body.
		return "loom://enroll#" + base64.RawURLEncoding.EncodeToString(body), nil
	}
	return &webui.ClientControlDeps{
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
		EnrollmentProfile: func() (webui.DeviceEnrollmentProfileView, error) {
			profile, err := defaultDeviceEnrollmentProfile(c)
			if err != nil {
				return webui.DeviceEnrollmentProfileView{}, err
			}
			return deviceEnrollmentProfileView(profile), nil
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
				seen[client.ID] = true
				inventory.Clients = append(inventory.Clients, webui.ClientView{
					ID: client.ID, Name: client.Name, Platform: client.Platform,
					Status: client.Status, KeyFingerprint: client.KeyFingerprint,
					CreatedAt: client.CreatedAt, EnrolledAt: client.EnrolledAt,
					DataPlaneStatus: "pending", ConfigState: "pending",
					Membership:        registryMembership(client.Status),
					ProfileVersion:    client.ProfileVersion,
					Responsibilities:  append([]string(nil), client.Responsibilities...),
					DestinationGrants: append([]string(nil), client.DestinationGrants...),
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
		CreateInvite: func(input webui.ClientInviteInput) (webui.ClientInviteView, error) {
			endpoint, err := validClientEnrollmentURL(c.ClientEnrollmentURL)
			if err != nil {
				return webui.ClientInviteView{}, err
			}
			profile, err := defaultDeviceEnrollmentProfile(c)
			if err != nil {
				return webui.ClientInviteView{}, err
			}
			created, err := store.CreateWithProfile(input.Name, clientregistry.ProfileAssignment{
				Version: profile.Reference(), Digest: profile.Digest(),
				Responsibilities:  append([]string(nil), profile.Responsibilities...),
				DestinationGrants: append([]string(nil), profile.DestinationGrants...),
			})
			if err != nil {
				return webui.ClientInviteView{}, err
			}
			uri, err := inviteURI(created.Token, created.Invite.ExpiresAt)
			if err != nil {
				return webui.ClientInviteView{}, err
			}
			return webui.ClientInviteView{
				InviteID: created.Invite.ID, ClientID: created.Client.ID,
				ClientName: created.Client.Name, InviteURI: uri,
				EnrollmentURL: endpoint, ExpiresAt: created.Invite.ExpiresAt,
				ProfileVersion:    created.Client.ProfileVersion,
				Responsibilities:  append([]string(nil), created.Client.Responsibilities...),
				DestinationGrants: append([]string(nil), created.Client.DestinationGrants...),
			}, nil
		},
		InviteArtifact: func(inviteID string) (webui.ClientInviteArtifact, error) {
			token, invite, err := store.Artifact(inviteID)
			if err != nil {
				return webui.ClientInviteArtifact{}, err
			}
			clients, _, err := store.List()
			if err != nil {
				return webui.ClientInviteArtifact{}, err
			}
			var invitedClient *clientregistry.Client
			for _, client := range clients {
				if client.ID == invite.ClientID {
					copy := client
					invitedClient = &copy
					break
				}
			}
			if invitedClient == nil {
				return webui.ClientInviteArtifact{}, fmt.Errorf("invitation %s references an unknown client", invite.ID)
			}
			uri, err := inviteURI(token, invite.ExpiresAt)
			if err != nil {
				return webui.ClientInviteArtifact{}, err
			}
			return webui.ClientInviteArtifact{
				ClientID: invite.ClientID, ClientName: invitedClient.Name,
				InviteURI: uri, ExpiresAt: invite.ExpiresAt,
				ProfileVersion:    invitedClient.ProfileVersion,
				Responsibilities:  append([]string(nil), invitedClient.Responsibilities...),
				DestinationGrants: append([]string(nil), invitedClient.DestinationGrants...),
			}, nil
		},
		Claim: func(input webui.ClientClaimInput) (webui.ClientClaimResult, error) {
			claimed, err := store.Claim(clientregistry.ClaimInput{
				Token: input.Token, Platform: input.Platform,
				CSRPEM: input.CSRPEM, RequestID: input.RequestID,
			})
			if err != nil {
				return webui.ClientClaimResult{}, err
			}
			result := webui.ClientClaimResult{
				Schema: 1, ClientID: claimed.Client.ID,
				Status: "provisioning", EnrolledAt: claimed.Client.EnrolledAt,
				Replay: claimed.Replay, Next: "wait_for_configuration",
				Configuration: "pending",
			}
			if provision == nil {
				return result, nil
			}
			bootstrap, err := provision(claimed.Client, input.CSRPEM)
			if err != nil {
				return webui.ClientClaimResult{}, err
			}
			if bootstrap == nil {
				return result, nil
			}
			if err := validateClientBootstrap(*bootstrap, claimed.Client.ID); err != nil {
				return webui.ClientClaimResult{}, err
			}
			if _, err := store.MarkReady(claimed.Client.ID); err != nil {
				return webui.ClientClaimResult{}, err
			}
			result.Status = "ready"
			result.Configuration = "ready"
			result.Next = "pull"
			result.Bootstrap = bootstrap
			return result, nil
		},
	}
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

func defaultDeviceEnrollmentProfile(c *Control) (*model.EnrollmentProfileVersion, error) {
	if c == nil {
		return nil, fmt.Errorf("control configuration is unavailable")
	}
	ssot, _, err := loadValidatedSSOTSnapshot(c.SSOTPath)
	if err != nil {
		return nil, fmt.Errorf("read enrollment profile: %w", err)
	}
	profile, err := ssot.DefaultEnrollmentProfile()
	if err != nil {
		return nil, err
	}
	// The current E1 renderer can materialize the use_loom responsibility. Keep
	// future server responsibilities declarable, but fail closed until their
	// endpoint/direction facts have a complete enrollment transaction.
	for _, responsibility := range profile.Responsibilities {
		if responsibility != "use_loom" {
			return nil, fmt.Errorf("default enrollment profile %s requires unsupported responsibility %q", profile.Reference(), responsibility)
		}
	}
	if len(profile.DestinationGrants) == 0 {
		return nil, fmt.Errorf("default enrollment profile %s has no destination grants", profile.Reference())
	}
	return profile, nil
}

func deviceEnrollmentProfileView(profile *model.EnrollmentProfileVersion) webui.DeviceEnrollmentProfileView {
	if profile == nil {
		return webui.DeviceEnrollmentProfileView{}
	}
	return webui.DeviceEnrollmentProfileView{
		Version:           profile.Reference(),
		Responsibilities:  append([]string(nil), profile.Responsibilities...),
		DestinationGrants: append([]string(nil), profile.DestinationGrants...),
	}
}

func validateClientBootstrap(bootstrap webui.ClientBootstrap, clientID string) error {
	if bootstrap.NodeID != clientID || len(bootstrap.DistributionURLs) == 0 ||
		strings.TrimSpace(bootstrap.SecretsEnv) == "" || strings.TrimSpace(bootstrap.PlatformPublicKey) == "" ||
		strings.TrimSpace(bootstrap.ReleaseAuthority) == "" || strings.TrimSpace(bootstrap.CACertPEM) == "" ||
		strings.TrimSpace(bootstrap.NodeCertPEM) == "" {
		return fmt.Errorf("client provisioner returned an incomplete bootstrap for %s", clientID)
	}
	for _, raw := range bootstrap.DistributionURLs {
		u, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || u.Fragment != "" {
			return fmt.Errorf("client provisioner returned an invalid distribution URL")
		}
	}
	return nil
}

func validClientEnrollmentURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil ||
		u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("client_enrollment_url must be an absolute HTTPS URL without credentials, query, or fragment")
	}
	return u.String(), nil
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
