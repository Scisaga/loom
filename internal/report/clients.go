package report

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"loom/internal/clientdist"
	"loom/internal/clientregistry"
	"loom/internal/model"
	"loom/internal/ssotedit"
	"loom/internal/validate"
	"loom/internal/version"
	"loom/internal/webui"
)

type clientInvitePayload struct {
	Schema            int    `json:"schema"`
	Endpoint          string `json:"endpoint"`
	Token             string `json:"token"`
	ExpiresAt         string `json:"expires_at"`
	PlatformKeySHA256 string `json:"platform_key_sha256"`
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
		paths, err := clientPaths(c)
		if err != nil {
			return "", err
		}
		key, err := readClientPlatformPublicKey(paths.platformPublic)
		if err != nil {
			return "", err
		}
		keyDigest := sha256.Sum256(key)
		body, err := json.Marshal(clientInvitePayload{
			Schema: 1, Endpoint: endpoint, Token: token, ExpiresAt: expires,
			PlatformKeySHA256: hex.EncodeToString(keyDigest[:]),
		})
		if err != nil {
			return "", err
		}
		// Fragment material is never sent as an HTTP request target. The client
		// decodes it locally and sends the bearer token only in the claim POST body.
		return "loom://enroll#" + base64.RawURLEncoding.EncodeToString(body), nil
	}
	inviteView := func(created clientregistry.CreateResult) (webui.ClientInviteView, error) {
		uri, err := inviteURI(created.Token, created.Invite.ExpiresAt)
		if err != nil {
			return webui.ClientInviteView{}, err
		}
		return webui.ClientInviteView{
			InviteID: created.Invite.ID, ClientID: created.Client.ID, ClientName: created.Client.Name,
			InviteURI: uri, EnrollmentURL: c.ClientEnrollmentURL, ExpiresAt: created.Invite.ExpiresAt,
			Platform: created.Client.Platform, Direction: created.Client.Direction, Replaces: created.Client.Replaces,
			Responsibilities:  append([]string(nil), created.Client.Responsibilities...),
			DestinationGrants: append([]string(nil), created.Client.DestinationGrants...),
		}, nil
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
				seen[client.ID] = true
				inventory.Clients = append(inventory.Clients, webui.ClientView{
					ID: client.ID, Name: client.Name, Platform: client.Platform,
					IdentitySource: client.IdentitySource,
					ReplacedBy:     client.ReplacedBy, Replaces: client.Replaces,
					Status: client.Status, KeyFingerprint: client.KeyFingerprint,
					CreatedAt: client.CreatedAt, EnrolledAt: client.EnrolledAt,
					DataPlaneStatus: "pending", ConfigState: "pending",
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
		DiscardPending: store.DiscardPending,
		RenewInvite: func(id string) (webui.ClientInviteView, error) {
			// 先核对公开签发信息，避免入口配置损坏时先让旧二维码失效。
			if _, err := inviteURI("", ""); err != nil {
				return webui.ClientInviteView{}, err
			}
			created, err := store.RenewInvitation(id)
			if err != nil {
				return webui.ClientInviteView{}, err
			}
			return inviteView(created)
		},
		ReplaceDevice: func(id string) (webui.ClientInviteView, error) {
			if _, err := inviteURI("", ""); err != nil {
				return webui.ClientInviteView{}, err
			}
			var created clientregistry.CreateResult
			err := withSSOTLock(c.SSOTPath, func() error {
				snapshot, err := readSSOTSnapshot(c.SSOTPath)
				if err != nil {
					return err
				}
				current, err := model.Load(snapshot.body)
				if err != nil {
					return err
				}
				if findings := validate.Validate(current); len(findings) > 0 {
					return fmt.Errorf("current SSOT is invalid: %s", validate.Format(findings))
				}
				created, err = store.ReplaceWithInvitation(id, func(previous clientregistry.Client) error {
					if err := validateEnrollmentIntent(current, previous); err != nil {
						return err
					}
					node := current.NodeByID()[id]
					if node == nil {
						// SSOT 已撤销但 registry 落盘失败时，重试只补齐身份事务。
						return nil
					}
					if err := validateProvisionedClient(current, node, previous); err != nil {
						return err
					}
					plan, err := ssotedit.RemoveLostAccessDevice(snapshot.body, id)
					if err != nil {
						return err
					}
					return saveSSOTAtomicFromSnapshot(c.SSOTPath, plan.Content, snapshot)
				})
				return err
			})
			if err != nil {
				return webui.ClientInviteView{}, err
			}
			return inviteView(created)
		},
		CreateInvite: func(input webui.ClientInviteInput) (webui.ClientInviteView, error) {
			endpoint, err := validClientEnrollmentURL(c.ClientEnrollmentURL)
			if err != nil {
				return webui.ClientInviteView{}, err
			}
			if err := validateDeviceInviteInput(c, input); err != nil {
				return webui.ClientInviteView{}, err
			}
			created, err := store.Create(input.Name, clientregistry.EnrollmentIntent{
				Platform: input.Platform, Responsibilities: append([]string(nil), input.Responsibilities...),
				DestinationGrants: append([]string(nil), input.DestinationGrants...), Direction: input.Direction,
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
				Platform:          created.Client.Platform,
				Responsibilities:  append([]string(nil), created.Client.Responsibilities...),
				DestinationGrants: append([]string(nil), created.Client.DestinationGrants...),
				Direction:         created.Client.Direction,
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
				Platform:          invitedClient.Platform,
				Responsibilities:  append([]string(nil), invitedClient.Responsibilities...),
				DestinationGrants: append([]string(nil), invitedClient.DestinationGrants...),
				Direction:         invitedClient.Direction,
				Replaces:          invitedClient.Replaces,
			}, nil
		},
		Claim: func(input webui.ClientClaimInput) (webui.ClientClaimResult, error) {
			var server *clientregistry.ServerEnrollment
			if input.Server != nil {
				server = &clientregistry.ServerEnrollment{
					PublicEndpoint: input.Server.PublicEndpoint, InboundPort: input.Server.InboundPort,
					Direction: input.Server.Direction, WGPublicKey: input.Server.WGPublicKey,
					Country: input.Server.Country, City: input.Server.City, Provider: input.Server.Provider,
				}
			}
			claimed, err := store.Claim(clientregistry.ClaimInput{
				Token: input.Token, Platform: input.Platform,
				CSRPEM: input.CSRPEM, RequestID: input.RequestID, Server: server,
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

func readClientPlatformPublicKey(path string) (ed25519.PublicKey, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("deployment platform public key is unavailable")
	}
	defer file.Close()
	body, err := io.ReadAll(io.LimitReader(file, 1025))
	if err != nil || len(body) == 0 || len(body) > 1024 {
		return nil, errors.New("deployment platform public key is unavailable")
	}
	encoded := strings.TrimSpace(string(body))
	key, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(key) != ed25519.PublicKeySize || base64.StdEncoding.EncodeToString(key) != encoded {
		return nil, errors.New("deployment platform public key is invalid")
	}
	return ed25519.PublicKey(key), nil
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

func validateDeviceInviteInput(c *Control, input webui.ClientInviteInput) error {
	options, err := deviceEnrollmentOptions(c)
	if err != nil {
		return err
	}
	allowed := make(map[string]bool, len(options.DestinationGrants))
	for _, option := range options.DestinationGrants {
		allowed[option.ID] = true
	}
	for _, grant := range input.DestinationGrants {
		if !allowed[strings.TrimSpace(grant)] {
			return fmt.Errorf("destination grant %q is not an available from_request declaration", grant)
		}
	}
	return nil
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
