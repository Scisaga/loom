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
	loadLinuxPackage := func() (webui.LinuxClientPackageView, []byte, error) {
		published, err := clientdist.VerifyFiles(c.ClientLinuxPackagePath, "/etc/loom/trust/platform.pub")
		if err != nil {
			return webui.LinuxClientPackageView{}, nil, err
		}
		view := webui.LinuxClientPackageView{
			Filename: filepath.Base(c.ClientLinuxPackagePath), URL: "/clients/download/linux-amd64",
			SHA256: published.SHA256, Version: version.Short(published.Manifest.Loom.Commit),
			Arch: published.Manifest.OS + "/" + published.Manifest.Arch, Size: published.Size,
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

			// Access nodes are still the SSOT source of network authorization. Merge
			// them into inventory so introducing the registry never hides jm24 or an
			// older managed Linux access node.
			ssot, _, err := loadValidatedSSOTSnapshot(c.SSOTPath)
			if err != nil {
				return webui.ClientInventory{}, fmt.Errorf("read SSOT client inventory: %w", err)
			}
			for _, node := range ssot.AccessNodes() {
				if seen[node.ID] {
					for i := range inventory.Clients {
						if inventory.Clients[i].ID == node.ID {
							inventory.Clients[i].DataPlaneStatus = "declared"
							inventory.Clients[i].ConfigState = "managed by SSOT"
						}
					}
					continue
				}
				name := strings.TrimSpace(node.Name)
				if name == "" {
					name = node.ID
				}
				inventory.Clients = append(inventory.Clients, webui.ClientView{
					ID: node.ID, Name: name, Platform: string(node.Access.Platform),
					Status: "managed", DataPlaneStatus: "declared",
					ConfigState: "managed by SSOT",
				})
			}
			return inventory, nil
		},
		CreateInvite: func(input webui.ClientInviteInput) (webui.ClientInviteView, error) {
			endpoint, err := validClientEnrollmentURL(c.ClientEnrollmentURL)
			if err != nil {
				return webui.ClientInviteView{}, err
			}
			created, err := store.Create(input.Name)
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
			clientName := ""
			for _, client := range clients {
				if client.ID == invite.ClientID {
					clientName = client.Name
					break
				}
			}
			if clientName == "" {
				return webui.ClientInviteArtifact{}, fmt.Errorf("invitation %s references an unknown client", invite.ID)
			}
			uri, err := inviteURI(token, invite.ExpiresAt)
			if err != nil {
				return webui.ClientInviteArtifact{}, err
			}
			return webui.ClientInviteArtifact{
				ClientID: invite.ClientID, ClientName: clientName,
				InviteURI: uri, ExpiresAt: invite.ExpiresAt,
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
