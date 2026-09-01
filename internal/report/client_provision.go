package report

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"loom/internal/clientregistry"
	"loom/internal/enrollplan"
	"loom/internal/model"
	"loom/internal/secret"
	"loom/internal/ssotedit"
	"loom/internal/validate"
)

const (
	linuxClientPackagePath = "/var/lib/loom/client-dist/loom-client-linux-amd64.tar.gz"
	clientNodeSecretsPath  = "/etc/loom/secrets/node.env"
)

// clientBootstrap is the one-time trust and secret material returned only to
// the device identity that consumed an invitation. It deliberately contains
// no private key: the TLS/attestation key is created beside the CSR on-device.
type clientBootstrap struct {
	NodeID            string
	DistributionURLs  []string
	DNS               []string
	SecretsEnv        string
	PlatformPublicKey string
	ReleaseAuthority  string
	CACertPEM         string
	NodeCertPEM       string
}

type clientProvisioningResult struct {
	Ready     bool
	Bootstrap clientBootstrap
}

type clientProvisioner struct {
	control *Control
	saveMu  *sync.Mutex
	now     func() time.Time
	install func(context.Context, string, []byte) error
	health  string
}

func newClientProvisioner(c *Control, saveMu *sync.Mutex) *clientProvisioner {
	p := &clientProvisioner{control: c, saveMu: saveMu, now: time.Now, health: PublisherHealthPath}
	p.install = p.installNodeSecrets
	return p
}

type clientProvisionPaths struct {
	masterSecrets, caCert, caKey, platformPublic, releaseArchive, sshConfig string
}

func clientPaths(c *Control) (clientProvisionPaths, error) {
	if c == nil || !filepath.IsAbs(c.SSOTPath) || filepath.Clean(c.SSOTPath) != c.SSOTPath {
		return clientProvisionPaths{}, errors.New("client provisioning requires an absolute clean ssot_path")
	}
	deployDir := filepath.Dir(c.SSOTPath)
	projectDir := filepath.Dir(deployDir)
	return clientProvisionPaths{
		masterSecrets:  filepath.Join(deployDir, "secrets.env"),
		caCert:         filepath.Join(deployDir, "pki", "ca.crt"),
		caKey:          filepath.Join(deployDir, "pki", "ca.key"),
		platformPublic: filepath.Join(deployDir, "keys", "platform-signing.pub"),
		releaseArchive: filepath.Join(deployDir, "ssot-history"),
		sshConfig:      filepath.Join(projectDir, ".ssh_config"),
	}, nil
}

// provision performs the existing Loom transaction in its safe order:
// secrets first, existing nodes second, SSOT last. A caller may replay the
// same claim; once the publisher reports the exact SSOT digest, provision
// returns the signed first-pull trust material.
func (p *clientProvisioner) provision(client clientregistry.Client, csrPEM string) (clientProvisioningResult, error) {
	if p == nil || p.control == nil || p.saveMu == nil || p.install == nil {
		return clientProvisioningResult{}, errors.New("client provisioning is not configured")
	}
	if client.Platform != string(model.LinuxServer) {
		return clientProvisioningResult{}, fmt.Errorf("client platform %q is not delivered in v1", client.Platform)
	}
	paths, err := clientPaths(p.control)
	if err != nil {
		return clientProvisioningResult{}, err
	}

	var (
		ssot          *model.SSOT
		ssotBody      []byte
		clientSecrets []byte
		added         bool
	)
	p.saveMu.Lock()
	err = withSSOTLock(p.control.SSOTPath, func() error {
		snapshot, err := readSSOTSnapshot(p.control.SSOTPath)
		if err != nil {
			return fmt.Errorf("read SSOT before client provisioning: %w", err)
		}
		current, err := model.Load(snapshot.body)
		if err != nil {
			return fmt.Errorf("parse current SSOT: %w", err)
		}
		if findings := validate.Validate(current); len(findings) > 0 {
			return fmt.Errorf("current SSOT is invalid: %s", validate.Format(findings))
		}

		node := current.NodeByID()[client.ID]
		if node == nil {
			if err := validatePinnedEnrollmentProfile(current, client); err != nil {
				return err
			}
			candidateBody := snapshot.body
			if hasResponsibility(client, "forward") {
				egress := hasResponsibility(client, "internet_egress")
				server := client.Server
				candidateBody, err = enrollplan.Apply(candidateBody, enrollplan.NodeInput{
					ID: client.ID, Name: client.Name, Country: server.Country, City: server.City,
					Provider: server.Provider, PublicEndpoint: server.PublicEndpoint,
					Direction: model.Direction(server.Direction), WGPublicKey: server.WGPublicKey,
					InboundPort: server.InboundPort, SecretGeneration: 1, EgressCapable: &egress,
				})
				if err != nil {
					return fmt.Errorf("plan server Device enrollment: %w", err)
				}
			}
			var accessPlan ssotedit.ClientPlan
			if hasResponsibility(client, "use_loom") {
				input := ssotedit.ClientInput{
					ID: client.ID, Name: client.Name, Platform: model.LinuxServer,
					DestinationGrants: append([]string(nil), client.DestinationGrants...),
				}
				if hasResponsibility(client, "forward") {
					accessPlan, err = ssotedit.AddAccessRole(candidateBody, input)
				} else {
					accessPlan, err = ssotedit.AddAccessClient(candidateBody, input)
				}
				if err != nil {
					return err
				}
				candidateBody = accessPlan.Content
			}
			candidate, err := model.Load(candidateBody)
			if err != nil {
				return fmt.Errorf("parse client SSOT candidate: %w", err)
			}
			all, err := secret.Load(paths.masterSecrets)
			if err != nil {
				return fmt.Errorf("read master secrets: %w", err)
			}
			allowedNew := map[string]bool{
				"api/" + client.ID: true, "probe/" + client.ID: true,
				"telemetry/" + client.ID: true,
			}
			for _, ref := range accessPlan.CredentialRefs {
				allowedNew[ref] = true
			}
			for _, link := range ExpectedDirectLinksForSSOT(candidate) {
				if link.From == client.ID || link.To == client.ID {
					allowedNew["telemetry/"+link.From] = true
				}
			}
			for _, node := range candidate.Nodes {
				for _, ref := range nodeSecretRefs(candidate, node.ID, all) {
					if _, ok := all[ref]; ok {
						continue
					}
					if !allowedNew[ref] {
						return fmt.Errorf("master secrets are missing existing ref %q", ref)
					}
					value, err := randomClientSecret()
					if err != nil {
						return err
					}
					all[ref] = value
				}
			}
			masterBody := secret.Encode(all, masterSecretsHeader())
			if err := writeClientFileAtomic(paths.masterSecrets, masterBody, 0o600); err != nil {
				return fmt.Errorf("publish master secrets before SSOT: %w", err)
			}

			byOwner := make(map[string][]byte, len(candidate.Nodes))
			for _, node := range candidate.Nodes {
				if node.Decommission {
					continue
				}
				mine, err := encodedNodeSecrets(candidate, node.ID, all)
				if err != nil {
					return err
				}
				byOwner[node.ID] = mine
			}
			clientSecrets = byOwner[client.ID]
			if len(clientSecrets) == 0 {
				return fmt.Errorf("rendered client %q has no bootstrap secret layer", client.ID)
			}
			if err := p.installExistingNodeSecrets(current, byOwner); err != nil {
				return err
			}
			// This is the commit point. Publisher observation can only begin after
			// every existing node can hydrate the candidate snapshot.
			if err := saveSSOTAtomicFromSnapshot(p.control.SSOTPath, candidateBody, snapshot); err != nil {
				return fmt.Errorf("commit provisioned client SSOT: %w", err)
			}
			ssot, ssotBody, added = candidate, candidateBody, true
			return nil
		}

		if err := validateProvisionedClient(current, node, client); err != nil {
			return err
		}
		all, err := secret.Load(paths.masterSecrets)
		if err != nil {
			return fmt.Errorf("read master secrets: %w", err)
		}
		clientSecrets, err = encodedNodeSecrets(current, client.ID, all)
		if err != nil {
			return err
		}
		if len(clientSecrets) == 0 {
			return fmt.Errorf("provisioned client %q has no rendered bootstrap secret layer", client.ID)
		}
		ssot, ssotBody = current, snapshot.body
		return nil
	})
	p.saveMu.Unlock()
	if err != nil {
		return clientProvisioningResult{}, err
	}

	if added {
		return clientProvisioningResult{Ready: false}, nil
	}
	node := ssot.NodeByID()[client.ID]
	bootstrap, err := p.readyBootstrap(paths, ssot, node, clientSecrets, csrPEM, ssotBody)
	if err != nil {
		if errors.Is(err, errDistributionNotReady) {
			return clientProvisioningResult{Ready: false}, nil
		}
		return clientProvisioningResult{}, err
	}
	return clientProvisioningResult{Ready: true, Bootstrap: bootstrap}, nil
}

func validateProvisionedClient(s *model.SSOT, node *model.Node, client clientregistry.Client) error {
	if node == nil {
		return fmt.Errorf("device id %q is missing from SSOT", client.ID)
	}
	if node.Name != client.Name {
		return fmt.Errorf("device id %q already has a different display name in SSOT", client.ID)
	}
	wantsAccess := client.ProfileVersion == "" || hasResponsibility(client, "use_loom")
	if wantsAccess {
		if node.Access == nil || node.Access.Platform != model.LinuxServer {
			return fmt.Errorf("device id %q is missing its linux-server use_loom role", client.ID)
		}
		if err := ssotedit.ValidateAccessClientShape(s, node, ssotedit.ClientInput{
			ID: client.ID, Name: client.Name, Platform: model.LinuxServer,
			DestinationGrants: clientDestinationGrants(client),
		}); err != nil {
			return fmt.Errorf("device id %q has an incomplete or broadened access shape: %w", client.ID, err)
		}
	} else if node.Access != nil {
		return fmt.Errorf("device id %q gained an access role outside its pinned profile", client.ID)
	}

	wantsServer := hasResponsibility(client, "forward")
	if wantsServer {
		if err := validateProvisionedServerShape(s, node, client); err != nil {
			return err
		}
	} else if node.Server != nil {
		return fmt.Errorf("device id %q gained a server role outside its pinned profile", client.ID)
	}
	return nil
}

func validateProvisionedServerShape(s *model.SSOT, node *model.Node, client clientregistry.Client) error {
	server := client.Server
	if server == nil || node.Server == nil {
		return fmt.Errorf("device id %q is missing pinned server enrollment facts", client.ID)
	}
	if node.PublicEndpoint != server.PublicEndpoint || node.Country != server.Country || node.City != server.City ||
		node.Provider != server.Provider || node.Server.InboundPort != server.InboundPort ||
		node.Server.Direction != model.Direction(server.Direction) || node.Server.WGPublicKey != server.WGPublicKey ||
		node.Server.SecretGeneration != 1 || node.Server.EgressCapable != hasResponsibility(client, "internet_egress") {
		return fmt.Errorf("device id %q server shape differs from its pinned claim", client.ID)
	}
	pairs := map[string]int{}
	for i := range s.Tunnels {
		tunnel := &s.Tunnels[i]
		if tunnel.From == client.ID {
			pairs[tunnel.To]++
		} else if tunnel.To == client.ID {
			pairs[tunnel.From]++
		}
	}
	for i := range s.Nodes {
		peer := &s.Nodes[i]
		if peer.ID == client.ID {
			continue
		}
		want := model.NeedsTunnel(node, peer)
		if (want && pairs[peer.ID] != 1) || (!want && pairs[peer.ID] != 0) {
			return fmt.Errorf("device id %q tunnel relation with %q does not match direction matrix", client.ID, peer.ID)
		}
	}
	return nil
}

func validatePinnedEnrollmentProfile(s *model.SSOT, client clientregistry.Client) error {
	if s == nil || client.ProfileVersion == "" || client.ProfileDigest == "" {
		return fmt.Errorf("device %q has no pinned enrollment ProfileVersion", client.ID)
	}
	profile := s.EnrollmentProfileByReference(client.ProfileVersion)
	if profile == nil {
		return fmt.Errorf("device %q pins missing enrollment profile %q", client.ID, client.ProfileVersion)
	}
	if profile.Digest() != client.ProfileDigest {
		return fmt.Errorf("enrollment profile %q content changed after invitation creation", client.ProfileVersion)
	}
	if !sameStrings(profile.Responsibilities, client.Responsibilities) ||
		!sameStrings(profile.DestinationGrants, client.DestinationGrants) {
		return fmt.Errorf("device %q profile expansion does not match pinned digest", client.ID)
	}
	hasUse := hasResponsibility(client, "use_loom")
	hasForward := hasResponsibility(client, "forward")
	hasEgress := hasResponsibility(client, "internet_egress")
	if hasEgress && !hasForward {
		return fmt.Errorf("enrollment profile %q grants internet_egress without forward", client.ProfileVersion)
	}
	if hasForward != (client.Server != nil) {
		return fmt.Errorf("device %q server claim does not match pinned responsibilities", client.ID)
	}
	if hasUse != (len(client.DestinationGrants) > 0) {
		return fmt.Errorf("device %q destination grants do not match use_loom responsibility", client.ID)
	}
	return nil
}

func hasResponsibility(client clientregistry.Client, responsibility string) bool {
	for _, candidate := range client.Responsibilities {
		if candidate == responsibility {
			return true
		}
	}
	return false
}

func clientDestinationGrants(client clientregistry.Client) []string {
	if client.ProfileVersion == "" {
		return nil // validate the historical all-from_request shape for legacy records
	}
	return append([]string(nil), client.DestinationGrants...)
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func nodeSecretRefs(s *model.SSOT, owner string, all map[string]string) []string {
	seen := map[string]bool{}
	node := s.NodeByID()[owner]
	if node != nil && node.IsAccess() {
		credentials := s.CredentialByID()
		for _, id := range node.Access.Credentials {
			credential := credentials[id]
			if credential == nil || credential.Revoked() {
				continue
			}
			seen[credential.Ref()] = true
			if credential.RotationPending() {
				seen[credential.PrevRef()] = true
			}
		}
		// Every managed access node runs the selector Agent when at least one
		// authorized declaration can produce candidates. These deterministic
		// local control secrets are harmless extras if a declaration is currently
		// unrenderable and avoid coupling this package back to render -> report.
		seen["api/"+owner] = true
		seen["probe/"+owner] = true
	}
	if node != nil && node.IsServer() {
		declarations := s.DeclarationByID()
		for _, credential := range s.Credentials {
			if credential.Revoked() {
				continue
			}
			// Credential.Owner is operator-facing metadata and is not the
			// authorization binding. The access node's credentials list is the
			// canonical relation used by validation and rendering too.
			access := s.AccessNodeForCredential(credential.ID)
			declaration := declarations[credential.Declaration]
			if access == nil || declaration == nil {
				continue
			}
			candidates, _ := s.EnumerateCandidates(access, declaration)
			used := false
			for _, candidate := range candidates {
				for _, server := range candidate.ServerChain {
					used = used || server == owner
				}
			}
			if !used {
				continue
			}
			seen[credential.Ref()] = true
			if credential.RotationPending() {
				seen[credential.PrevRef()] = true
			}
		}
	}
	for _, link := range ExpectedDirectLinksForSSOT(s) {
		if link.From == owner || link.To == owner {
			seen["telemetry/"+link.From] = true
		}
	}
	for ref := range all {
		if _, refOwner, ok := strings.Cut(ref, "/"); ok && refOwner == owner {
			seen[ref] = true
		}
	}
	refs := make([]string, 0, len(seen))
	for ref := range seen {
		refs = append(refs, ref)
	}
	sort.Strings(refs)
	return refs
}

func encodedNodeSecrets(s *model.SSOT, owner string, all map[string]string) ([]byte, error) {
	mine := map[string]string{}
	var missing []string
	for _, ref := range nodeSecretRefs(s, owner, all) {
		value, ok := all[ref]
		if !ok {
			missing = append(missing, ref)
			continue
		}
		mine[ref] = value
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("master secrets are missing refs for %s: %s", owner, strings.Join(missing, ", "))
	}
	header := fmt.Sprintf("# %s 的秘密层 —— 由中控客户端注册事务生成\n"+
		"# 只含这台机器自己用得到的引用。0600。\n\n", owner)
	return secret.Encode(mine, header), nil
}

func masterSecretsHeader() string {
	return "# Loom 秘密层。渲染产物里的 ${secret:REF} 由 loom hydrate 从这里取值。\n" +
		"# 绝不进版本库(.gitignore 已排除)。0600。\n\n"
}

func randomClientSecret() (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate client secret: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func (p *clientProvisioner) installExistingNodeSecrets(current *model.SSOT, byOwner map[string][]byte) error {
	ids := make([]string, 0, len(current.Nodes))
	for i := range current.Nodes {
		if current.Nodes[i].Decommission {
			continue
		}
		ids = append(ids, current.Nodes[i].ID)
	}
	sort.Strings(ids)
	type result struct {
		id  string
		err error
	}
	results := make(chan result, len(ids))
	for _, id := range ids {
		body := byOwner[id]
		if len(body) == 0 {
			return fmt.Errorf("candidate render has no secret layer for existing node %q", id)
		}
		go func(id string, body []byte) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			results <- result{id: id, err: p.install(ctx, id, body)}
		}(id, body)
	}
	var failures []string
	for range ids {
		result := <-results
		if result.err != nil {
			failures = append(failures, result.id+": "+result.err.Error())
		}
	}
	sort.Strings(failures)
	if len(failures) > 0 {
		return fmt.Errorf("pre-provision client secrets failed; SSOT was not changed: %s", strings.Join(failures, "; "))
	}
	return nil
}

func (p *clientProvisioner) installNodeSecrets(ctx context.Context, nodeID string, body []byte) error {
	if !model.ValidNodeID(nodeID) {
		return fmt.Errorf("invalid node id %q", nodeID)
	}
	local, err := controlNodeID(p.control)
	if err != nil {
		return err
	}
	if nodeID == local {
		return writeClientFileAtomic(clientNodeSecretsPath, body, 0o600)
	}
	paths, err := clientPaths(p.control)
	if err != nil {
		return err
	}
	if err := validateClientProvisionSSHFile(paths.sshConfig, "client provisioning SSH config", false); err != nil {
		return err
	}
	if err := validateClientProvisionSSHFile(p.control.BootstrapSSHKey, "control bootstrap SSH private key", true); err != nil {
		return err
	}
	if err := validateClientProvisionSSHFile(p.control.KnownHostsPath, "control SSH known_hosts", false); err != nil {
		return err
	}
	payload := base64.StdEncoding.EncodeToString(body)
	script := `set -eu
	set -f
directory=/etc/loom/secrets
target=$directory/node.env
[ ! -L "$directory" ] || { echo 'secrets directory is a symlink' >&2; exit 41; }
install -d -m 700 "$directory"
	[ ! -L "$target" ] || { echo 'node.env is a symlink' >&2; exit 42; }
	temporary=$(mktemp "$directory/.node.env.XXXXXX")
	trap 'rm -f "$temporary"' EXIT HUP INT TERM
	printf '%s' '` + payload + `' | base64 -d >"$temporary"
	chmod 600 "$temporary"
	sync_path() {
	    path=$1
	    command -v sync >/dev/null 2>&1 || { echo 'sync command is required for durable secret installation' >&2; exit 43; }
	    sync "$path" 2>/dev/null && return 0
	    sync -f "$path" 2>/dev/null && return 0
	    echo 'could not durably sync installed secrets' >&2
	    exit 44
	}
	sync_path "$temporary"
	mv -f "$temporary" "$target"
	sync_path "$directory"
	trap - EXIT HUP INT TERM
	`
	cmd := exec.CommandContext(ctx, "ssh", clientProvisionSSHArgs(
		paths.sshConfig, p.control.BootstrapSSHKey, p.control.KnownHostsPath, nodeID)...)
	cmd.Stdin = strings.NewReader(script)
	// The remote receives a complete node secret layer. Never copy remote output
	// into an HTTP-visible error: a failing or compromised peer could echo stdin.
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("SSH secret install failed for node %s: %w", nodeID, err)
	}
	return nil
}

func clientProvisionSSHArgs(configPath, privateKeyPath, knownHostsPath, nodeID string) []string {
	return []string{
		"-F", configPath,
		"-o", "BatchMode=yes",
		"-o", "IdentitiesOnly=yes",
		"-o", "StrictHostKeyChecking=yes",
		"-o", "GlobalKnownHostsFile=/dev/null",
		"-o", "UserKnownHostsFile=" + knownHostsPath,
		"-o", "UpdateHostKeys=no",
		"-o", "ClearAllForwardings=yes",
		"-o", "RequestTTY=no",
		"-o", "ConnectTimeout=10",
		"-i", privateKeyPath,
		"--", nodeID, "/bin/sh", "-s", "--",
	}
}

func validateClientProvisionSSHFile(path, label string, privateKey bool) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("%s path must be absolute and clean", label)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect %s: %w", label, err)
	}
	if err := validateClientProvisionSSHMetadata(info, label, privateKey); err != nil {
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
	return validateClientProvisionSSHMetadata(opened, label, privateKey)
}

func validateClientProvisionSSHMetadata(info os.FileInfo, label string, privateKey bool) error {
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s must be a regular file; symlinks are not accepted", label)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("inspect %s owner and link count: filesystem metadata unavailable", label)
	}
	if stat.Uid != 0 {
		return fmt.Errorf("%s owner is uid %d, require root", label, stat.Uid)
	}
	if stat.Nlink != 1 {
		return fmt.Errorf("%s must have exactly one hard link", label)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s must not be group/world writable", label)
	}
	if privateKey && info.Mode().Perm() != 0o600 {
		return fmt.Errorf("%s permissions are %04o, require exactly 0600", label, info.Mode().Perm())
	}
	return nil
}

func controlNodeID(c *Control) (string, error) {
	_, id, ok := strings.Cut(strings.TrimSpace(c.OperatorRef), "/")
	if !ok || !model.ValidNodeID(id) {
		return "", fmt.Errorf("operator_ref %q does not identify the control node", c.OperatorRef)
	}
	return id, nil
}

func publisherHasSSOT(path string, body []byte, now time.Time) bool {
	health, err := readPublisherState(path)
	return err == nil && publisherStateHasSSOT(health, body, now)
}

func publisherStateHasSSOT(health *PublisherState, body []byte, now time.Time) bool {
	if health == nil || health.Unhealthy(now) {
		return false
	}
	sum := sha256.Sum256(body)
	return health.LastSSOT == hex.EncodeToString(sum[:]) && health.LastSnapshot != "" && health.LastSuccess != ""
}

func (p *clientProvisioner) readyBootstrap(paths clientProvisionPaths, s *model.SSOT, node *model.Node, secrets []byte, csrPEM string, expectedSSOT []byte) (clientBootstrap, error) {
	if node == nil {
		return clientBootstrap{}, errors.New("provisioned client disappeared from SSOT")
	}
	health, err := readPublisherState(p.health)
	if err != nil {
		return clientBootstrap{}, fmt.Errorf("%w: read publisher evidence: %v", errDistributionNotReady, err)
	}
	distributionURLs, verifiedSnapshot, err := verifiedEnrollmentDistributionURLs(s, health, expectedSSOT, p.now().UTC())
	if err != nil {
		return clientBootstrap{}, err
	}
	platformBody, err := os.ReadFile(paths.platformPublic)
	if err != nil {
		return clientBootstrap{}, fmt.Errorf("read platform public key: %w", err)
	}
	platformKey, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(platformBody)))
	if err != nil || len(platformKey) != ed25519.PublicKeySize {
		return clientBootstrap{}, errors.New("platform public key is not a 32-byte Ed25519 key")
	}
	authorityPath := filepath.Join(paths.releaseArchive, "release-authority.json")
	authorityBody, err := os.ReadFile(authorityPath)
	if err != nil {
		return clientBootstrap{}, fmt.Errorf("read release authority: %w", err)
	}
	authority, err := verifyClientReleaseAuthority(authorityBody, ed25519.PublicKey(platformKey), node.ID)
	if err != nil {
		return clientBootstrap{}, fmt.Errorf("release authority is not a valid platform-signed current: %w", err)
	}
	if authority.Snapshot != verifiedSnapshot {
		return clientBootstrap{}, errors.New("release authority does not match the healthy publisher state for the provisioned SSOT")
	}
	caBody, certBody, err := signClientCSR(paths.caCert, paths.caKey, node.ID, csrPEM, p.now().UTC())
	if err != nil {
		return clientBootstrap{}, err
	}
	return clientBootstrap{
		NodeID: node.ID, DistributionURLs: distributionURLs,
		DNS: append([]string(nil), s.DNSFor(node)...), SecretsEnv: string(secrets),
		PlatformPublicKey: string(platformBody), ReleaseAuthority: string(authorityBody),
		CACertPEM: string(caBody), NodeCertPEM: string(certBody),
	}, nil
}

var errDistributionNotReady = errors.New("no verified public distribution URL for enrollment")

func verifiedEnrollmentDistributionURLs(s *model.SSOT, health *PublisherState, expectedSSOT []byte, now time.Time) ([]string, string, error) {
	if s == nil || health == nil {
		return nil, "", fmt.Errorf("%w: publisher evidence is unavailable", errDistributionNotReady)
	}
	updatedAt, err := time.Parse(time.RFC3339Nano, health.UpdatedAt)
	if err != nil || now.Sub(updatedAt) > publisherHeartbeatLimit(health.IntervalSeconds) || now.Sub(updatedAt) < -time.Minute ||
		health.PID <= 0 || syscall.Kill(health.PID, 0) == syscall.ESRCH {
		return nil, "", fmt.Errorf("%w: publisher heartbeat is unavailable", errDistributionNotReady)
	}
	ssotSum := sha256.Sum256(expectedSSOT)
	wantSSOT := hex.EncodeToString(ssotSum[:])
	type verified struct {
		snapshot string
		at       time.Time
	}
	checks := map[string]verified{}
	for _, check := range health.DistributionChecks {
		if !check.Success || check.SSOT != wantSSOT || check.Snapshot == "" {
			continue
		}
		checkedAt, err := time.Parse(time.RFC3339Nano, check.CheckedAt)
		if err != nil || checkedAt.After(now.Add(time.Minute)) {
			continue
		}
		checks[canonicalDistributionURL(check.URL)] = verified{snapshot: check.Snapshot, at: checkedAt}
	}
	seen := map[string]bool{}
	var selected []string
	snapshot := ""
	for _, candidate := range s.DistributionURLs() {
		candidate = strings.TrimSpace(candidate)
		canonical := canonicalDistributionURL(candidate)
		if candidate == "" || seen[canonical] || !safeEnrollmentDistributionURL(candidate) {
			continue
		}
		seen[canonical] = true
		proof, ok := checks[canonical]
		if !ok || proof.at.IsZero() {
			continue
		}
		if snapshot != "" && proof.snapshot != snapshot {
			continue
		}
		if snapshot == "" {
			snapshot = proof.snapshot
		}
		selected = append(selected, candidate)
	}
	if len(selected) == 0 {
		return nil, "", fmt.Errorf("%w: no defaults.distribution_urls candidate has exact VerifyServed evidence for SSOT %s", errDistributionNotReady, wantSSOT[:8])
	}
	return selected, snapshot, nil
}

func publisherHeartbeatLimit(intervalSeconds int64) time.Duration {
	limit := PublisherHeartbeatStale
	if intervalSeconds > 0 {
		if candidate := 3 * time.Duration(intervalSeconds) * time.Second; candidate > limit {
			limit = candidate
		}
	}
	return limit
}

func canonicalDistributionURL(raw string) string {
	return strings.TrimRight(strings.TrimSpace(raw), "/")
}

func safeEnrollmentDistributionURL(raw string) bool {
	parsed, err := url.ParseRequestURI(raw)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") ||
		parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return false
	}
	host := strings.TrimSuffix(strings.ToLower(parsed.Hostname()), ".")
	if host == "" || host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		return !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() &&
			!ip.IsLinkLocalMulticast() && !ip.IsUnspecified() && !ip.IsMulticast()
	}
	return true
}

type clientReleaseAssignment struct {
	Node     string `json:"node"`
	Snapshot string `json:"snapshot"`
}

type clientReleaseAuthority struct {
	Schema      int                       `json:"schema"`
	Generation  uint64                    `json:"generation"`
	Snapshot    string                    `json:"snapshot"`
	Assignments []clientReleaseAssignment `json:"assignments,omitempty"`
	PublishedAt string                    `json:"published_at"`
	Signature   string                    `json:"signature"`
}

type clientReleasePayload struct {
	Schema      int                       `json:"schema"`
	Generation  uint64                    `json:"generation"`
	Snapshot    string                    `json:"snapshot"`
	Assignments []clientReleaseAssignment `json:"assignments,omitempty"`
	PublishedAt string                    `json:"published_at"`
}

// report cannot import publish (publish -> render -> report). Verify the small
// signed-current wire contract here, just as PublisherState mirrors the health
// wire format on this side of that dependency boundary.
func verifyClientReleaseAuthority(body []byte, publicKey ed25519.PublicKey, nodeID string) (*clientReleaseAuthority, error) {
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields()
	var authority clientReleaseAuthority
	if err := dec.Decode(&authority); err != nil {
		return nil, err
	}
	if err := dec.Decode(new(any)); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("release authority has trailing JSON")
		}
		return nil, fmt.Errorf("release authority trailing JSON: %w", err)
	}
	if authority.Schema != 1 || authority.Generation == 0 || !validClientSnapshot(authority.Snapshot) {
		return nil, errors.New("release authority coordinates are invalid")
	}
	if _, err := time.Parse(time.RFC3339Nano, authority.PublishedAt); err != nil {
		return nil, errors.New("release authority published_at is invalid")
	}
	sort.Slice(authority.Assignments, func(i, j int) bool {
		if authority.Assignments[i].Node != authority.Assignments[j].Node {
			return authority.Assignments[i].Node < authority.Assignments[j].Node
		}
		return authority.Assignments[i].Snapshot < authority.Assignments[j].Snapshot
	})
	seen := map[string]bool{}
	assigned := len(authority.Assignments) == 0
	for _, assignment := range authority.Assignments {
		if !model.ValidNodeID(assignment.Node) || !validClientSnapshot(assignment.Snapshot) || seen[assignment.Node] {
			return nil, errors.New("release authority assignments are invalid")
		}
		seen[assignment.Node] = true
		assigned = assigned || assignment.Node == nodeID
	}
	if !assigned {
		return nil, fmt.Errorf("release authority has no assignment for client %s", nodeID)
	}
	signature, err := base64.StdEncoding.DecodeString(authority.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || base64.StdEncoding.EncodeToString(signature) != authority.Signature {
		return nil, errors.New("release authority signature encoding is invalid")
	}
	payload, err := json.Marshal(clientReleasePayload{
		Schema: authority.Schema, Generation: authority.Generation, Snapshot: authority.Snapshot,
		Assignments: authority.Assignments, PublishedAt: authority.PublishedAt,
	})
	if err != nil {
		return nil, err
	}
	message := append([]byte("loom-current-v1\x00"), payload...)
	if !ed25519.Verify(publicKey, message, signature) {
		return nil, errors.New("release authority signature verification failed")
	}
	return &authority, nil
}

func validClientSnapshot(value string) bool {
	if len(value) != 12 {
		return false
	}
	for _, c := range []byte(value) {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func signClientCSR(caCertPath, caKeyPath, nodeID, csrPEM string, now time.Time) ([]byte, []byte, error) {
	caBody, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read internal CA certificate: %w", err)
	}
	caBlock, rest := pem.Decode(caBody)
	if caBlock == nil || caBlock.Type != "CERTIFICATE" || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, nil, errors.New("internal CA certificate must contain exactly one PEM certificate")
	}
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil || !caCert.IsCA {
		return nil, nil, errors.New("internal CA certificate is invalid or not a CA")
	}
	if caCert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, nil, errors.New("internal CA certificate is not authorized to sign certificates")
	}
	if now.Before(caCert.NotBefore) || now.After(caCert.NotAfter) {
		return nil, nil, errors.New("internal CA certificate is not currently valid")
	}
	keyBody, err := os.ReadFile(caKeyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read internal CA private key: %w", err)
	}
	caKey, err := parseECDSAPrivateKey(keyBody)
	if err != nil {
		return nil, nil, fmt.Errorf("parse internal CA private key: %w", err)
	}
	if !caKey.PublicKey.Equal(caCert.PublicKey) {
		return nil, nil, errors.New("internal CA certificate and private key do not match")
	}
	csrBlock, csrRest := pem.Decode([]byte(csrPEM))
	if csrBlock == nil || csrBlock.Type != "CERTIFICATE REQUEST" || len(strings.TrimSpace(string(csrRest))) != 0 {
		return nil, nil, errors.New("client CSR must contain exactly one PEM certificate request")
	}
	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		return nil, nil, errors.New("client CSR signature is invalid")
	}
	publicKey, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || publicKey.Curve.Params().Name != "P-256" {
		return nil, nil, errors.New("client CSR must use ECDSA P-256")
	}
	serialBytes := make([]byte, 20)
	if _, err := rand.Read(serialBytes); err != nil {
		return nil, nil, fmt.Errorf("generate client certificate serial: %w", err)
	}
	serialBytes[0] &= 0x7f
	serial := new(big.Int).SetBytes(serialBytes)
	if serial.Sign() == 0 {
		serial.SetInt64(1)
	}
	notAfter := now.Add(825 * 24 * time.Hour)
	if caCert.NotAfter.Before(notAfter) {
		notAfter = caCert.NotAfter
	}
	domain := nodeID + ".node.internal"
	spki, _ := x509.MarshalPKIXPublicKey(publicKey)
	skid := sha256.Sum256(spki)
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: domain},
		DNSNames: []string{domain}, NotBefore: now.Add(-5 * time.Minute), NotAfter: notAfter,
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, SubjectKeyId: skid[:20],
		AuthorityKeyId: append([]byte(nil), caCert.SubjectKeyId...),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, caCert, publicKey, caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("sign client certificate: %w", err)
	}
	certBody := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return caBody, certBody, nil
}

func parseECDSAPrivateKey(body []byte) (*ecdsa.PrivateKey, error) {
	block, rest := pem.Decode(body)
	if block == nil || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, errors.New("expected exactly one PEM private key")
	}
	if block.Type == "EC PRIVATE KEY" {
		return x509.ParseECPrivateKey(block.Bytes)
	}
	if block.Type == "PRIVATE KEY" {
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		ec, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("PKCS#8 key is not ECDSA")
		}
		return ec, nil
	}
	return nil, fmt.Errorf("unsupported private key PEM type %q", block.Type)
}

func writeClientFileAtomic(path string, body []byte, mode os.FileMode) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("path must be absolute and clean: %q", path)
	}
	parent := filepath.Dir(path)
	info, err := os.Lstat(parent)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("parent %q must be a non-symlink directory", parent)
	}
	if existing, err := os.Lstat(path); err == nil {
		if !existing.Mode().IsRegular() || existing.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("target %q must be a regular file", path)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	tmp, err := os.CreateTemp(parent, ".client-bootstrap-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(body); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	dir, err := os.Open(parent)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
