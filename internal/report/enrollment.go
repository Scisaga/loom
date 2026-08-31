package report

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"loom/internal/enrollplan"
	"loom/internal/enrollssh"
	"loom/internal/model"
	"loom/internal/netx"
	"loom/internal/webui"
)

// previewWGPublicKey is a syntactically valid, non-secret WireGuard public
// key used only to make Review run the exact enrollplan validation/allocation
// path. Commit always replaces it with the public key read from the node.
const previewWGPublicKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

type enrollmentBackend struct {
	scan           func(context.Context, enrollssh.Connection) (enrollssh.HostKey, error)
	confirm        func(context.Context, enrollssh.Connection, enrollssh.HostKey) (enrollssh.HostKey, error)
	preflight      func(context.Context, enrollssh.Connection) (enrollssh.PreflightResult, error)
	installWGTools func(context.Context, enrollssh.Connection) (bool, error)
	prepareWG      func(context.Context, enrollssh.Connection) (enrollssh.PrepareWGResult, error)
	lookupIP       func(context.Context, string) ([]net.IPAddr, error)
	lookupGeoIP    func(context.Context, string) (geoIPLocation, error)

	read          func() ([]byte, error)
	revision      func([]byte) string
	guardRevision func([]byte, string) error
	saveMu        *sync.Mutex
	ssotPath      string
}

// newNodeEnrollmentDeps wires the process-owning SSH boundary to webui's
// data-only contract. The function is deliberately parameterized by the same
// transaction primitives as the other structured SSOT writers, so enrollment
// cannot race them inside one control process.
func newNodeEnrollmentDeps(
	c *Control,
	saveMu *sync.Mutex,
	read func() ([]byte, error),
	revision func([]byte) string,
	guardRevision func([]byte, string) error,
) *webui.NodeEnrollmentDeps {
	scanner := enrollssh.Scanner{}
	knownHosts := enrollssh.KnownHostsStore{Path: c.KnownHostsPath, Scanner: scanner}
	client := enrollssh.Client{
		PrivateKeyPath: c.BootstrapSSHKey,
		KnownHostsPath: c.KnownHostsPath,
	}
	b := enrollmentBackend{
		scan:           scanner.Scan,
		confirm:        knownHosts.ConfirmKnownHost,
		preflight:      client.Preflight,
		installWGTools: client.EnsureWireGuardTools,
		prepareWG:      client.PrepareWG,
		lookupIP:       net.DefaultResolver.LookupIPAddr,
		read:           read,
		revision:       revision,
		guardRevision:  guardRevision,
		saveMu:         saveMu,
		ssotPath:       c.SSOTPath,
	}
	if !c.GeoIPDisabled {
		geoClient := netx.Client("", 3*time.Second)
		geoClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 || req.URL.Scheme != "https" || req.URL.Hostname() != defaultGeoIPProvider {
				return http.ErrUseLastResponse
			}
			return nil
		}
		b.lookupGeoIP = func(ctx context.Context, ip string) (geoIPLocation, error) {
			return lookupIPWhoIs(ctx, geoClient, ip)
		}
	}
	return b.dependencies()
}

func (b enrollmentBackend) dependencies() *webui.NodeEnrollmentDeps {
	return &webui.NodeEnrollmentDeps{
		Scan:   b.scanHostKey,
		Review: b.review,
		Commit: b.commit,
	}
}

func (b enrollmentBackend) scanHostKey(ctx context.Context, input webui.EnrollmentConnection) (webui.EnrollmentHostKey, error) {
	connection, err := sshConnection(input)
	if err != nil {
		return webui.EnrollmentHostKey{}, err
	}
	key, err := b.scan(ctx, connection)
	if err != nil {
		return webui.EnrollmentHostKey{}, err
	}
	return enrollmentHostKey(key), nil
}

type enrollmentDiscovery struct {
	connection         enrollssh.Connection
	hostKey            enrollssh.HostKey
	preflight          enrollssh.PreflightResult
	nodeID             string
	wgToolsInstalled   bool
	endpoint           string
	endpointEvidence   string
	endpointResolution string
	requestedDirection string
	direction          model.Direction
	directionEvidence  string
}

func (b enrollmentBackend) discover(ctx context.Context, input webui.EnrollmentReviewInput) (enrollmentDiscovery, error) {
	connection, err := sshConnection(input.Connection)
	if err != nil {
		return enrollmentDiscovery{}, err
	}
	expectedKey := enrollssh.HostKey{
		Algorithm: input.HostKey.Algorithm, PublicKey: input.HostKey.PublicKey,
		Fingerprint: input.HostKey.Fingerprint,
	}
	confirmed, err := b.confirm(ctx, connection, expectedKey)
	if err != nil {
		return enrollmentDiscovery{}, fmt.Errorf("confirm SSH host key: %w", err)
	}
	preflight, err := b.preflight(ctx, connection)
	if err != nil {
		return enrollmentDiscovery{}, fmt.Errorf("trusted SSH preflight: %w", err)
	}
	nodeID, err := enrollmentNodeID(preflight.Hostname)
	if err != nil {
		return enrollmentDiscovery{}, err
	}
	if err := validateEnrollmentPreflightPrerequisites(preflight); err != nil {
		return enrollmentDiscovery{}, err
	}
	endpoint, endpointEvidence, endpointResolution, err := determinePublicEndpoint(ctx, connection.Host, preflight.ObservedSSHServerAddress, b.lookupIP)
	if err != nil {
		return enrollmentDiscovery{}, err
	}
	direction, directionEvidence, err := resolveEnrollmentDirection(input.RequestedDirection)
	if err != nil {
		return enrollmentDiscovery{}, err
	}
	wgToolsInstalled := false
	if !preflight.WGCommand {
		if b.installWGTools == nil {
			return enrollmentDiscovery{}, errors.New("automatic wireguard-tools installer is unavailable")
		}
		beforeInstall := preflight
		wgToolsInstalled, err = b.installWGTools(ctx, connection)
		if err != nil {
			return enrollmentDiscovery{}, fmt.Errorf("install wireguard-tools during trusted SSH preflight: %w", err)
		}
		preflight, err = b.preflight(ctx, connection)
		if err != nil {
			return enrollmentDiscovery{}, fmt.Errorf("verify wireguard-tools after installation: %w", err)
		}
		afterNodeID, normalizeErr := enrollmentNodeID(preflight.Hostname)
		if normalizeErr != nil {
			return enrollmentDiscovery{}, normalizeErr
		}
		if preflight.Hostname != beforeInstall.Hostname || afterNodeID != nodeID || !sameIPAddress(preflight.ObservedSSHServerAddress, beforeInstall.ObservedSSHServerAddress) {
			return enrollmentDiscovery{}, fmt.Errorf("remote identity changed while installing wireguard-tools: hostname %q → %q, SSH address %q → %q",
				beforeInstall.Hostname, preflight.Hostname, beforeInstall.ObservedSSHServerAddress, preflight.ObservedSSHServerAddress)
		}
	}
	if err := validateEnrollmentPreflight(preflight); err != nil {
		return enrollmentDiscovery{}, err
	}
	return enrollmentDiscovery{
		connection: connection, hostKey: confirmed, preflight: preflight, nodeID: nodeID,
		wgToolsInstalled: wgToolsInstalled,
		endpoint:         endpoint, endpointEvidence: endpointEvidence, endpointResolution: endpointResolution,
		requestedDirection: input.RequestedDirection,
		direction:          direction, directionEvidence: directionEvidence,
	}, nil
}

func (b enrollmentBackend) review(ctx context.Context, input webui.EnrollmentReviewInput) (webui.EnrollmentReview, error) {
	discovered, err := b.discover(ctx, input)
	if err != nil {
		return webui.EnrollmentReview{}, err
	}
	current, err := b.read()
	if err != nil {
		return webui.EnrollmentReview{}, fmt.Errorf("read SSOT for enrollment review: %w", err)
	}
	country, city := strings.ToUpper(strings.TrimSpace(input.Country)), strings.TrimSpace(input.City)
	geoIPEvidence := "GeoIP suggestion was disabled for this declaration review."
	geoIPSuggested := false
	if !input.DisableGeoIP {
		geoIPEvidence = "Country and city were supplied by the operator; GeoIP was not queried again."
		if (country == "" || city == "") && b.lookupGeoIP != nil {
			address, addressErr := firstEndpointAddress(discovered.endpointResolution)
			if addressErr != nil {
				geoIPEvidence = "GeoIP suggestion unavailable: " + addressErr.Error()
			} else if location, lookupErr := b.lookupGeoIP(ctx, address); lookupErr != nil {
				geoIPEvidence = "GeoIP suggestion unavailable: " + lookupErr.Error()
			} else {
				if country == "" {
					country = location.Country
					geoIPSuggested = country != ""
				}
				if city == "" {
					city = location.City
					geoIPSuggested = geoIPSuggested || city != ""
				}
				geoIPEvidence = location.Evidence
			}
		} else if country == "" || city == "" {
			geoIPEvidence = "GeoIP suggestion is unavailable on this control node; empty location fields remain optional."
		}
	}
	plan, err := enrollplan.Preview(current, discovered.nodeInput(previewWGPublicKey, country, city))
	if err != nil {
		return webui.EnrollmentReview{}, fmt.Errorf("preview node enrollment: %w", err)
	}
	tunnels, err := enrollmentTunnelViews(current, plan)
	if err != nil {
		return webui.EnrollmentReview{}, err
	}
	review := webui.EnrollmentReview{
		Connection:              input.Connection,
		HostKey:                 enrollmentHostKey(discovered.hostKey),
		NodeID:                  discovered.nodeID,
		ObservedHostname:        discovered.preflight.Hostname,
		PublicEndpoint:          discovered.endpoint,
		Country:                 plan.Node.Country,
		City:                    plan.Node.City,
		DisableGeoIP:            input.DisableGeoIP,
		GeoIPSuggested:          geoIPSuggested,
		GeoIPEvidence:           geoIPEvidence,
		EndpointEvidence:        discovered.endpointEvidence,
		EndpointResolution:      discovered.endpointResolution,
		System:                  discovered.preflight.Uname,
		Privilege:               string(discovered.preflight.Privilege),
		KernelWireGuard:         discovered.preflight.KernelWireGuard,
		WGCommand:               discovered.preflight.WGCommand,
		WireGuardToolsInstalled: discovered.wgToolsInstalled,
		RequestedDirection:      discovered.requestedDirection,
		ResolvedDirection:       string(discovered.direction),
		DirectionEvidence:       discovered.directionEvidence,
		Revision:                b.revision(current),
		EgressEnabled:           true,
		Tunnels:                 tunnels,
	}
	for _, policy := range plan.ExpandedPolicies {
		review.ExpandedPolicies = append(review.ExpandedPolicies, webui.EnrollmentPolicy{
			ID: policy.ID, Name: policy.Name,
		})
	}
	for _, policy := range plan.FixedPolicies {
		review.FixedPolicies = append(review.FixedPolicies, webui.EnrollmentPolicy{
			ID: policy.ID, Name: policy.Name,
		})
	}
	return review, nil
}

func (b enrollmentBackend) commit(ctx context.Context, input webui.EnrollmentCommitInput) (string, error) {
	discovered, err := b.discover(ctx, input.EnrollmentReviewInput)
	if err != nil {
		return "", err
	}
	if input.ExpectedNodeID == "" || discovered.nodeID != input.ExpectedNodeID {
		return "", fmt.Errorf("remote node identity drifted after review: expected %q, derived %q from hostname %q", input.ExpectedNodeID, discovered.nodeID, discovered.preflight.Hostname)
	}
	if input.ExpectedEndpoint == "" || discovered.endpoint != input.ExpectedEndpoint {
		return "", fmt.Errorf("control-determined public endpoint drifted after review: expected %q, observed %q", input.ExpectedEndpoint, discovered.endpoint)
	}
	if input.ExpectedEndpointResolution == "" || discovered.endpointResolution != input.ExpectedEndpointResolution {
		return "", fmt.Errorf("control DNS/address evidence drifted after review: expected %q, observed %q",
			input.ExpectedEndpointResolution, discovered.endpointResolution)
	}
	prepared, err := b.prepareWG(ctx, discovered.connection)
	if err != nil {
		return "", fmt.Errorf("prepare node WireGuard identity: %w", err)
	}
	preparedNodeID, err := enrollmentNodeID(prepared.Hostname)
	if err != nil {
		return "", err
	}
	if prepared.Hostname != discovered.preflight.Hostname || preparedNodeID != input.ExpectedNodeID {
		return "", fmt.Errorf("remote node identity changed between trusted SSH sessions: preflight %q, key preparation %q",
			discovered.preflight.Hostname, prepared.Hostname)
	}
	if !sameIPAddress(prepared.ObservedSSHServerAddress, discovered.preflight.ObservedSSHServerAddress) {
		return "", fmt.Errorf("SSH server address changed between preflight and key preparation: %q → %q",
			discovered.preflight.ObservedSSHServerAddress, prepared.ObservedSSHServerAddress)
	}

	// Remote key preparation is intentionally outside this lock: it can be
	// slow, and is idempotent. The only state that must be all-or-nothing is the
	// local revision check + complete SSOT replacement below.
	b.saveMu.Lock()
	defer b.saveMu.Unlock()
	if err := withSSOTLock(b.ssotPath, func() error {
		snapshot, err := readSSOTSnapshot(b.ssotPath)
		if err != nil {
			return fmt.Errorf("read SSOT before node enrollment: %w", err)
		}
		if err := b.guardRevision(snapshot.body, input.ExpectedRevision); err != nil {
			return err
		}
		next, err := enrollplan.Apply(snapshot.body, discovered.nodeInput(prepared.PublicKey, input.Country, input.City))
		if err != nil {
			return fmt.Errorf("apply node enrollment: %w", err)
		}
		return saveSSOTAtomicFromSnapshot(b.ssotPath, next, snapshot)
	}); err != nil {
		return "", err
	}
	return discovered.nodeID, nil
}

func (d enrollmentDiscovery) nodeInput(publicKey, country, city string) enrollplan.NodeInput {
	egress := true
	return enrollplan.NodeInput{
		ID:             d.nodeID,
		Country:        country,
		City:           city,
		PublicEndpoint: d.endpoint,
		SSHPort:        d.connection.Port,
		Direction:      d.direction,
		WGPublicKey:    publicKey,
		EgressCapable:  &egress,
	}
}

func sshConnection(input webui.EnrollmentConnection) (enrollssh.Connection, error) {
	c := enrollssh.Connection{Host: input.Host, User: input.User, Port: input.Port}
	if err := c.Validate(); err != nil {
		return enrollssh.Connection{}, err
	}
	return c, nil
}

func enrollmentHostKey(key enrollssh.HostKey) webui.EnrollmentHostKey {
	return webui.EnrollmentHostKey{
		Algorithm: key.Algorithm, PublicKey: key.PublicKey, Fingerprint: key.Fingerprint,
	}
}

func validateEnrollmentPreflightPrerequisites(p enrollssh.PreflightResult) error {
	if !p.KernelWireGuard {
		return errors.New("remote preflight did not prove WireGuard kernel support")
	}
	if p.Privilege != enrollssh.PrivilegeRoot && p.Privilege != enrollssh.PrivilegeSudo {
		return errors.New("remote preflight requires root or passwordless sudo for bootstrap")
	}
	return nil
}

func validateEnrollmentPreflight(p enrollssh.PreflightResult) error {
	if err := validateEnrollmentPreflightPrerequisites(p); err != nil {
		return err
	}
	if !p.WGCommand {
		return errors.New("remote preflight did not find the wg command after automatic installation")
	}
	return nil
}

// enrollmentNodeID keeps the remote hostname as evidence while deriving the
// canonical identity used across DNS, paths and routing tags. ASCII case and
// separator differences are harmless; an empty or still-invalid result fails
// closed instead of inventing an unrelated identity.
func enrollmentNodeID(hostname string) (string, error) {
	var b strings.Builder
	separator := false
	for i := 0; i < len(hostname); i++ {
		c := hostname[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
			if separator && b.Len() > 0 {
				b.WriteByte('-')
			}
			separator = false
			b.WriteByte(c)
			continue
		}
		if c == '-' || c == '_' {
			separator = true
			continue
		}
		return "", fmt.Errorf("remote hostname %q contains a character that cannot be normalized into a Node ID", hostname)
	}
	nodeID := b.String()
	if !model.ValidNodeID(nodeID) {
		return "", fmt.Errorf("remote hostname %q cannot be normalized into a valid Node ID; require at least one ASCII letter or digit and at most 63 characters", hostname)
	}
	maxPeerIDLen := model.LinuxIfnameMax - len("wg-")
	if len(nodeID) > maxPeerIDLen {
		digest := sha256.Sum256([]byte(nodeID))
		suffix := fmt.Sprintf("%x", digest[:2])
		prefix := strings.TrimRight(nodeID[:maxPeerIDLen-len(suffix)-1], "-")
		nodeID = prefix + "-" + suffix
	}
	return nodeID, nil
}

func resolveEnrollmentDirection(requested string) (model.Direction, string, error) {
	switch requested {
	case "automatic":
		return model.ReverseOnly,
			"Automatic resolved conservatively to reverse_only: bootstrap has no authenticated UDP inbound reachability proof.", nil
	case string(model.Bidirectional), string(model.ReverseOnly), string(model.DirectOnly):
		direction := model.Direction(requested)
		return direction,
			fmt.Sprintf("Operator explicitly requested %s; this overrides Automatic but is not an inbound UDP reachability measurement.", direction), nil
	default:
		return "", "", fmt.Errorf("direction %q is invalid: use automatic, bidirectional, reverse_only, or direct_only", requested)
	}
}

// determinePublicEndpoint accepts only an address that the control node can
// classify itself. SSH_CONNECTION is retained as diagnostic evidence only;
// it commonly contains a post-NAT private address and must never be promoted
// to public_endpoint.
func determinePublicEndpoint(
	ctx context.Context,
	host, observedSSHServer string,
	lookup func(context.Context, string) ([]net.IPAddr, error),
) (string, string, string, error) {
	if parsed, err := netip.ParseAddr(host); err == nil {
		parsed = parsed.Unmap()
		if !isPublicGlobalUnicast(parsed) {
			return "", "", "", fmt.Errorf("SSH host %q is private, local, reserved, or otherwise not a public global-unicast endpoint", host)
		}
		return parsed.String(), fmt.Sprintf(
			"Control connected to the literal public global-unicast address %s; remote SSH_CONNECTION address %q was not used as endpoint evidence.",
			parsed, observedSSHServer), parsed.String(), nil
	}
	if lookup == nil {
		return "", "", "", errors.New("control DNS resolver is unavailable")
	}
	addresses, err := lookup(ctx, host)
	if err != nil {
		return "", "", "", fmt.Errorf("control could not resolve SSH DNS name %q: %w", host, err)
	}
	public := make([]string, 0, len(addresses))
	seen := make(map[string]bool, len(addresses))
	for _, address := range addresses {
		parsed, ok := netip.AddrFromSlice(address.IP)
		if !ok {
			continue
		}
		parsed = parsed.Unmap()
		if !isPublicGlobalUnicast(parsed) || seen[parsed.String()] {
			continue
		}
		seen[parsed.String()] = true
		public = append(public, parsed.String())
	}
	if len(public) == 0 {
		return "", "", "", fmt.Errorf("SSH DNS name %q did not resolve on the control node to any public global-unicast address", host)
	}
	sort.Strings(public)
	endpoint := strings.ToLower(host)
	return endpoint, fmt.Sprintf(
		"Control DNS resolved %s to public global-unicast address(es) %s; remote SSH_CONNECTION address %q was not used as endpoint evidence.",
		endpoint, strings.Join(public, ", "), observedSSHServer), strings.Join(public, ","), nil
}

func sameIPAddress(a, b string) bool {
	aAddr, aErr := netip.ParseAddr(a)
	bAddr, bErr := netip.ParseAddr(b)
	return aErr == nil && bErr == nil && aAddr.Unmap() == bAddr.Unmap()
}

var nonPublicGlobalPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001:db8::/32"),
}

func isPublicGlobalUnicast(address netip.Addr) bool {
	address = address.Unmap()
	if !address.IsValid() || !address.IsGlobalUnicast() || address.IsPrivate() ||
		address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsUnspecified() {
		return false
	}
	for _, prefix := range nonPublicGlobalPrefixes {
		if prefix.Contains(address) {
			return false
		}
	}
	return true
}

func enrollmentTunnelViews(content []byte, plan enrollplan.Plan) ([]webui.EnrollmentTunnel, error) {
	ssot, err := model.Load(content)
	if err != nil {
		return nil, fmt.Errorf("load SSOT while mapping enrollment tunnels: %w", err)
	}
	nodes := ssot.NodeByID()
	nodes[plan.Node.ID] = &plan.Node
	views := make([]webui.EnrollmentTunnel, 0, len(plan.Tunnels))
	for _, tunnel := range plan.Tunnels {
		from, to := nodes[tunnel.From], nodes[tunnel.To]
		if from == nil || to == nil || from.Server == nil || to.Server == nil {
			return nil, fmt.Errorf("planned tunnel %s ↔ %s references a missing server node", tunnel.From, tunnel.To)
		}
		fromInitiates, err := model.ResolveInitiator(from.ID, from.Server.Direction, to.ID, to.Server.Direction)
		if err != nil {
			return nil, err
		}
		initiator, acceptor := to.ID, from.ID
		if fromInitiates {
			initiator, acceptor = from.ID, to.ID
		}
		views = append(views, webui.EnrollmentTunnel{
			From: tunnel.From, To: tunnel.To,
			FromAddress: tunnel.FromAddr, ToAddress: tunnel.ToAddr,
			Initiator: initiator, Acceptor: acceptor,
			ListenPort: tunnel.ListenPort,
		})
	}
	return views, nil
}
