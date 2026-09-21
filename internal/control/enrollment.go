package control

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"

	"loom/internal/clientmodel"
)

const (
	endpointSchema     = 1
	enrollmentSchema   = 1
	enrollmentSchemaV2 = 2
	deviceViewSchema   = 1
	deviceViewSchemaV2 = 2

	capabilityDomain = "loom-bootstrap-capability-v1\n"
	constraintDomain = "loom-enrollment-constraint-v1\n"
	deviceViewDomain = "loom-device-view-v1\n"
	deviceNodeDomain = "loom-device-view-node-v1\n"
)

type EndpointGeneration struct {
	Schema             int    `json:"schema"`
	EndpointID         string `json:"endpoint_id"`
	Generation         uint64 `json:"generation"`
	Node               string `json:"node"`
	EdgeNode           string `json:"edge_node,omitempty"`
	EdgeListen         string `json:"edge_listen,omitempty"`
	Transport          string `json:"transport"`
	Listen             string `json:"listen"`
	Address            string `json:"address"`
	ServerName         string `json:"server_name"`
	TLSCertificateFile string `json:"tls_certificate_file"`
	TLSPrivateKeyFile  string `json:"tls_private_key_file"`
	SPKISHA256         string `json:"spki_sha256"`
	State              string `json:"state"`
	Preference         int    `json:"preference"`
}

type EndpointReference struct {
	EndpointID string `json:"endpoint_id"`
	Generation uint64 `json:"generation"`
	Transport  string `json:"transport"`
	Address    string `json:"address"`
	ServerName string `json:"server_name"`
	SPKISHA256 string `json:"spki_sha256"`
	State      string `json:"state"`
	Preference int    `json:"preference"`
}

type RouteCandidate = clientmodel.RouteCandidate
type RuntimeProfile = clientmodel.RuntimeProfile

type EnrollmentIntent struct {
	Schema            int              `json:"schema,omitempty"`
	DeviceID          string           `json:"device_id"`
	Name              string           `json:"name"`
	Platform          string           `json:"platform"`
	Roles             []string         `json:"roles"`
	Routes            []RouteCandidate `json:"routes"`
	Runtime           *RuntimeProfile  `json:"runtime_profile,omitempty"`
	DestinationGrants []string         `json:"destination_grants,omitempty"`
	Server            *ServerIntent    `json:"server,omitempty"`
}

type BootstrapCapability struct {
	Schema           int                 `json:"schema"`
	TransactionID    string              `json:"transaction_id"`
	IssuedHead       string              `json:"issued_head"`
	ConfigMaterial   string              `json:"control_config_material"`
	ControlConfig    ControlConfig       `json:"control_config"`
	ExpiresAt        string              `json:"expires_at"`
	Actions          []string            `json:"actions"`
	Endpoints        []EndpointReference `json:"endpoints"`
	ConstraintDigest string              `json:"constraint_digest"`
	IssuerMemberID   string              `json:"issuer_member_id"`
	Signature        string              `json:"signature"`
}

type BootstrapInvite struct {
	Schema     int                 `json:"schema"`
	Capability BootstrapCapability `json:"capability"`
}

type EnrollmentOpen struct {
	TransactionID string              `json:"transaction_id"`
	Intent        EnrollmentIntent    `json:"intent"`
	Capability    BootstrapCapability `json:"capability"`
}

type EnrollmentBind struct {
	TransactionID   string         `json:"transaction_id"`
	ClaimRequestID  string         `json:"claim_request_id"`
	DevicePublicKey string         `json:"device_public_key"`
	ClaimedAt       string         `json:"claimed_at"`
	Server          *ServerClaimV2 `json:"server,omitempty"`
}

type EnrollmentApprove struct {
	TransactionID string `json:"transaction_id"`
}

type EnrollmentComplete struct {
	TransactionID string              `json:"transaction_id"`
	Authorization DeviceAuthorization `json:"authorization"`
	ResultDigest  string              `json:"result_digest"`
}

type EnrollmentExpire struct {
	TransactionID string `json:"transaction_id"`
	ExpiredAt     string `json:"expired_at"`
}

type EnrollmentTransaction struct {
	Schema           int              `json:"schema"`
	ID               string           `json:"id"`
	State            string           `json:"state"`
	Intent           EnrollmentIntent `json:"intent"`
	CapabilityDigest string           `json:"capability_digest"`
	ExpiresAt        string           `json:"expires_at"`
	ClaimRequestID   string           `json:"claim_request_id,omitempty"`
	DevicePublicKey  string           `json:"device_public_key,omitempty"`
	ClaimedAt        string           `json:"claimed_at,omitempty"`
	ClaimedServer    *ServerClaimV2   `json:"claimed_server,omitempty"`
	ResultDigest     string           `json:"result_digest,omitempty"`
}

type DeviceAuthorization struct {
	Schema            int              `json:"schema"`
	DeviceID          string           `json:"device_id"`
	Name              string           `json:"name,omitempty"`
	Platform          string           `json:"platform,omitempty"`
	Roles             []string         `json:"roles,omitempty"`
	Routes            []RouteCandidate `json:"routes,omitempty"`
	Runtime           *RuntimeProfile  `json:"runtime_profile,omitempty"`
	DevicePublicKey   string           `json:"device_public_key"`
	Floor             uint64           `json:"floor"`
	DestinationGrants []string         `json:"destination_grants,omitempty"`
	Server            *ServerIntent    `json:"server,omitempty"`
	RuntimeKey        string           `json:"runtime_key,omitempty"`
	// RuntimeContract versions the deterministic DeviceView projection. Zero
	// preserves the schema-2 contract certified before this field existed;
	// contract 2 binds data-plane TLS to the stable node identity.
	RuntimeContract int `json:"runtime_contract,omitempty"`
}

const (
	runtimeContractNodeTLS = 2
	runtimeContractDNSACL  = 3
	runtimeContractViewDNS = 4
	runtimeContractProbe   = 5
	runtimeContractCurrent = runtimeContractProbe
)

// ServerRuntimeProfile is a private, deterministic projection for the
// authorized server device. It is carried only in that device's certified
// DeviceView; WebProjection never contains it. Passwords are derived from the
// originating access authorization RuntimeKey and therefore do not create a
// second credential store.
type ServerRuntimeProfile struct {
	Kind       string                   `json:"kind"`
	Protocol   string                   `json:"protocol"`
	ListenPort int                      `json:"listen_port"`
	Users      []ServerRuntimeUser      `json:"users"`
	ACL        []ServerRuntimeACL       `json:"acl"`
	WireGuard  []ServerWireGuardRuntime `json:"wireguard"`
}

type DeviceRuntimeUpgrade struct {
	DeviceID        string `json:"device_id"`
	RuntimeContract int    `json:"runtime_contract"`
}

type ServerRuntimeUser struct {
	Name     string `json:"name"`
	Password string `json:"password"`
}

type ServerRuntimeACL struct {
	User                string   `json:"user"`
	Action              string   `json:"action"`
	DestinationMatchers []string `json:"destination_matchers,omitempty"`
	DNSAddresses        []string `json:"dns_addresses,omitempty"`
	NextHost            string   `json:"next_host,omitempty"`
	NextPort            int      `json:"next_port,omitempty"`
	BindInterface       string   `json:"bind_interface,omitempty"`
}

type ServerWireGuardRuntime struct {
	LinkID              string `json:"link_id"`
	Interface           string `json:"interface"`
	LocalAddress        string `json:"local_address"`
	PeerID              string `json:"peer_id"`
	PeerPublicKey       string `json:"peer_public_key"`
	AllowedIP           string `json:"allowed_ip"`
	Mode                string `json:"mode"`
	ListenPort          int    `json:"listen_port,omitempty"`
	Endpoint            string `json:"endpoint,omitempty"`
	PersistentKeepalive int    `json:"persistent_keepalive"`
	ProbeTarget         string `json:"probe_target"`
}

type ServerClaimV2 struct {
	PublicEndpoint  string `json:"public_endpoint"`
	InboundPort     int    `json:"inbound_port"`
	InboundProtocol string `json:"inbound_protocol"`
	WGPublicKey     string `json:"wg_public_key"`
}

func (claim ServerClaimV2) Validate() error {
	server := ServerIntent{Direction: "bidirectional", PublicEndpoint: claim.PublicEndpoint, InboundPort: claim.InboundPort,
		InboundProtocol: claim.InboundProtocol, WGPublicKey: claim.WGPublicKey}
	return validateServerIntent(&server)
}

func serverIntentFromClaim(intent *ServerIntent, claim *ServerClaimV2) (*ServerIntent, error) {
	if intent == nil || claim == nil || claim.Validate() != nil || validateServerDirection(intent) != nil {
		return nil, errors.New("server claim does not match product intent")
	}
	return &ServerIntent{Direction: intent.Direction, PublicDataIngress: intent.PublicDataIngress,
		PublicEndpoint: claim.PublicEndpoint, InboundPort: claim.InboundPort, InboundProtocol: claim.InboundProtocol,
		EgressCapable: intent.EgressCapable, WGPublicKey: claim.WGPublicKey}, nil
}

func (profile ServerRuntimeProfile) Validate() error {
	if profile.Kind != "sing_box" || profile.ListenPort < 1 || profile.ListenPort > 65535 {
		return errors.New("server runtime profile is incomplete")
	}
	if profile.Protocol != "hysteria2" && profile.Protocol != "trojan" {
		return errors.New("server runtime protocol is unsupported")
	}
	users := map[string]bool{}
	used := map[string]bool{}
	for index, user := range profile.Users {
		if !validName(user.Name) || !validRuntimeKey(user.Password) ||
			index > 0 && profile.Users[index-1].Name >= user.Name {
			return errors.New("server runtime users are not uniquely sorted")
		}
		users[user.Name] = true
	}
	previous := ""
	for _, rule := range profile.ACL {
		key := fmt.Sprintf("%s\x00%s\x00%s\x00%05d\x00%s\x00%s\x00%s", rule.User, rule.Action, rule.NextHost,
			rule.NextPort, rule.BindInterface, strings.Join(rule.DestinationMatchers, "\x00"), strings.Join(rule.DNSAddresses, "\x00"))
		if !users[rule.User] || previous >= key && previous != "" {
			return errors.New("server runtime ACL is not uniquely sorted")
		}
		switch rule.Action {
		case "egress":
			if rule.NextHost != "" || rule.NextPort != 0 || rule.BindInterface != "" ||
				validateSortedNames(rule.DestinationMatchers, "server runtime destination matchers") != nil ||
				validIPList(rule.DNSAddresses, "server runtime DNS addresses") != nil ||
				(len(rule.DestinationMatchers) == 0) == (len(rule.DNSAddresses) == 0) {
				return errors.New("server runtime egress ACL is invalid")
			}
		case "next_hop":
			if len(rule.DestinationMatchers) != 0 || len(rule.DNSAddresses) != 0 || !validName(rule.NextHost) || rule.NextPort < 1 || rule.NextPort > 65535 ||
				!validName(rule.BindInterface) {
				return errors.New("server runtime next-hop ACL is incomplete")
			}
		default:
			return errors.New("server runtime ACL action is invalid")
		}
		used[rule.User] = true
		previous = key
	}
	for user := range users {
		if !used[user] {
			return errors.New("server runtime user has no authorized destination")
		}
	}
	previous = ""
	for _, link := range profile.WireGuard {
		localPrefix, localErr := netip.ParsePrefix(link.LocalAddress)
		allowedPrefix, allowedErr := netip.ParsePrefix(link.AllowedIP)
		probeAddress, probeErr := netip.ParseAddr(link.ProbeTarget)
		key := link.LinkID + "\x00" + link.PeerID
		if !validName(link.LinkID) || !validName(link.Interface) || len(link.Interface) > 15 || !validName(link.PeerID) ||
			!validWGPublicKey(link.PeerPublicKey) || link.LocalAddress == "" || link.AllowedIP == "" ||
			localErr != nil || localPrefix.String() != link.LocalAddress || allowedErr != nil || allowedPrefix.String() != link.AllowedIP ||
			probeErr != nil || probeAddress.String() != link.ProbeTarget || previous >= key && previous != "" {
			return errors.New("server runtime WireGuard links are invalid")
		}
		switch link.Mode {
		case "initiator":
			if link.ListenPort != 0 || !validAddress(link.Endpoint) || link.PersistentKeepalive != 25 {
				return errors.New("server runtime WireGuard initiator is invalid")
			}
		case "acceptor":
			if link.ListenPort < 1 || link.ListenPort > 65535 || link.Endpoint != "" || link.PersistentKeepalive != 0 {
				return errors.New("server runtime WireGuard acceptor is invalid")
			}
		default:
			return errors.New("server runtime WireGuard mode is invalid")
		}
		previous = key
	}
	return nil
}

// DeviceRevoke is a Material payload, not a new lifecycle entity. Applying it
// removes the existing DeviceAuthorization from Projection while immutable
// enrollment history remains in the consensus log.
type DeviceRevoke struct {
	DeviceID string `json:"device_id"`
}

type DeviceView struct {
	Schema               int                    `json:"schema"`
	DeviceID             string                 `json:"device_id"`
	Name                 string                 `json:"name"`
	Platform             string                 `json:"platform"`
	Roles                []string               `json:"roles"`
	DevicePublicKey      string                 `json:"device_public_key"`
	Floor                uint64                 `json:"floor"`
	Endpoints            []EndpointReference    `json:"endpoint_generations"`
	Routes               []RouteCandidate       `json:"route_candidates"`
	Runtime              *RuntimeProfile        `json:"runtime_profile,omitempty"`
	DestinationGrants    []string               `json:"destination_grants,omitempty"`
	Server               *ServerIntent          `json:"server,omitempty"`
	ServerRuntime        *ServerRuntimeProfile  `json:"server_runtime,omitempty"`
	PublicDataPlaneCA    string                 `json:"public_data_plane_ca,omitempty"`
	RuntimeContract      int                    `json:"runtime_contract,omitempty"`
	DNS                  []string               `json:"dns,omitempty"`
	BusinessProbeTargets []string               `json:"business_probe_targets,omitempty"`
	ExpectedComponents   []ComponentExpectation `json:"expected_components,omitempty"`
	LinkProbeTargets     []LinkProbeTarget      `json:"link_probe_targets,omitempty"`
}

// RequiresServerDomainIdentification reports whether the certified runtime
// contract requires a server HostAdapter to recover HTTP Host/TLS SNI before
// applying Service matcher ACLs. Keeping this on the versioned view prevents a
// newer binary from silently changing historical runtime projection.
func (view DeviceView) RequiresServerDomainIdentification() bool {
	return view.RuntimeContract >= runtimeContractProbe
}

type DeviceViewProof struct {
	Index    int      `json:"index"`
	Size     int      `json:"size"`
	Siblings []string `json:"siblings"`
}

type DeviceViewEnvelope struct {
	Schema        int             `json:"schema"`
	View          DeviceView      `json:"view"`
	Head          GovernanceHead  `json:"certified_head"`
	ControlConfig ControlConfig   `json:"control_config"`
	Proof         DeviceViewProof `json:"proof"`
}

func validName(value string) bool {
	return value != "" && len(value) <= 128 && strings.TrimSpace(value) == value &&
		strings.IndexFunc(value, unicode.IsControl) < 0
}

func validDigest(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != 71 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
}

func validLowerHex(value string, byteLength int) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == byteLength && hex.EncodeToString(decoded) == value
}

func validRawKey(value string) bool {
	key, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(key) == ed25519.PublicKeySize && base64.RawURLEncoding.EncodeToString(key) == value
}

func validRuntimeKey(value string) bool {
	key, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(key) == 32 && base64.RawURLEncoding.EncodeToString(key) == value
}

func validWGPublicKey(value string) bool {
	key, err := base64.StdEncoding.DecodeString(value)
	return err == nil && len(key) == 32 && base64.StdEncoding.EncodeToString(key) == value
}

func validateServerIntent(server *ServerIntent) error {
	if server == nil || !validName(server.Direction) || server.PublicEndpoint == "" ||
		server.InboundPort < 1 || server.InboundPort > 65535 || !validName(server.InboundProtocol) ||
		!validWGPublicKey(server.WGPublicKey) {
		return errors.New("server intent is incomplete")
	}
	switch server.Direction {
	case "direct_only", "reverse_only", "bidirectional":
	default:
		return errors.New("server direction is invalid")
	}
	switch server.InboundProtocol {
	case "hysteria2", "trojan":
	default:
		return errors.New("server inbound protocol is invalid")
	}
	return nil
}

func validateServerDirection(server *ServerIntent) error {
	if server == nil {
		return errors.New("server direction is missing")
	}
	switch server.Direction {
	case "direct_only", "reverse_only", "bidirectional":
	default:
		return errors.New("server direction is invalid")
	}
	if server.PublicEndpoint != "" || server.InboundPort != 0 || server.InboundProtocol != "" || server.WGPublicKey != "" ||
		server.Country != "" || server.City != "" || server.Provider != "" {
		return errors.New("enrollment intent contains claim-time server facts")
	}
	return nil
}

func validAddress(value string) bool {
	host, port, err := net.SplitHostPort(value)
	if err != nil || host == "" || port == "" {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.String() == host || ip.To4() != nil && ip.To4().String() == host
	}
	u, err := url.Parse("https://" + value)
	return err == nil && u.Host == value && !strings.ContainsAny(host, " /@")
}

func (generation EndpointGeneration) Validate() error {
	if generation.Schema != endpointSchema || !validName(generation.EndpointID) || generation.Generation == 0 ||
		!validName(generation.Node) || generation.Transport != "tls_tunnel" || !validAddress(generation.Listen) ||
		!validAddress(generation.Address) || !validName(generation.ServerName) || generation.Preference < 0 ||
		len(generation.SPKISHA256) != sha256.Size*2 {
		return errors.New("endpoint generation is incomplete")
	}
	if (generation.EdgeNode == "") != (generation.EdgeListen == "") || generation.EdgeNode != "" &&
		(!validName(generation.EdgeNode) || generation.EdgeNode == generation.Node || !validAddress(generation.EdgeListen)) {
		return errors.New("endpoint generation edge is invalid")
	}
	if generation.EdgeNode != "" {
		host, _, _ := net.SplitHostPort(generation.Listen)
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsPrivate() && !ip.IsLoopback() {
			return errors.New("endpoint generation edge target is not private")
		}
	}
	if digest, err := hex.DecodeString(generation.SPKISHA256); err != nil || hex.EncodeToString(digest) != generation.SPKISHA256 {
		return errors.New("endpoint generation SPKI digest is invalid")
	}
	for _, name := range []string{generation.TLSCertificateFile, generation.TLSPrivateKeyFile} {
		if name == "" || !filepath.IsAbs(name) || filepath.Clean(name) != name {
			return errors.New("endpoint generation TLS reference is invalid")
		}
	}
	switch generation.State {
	case "prepared", "serving", "draining", "retired":
	default:
		return errors.New("endpoint generation state is invalid")
	}
	return nil
}

func (generation EndpointGeneration) Reference() EndpointReference {
	return EndpointReference{EndpointID: generation.EndpointID, Generation: generation.Generation,
		Transport: generation.Transport, Address: generation.Address, ServerName: generation.ServerName,
		SPKISHA256: generation.SPKISHA256, State: generation.State, Preference: generation.Preference}
}

func (endpoint EndpointReference) Validate() error {
	if !validName(endpoint.EndpointID) || endpoint.Generation == 0 || endpoint.Transport != "tls_tunnel" ||
		!validAddress(endpoint.Address) || !validName(endpoint.ServerName) || endpoint.Preference < 0 || len(endpoint.SPKISHA256) != sha256.Size*2 {
		return errors.New("endpoint reference is incomplete")
	}
	digest, err := hex.DecodeString(endpoint.SPKISHA256)
	if err != nil || hex.EncodeToString(digest) != endpoint.SPKISHA256 {
		return errors.New("endpoint reference SPKI digest is invalid")
	}
	switch endpoint.State {
	case "serving", "draining":
		return nil
	default:
		return errors.New("endpoint reference state is invalid")
	}
}

func (intent EnrollmentIntent) Validate() error {
	if !validName(intent.DeviceID) || !validName(intent.Name) {
		return errors.New("enrollment intent device is invalid")
	}
	switch intent.Platform {
	case "android", "linux", "windows":
	default:
		return errors.New("enrollment intent platform is invalid")
	}
	for index, role := range intent.Roles {
		if !validName(role) || index > 0 && intent.Roles[index-1] >= role {
			return errors.New("enrollment roles are not uniquely sorted")
		}
	}
	if intent.Schema == enrollmentSchemaV2 {
		if len(intent.Routes) != 0 || intent.Runtime != nil {
			return errors.New("schema-2 enrollment intent contains derived fields")
		}
		if err := validateSortedNames(intent.DestinationGrants, "enrollment grants"); err != nil {
			return err
		}
		hasServer, hasAccess := false, false
		for _, role := range intent.Roles {
			if role != "access" && role != "server" {
				return errors.New("schema-2 enrollment role is invalid")
			}
			hasServer = hasServer || role == "server"
			hasAccess = hasAccess || role == "access"
		}
		egress := hasServer && intent.Server != nil && intent.Server.EgressCapable
		if (intent.Platform == "android" || intent.Platform == "windows") && hasServer {
			return errors.New("schema-2 client platform cannot provide a server role")
		}
		if hasAccess && len(intent.DestinationGrants) == 0 || !hasAccess && !egress && len(intent.DestinationGrants) != 0 {
			return errors.New("schema-2 responsibilities and grants disagree")
		}
		if hasServer {
			if err := validateServerDirection(intent.Server); err != nil {
				return err
			}
		} else if intent.Server != nil {
			return errors.New("access-only enrollment contains server attributes")
		}
		return nil
	}
	if intent.Schema != 0 || len(intent.DestinationGrants) != 0 || intent.Server != nil {
		return errors.New("enrollment intent schema is invalid")
	}
	for index, candidate := range intent.Routes {
		if err := candidate.Validate(); err != nil || index > 0 && intent.Routes[index-1].ID >= candidate.ID {
			return errors.New("route candidates are not uniquely sorted")
		}
	}
	if intent.Platform == "android" || intent.Platform == "windows" {
		if intent.Runtime == nil || intent.Runtime.Validate(intent.Routes) != nil {
			return fmt.Errorf("%s enrollment runtime profile is invalid", intent.Platform)
		}
	} else if intent.Runtime != nil && intent.Runtime.Validate(intent.Routes) != nil {
		return errors.New("enrollment runtime profile is invalid")
	}
	return nil
}

func intentDigest(intent EnrollmentIntent) (string, error) {
	if err := intent.Validate(); err != nil {
		return "", err
	}
	body, err := canonical(intent)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append([]byte(constraintDomain), body...))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func capabilitySigningBytes(capability BootstrapCapability) ([]byte, error) {
	capability.Signature = ""
	body, err := canonical(capability)
	if err != nil {
		return nil, err
	}
	return append([]byte(capabilityDomain), body...), nil
}

func SignBootstrapCapability(capability BootstrapCapability, config NodeConfig) (BootstrapCapability, error) {
	capability.Signature = ""
	if capability.IssuerMemberID != config.MemberID {
		return capability, errors.New("bootstrap capability issuer is not local member")
	}
	message, err := capabilitySigningBytes(capability)
	if err != nil {
		return capability, err
	}
	capability.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(config.PrivateKey(), message))
	return capability, capability.Validate()
}

func (capability BootstrapCapability) Validate() error {
	if capability.Schema != enrollmentSchema || !validName(capability.TransactionID) || !validDigest(capability.IssuedHead) ||
		!validDigest(capability.ConfigMaterial) || !validDigest(capability.ConstraintDigest) || !validName(capability.IssuerMemberID) ||
		capability.ControlConfig.Validate() != nil || len(capability.Actions) != 2 || capability.Actions[0] != "claim" || capability.Actions[1] != "resume" ||
		len(capability.Endpoints) == 0 {
		return errors.New("bootstrap capability is incomplete")
	}
	if _, err := time.Parse(time.RFC3339, capability.ExpiresAt); err != nil {
		return errors.New("bootstrap capability expiry is invalid")
	}
	for index, endpoint := range capability.Endpoints {
		if endpoint.Validate() != nil || endpoint.State != "serving" ||
			index > 0 && !endpointReferenceLess(capability.Endpoints[index-1], endpoint) {
			return errors.New("bootstrap capability endpoints are invalid")
		}
	}
	member, found := configMember(capability.ControlConfig, capability.IssuerMemberID)
	if !found {
		return errors.New("bootstrap capability issuer is not in control config")
	}
	key, _ := base64.RawURLEncoding.DecodeString(member.PublicKey)
	signature, err := base64.RawURLEncoding.DecodeString(capability.Signature)
	if err != nil {
		return errors.New("bootstrap capability signature is invalid")
	}
	message, _ := capabilitySigningBytes(capability)
	if !ed25519.Verify(key, message, signature) {
		return errors.New("bootstrap capability signature is invalid")
	}
	return nil
}

func configMember(config ControlConfig, id string) (Member, bool) {
	for _, member := range uniqueConfigMembers(config) {
		if member.ID == id {
			return member, true
		}
	}
	return Member{}, false
}

func capabilityDigest(capability BootstrapCapability) (string, error) {
	if err := capability.Validate(); err != nil {
		return "", err
	}
	body, err := canonical(capability)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append([]byte(capabilityDomain+"id\n"), body...))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func EncodeInvite(invite BootstrapInvite) (string, error) {
	if invite.Schema != enrollmentSchema || invite.Capability.Validate() != nil {
		return "", errors.New("bootstrap invite is invalid")
	}
	body, err := canonical(invite)
	if err != nil {
		return "", err
	}
	return "loom://enroll#" + base64.RawURLEncoding.EncodeToString(body), nil
}

func DecodeInvite(raw string) (BootstrapInvite, error) {
	var invite BootstrapInvite
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme != "loom" || parsed.Host != "enroll" || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment == "" {
		return invite, errors.New("invalid bootstrap invite")
	}
	body, err := base64.RawURLEncoding.DecodeString(parsed.Fragment)
	if err != nil || len(body) > 64<<10 || base64.RawURLEncoding.EncodeToString(body) != parsed.Fragment || decodeCanonicalValue(body, &invite) != nil ||
		invite.Schema != enrollmentSchema || invite.Capability.Validate() != nil {
		return BootstrapInvite{}, errors.New("invalid bootstrap invite")
	}
	return invite, nil
}

func (open EnrollmentOpen) Validate() error {
	if !validName(open.TransactionID) || open.TransactionID != open.Capability.TransactionID || open.Intent.Validate() != nil || open.Capability.Validate() != nil {
		return errors.New("enrollment open is invalid")
	}
	digest, _ := intentDigest(open.Intent)
	if digest != open.Capability.ConstraintDigest {
		return errors.New("enrollment capability does not bind intent")
	}
	return nil
}

func (bind EnrollmentBind) Validate() error {
	if !validName(bind.TransactionID) || !validName(bind.ClaimRequestID) || !validRawKey(bind.DevicePublicKey) {
		return errors.New("enrollment binding is invalid")
	}
	if _, err := time.Parse(time.RFC3339, bind.ClaimedAt); err != nil {
		return errors.New("enrollment claim time is invalid")
	}
	if bind.Server != nil && bind.Server.Validate() != nil {
		return errors.New("enrollment server claim is invalid")
	}
	return nil
}

func (approve EnrollmentApprove) Validate() error {
	if !validName(approve.TransactionID) {
		return errors.New("enrollment approval is invalid")
	}
	return nil
}

func (authorization DeviceAuthorization) Validate() error {
	if !validName(authorization.DeviceID) || !validRawKey(authorization.DevicePublicKey) || authorization.Floor == 0 {
		return errors.New("device authorization is invalid")
	}
	switch authorization.Schema {
	case enrollmentSchema:
		intent := EnrollmentIntent{DeviceID: authorization.DeviceID, Name: authorization.Name, Platform: authorization.Platform,
			Roles: authorization.Roles, Routes: authorization.Routes, Runtime: authorization.Runtime}
		if intent.Validate() != nil || authorization.RuntimeKey != "" || len(authorization.DestinationGrants) != 0 || authorization.Server != nil ||
			authorization.RuntimeContract != 0 {
			return errors.New("legacy device authorization is invalid")
		}
	case enrollmentSchemaV2:
		if authorization.Name != "" || authorization.Platform != "" || len(authorization.Roles) != 0 || len(authorization.Routes) != 0 ||
			authorization.Runtime != nil || authorization.Server != nil || !validRuntimeKey(authorization.RuntimeKey) ||
			authorization.RuntimeContract != 0 &&
				(authorization.RuntimeContract < runtimeContractNodeTLS || authorization.RuntimeContract > runtimeContractCurrent) ||
			validateSortedNames(authorization.DestinationGrants, "device authorization grants") != nil {
			return errors.New("schema-2 device authorization contains duplicated or invalid facts")
		}
	default:
		return errors.New("device authorization schema is invalid")
	}
	return nil
}

func (upgrade DeviceRuntimeUpgrade) Validate() error {
	if !validName(upgrade.DeviceID) || upgrade.RuntimeContract < runtimeContractNodeTLS || upgrade.RuntimeContract > runtimeContractCurrent {
		return errors.New("device runtime upgrade is invalid")
	}
	return nil
}

func (revoke DeviceRevoke) Validate() error {
	if !validName(revoke.DeviceID) {
		return errors.New("device revocation is invalid")
	}
	return nil
}

func (complete EnrollmentComplete) Validate() error {
	if !validName(complete.TransactionID) || complete.Authorization.Validate() != nil || !validDigest(complete.ResultDigest) {
		return errors.New("enrollment completion is invalid")
	}
	return nil
}

func (expire EnrollmentExpire) Validate() error {
	expiredAt, err := time.Parse(time.RFC3339, expire.ExpiredAt)
	if !validName(expire.TransactionID) || err != nil || expire.ExpiredAt != expiredAt.UTC().Format(time.RFC3339) {
		return errors.New("enrollment expiration is invalid")
	}
	return nil
}

func endpointReferenceLess(left, right EndpointReference) bool {
	if left.Preference != right.Preference {
		return left.Preference < right.Preference
	}
	if left.EndpointID != right.EndpointID {
		return left.EndpointID < right.EndpointID
	}
	return left.Generation < right.Generation
}

func sameGenerationConfiguration(left, right EndpointGeneration) bool {
	left.State, right.State = "", ""
	left.Preference, right.Preference = 0, 0
	a, _ := canonical(left)
	b, _ := canonical(right)
	return bytes.Equal(a, b)
}

func reduceEndpointGeneration(projection *Projection, generation EndpointGeneration) error {
	index := sort.Search(len(projection.EndpointGenerations), func(index int) bool {
		current := projection.EndpointGenerations[index]
		return current.EndpointID > generation.EndpointID || current.EndpointID == generation.EndpointID && current.Generation >= generation.Generation
	})
	if index == len(projection.EndpointGenerations) || projection.EndpointGenerations[index].EndpointID != generation.EndpointID ||
		projection.EndpointGenerations[index].Generation != generation.Generation {
		if generation.State != "prepared" {
			return errors.New("new endpoint generation must be prepared")
		}
		for _, current := range projection.EndpointGenerations {
			if current.EndpointID == generation.EndpointID && current.Generation >= generation.Generation {
				return errors.New("endpoint generation is not monotonic")
			}
		}
		projection.EndpointGenerations = append(projection.EndpointGenerations, EndpointGeneration{})
		copy(projection.EndpointGenerations[index+1:], projection.EndpointGenerations[index:])
		projection.EndpointGenerations[index] = generation
		return nil
	}
	previous := projection.EndpointGenerations[index]
	if !sameGenerationConfiguration(previous, generation) {
		return errors.New("endpoint generation configuration is immutable")
	}
	allowed := previous.State == "prepared" && generation.State == "serving" ||
		previous.State == "serving" && (generation.State == "serving" || generation.State == "draining") ||
		previous.State == "draining" && generation.State == "retired"
	if !allowed {
		return fmt.Errorf("invalid endpoint generation transition %s -> %s", previous.State, generation.State)
	}
	if previous.State != "serving" && previous.Preference != generation.Preference {
		return errors.New("endpoint preference may only change while serving")
	}
	projection.EndpointGenerations[index] = generation
	return nil
}

func findEnrollment(projection *Projection, id string) (int, *EnrollmentTransaction) {
	index := sort.Search(len(projection.Enrollments), func(index int) bool { return projection.Enrollments[index].ID >= id })
	if index == len(projection.Enrollments) || projection.Enrollments[index].ID != id {
		return index, nil
	}
	return index, &projection.Enrollments[index]
}

func reduceEnrollmentOpen(projection *Projection, open EnrollmentOpen) error {
	index, existing := findEnrollment(projection, open.TransactionID)
	if existing != nil {
		return errors.New("enrollment transaction already exists")
	}
	for _, transaction := range projection.Enrollments {
		if transaction.Intent.DeviceID == open.Intent.DeviceID && transaction.State != "completed" && transaction.State != "rejected" &&
			transaction.State != "expired" && transaction.State != "cancelled" {
			return errors.New("device already has an enrollment transaction")
		}
	}
	for _, authorization := range projection.DeviceAuthorizations {
		if authorization.DeviceID == open.Intent.DeviceID {
			return errors.New("device already has an authorization")
		}
	}
	digest, _ := capabilityDigest(open.Capability)
	transaction := EnrollmentTransaction{Schema: enrollmentSchema, ID: open.TransactionID, State: "open", Intent: open.Intent,
		CapabilityDigest: digest, ExpiresAt: open.Capability.ExpiresAt}
	projection.Enrollments = append(projection.Enrollments, EnrollmentTransaction{})
	copy(projection.Enrollments[index+1:], projection.Enrollments[index:])
	projection.Enrollments[index] = transaction
	return nil
}

func reduceEnrollmentExpire(projection *Projection, expire EnrollmentExpire) error {
	index, transaction := findEnrollment(projection, expire.TransactionID)
	if transaction == nil {
		return errors.New("enrollment transaction does not exist")
	}
	if transaction.State == "expired" {
		return nil
	}
	if transaction.State != "open" && transaction.State != "bound" {
		return errors.New("enrollment transaction cannot expire from its current state")
	}
	expiresAt, expiresErr := time.Parse(time.RFC3339, transaction.ExpiresAt)
	expiredAt, expiredErr := time.Parse(time.RFC3339, expire.ExpiredAt)
	if expiresErr != nil || expiredErr != nil || expiredAt.Before(expiresAt) {
		return errors.New("enrollment transaction has not reached its certified expiry")
	}
	projection.Enrollments[index].State = "expired"
	return nil
}

func validateNewEnrollmentIdentity(projection Projection, deviceID string) error {
	for _, device := range projection.Web.Devices {
		if device.ID == deviceID {
			return errors.New("device id is already reserved by the certified projection")
		}
	}
	for _, member := range uniqueConfigMembers(projection.Config) {
		if member.ID == deviceID || member.Node == deviceID {
			return errors.New("device id is already reserved by the control configuration")
		}
	}
	return nil
}

func reduceEnrollmentBind(projection *Projection, bind EnrollmentBind) error {
	_, transaction := findEnrollment(projection, bind.TransactionID)
	if transaction == nil {
		return errors.New("enrollment transaction does not exist")
	}
	if transaction.State != "open" {
		return errors.New("only open enrollment may bind")
	}
	if transaction.Intent.Schema == enrollmentSchemaV2 {
		declared := transaction.Intent.Server
		if (declared == nil) != (bind.Server == nil) {
			return errors.New("device claim changes certified server responsibilities")
		}
	}
	transaction.State = "bound"
	transaction.ClaimRequestID = bind.ClaimRequestID
	transaction.DevicePublicKey = bind.DevicePublicKey
	transaction.ClaimedAt = bind.ClaimedAt
	transaction.ClaimedServer = bind.Server
	return nil
}

func reduceEnrollmentApprove(projection *Projection, approve EnrollmentApprove) error {
	_, transaction := findEnrollment(projection, approve.TransactionID)
	if transaction == nil || transaction.State != "bound" {
		return errors.New("only bound enrollment may be approved")
	}
	transaction.State = "approved"
	return nil
}

func reduceEnrollmentComplete(projection *Projection, complete EnrollmentComplete) error {
	_, transaction := findEnrollment(projection, complete.TransactionID)
	if transaction == nil || transaction.State != "approved" && (transaction.State != "bound" || transaction.Intent.Schema != enrollmentSchemaV2) {
		return errors.New("only approved legacy or bound schema-2 enrollment may complete")
	}
	intent := transaction.Intent
	authorization := complete.Authorization
	if authorization.DeviceID != intent.DeviceID || authorization.DevicePublicKey != transaction.DevicePublicKey ||
		!equalStrings(authorization.DestinationGrants, intent.DestinationGrants) {
		return errors.New("device authorization does not match enrollment")
	}
	if intent.Schema == enrollmentSchemaV2 {
		if authorization.Schema != enrollmentSchemaV2 || (transaction.ClaimedServer == nil) != (intent.Server == nil) {
			return errors.New("schema-2 device authorization does not match claim")
		}
		server := (*ServerIntent)(nil)
		if transaction.ClaimedServer != nil {
			var err error
			server, err = serverIntentFromClaim(intent.Server, transaction.ClaimedServer)
			if err != nil {
				return err
			}
		}
		if err := integrateEnrollmentNetworkIntent(projection, intent, server); err != nil {
			return err
		}
	} else {
		leftRuntime, _ := canonical(authorization.Runtime)
		rightRuntime, _ := canonical(intent.Runtime)
		if authorization.Name != intent.Name || authorization.Platform != intent.Platform ||
			!equalStrings(authorization.Roles, intent.Roles) || !equalRoutes(authorization.Routes, intent.Routes) ||
			!bytes.Equal(leftRuntime, rightRuntime) {
			return errors.New("legacy device authorization does not match enrollment")
		}
	}
	index := sort.Search(len(projection.DeviceAuthorizations), func(index int) bool {
		return projection.DeviceAuthorizations[index].DeviceID >= authorization.DeviceID
	})
	if index < len(projection.DeviceAuthorizations) && projection.DeviceAuthorizations[index].DeviceID == authorization.DeviceID {
		return errors.New("device authorization already exists")
	}
	projection.DeviceAuthorizations = append(projection.DeviceAuthorizations, DeviceAuthorization{})
	copy(projection.DeviceAuthorizations[index+1:], projection.DeviceAuthorizations[index:])
	projection.DeviceAuthorizations[index] = authorization
	view, found := projectDeviceView(*projection, authorization.DeviceID)
	if !found {
		return errors.New("completed device view is unavailable")
	}
	digest, _ := DeviceViewDigest(view)
	if digest != complete.ResultDigest {
		return errors.New("completed device view digest does not match")
	}
	transaction.State = "completed"
	transaction.ResultDigest = digest
	return nil
}

func integrateEnrollmentNetworkIntent(projection *Projection, intent EnrollmentIntent, claimedServer *ServerIntent) error {
	if projection.NetworkIntent == nil {
		return errors.New("schema-2 enrollment has no network intent")
	}
	node := NetworkNode{ID: intent.DeviceID, Name: intent.Name, Platform: intent.Platform,
		Roles: append([]string(nil), intent.Roles...), Server: claimedServer}
	if existing, found := networkNode(projection.NetworkIntent, intent.DeviceID); found {
		// A rejoining device proves only the server facts that can originate on
		// that device.  Location/provider and node-level overrides remain
		// certified NetworkIntent facts: the claim neither carries nor clears
		// them.  Compare normalized copies so the check cannot mutate the
		// authoritative node through the Server pointer shared by the value copy.
		comparable := existing
		comparable.DNS = nil
		comparable.Components = nil
		comparable.ProbeTargets = nil
		comparable.DistributionURLs = nil
		if comparable.Server != nil {
			server := *comparable.Server
			server.Country = ""
			server.City = ""
			server.Provider = ""
			comparable.Server = &server
		}
		left, _ := canonical(comparable)
		right, _ := canonical(node)
		if !bytes.Equal(left, right) {
			return errors.New("existing-node rejoin does not match certified network intent")
		}
	} else {
		projection.NetworkIntent.Nodes = append(projection.NetworkIntent.Nodes, node)
		sort.Slice(projection.NetworkIntent.Nodes, func(i, j int) bool {
			return projection.NetworkIntent.Nodes[i].ID < projection.NetworkIntent.Nodes[j].ID
		})
	}
	if claimedServer != nil && claimedServer.EgressCapable {
		for _, grant := range intent.DestinationGrants {
			index := sort.Search(len(projection.NetworkIntent.Policies), func(index int) bool {
				return projection.NetworkIntent.Policies[index].ID >= grant
			})
			if index == len(projection.NetworkIntent.Policies) || projection.NetworkIntent.Policies[index].ID != grant {
				return errors.New("schema-2 egress enrollment references an unknown policy")
			}
			policy := &projection.NetworkIntent.Policies[index]
			if !contains(policy.AllowedServers, intent.DeviceID) {
				policy.AllowedServers = append(policy.AllowedServers, intent.DeviceID)
				sort.Strings(policy.AllowedServers)
			}
			if !contains(policy.AllowedExits, intent.DeviceID) {
				policy.AllowedExits = append(policy.AllowedExits, intent.DeviceID)
				sort.Strings(policy.AllowedExits)
			}
		}
	}
	return projection.NetworkIntent.Validate()
}

func reduceDeviceAuthorization(projection *Projection, authorization DeviceAuthorization) error {
	index := sort.Search(len(projection.DeviceAuthorizations), func(index int) bool {
		return projection.DeviceAuthorizations[index].DeviceID >= authorization.DeviceID
	})
	if index == len(projection.DeviceAuthorizations) || projection.DeviceAuthorizations[index].DeviceID != authorization.DeviceID {
		return errors.New("device authorization does not exist")
	}
	previous := projection.DeviceAuthorizations[index]
	stableChanged := authorization.DevicePublicKey != previous.DevicePublicKey || authorization.Schema != previous.Schema
	if authorization.Schema == enrollmentSchema {
		stableChanged = stableChanged || authorization.Name != previous.Name || authorization.Platform != previous.Platform ||
			!equalStrings(authorization.Roles, previous.Roles)
	}
	if stableChanged || authorization.Floor <= previous.Floor {
		return errors.New("device update changes stable identity or does not advance floor")
	}
	projection.DeviceAuthorizations[index] = authorization
	view, _ := projectDeviceView(*projection, authorization.DeviceID)
	digest, err := DeviceViewDigest(view)
	if err != nil {
		return err
	}
	for transactionIndex := range projection.Enrollments {
		transaction := &projection.Enrollments[transactionIndex]
		if transaction.Intent.DeviceID == authorization.DeviceID && transaction.State == "completed" {
			transaction.ResultDigest = digest
		}
	}
	return nil
}

func reduceDeviceRuntimeUpgrade(projection *Projection, upgrade DeviceRuntimeUpgrade, floor uint64) error {
	index := sort.Search(len(projection.DeviceAuthorizations), func(index int) bool {
		return projection.DeviceAuthorizations[index].DeviceID >= upgrade.DeviceID
	})
	if index == len(projection.DeviceAuthorizations) || projection.DeviceAuthorizations[index].DeviceID != upgrade.DeviceID {
		return errors.New("device authorization does not exist")
	}
	authorization := projection.DeviceAuthorizations[index]
	if authorization.Schema != enrollmentSchemaV2 || authorization.RuntimeContract >= upgrade.RuntimeContract ||
		floor <= authorization.Floor {
		return errors.New("device runtime upgrade does not advance the certified contract")
	}
	authorization.RuntimeContract = upgrade.RuntimeContract
	authorization.Floor = floor
	projection.DeviceAuthorizations[index] = authorization
	view, found := projectDeviceView(*projection, authorization.DeviceID)
	if !found {
		return errors.New("upgraded device view is unavailable")
	}
	digest, err := DeviceViewDigest(view)
	if err != nil {
		return err
	}
	for transactionIndex := range projection.Enrollments {
		transaction := &projection.Enrollments[transactionIndex]
		if transaction.Intent.DeviceID == authorization.DeviceID && transaction.State == "completed" {
			transaction.ResultDigest = digest
		}
	}
	return nil
}

func reduceDeviceRevoke(projection *Projection, revoke DeviceRevoke) error {
	index := sort.Search(len(projection.DeviceAuthorizations), func(index int) bool {
		return projection.DeviceAuthorizations[index].DeviceID >= revoke.DeviceID
	})
	if index == len(projection.DeviceAuthorizations) || projection.DeviceAuthorizations[index].DeviceID != revoke.DeviceID {
		return errors.New("device authorization does not exist")
	}
	projection.DeviceAuthorizations = append(projection.DeviceAuthorizations[:index], projection.DeviceAuthorizations[index+1:]...)
	return nil
}

func equalStrings(left, right []string) bool {
	a, _ := json.Marshal(left)
	b, _ := json.Marshal(right)
	return bytes.Equal(a, b)
}

func equalRoutes(left, right []RouteCandidate) bool {
	a, _ := json.Marshal(left)
	b, _ := json.Marshal(right)
	return bytes.Equal(a, b)
}

func projectDeviceView(projection Projection, deviceID string) (DeviceView, bool) {
	index := sort.Search(len(projection.DeviceAuthorizations), func(index int) bool {
		return projection.DeviceAuthorizations[index].DeviceID >= deviceID
	})
	if index == len(projection.DeviceAuthorizations) || projection.DeviceAuthorizations[index].DeviceID != deviceID {
		return DeviceView{}, false
	}
	authorization := projection.DeviceAuthorizations[index]
	routes, runtime, err := projectAuthorizationRuntime(projection, authorization)
	if err != nil {
		return DeviceView{}, false
	}
	schema := deviceViewSchema
	name, platform := authorization.Name, authorization.Platform
	roles := append([]string(nil), authorization.Roles...)
	server := authorization.Server
	if authorization.Schema == enrollmentSchemaV2 {
		schema = deviceViewSchemaV2
		node, found := networkNode(projection.NetworkIntent, authorization.DeviceID)
		if !found {
			return DeviceView{}, false
		}
		name, platform = node.Name, node.Platform
		roles = append([]string(nil), node.Roles...)
		server = node.Server
	}
	view := DeviceView{Schema: schema, DeviceID: authorization.DeviceID, Name: name,
		Platform: platform, Roles: roles,
		DevicePublicKey: authorization.DevicePublicKey, Floor: authorization.Floor,
		Routes: routes, Runtime: runtime, DestinationGrants: append([]string(nil), authorization.DestinationGrants...),
		Server: server}
	if authorization.Schema == enrollmentSchemaV2 && projection.NetworkIntent != nil {
		view.PublicDataPlaneCA = projection.NetworkIntent.PublicDataPlaneCA
		if authorization.RuntimeContract >= runtimeContractViewDNS {
			view.RuntimeContract = authorization.RuntimeContract
			view.DNS = deviceDNSAddresses(projection.NetworkIntent, authorization.DeviceID)
		}
		if authorization.RuntimeContract >= runtimeContractProbe && contains(roles, "access") {
			node, found := networkNode(projection.NetworkIntent, authorization.DeviceID)
			if !found {
				return DeviceView{}, false
			}
			view.BusinessProbeTargets = append([]string(nil), node.ProbeTargets...)
			if !authorizedBusinessProbeTargets(projection.NetworkIntent, authorization.DestinationGrants, view.BusinessProbeTargets) {
				return DeviceView{}, false
			}
		}
		componentByName := map[string]ComponentExpectation{}
		for _, component := range projection.NetworkIntent.Components {
			componentByName[component.Name] = component
		}
		if node, found := networkNode(projection.NetworkIntent, authorization.DeviceID); found {
			for _, component := range node.Components {
				componentByName[component.Name] = component
			}
		}
		for _, component := range componentByName {
			view.ExpectedComponents = append(view.ExpectedComponents, component)
		}
		sort.Slice(view.ExpectedComponents, func(i, j int) bool { return view.ExpectedComponents[i].Name < view.ExpectedComponents[j].Name })
		for _, link := range projection.NetworkIntent.Links {
			peer := ""
			if link.From == authorization.DeviceID {
				peer = link.To
			} else if link.To == authorization.DeviceID {
				peer = link.From
			}
			if peer != "" {
				target := ""
				for _, probe := range link.ProbeTargets {
					if probe.Reporter == authorization.DeviceID {
						target = probe.Target
					}
				}
				peerKey := ""
				if peerNode, ok := networkNode(projection.NetworkIntent, peer); ok && peerNode.Server != nil {
					peerKey = peerNode.Server.WGPublicKey
				}
				view.LinkProbeTargets = append(view.LinkProbeTargets, LinkProbeTarget{LinkID: link.ID, Peer: peer,
					Transport: link.Transport, Target: target, PeerWGPublicKey: peerKey})
			}
		}
		sort.Slice(view.LinkProbeTargets, func(i, j int) bool { return view.LinkProbeTargets[i].LinkID < view.LinkProbeTargets[j].LinkID })
		if server != nil {
			view.ServerRuntime, err = projectServerRuntime(projection, authorization.DeviceID, *server)
			if err != nil {
				return DeviceView{}, false
			}
		}
	}
	for _, generation := range projection.EndpointGenerations {
		if generation.State == "serving" || generation.State == "draining" {
			view.Endpoints = append(view.Endpoints, generation.Reference())
		}
	}
	sort.Slice(view.Endpoints, func(i, j int) bool { return endpointReferenceLess(view.Endpoints[i], view.Endpoints[j]) })
	return view, true
}

func (view DeviceView) Validate() error {
	if view.Schema != deviceViewSchema && view.Schema != deviceViewSchemaV2 || !validName(view.DeviceID) || !validName(view.Name) ||
		(view.Platform != "android" && view.Platform != "linux" && view.Platform != "windows") ||
		!validRawKey(view.DevicePublicKey) || view.Floor == 0 || len(view.Endpoints) == 0 ||
		validateSortedNames(view.Roles, "device view roles") != nil {
		return errors.New("device view is invalid")
	}
	if view.Schema == deviceViewSchema {
		authorization := DeviceAuthorization{Schema: enrollmentSchema, DeviceID: view.DeviceID, Name: view.Name,
			Platform: view.Platform, Roles: view.Roles, Routes: view.Routes, Runtime: view.Runtime,
			DevicePublicKey: view.DevicePublicKey, Floor: view.Floor}
		if authorization.Validate() != nil || len(view.DestinationGrants) != 0 || view.Server != nil || view.ServerRuntime != nil ||
			view.PublicDataPlaneCA != "" || view.RuntimeContract != 0 || len(view.DNS) != 0 || len(view.BusinessProbeTargets) != 0 ||
			len(view.ExpectedComponents) != 0 || len(view.LinkProbeTargets) != 0 {
			return errors.New("legacy device view is invalid")
		}
	}
	if view.Schema == deviceViewSchemaV2 {
		if validateSortedNames(view.DestinationGrants, "device view grants") != nil {
			return errors.New("schema-2 device view grants are invalid")
		}
		hasAccess := contains(view.Roles, "access")
		hasServer := contains(view.Roles, "server")
		invalidRuntime := hasAccess && (view.Runtime == nil || view.Runtime.Validate(view.Routes) != nil) ||
			!hasAccess && (view.Runtime != nil || len(view.Routes) != 0)
		invalidServerRuntime := hasServer && (view.Server == nil || view.ServerRuntime == nil || view.ServerRuntime.Validate() != nil) ||
			!hasServer && view.ServerRuntime != nil
		invalidDNS := view.RuntimeContract != 0 && view.RuntimeContract != runtimeContractViewDNS && view.RuntimeContract != runtimeContractProbe ||
			view.RuntimeContract >= runtimeContractViewDNS && (len(view.DNS) == 0 || validIPList(view.DNS, "device view DNS") != nil) ||
			view.RuntimeContract == 0 && len(view.DNS) != 0
		invalidBusinessProbes := view.RuntimeContract < runtimeContractProbe && len(view.BusinessProbeTargets) != 0 ||
			hasAccess && view.RuntimeContract == runtimeContractProbe && !validBusinessProbeTargets(view.BusinessProbeTargets) ||
			!hasAccess && len(view.BusinessProbeTargets) != 0
		if view.PublicDataPlaneCA == "" || invalidRuntime || invalidServerRuntime || invalidDNS || invalidBusinessProbes || validateComponents(view.ExpectedComponents) != nil {
			return errors.New("schema-2 device view is incomplete")
		}
		for index, target := range view.LinkProbeTargets {
			if !validName(target.LinkID) || !validName(target.Peer) || !validName(target.Transport) || !validName(target.Target) ||
				index > 0 && view.LinkProbeTargets[index-1].LinkID >= target.LinkID ||
				target.PeerWGPublicKey != "" && !validWGPublicKey(target.PeerWGPublicKey) {
				return errors.New("device view probe targets are invalid")
			}
		}
	}
	for index, endpoint := range view.Endpoints {
		if endpoint.Validate() != nil || index > 0 && !endpointReferenceLess(view.Endpoints[index-1], endpoint) {
			return errors.New("device view endpoints are invalid")
		}
	}
	return nil
}

func validBusinessProbeTargets(targets []string) bool {
	if len(targets) == 0 || validateProbeTargets(targets) != nil {
		return false
	}
	for _, target := range targets {
		parsed, err := url.Parse(target)
		if err != nil || parsed.Scheme != "https" || parsed.Port() != "" && parsed.Port() != "443" {
			return false
		}
	}
	return true
}

func authorizedBusinessProbeTargets(intent *NetworkIntent, grants, targets []string) bool {
	if intent == nil || !validBusinessProbeTargets(targets) {
		return false
	}
	matchers := []string{}
	for _, grant := range grants {
		matchers = append(matchers, policyMatchers(intent, grant)...)
	}
	for _, target := range targets {
		parsed, _ := url.Parse(target)
		host := parsed.Hostname()
		authorized := false
		for _, matcher := range matchers {
			authorized = authorized || host == matcher || strings.HasPrefix(matcher, ".") && strings.HasSuffix(host, matcher)
		}
		if !authorized {
			return false
		}
	}
	return true
}

func cloneRuntimeProfile(profile *RuntimeProfile) *RuntimeProfile {
	if profile == nil {
		return nil
	}
	copy := *profile
	return &copy
}

func DeviceViewDigest(view DeviceView) (string, error) {
	if err := view.Validate(); err != nil {
		return "", err
	}
	body, err := canonical(view)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append([]byte(deviceViewDomain), body...))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func deviceViewLeaf(view DeviceView) ([]byte, error) {
	digest, err := DeviceViewDigest(view)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(append([]byte(deviceNodeDomain+"leaf\n"), []byte(digest)...))
	return sum[:], nil
}

func deviceViewNode(left, right []byte) []byte {
	body := append([]byte(deviceNodeDomain+"pair\n"), left...)
	body = append(body, right...)
	sum := sha256.Sum256(body)
	return sum[:]
}

func projectedDeviceViews(projection Projection) ([]DeviceView, error) {
	views := make([]DeviceView, 0, len(projection.DeviceAuthorizations))
	for _, authorization := range projection.DeviceAuthorizations {
		view, found := projectDeviceView(projection, authorization.DeviceID)
		if !found {
			return nil, errors.New("device authorization cannot be projected")
		}
		if err := view.Validate(); err != nil {
			return nil, err
		}
		views = append(views, view)
	}
	return views, nil
}

func deviceMerkleRoot(leaves [][]byte) []byte {
	if len(leaves) == 0 {
		return nil
	}
	level := make([][]byte, len(leaves))
	for index := range leaves {
		level[index] = append([]byte(nil), leaves[index]...)
	}
	for len(level) > 1 {
		next := make([][]byte, 0, (len(level)+1)/2)
		for index := 0; index < len(level); index += 2 {
			right := level[index]
			if index+1 < len(level) {
				right = level[index+1]
			}
			next = append(next, deviceViewNode(level[index], right))
		}
		level = next
	}
	return level[0]
}

func deviceViewsDigest(projection Projection) (string, error) {
	views, err := projectedDeviceViews(projection)
	if err != nil || len(views) == 0 {
		return "", err
	}
	leaves := make([][]byte, len(views))
	for index, view := range views {
		leaves[index], err = deviceViewLeaf(view)
		if err != nil {
			return "", err
		}
	}
	return "sha256:" + hex.EncodeToString(deviceMerkleRoot(leaves)), nil
}

func DeviceViewFor(projection Projection, head GovernanceHead, deviceID string) (DeviceViewEnvelope, error) {
	views, err := projectedDeviceViews(projection)
	if err != nil {
		return DeviceViewEnvelope{}, err
	}
	index := sort.Search(len(views), func(index int) bool { return views[index].DeviceID >= deviceID })
	if index == len(views) || views[index].DeviceID != deviceID {
		return DeviceViewEnvelope{}, fmt.Errorf("device view: %w", os.ErrNotExist)
	}
	leaves := make([][]byte, len(views))
	for leafIndex, view := range views {
		leaves[leafIndex], err = deviceViewLeaf(view)
		if err != nil {
			return DeviceViewEnvelope{}, err
		}
	}
	proof := DeviceViewProof{Index: index, Size: len(leaves), Siblings: []string{}}
	position := index
	for level := leaves; len(level) > 1; {
		sibling := position ^ 1
		if sibling >= len(level) {
			sibling = position
		}
		proof.Siblings = append(proof.Siblings, hex.EncodeToString(level[sibling]))
		next := make([][]byte, 0, (len(level)+1)/2)
		for offset := 0; offset < len(level); offset += 2 {
			right := level[offset]
			if offset+1 < len(level) {
				right = level[offset+1]
			}
			next = append(next, deviceViewNode(level[offset], right))
		}
		position /= 2
		level = next
	}
	return DeviceViewEnvelope{Schema: deviceViewSchema, View: views[index], Head: head,
		ControlConfig: projection.Config, Proof: proof}, nil
}

func VerifyDeviceViewEnvelope(envelope DeviceViewEnvelope, trusted BootstrapCapability) error {
	if envelope.Schema != deviceViewSchema || envelope.View.Validate() != nil || trusted.Validate() != nil ||
		envelope.Head.ConfigMaterial != trusted.ConfigMaterial || !sameControlConfig(envelope.ControlConfig, trusted.ControlConfig) ||
		envelope.Head.Index < envelope.View.Floor || envelope.Head.DeviceViewsDigest == "" {
		return errors.New("device view envelope boundary is invalid")
	}
	if err := verifyHeadSignatures(envelope.Head, envelope.ControlConfig); err != nil {
		return err
	}
	leaf, _ := deviceViewLeaf(envelope.View)
	proof := envelope.Proof
	if proof.Size < 1 || proof.Index < 0 || proof.Index >= proof.Size {
		return errors.New("device view proof is invalid")
	}
	position, width := proof.Index, proof.Size
	value := leaf
	for _, encoded := range proof.Siblings {
		sibling, err := hex.DecodeString(encoded)
		if err != nil || len(sibling) != sha256.Size || width <= 1 {
			return errors.New("device view proof is invalid")
		}
		if position%2 == 0 {
			value = deviceViewNode(value, sibling)
		} else {
			value = deviceViewNode(sibling, value)
		}
		position /= 2
		width = (width + 1) / 2
	}
	if width != 1 || "sha256:"+hex.EncodeToString(value) != envelope.Head.DeviceViewsDigest {
		return errors.New("device view proof does not match certified head")
	}
	return nil
}

func sameControlConfig(left, right ControlConfig) bool {
	a, _ := canonical(left)
	b, _ := canonical(right)
	return bytes.Equal(a, b)
}

func verifyHeadSignatures(head GovernanceHead, config ControlConfig) error {
	if head.Schema != HeadSchema || head.Index == 0 || !validDigest(head.LogDigest) || !validDigest(head.ProjectionDigest) ||
		!validDigest(head.ConfigMaterial) || !validDigest(head.DeviceViewsDigest) || config.Validate() != nil {
		return errors.New("certified head is invalid")
	}
	message, err := headSigningBytes(head)
	if err != nil {
		return err
	}
	members := map[string]Member{}
	for _, member := range uniqueConfigMembers(config) {
		members[member.ID] = member
	}
	valid := map[string]bool{}
	previous := ""
	for _, signature := range head.Signatures {
		member, ok := members[signature.MemberID]
		if !ok || previous >= signature.MemberID && previous != "" || valid[signature.MemberID] {
			return errors.New("certified head signatures are invalid")
		}
		key, _ := base64.RawURLEncoding.DecodeString(member.PublicKey)
		value, decodeErr := base64.RawURLEncoding.DecodeString(signature.Value)
		if decodeErr != nil || !ed25519.Verify(key, message, value) {
			return errors.New("certified head signature is invalid")
		}
		valid[signature.MemberID] = true
		previous = signature.MemberID
	}
	count := func(set []Member) int {
		total := 0
		for _, member := range set {
			if valid[member.ID] {
				total++
			}
		}
		return total
	}
	if config.Mode == "stable" && count(config.Members) < config.Quorum ||
		config.Mode == "joint" && (count(config.Old) < config.OldQuorum || count(config.New) < config.NewQuorum) {
		return errors.New("certified head lacks quorum")
	}
	return nil
}

func projectEnrollmentWeb(projection *Projection) {
	authorizations := map[string]DeviceAuthorization{}
	for _, authorization := range projection.DeviceAuthorizations {
		authorizations[authorization.DeviceID] = authorization
	}
	transactions := projection.Enrollments
	if projection.NetworkIntent != nil {
		current := map[string]EnrollmentTransaction{}
		for _, transaction := range projection.Enrollments {
			_, authorized := authorizations[transaction.Intent.DeviceID]
			active := transaction.State == "open" || transaction.State == "bound" || transaction.State == "approved"
			if !active && !(transaction.State == "completed" && authorized) {
				continue
			}
			previous, found := current[transaction.Intent.DeviceID]
			if !found || currentEnrollmentCoordinate(previous) < currentEnrollmentCoordinate(transaction) {
				current[transaction.Intent.DeviceID] = transaction
			}
		}
		deviceIDs := make([]string, 0, len(current))
		for deviceID := range current {
			deviceIDs = append(deviceIDs, deviceID)
		}
		sort.Strings(deviceIDs)
		transactions = make([]EnrollmentTransaction, 0, len(deviceIDs))
		for _, deviceID := range deviceIDs {
			transactions = append(transactions, current[deviceID])
		}
	}
	for _, transaction := range transactions {
		index := sort.Search(len(projection.Web.Devices), func(index int) bool {
			return projection.Web.Devices[index].ID >= transaction.Intent.DeviceID
		})
		authorization, authorized := authorizations[transaction.Intent.DeviceID]
		device := Device{ID: transaction.Intent.DeviceID, Name: transaction.Intent.Name, Platform: transaction.Intent.Platform,
			Roles: append([]string(nil), transaction.Intent.Roles...), Authorized: authorized,
			Availability: "unknown", EnrollmentID: transaction.ID, Enrollment: transaction.State, ViewDigest: transaction.ResultDigest}
		if index < len(projection.Web.Devices) && projection.Web.Devices[index].ID == device.ID {
			existing := projection.Web.Devices[index]
			device.Endpoint = existing.Endpoint
			device.Location = existing.Location
			device.ExpectedComponents = append([]ComponentExpectation(nil), existing.ExpectedComponents...)
		}
		server := transaction.Intent.Server
		if transaction.ClaimedServer != nil {
			server, _ = serverIntentFromClaim(transaction.Intent.Server, transaction.ClaimedServer)
		}
		if authorized && authorization.Schema == enrollmentSchemaV2 {
			if node, found := networkNode(projection.NetworkIntent, authorization.DeviceID); found {
				server = node.Server
			}
		} else if authorized && authorization.Server != nil {
			server = authorization.Server
		}
		if server != nil {
			device.Direction = server.Direction
			device.EgressCapable = server.EgressCapable
			if server.PublicEndpoint != "" {
				device.Endpoint = server.PublicEndpoint
			}
			if server.Country != "" {
				device.Location = server.Country
				if server.City != "" {
					device.Location += " " + server.City
				}
			}
		}
		if index < len(projection.Web.Devices) && projection.Web.Devices[index].ID == device.ID {
			projection.Web.Devices[index] = device
		} else {
			projection.Web.Devices = append(projection.Web.Devices, Device{})
			copy(projection.Web.Devices[index+1:], projection.Web.Devices[index:])
			projection.Web.Devices[index] = device
		}
		filtered := projection.Web.Paths[:0]
		for _, path := range projection.Web.Paths {
			if path.Device != transaction.Intent.DeviceID {
				filtered = append(filtered, path)
			}
		}
		projection.Web.Paths = filtered
		if !authorized {
			continue
		}
		routes, _, err := projectAuthorizationRuntime(*projection, authorization)
		if err != nil {
			continue
		}
		for _, candidate := range routes {
			chain := append([]string(nil), candidate.Chain...)
			if len(chain) > 0 && chain[0] == transaction.Intent.DeviceID {
				chain = chain[1:]
			}
			projection.Web.Paths = append(projection.Web.Paths, Path{CandidateID: candidate.ID, Device: transaction.Intent.DeviceID,
				Scope: candidate.Scope, FinalExit: candidate.FinalExit, Chain: chain, Availability: "unknown"})
		}
	}
	sort.Slice(projection.Web.Paths, func(i, j int) bool {
		return projection.Web.Paths[i].Device+"\x00"+projection.Web.Paths[i].CandidateID <
			projection.Web.Paths[j].Device+"\x00"+projection.Web.Paths[j].CandidateID
	})
}

func currentEnrollmentCoordinate(transaction EnrollmentTransaction) string {
	priority := "0"
	if transaction.State == "completed" {
		priority = "1"
	}
	when := transaction.ClaimedAt
	if when == "" {
		when = transaction.ExpiresAt
	}
	return priority + "\x00" + when + "\x00" + transaction.ID
}
