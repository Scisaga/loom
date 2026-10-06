package control

import (
	"bytes"
	"compress/zlib"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net/netip"
	"strings"
)

const deviceViewDomain = "loom-device-view-v3\x00"

type EndpointGeneration struct {
	ID                string   `json:"id"`
	Generation        U64      `json:"generation"`
	OwnerControlID    string   `json:"owner_control_id"`
	Host              string   `json:"host"`
	Port              int      `json:"port"`
	ServerName        string   `json:"server_name"`
	SPKISHA256        string   `json:"spki_sha256"`
	CertificateDigest string   `json:"certificate_digest"`
	WebsiteTrustID    string   `json:"website_trust_id,omitempty"`
	Modes             []string `json:"modes"`
	State             string   `json:"state"`
	DrainUntil        int64    `json:"drain_until"`
	Preference        int      `json:"preference"`
}

func canonicalHost(host string) bool {
	if address, err := netip.ParseAddr(host); err == nil {
		return address.Zone() == "" && address.String() == host
	}
	return contractDNSName(host)
}

func (endpoint EndpointGeneration) Validate() error {
	if ValidateID(endpoint.ID) != nil || ValidateID(endpoint.OwnerControlID) != nil || endpoint.Generation == 0 ||
		!canonicalHost(endpoint.Host) || !canonicalHost(endpoint.ServerName) || endpoint.Port < 1 || endpoint.Port > 65535 ||
		ValidateDigest(endpoint.SPKISHA256) != nil || ValidateDigest(endpoint.CertificateDigest) != nil ||
		endpoint.Preference < 0 || endpoint.Preference > 65535 || len(endpoint.Modes) == 0 {
		return errors.New("endpoint generation is invalid")
	}
	for index, mode := range endpoint.Modes {
		if mode != "bootstrap" && mode != "device" && mode != "web" || index > 0 && endpoint.Modes[index-1] >= mode {
			return errors.New("endpoint modes are invalid or not uniquely sorted")
		}
	}
	website := endpoint.ServerName == "control.loom" && containsString(endpoint.Modes, "web")
	if website != (endpoint.WebsiteTrustID != "") || website && (ValidateID(endpoint.WebsiteTrustID) != nil || endpoint.Host == "loom" || strings.HasSuffix(endpoint.Host, ".loom")) {
		return errors.New("control.loom requires an explicit website trust grant and an independent underlay host")
	}
	if !validateTime(endpoint.DrainUntil) || endpoint.State == "draining" && endpoint.DrainUntil == 0 || endpoint.State != "draining" && endpoint.DrainUntil != 0 {
		return errors.New("endpoint drain deadline does not match its state")
	}
	switch endpoint.State {
	case "prepared", "serving", "draining", "retired":
		return nil
	}
	return errors.New("endpoint state is invalid")
}

type Invite struct {
	ID               string             `json:"id"`
	GenesisDigest    string             `json:"genesis_digest"`
	IssuerControlID  string             `json:"issuer_control_id"`
	DeviceID         string             `json:"device_id"`
	Name             string             `json:"name"`
	Responsibilities []string           `json:"responsibilities"`
	PolicyIDs        []string           `json:"policy_ids"`
	DNSServers       []string           `json:"dns_servers,omitempty"`
	Medium           string             `json:"medium"`
	SSHTarget        string             `json:"ssh_target,omitempty"`
	Endpoint         EndpointGeneration `json:"endpoint"`
	ExpiresAt        int64              `json:"expires_at"`
}

func validateIDSet(values []string) error {
	if values == nil {
		return errors.New("ID collection must be explicit")
	}
	for index, value := range values {
		if ValidateID(value) != nil || index > 0 && values[index-1] >= value {
			return errors.New("ID collection is invalid or not uniquely sorted")
		}
	}
	return nil
}

func containsString(values []string, value string) bool {
	for _, item := range values {
		if item == value {
			return true
		}
	}
	return false
}

func validateResponsibilities(values []string, allowControl bool) error {
	if err := validateIDSet(values); err != nil {
		return err
	}
	for _, value := range values {
		if value != "access" && value != "forward" && value != "internet_egress" && !(allowControl && value == "control") {
			return errors.New("responsibility is invalid")
		}
	}
	return nil
}

func validateTime(value int64) bool { return value >= 0 && value <= 253402300799999 }
func validatePlatform(value string) bool {
	return value == "android" || value == "linux" || value == "windows"
}

func (invite Invite) Validate() error {
	if invite.SSHTarget != "" && (invite.Medium != "ssh" || ValidateSSHTarget(invite.SSHTarget) != nil) {
		return errors.New("SSH delivery target is invalid or differs from the signed medium")
	}
	if err := validateOptionalDNS(invite.DNSServers); err != nil {
		return err
	}
	if ValidateID(invite.ID) != nil || ValidateDigest(invite.GenesisDigest) != nil || ValidateID(invite.IssuerControlID) != nil ||
		ValidateID(invite.DeviceID) != nil || invite.DeviceID == "direct" || ValidateText(invite.Name) != nil ||
		len(invite.Responsibilities) == 0 || validateResponsibilities(invite.Responsibilities, true) != nil ||
		validateIDSet(invite.PolicyIDs) != nil || !validateTime(invite.ExpiresAt) || invite.Endpoint.Validate() != nil {
		return errors.New("invite is invalid")
	}
	if !containsString(invite.Responsibilities, "access") && len(invite.PolicyIDs) != 0 {
		return errors.New("non-access invite cannot assign access policies")
	}
	pureAccess := len(invite.Responsibilities) == 1 && invite.Responsibilities[0] == "access"
	if pureAccess && invite.Medium != "qr" || !pureAccess && invite.Medium != "ssh" && invite.Medium != "sh" {
		return errors.New("invite medium does not match responsibilities")
	}
	if invite.Endpoint.OwnerControlID != invite.IssuerControlID || invite.Endpoint.State != "serving" || !containsString(invite.Endpoint.Modes, "bootstrap") {
		return errors.New("invite endpoint is not the issuer's serving bootstrap endpoint")
	}
	return nil
}

type EnrollmentBind struct {
	TransactionID    string `json:"transaction_id"`
	InviteMaterialID string `json:"invite_material_id"`
	ClaimRequestID   string `json:"claim_request_id"`
	DevicePublicKey  string `json:"device_public_key"`
	Platform         string `json:"platform"`
}

func (binding EnrollmentBind) Validate() error {
	if ValidateID(binding.TransactionID) != nil || ValidateDigest(binding.InviteMaterialID) != nil || ValidateID(binding.ClaimRequestID) != nil || ValidatePublicKey(binding.DevicePublicKey) != nil || !validatePlatform(binding.Platform) {
		return errors.New("enrollment binding is invalid")
	}
	return nil
}

type EnrollmentTermination struct {
	TransactionID    string `json:"transaction_id"`
	InviteMaterialID string `json:"invite_material_id"`
	ExpiredAt        *int64 `json:"expired_at,omitempty"`
}

func (termination EnrollmentTermination) Validate() error {
	if ValidateID(termination.TransactionID) != nil || ValidateDigest(termination.InviteMaterialID) != nil || termination.ExpiredAt != nil && !validateTime(*termination.ExpiredAt) {
		return errors.New("enrollment termination is invalid")
	}
	return nil
}

type DeviceAuthorization struct {
	ID                string   `json:"id"`
	Name              string   `json:"name"`
	Platform          string   `json:"platform"`
	DevicePublicKey   string   `json:"device_public_key"`
	Responsibilities  []string `json:"responsibilities"`
	PolicyIDs         []string `json:"policy_ids"`
	DistributionURLs  []string `json:"distribution_urls"`
	DNSServers        []string `json:"dns_servers,omitempty"`
	RuntimeKey        string   `json:"runtime_key"`
	TransactionID     string   `json:"transaction_id"`
	InviteMaterialID  string   `json:"invite_material_id"`
	BindingMaterialID string   `json:"binding_material_id"`
}

func (authorization DeviceAuthorization) Validate() error {
	if err := validateOptionalDNS(authorization.DNSServers); err != nil {
		return err
	}
	if ValidateID(authorization.ID) != nil || authorization.ID == "direct" || ValidateText(authorization.Name) != nil || !validatePlatform(authorization.Platform) || ValidatePublicKey(authorization.DevicePublicKey) != nil ||
		validateResponsibilities(authorization.Responsibilities, false) != nil || validateIDSet(authorization.PolicyIDs) != nil || ValidatePublicKey(authorization.RuntimeKey) != nil || ValidateID(authorization.TransactionID) != nil ||
		ValidateDigest(authorization.InviteMaterialID) != nil || ValidateDigest(authorization.BindingMaterialID) != nil || authorization.DistributionURLs == nil {
		return errors.New("device authorization is invalid")
	}
	if !containsString(authorization.Responsibilities, "access") && len(authorization.PolicyIDs) != 0 {
		return errors.New("non-access authorization cannot assign access policies")
	}
	for index, value := range authorization.DistributionURLs {
		if ValidateHTTPSURL(value) != nil || index > 0 && authorization.DistributionURLs[index-1] >= value {
			return errors.New("distribution URLs are invalid or not uniquely sorted")
		}
	}
	return nil
}

type BootstrapInvite struct {
	Schema        int          `json:"schema"`
	NetworkID     string       `json:"network_id"`
	GenesisDigest string       `json:"genesis_digest"`
	ControlProof  ControlProof `json:"control_proof"`
	Material      Material     `json:"material"`
}

func (bootstrap BootstrapInvite) Validate() error {
	if bootstrap.Schema != 3 || bootstrap.Material.Operation != "invite.issue" || bootstrap.Material.NetworkID != bootstrap.NetworkID {
		return errors.New("bootstrap invite boundary is invalid")
	}
	config, err := VerifyControlProof(bootstrap.ControlProof, bootstrap.NetworkID, bootstrap.GenesisDigest)
	if err != nil {
		return err
	}
	configID, err := ConfigID(config)
	invite, ok := bootstrap.Material.Payload.(Invite)
	if err != nil || !ok || invite.Validate() != nil || invite.GenesisDigest != bootstrap.GenesisDigest || invite.IssuerControlID != bootstrap.Material.IssuerControlID || bootstrap.Material.ControlConfigID != configID || bootstrap.Material.TargetID != invite.ID {
		return errors.New("bootstrap invite does not match its material or member proof")
	}
	member, found := proofMember(config, invite.IssuerControlID)
	keyID, keyErr := KeyID(member.PublicKey)
	key, decodeErr := base64.RawURLEncoding.DecodeString(member.PublicKey)
	if !found || keyErr != nil || decodeErr != nil || keyID != bootstrap.Material.IssuerKeyID {
		return errors.New("invite issuer is not a proven member")
	}
	if containsString(invite.Responsibilities, "control") && invite.DeviceID != member.NodeID {
		return errors.New("initial control binding must target the issuer's own member node")
	}
	return VerifyMaterial(bootstrap.Material, ed25519.PublicKey(key))
}

func EncodeInvite(invite BootstrapInvite) (string, error) {
	body, err := CanonicalEncode(invite)
	if err != nil {
		return "", err
	}
	if len(body) > 8<<20 {
		return "", errors.New("bootstrap invite exceeds delivery resource limit")
	}
	var compressed bytes.Buffer
	writer, err := zlib.NewWriterLevel(&compressed, zlib.BestCompression)
	if err != nil {
		return "", err
	}
	if _, err := writer.Write(body); err != nil {
		return "", err
	}
	if err := writer.Close(); err != nil {
		return "", err
	}
	if compressed.Len() > 8<<20 {
		return "", errors.New("bootstrap invite exceeds delivery resource limit")
	}
	return "loom://enroll#" + base64.RawURLEncoding.EncodeToString(compressed.Bytes()), nil
}

func DecodeInvite(raw string) (BootstrapInvite, error) {
	const prefix = "loom://enroll#"
	if !strings.HasPrefix(raw, prefix) {
		return BootstrapInvite{}, errors.New("invalid bootstrap invite prefix")
	}
	encoded := strings.TrimPrefix(raw, prefix)
	if len(encoded) == 0 || len(encoded) > base64.RawURLEncoding.EncodedLen(8<<20) {
		return BootstrapInvite{}, errors.New("bootstrap invite exceeds delivery resource limit")
	}
	compressed, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || base64.RawURLEncoding.EncodeToString(compressed) != encoded {
		return BootstrapInvite{}, errors.New("invalid bootstrap invite encoding")
	}
	input := bytes.NewReader(compressed)
	reader, err := zlib.NewReader(input)
	if err != nil {
		return BootstrapInvite{}, errors.New("invalid compressed bootstrap invite")
	}
	body, readErr := io.ReadAll(io.LimitReader(reader, (8<<20)+1))
	closeErr := reader.Close()
	if readErr != nil || closeErr != nil || len(body) > 8<<20 || input.Len() != 0 {
		return BootstrapInvite{}, errors.New("bootstrap invite contains an invalid, oversized or trailing compressed stream")
	}
	var invite BootstrapInvite
	if err := DecodeCanonical(body, &invite, ContractDecodeLimits{MaxBytes: 8 << 20, MaxDepth: 128, MaxItems: 1 << 20}); err != nil {
		return BootstrapInvite{}, err
	}
	canonical, err := EncodeInvite(invite)
	if err != nil || canonical != raw {
		return BootstrapInvite{}, errors.New("bootstrap invite delivery encoding is not canonical")
	}
	return invite, nil
}

type RouteCandidate struct {
	ID              string   `json:"id"`
	SpecDigest      string   `json:"spec_digest"`
	Scope           string   `json:"scope"`
	ServiceID       string   `json:"service_id"`
	FirstResourceID string   `json:"first_resource_id"`
	NodeChain       []string `json:"node_chain"`
	LinkIDs         []string `json:"link_ids"`
	FinalExit       string   `json:"final_exit"`
}

func (candidate RouteCandidate) Validate() error {
	if ValidateDigest(candidate.ID) != nil || ValidateDigest(candidate.SpecDigest) != nil || ValidateID(candidate.ServiceID) != nil || candidate.Scope != "service:"+candidate.ServiceID || ValidateID(candidate.FinalExit) != nil || candidate.NodeChain == nil || candidate.LinkIDs == nil {
		return errors.New("route candidate is invalid")
	}
	if len(candidate.NodeChain) == 0 {
		if candidate.FirstResourceID != "" || len(candidate.LinkIDs) != 0 {
			return errors.New("local candidate cannot use a remote resource or link")
		}
		return nil
	}
	if ValidateID(candidate.FirstResourceID) != nil || candidate.FinalExit == "direct" || len(candidate.LinkIDs) != len(candidate.NodeChain)-1 || candidate.NodeChain[len(candidate.NodeChain)-1] != candidate.FinalExit {
		return errors.New("remote candidate path is invalid")
	}
	for _, values := range [][]string{candidate.NodeChain, candidate.LinkIDs} {
		seen := map[string]bool{}
		for _, id := range values {
			if ValidateID(id) != nil || id == "direct" || seen[id] {
				return errors.New("candidate path contains an invalid or repeated identity")
			}
			seen[id] = true
		}
	}
	return nil
}

type RuntimeProfile struct {
	Kind   string `json:"kind"`
	Config string `json:"config"`
}

func (profile RuntimeProfile) Validate() error {
	if profile.Kind != "sing_box" || profile.Config == "" {
		return errors.New("runtime profile is invalid")
	}
	value, err := parseContractJSON([]byte(profile.Config), ContractDecodeLimits{MaxBytes: 8 << 20, MaxDepth: 128, MaxItems: 1 << 20})
	if err != nil || !bytes.Equal(appendContractJSON(nil, value), []byte(profile.Config)) {
		return errors.New("runtime profile config is not canonical")
	}
	if _, ok := value.(map[string]any); !ok {
		return errors.New("runtime profile config must be an object")
	}
	return nil
}

type ServiceProbeTargets struct {
	ServiceID string   `json:"service_id"`
	Targets   []string `json:"targets"`
}
type InboundCredential struct {
	DeviceID        string           `json:"device_id"`
	ServiceID       string           `json:"service_id"`
	PolicyID        string           `json:"policy_id"`
	ResourceID      string           `json:"resource_id"`
	ReceiverNodeID  string           `json:"receiver_node_id"`
	Credential      string           `json:"credential"`
	AllowedTargets  []ServiceMatcher `json:"allowed_targets"`
	ExcludedTargets []ServiceMatcher `json:"excluded_targets"`
	RelayTarget     *RelayTarget     `json:"relay_target,omitempty"`
}

// RelayTarget narrows this credential to an authenticated next transport hop.
// The final Service credential travels end to end inside that transport.
type RelayTarget struct {
	LinkID     string `json:"link_id"`
	ResourceID string `json:"resource_id"`
}

func (target RelayTarget) Validate() error {
	if ValidateID(target.LinkID) != nil || ValidateID(target.ResourceID) != nil {
		return errors.New("relay target references are invalid")
	}
	return nil
}

func (value InboundCredential) Validate() error {
	if value.RelayTarget != nil && value.RelayTarget.Validate() != nil {
		return errors.New("inbound relay target is invalid")
	}
	for _, id := range []string{value.DeviceID, value.ServiceID, value.PolicyID, value.ResourceID, value.ReceiverNodeID} {
		if ValidateID(id) != nil || id == "direct" {
			return errors.New("inbound credential binding is invalid")
		}
	}
	if value.DeviceID == value.ReceiverNodeID || ValidatePublicKey(value.Credential) != nil || len(value.AllowedTargets) == 0 || value.ExcludedTargets == nil {
		return errors.New("inbound credential has no distinct source, secret or target boundary")
	}
	for _, matchers := range [][]ServiceMatcher{value.AllowedTargets, value.ExcludedTargets} {
		for index, matcher := range matchers {
			if matcher.Validate() != nil || index > 0 && !serviceMatcherLess(matchers[index-1], matcher) {
				return errors.New("inbound target matchers are not valid and uniquely sorted")
			}
		}
	}
	return nil
}

type DeviceView struct {
	WebEndpoints         []EndpointGeneration  `json:"web_endpoints,omitempty"`
	PublicTrust          []PublicTrust         `json:"public_trust,omitempty"`
	DNSRecords           []DNSRecord           `json:"dns_records,omitempty"`
	Schema               int                   `json:"schema"`
	DeviceID             string                `json:"device_id"`
	Name                 string                `json:"name"`
	Platform             string                `json:"platform"`
	DevicePublicKey      string                `json:"device_public_key"`
	Responsibilities     []string              `json:"responsibilities"`
	PolicyIDs            []string              `json:"policy_ids"`
	Services             []Service             `json:"services"`
	Policies             []NetworkPolicy       `json:"policies"`
	Resources            []TransportResource   `json:"resources"`
	Links                []NetworkLink         `json:"links"`
	Endpoints            []EndpointGeneration  `json:"endpoints"`
	DNSServers           []string              `json:"dns_servers"`
	BusinessProbeTargets []ServiceProbeTargets `json:"business_probe_targets"`
	Routes               []RouteCandidate      `json:"routes"`
	RuntimeProfile       *RuntimeProfile       `json:"runtime_profile,omitempty"`
	InboundCredentials   []InboundCredential   `json:"inbound_credentials"`
	ExpectedComponents   []ComponentReadback   `json:"expected_components"`
}

func (view DeviceView) Validate() error {
	if view.Schema != 3 || ValidateID(view.DeviceID) != nil || view.DeviceID == "direct" || ValidateText(view.Name) != nil || !validatePlatform(view.Platform) || ValidatePublicKey(view.DevicePublicKey) != nil || validateResponsibilities(view.Responsibilities, true) != nil ||
		validateIDSet(view.PolicyIDs) != nil || view.Services == nil || view.Policies == nil || view.Resources == nil || view.Links == nil || view.Endpoints == nil || view.DNSServers == nil || view.BusinessProbeTargets == nil || view.Routes == nil || view.InboundCredentials == nil || view.ExpectedComponents == nil {
		return errors.New("device view fields are invalid or incomplete")
	}
	if view.DNSRecords != nil && len(view.DNSRecords) == 0 {
		return errors.New("empty overlay DNS must be omitted")
	}
	if view.PublicTrust != nil && len(view.PublicTrust) == 0 {
		return errors.New("empty public trust must be omitted")
	}
	if err := validatePublicTrust(view.PublicTrust); err != nil {
		return err
	}
	if err := validateWebsiteEndpoints(view.WebEndpoints, view.PublicTrust); err != nil {
		return err
	}
	if err := validateDNSRecords(view.DNSRecords); err != nil {
		return err
	}
	access := containsString(view.Responsibilities, "access")
	if access != (view.RuntimeProfile != nil) || !access && (len(view.PolicyIDs) != 0 || len(view.Routes) != 0) {
		return errors.New("device view access projection does not match its responsibilities")
	}
	if view.RuntimeProfile != nil && view.RuntimeProfile.Validate() != nil {
		return errors.New("device view runtime is invalid")
	}
	for index, address := range view.DNSServers {
		ip, err := netip.ParseAddr(address)
		if err != nil || ip.Zone() != "" || ip.String() != address || index > 0 && view.DNSServers[index-1] >= address {
			return errors.New("device DNS addresses are invalid or not uniquely sorted")
		}
	}
	return validateDeviceViewAuthorization(view)
}

type DeviceViewEnvelope struct {
	Schema          int            `json:"schema"`
	NetworkID       string         `json:"network_id"`
	GenesisDigest   string         `json:"genesis_digest"`
	IssuerControlID string         `json:"issuer_control_id"`
	IssuerKeyID     string         `json:"issuer_key_id"`
	ControlProof    ControlProof   `json:"control_proof"`
	FactFrontier    []FactFrontier `json:"fact_frontier"`
	View            DeviceView     `json:"view"`
	ViewDigest      string         `json:"view_digest"`
	Signature       string         `json:"signature"`
}

func (envelope DeviceViewEnvelope) unsigned() map[string]any {
	return map[string]any{"schema": envelope.Schema, "network_id": envelope.NetworkID, "genesis_digest": envelope.GenesisDigest, "issuer_control_id": envelope.IssuerControlID, "issuer_key_id": envelope.IssuerKeyID, "control_proof": envelope.ControlProof, "fact_frontier": envelope.FactFrontier, "view": envelope.View, "view_digest": envelope.ViewDigest}
}

func DeviceViewDigest(view DeviceView) (string, error) {
	body, err := CanonicalEncode(view)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append([]byte("loom-device-view-digest-v3\x00"), body...))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func validateFactFrontier(frontier []FactFrontier) error {
	if frontier == nil {
		return errors.New("fact frontier must be explicit")
	}
	for index, prefix := range frontier {
		if prefix.Validate() != nil || index > 0 && frontier[index-1].KeyID >= prefix.KeyID {
			return errors.New("fact frontier is invalid or not uniquely sorted")
		}
	}
	return nil
}

func (envelope DeviceViewEnvelope) Validate() error {
	if envelope.Schema != 3 || ValidateID(envelope.IssuerControlID) != nil || ValidateDigest(envelope.IssuerKeyID) != nil || validateFactFrontier(envelope.FactFrontier) != nil || envelope.View.Validate() != nil {
		return errors.New("device view envelope is invalid")
	}
	config, err := VerifyControlProof(envelope.ControlProof, envelope.NetworkID, envelope.GenesisDigest)
	if err != nil {
		return err
	}
	memberKeys := make(map[string]bool, len(config.Members))
	memberNodes := make(map[string]bool, len(config.Members))
	memberControls := make(map[string]bool, len(config.Members))
	for _, member := range config.Members {
		keyID, err := KeyID(member.PublicKey)
		if err != nil {
			return err

		}
		memberKeys[keyID] = true
		memberNodes[member.NodeID] = true
		memberControls[member.ControlID] = true
	}
	if containsString(envelope.View.Responsibilities, "control") != memberNodes[envelope.View.DeviceID] {
		return errors.New("device control responsibility does not match the proven member table")
	}
	for _, endpoints := range [][]EndpointGeneration{envelope.View.Endpoints, envelope.View.WebEndpoints} {
		for _, endpoint := range endpoints {
			if !memberControls[endpoint.OwnerControlID] {
				return errors.New("device endpoint owner is not a proven member")
			}
		}
	}
	for _, prefix := range envelope.FactFrontier {
		if !memberKeys[prefix.KeyID] {
			return errors.New("device fact frontier key is not proven")
		}
	}
	member, found := proofMember(config, envelope.IssuerControlID)
	keyID, err := KeyID(member.PublicKey)
	if !found || err != nil || keyID != envelope.IssuerKeyID {
		return errors.New("device view issuer is not a proven member")
	}
	digest, err := DeviceViewDigest(envelope.View)
	if err != nil || digest != envelope.ViewDigest {
		return errors.New("device view digest is invalid")
	}
	body, err := CanonicalEncode(envelope.unsigned())
	if err != nil {
		return err
	}
	key, _ := base64.RawURLEncoding.DecodeString(member.PublicKey)
	signature, err := base64.RawURLEncoding.DecodeString(envelope.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || base64.RawURLEncoding.EncodeToString(signature) != envelope.Signature || !ed25519.Verify(ed25519.PublicKey(key), append([]byte(deviceViewDomain), body...), signature) {
		return errors.New("device view envelope signature is invalid")
	}
	return nil
}

func SignDeviceViewEnvelope(envelope DeviceViewEnvelope, private ed25519.PrivateKey) (DeviceViewEnvelope, error) {
	if len(private) != ed25519.PrivateKeySize {
		return DeviceViewEnvelope{}, errors.New("device view signing key is invalid")
	}
	digest, err := DeviceViewDigest(envelope.View)
	if err != nil {
		return DeviceViewEnvelope{}, err
	}
	envelope.ViewDigest = digest
	body, err := CanonicalEncode(envelope.unsigned())
	if err != nil {
		return DeviceViewEnvelope{}, err
	}
	envelope.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, append([]byte(deviceViewDomain), body...)))
	if err := envelope.Validate(); err != nil {
		return DeviceViewEnvelope{}, err
	}
	return envelope, nil
}

func VerifyDeviceViewEnvelope(envelope DeviceViewEnvelope, trusted BootstrapInvite) error {
	if trusted.Validate() != nil || envelope.NetworkID != trusted.NetworkID || envelope.GenesisDigest != trusted.GenesisDigest {
		return errors.New("device view does not match its fixed network anchor")
	}
	invite := trusted.Material.Payload.(Invite)
	if envelope.View.DeviceID != invite.DeviceID {
		return errors.New("device view is bound to another device")
	}
	inviteID, err := MaterialID(trusted.Material)
	if err != nil {
		return err
	}
	foundPrefix := false
	for _, prefix := range envelope.FactFrontier {
		if prefix.KeyID == trusted.Material.IssuerKeyID {
			foundPrefix = prefix.Sequence >= trusted.Material.Sequence && (prefix.Sequence != trusted.Material.Sequence || prefix.TipMaterialID == inviteID)
		}
	}
	if !foundPrefix {
		return errors.New("device view does not include the authenticated invitation prefix")
	}
	return envelope.Validate()
}

// CheckDeviceViewAdvance performs no I/O. Save the envelope, member proof and
// accumulated high-water values in one durable replacement before execution.
func CheckDeviceViewAdvance(next, previous DeviceViewEnvelope, highWater []FactFrontier) error {
	if err := next.Validate(); err != nil {
		return err
	}
	if next.NetworkID != previous.NetworkID || next.GenesisDigest != previous.GenesisDigest || next.View.DeviceID != previous.View.DeviceID || next.View.DevicePublicKey != previous.View.DevicePublicKey || next.View.Platform != previous.View.Platform {
		return errors.New("device view changed its fixed identity")
	}
	if _, err := VerifyControlProofExtension(next.ControlProof, previous.ControlProof, next.NetworkID, next.GenesisDigest); err != nil {
		return err
	}
	if validateFactFrontier(highWater) != nil {
		return errors.New("saved fact high-water values are invalid")
	}
	current := map[string]FactFrontier{}
	for _, prefix := range next.FactFrontier {
		current[prefix.KeyID] = prefix
	}
	for _, prefix := range append(append([]FactFrontier(nil), highWater...), previous.FactFrontier...) {
		value, found := current[prefix.KeyID]
		if prefix.Sequence != 0 && !found || found && (value.Sequence < prefix.Sequence || value.Sequence == prefix.Sequence && value.TipMaterialID != prefix.TipMaterialID) {
			return errors.New("device view rolls back or forks a verified fact prefix")
		}
	}
	previousPrefixes := map[string]U64{}
	for _, prefix := range previous.FactFrontier {
		previousPrefixes[prefix.KeyID] = prefix.Sequence
	}
	advanced := false
	for _, prefix := range next.FactFrontier {
		if prefix.Sequence > previousPrefixes[prefix.KeyID] {
			advanced = true
		}
	}
	if !advanced && next.ViewDigest != previous.ViewDigest {
		return errors.New("device view changed without advancing its authenticated facts")
	}
	return nil
}
