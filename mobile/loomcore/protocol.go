package loomcore

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
	"net/url"
	"sort"
	"strings"
	"time"
	"unicode"

	"loom/internal/clientmodel"
)

const (
	capabilityDomain = "loom-bootstrap-capability-v1\n"
	claimDomain      = "loom-enrollment-claim-v1\n"
	resumeDomain     = "loom-enrollment-resume-v1\n"
	reportDomain     = "loom-device-report-v1\n"
	headDomain       = "loom-certified-head-v1\n"
	viewDomain       = "loom-device-view-v1\n"
	viewNodeDomain   = "loom-device-view-node-v1\n"
	tunnelDomain     = "loom-device-tunnel-proof-v1\n"
)

type member struct {
	ID                string `json:"id"`
	LegacyRaftAddress string `json:"raft_address,omitempty"`
	LegacyAPIAddress  string `json:"api_address,omitempty"`
	PublicKey         string `json:"public_key"`
	Node              string `json:"node,omitempty"`
}

type controlConfig struct {
	Mode      string   `json:"mode"`
	Members   []member `json:"members,omitempty"`
	Quorum    int      `json:"quorum,omitempty"`
	Old       []member `json:"old,omitempty"`
	OldQuorum int      `json:"old_quorum,omitempty"`
	New       []member `json:"new,omitempty"`
	NewQuorum int      `json:"new_quorum,omitempty"`
}

type endpointReference struct {
	EndpointID string `json:"endpoint_id"`
	Generation uint64 `json:"generation"`
	Transport  string `json:"transport"`
	Address    string `json:"address"`
	ServerName string `json:"server_name"`
	SPKISHA256 string `json:"spki_sha256"`
	State      string `json:"state"`
	Preference int    `json:"preference"`
}

type bootstrapCapability struct {
	Schema           int                 `json:"schema"`
	TransactionID    string              `json:"transaction_id"`
	IssuedHead       string              `json:"issued_head"`
	ConfigMaterial   string              `json:"control_config_material"`
	ControlConfig    controlConfig       `json:"control_config"`
	ExpiresAt        string              `json:"expires_at"`
	Actions          []string            `json:"actions"`
	Endpoints        []endpointReference `json:"endpoints"`
	ConstraintDigest string              `json:"constraint_digest"`
	IssuerMemberID   string              `json:"issuer_member_id"`
	Signature        string              `json:"signature"`
}

type bootstrapInvite struct {
	Schema     int                 `json:"schema"`
	Capability bootstrapCapability `json:"capability"`
}

type enrollmentIntent struct {
	DeviceID string                       `json:"device_id"`
	Name     string                       `json:"name"`
	Platform string                       `json:"platform"`
	Roles    []string                     `json:"roles"`
	Routes   []clientmodel.RouteCandidate `json:"routes"`
	Runtime  *clientmodel.RuntimeProfile  `json:"runtime_profile,omitempty"`
}

type enrollmentTransaction struct {
	Schema           int              `json:"schema"`
	ID               string           `json:"id"`
	State            string           `json:"state"`
	Intent           enrollmentIntent `json:"intent"`
	CapabilityDigest string           `json:"capability_digest"`
	ExpiresAt        string           `json:"expires_at"`
	ClaimRequestID   string           `json:"claim_request_id,omitempty"`
	DevicePublicKey  string           `json:"device_public_key,omitempty"`
	ClaimedAt        string           `json:"claimed_at,omitempty"`
	ResultDigest     string           `json:"result_digest,omitempty"`
}

type deviceView struct {
	Schema          int                          `json:"schema"`
	DeviceID        string                       `json:"device_id"`
	Name            string                       `json:"name"`
	Platform        string                       `json:"platform"`
	Roles           []string                     `json:"roles"`
	DevicePublicKey string                       `json:"device_public_key"`
	Floor           uint64                       `json:"floor"`
	Endpoints       []endpointReference          `json:"endpoint_generations"`
	Routes          []clientmodel.RouteCandidate `json:"route_candidates"`
	Runtime         *clientmodel.RuntimeProfile  `json:"runtime_profile,omitempty"`
}

type headSignature struct {
	MemberID string `json:"member_id"`
	Value    string `json:"value"`
}

type governanceHead struct {
	Schema            int             `json:"schema"`
	Index             uint64          `json:"index"`
	LogDigest         string          `json:"log_digest"`
	ProjectionDigest  string          `json:"projection_digest"`
	DeviceViewsDigest string          `json:"device_views_digest,omitempty"`
	ConfigMaterial    string          `json:"control_config_material"`
	Signatures        []headSignature `json:"signatures"`
}

type deviceViewProof struct {
	Index    int      `json:"index"`
	Size     int      `json:"size"`
	Siblings []string `json:"siblings"`
}

type deviceViewEnvelope struct {
	Schema        int             `json:"schema"`
	View          deviceView      `json:"view"`
	Head          governanceHead  `json:"certified_head"`
	ControlConfig controlConfig   `json:"control_config"`
	Proof         deviceViewProof `json:"proof"`
}

type enrollmentResponse struct {
	Schema      int                   `json:"schema"`
	Transaction enrollmentTransaction `json:"transaction"`
	DeviceView  *deviceViewEnvelope   `json:"device_view,omitempty"`
}

type enrollmentClaim struct {
	Schema          int                 `json:"schema"`
	Capability      bootstrapCapability `json:"capability"`
	RequestID       string              `json:"request_id"`
	DevicePublicKey string              `json:"device_public_key"`
	Signature       string              `json:"signature"`
}

type enrollmentResume struct {
	Schema          int    `json:"schema"`
	TransactionID   string `json:"transaction_id"`
	RequestID       string `json:"request_id"`
	DevicePublicKey string `json:"device_public_key"`
	Signature       string `json:"signature"`
}

type tunnelHello struct {
	Schema     int                  `json:"schema"`
	Mode       string               `json:"mode"`
	EndpointID string               `json:"endpoint_id"`
	Generation uint64               `json:"generation"`
	Capability *bootstrapCapability `json:"capability,omitempty"`
	DeviceID   string               `json:"device_id,omitempty"`
}

type tunnelChallenge struct {
	Schema int    `json:"schema"`
	Nonce  string `json:"nonce"`
}

type tunnelProof struct {
	Schema    int    `json:"schema"`
	Signature string `json:"signature"`
}

type tunnelReady struct {
	Schema int    `json:"schema"`
	Status string `json:"status"`
}

type deviceReport struct {
	Schema       int                       `json:"schema"`
	DeviceID     string                    `json:"device_id"`
	ViewDigest   string                    `json:"view_digest"`
	Selection    string                    `json:"selection,omitempty"`
	ReportedAt   string                    `json:"reported_at"`
	Observations []clientmodel.Observation `json:"observations"`
	Signature    string                    `json:"signature"`
}

func canonical(value any) ([]byte, error) { return json.Marshal(value) }

func validName(value string) bool {
	return value != "" && len(value) <= 128 && strings.TrimSpace(value) == value && strings.IndexFunc(value, unicode.IsControl) < 0
}

func validDigest(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != 71 {
		return false
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil && len(decoded) == sha256.Size
}

func rawKey(value string) (ed25519.PublicKey, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) != ed25519.PublicKeySize || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, errors.New("invalid Ed25519 public key")
	}
	return ed25519.PublicKey(decoded), nil
}

func validateEndpoint(endpoint endpointReference) error {
	host, port, err := net.SplitHostPort(endpoint.Address)
	if endpoint.Transport != "tls_tunnel" || endpoint.State != "serving" || !validName(endpoint.EndpointID) || endpoint.Generation == 0 ||
		!validName(endpoint.ServerName) || endpoint.Preference < 0 || err != nil || host == "" || port == "" {
		return errors.New("invalid endpoint")
	}
	spki, err := hex.DecodeString(endpoint.SPKISHA256)
	if err != nil || len(spki) != sha256.Size || hex.EncodeToString(spki) != endpoint.SPKISHA256 {
		return errors.New("invalid endpoint SPKI")
	}
	return nil
}

func uniqueMembers(config controlConfig) []member {
	if config.Mode == "stable" {
		return config.Members
	}
	byID := map[string]member{}
	for _, value := range append(append([]member{}, config.Old...), config.New...) {
		byID[value.ID] = value
	}
	result := make([]member, 0, len(byID))
	for _, value := range byID {
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}

func validateConfig(config controlConfig) error {
	check := func(values []member, quorum int) error {
		if len(values) == 0 || quorum != len(values)/2+1 {
			return errors.New("invalid quorum")
		}
		for index, value := range values {
			if !validName(value.ID) || value.Node == "" || value.LegacyRaftAddress != "" || value.LegacyAPIAddress != "" {
				return errors.New("invalid member")
			}
			if _, err := rawKey(value.PublicKey); err != nil || index > 0 && values[index-1].ID >= value.ID {
				return errors.New("invalid members")
			}
		}
		return nil
	}
	switch config.Mode {
	case "stable":
		if len(config.Old)+len(config.New) != 0 || config.OldQuorum != 0 || config.NewQuorum != 0 {
			return errors.New("invalid stable config")
		}
		return check(config.Members, config.Quorum)
	case "joint":
		if len(config.Members) != 0 || config.Quorum != 0 {
			return errors.New("invalid joint config")
		}
		if err := check(config.Old, config.OldQuorum); err != nil {
			return err
		}
		return check(config.New, config.NewQuorum)
	default:
		return errors.New("invalid control mode")
	}
}

func signingBytes(domain string, value any) ([]byte, error) {
	body, err := canonical(value)
	if err != nil {
		return nil, err
	}
	return append([]byte(domain), body...), nil
}

func validateCapability(capability bootstrapCapability) error {
	if capability.Schema != 1 || !validName(capability.TransactionID) || !validDigest(capability.IssuedHead) ||
		!validDigest(capability.ConfigMaterial) || !validDigest(capability.ConstraintDigest) || !validName(capability.IssuerMemberID) ||
		len(capability.Actions) != 2 || capability.Actions[0] != "claim" || capability.Actions[1] != "resume" || len(capability.Endpoints) == 0 ||
		validateConfig(capability.ControlConfig) != nil {
		return errors.New("invalid bootstrap capability")
	}
	if parsed, err := time.Parse(time.RFC3339, capability.ExpiresAt); err != nil || parsed.UTC().Format(time.RFC3339) != capability.ExpiresAt {
		return errors.New("invalid capability expiry")
	}
	for index, endpoint := range capability.Endpoints {
		if validateEndpoint(endpoint) != nil || index > 0 && !endpointLess(capability.Endpoints[index-1], endpoint) {
			return errors.New("invalid capability endpoints")
		}
	}
	var issuer *member
	for _, candidate := range uniqueMembers(capability.ControlConfig) {
		if candidate.ID == capability.IssuerMemberID {
			copy := candidate
			issuer = &copy
			break
		}
	}
	if issuer == nil {
		return errors.New("capability issuer is not a member")
	}
	copy := capability
	copy.Signature = ""
	message, _ := signingBytes(capabilityDomain, copy)
	key, _ := rawKey(issuer.PublicKey)
	signature, err := base64.RawURLEncoding.DecodeString(capability.Signature)
	if err != nil || !ed25519.Verify(key, message, signature) {
		return errors.New("invalid capability signature")
	}
	return nil
}

func endpointLess(left, right endpointReference) bool {
	if left.Preference != right.Preference {
		return left.Preference < right.Preference
	}
	if left.EndpointID != right.EndpointID {
		return left.EndpointID < right.EndpointID
	}
	return left.Generation < right.Generation
}

func validateView(view deviceView) error {
	if view.Schema != 1 || !validName(view.DeviceID) || !validName(view.Name) || view.Platform != "android" || view.Floor == 0 || len(view.Endpoints) == 0 {
		return errors.New("invalid device view")
	}
	if _, err := rawKey(view.DevicePublicKey); err != nil {
		return err
	}
	for index, role := range view.Roles {
		if !validName(role) || index > 0 && view.Roles[index-1] >= role {
			return errors.New("invalid roles")
		}
	}
	for index, route := range view.Routes {
		if route.Validate() != nil || index > 0 && view.Routes[index-1].ID >= route.ID {
			return errors.New("invalid routes")
		}
	}
	for index, endpoint := range view.Endpoints {
		if validateEndpoint(endpoint) != nil || index > 0 && !endpointLess(view.Endpoints[index-1], endpoint) {
			return errors.New("invalid endpoints")
		}
	}
	if view.Runtime == nil || view.Runtime.Validate(view.Routes) != nil {
		return errors.New("invalid runtime profile")
	}
	return nil
}

func viewDigest(view deviceView) (string, error) {
	if err := validateView(view); err != nil {
		return "", err
	}
	body, _ := canonical(view)
	sum := sha256.Sum256(append([]byte(viewDomain), body...))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func viewLeaf(view deviceView) ([]byte, error) {
	digest, err := viewDigest(view)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(append([]byte(viewNodeDomain+"leaf\n"), []byte(digest)...))
	return sum[:], nil
}

func viewNode(left, right []byte) []byte {
	body := append([]byte(viewNodeDomain+"pair\n"), left...)
	body = append(body, right...)
	sum := sha256.Sum256(body)
	return sum[:]
}

func verifyHead(head governanceHead, config controlConfig) error {
	if head.Schema != 1 || head.Index == 0 || !validDigest(head.LogDigest) || !validDigest(head.ProjectionDigest) ||
		!validDigest(head.DeviceViewsDigest) || !validDigest(head.ConfigMaterial) || validateConfig(config) != nil {
		return errors.New("invalid certified head")
	}
	copy := head
	copy.Signatures = nil
	message, _ := signingBytes(headDomain, copy)
	members := map[string]member{}
	for _, value := range uniqueMembers(config) {
		members[value.ID] = value
	}
	valid, previous := map[string]bool{}, ""
	for _, signature := range head.Signatures {
		member, ok := members[signature.MemberID]
		if !ok || valid[signature.MemberID] || previous != "" && previous >= signature.MemberID {
			return errors.New("invalid head signatures")
		}
		key, _ := rawKey(member.PublicKey)
		value, err := base64.RawURLEncoding.DecodeString(signature.Value)
		if err != nil || !ed25519.Verify(key, message, value) {
			return errors.New("invalid head signature")
		}
		valid[signature.MemberID], previous = true, signature.MemberID
	}
	count := func(values []member) int {
		total := 0
		for _, value := range values {
			if valid[value.ID] {
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

func verifyEnvelope(envelope deviceViewEnvelope, capability bootstrapCapability) error {
	left, _ := canonical(envelope.ControlConfig)
	right, _ := canonical(capability.ControlConfig)
	if envelope.Schema != 1 || validateView(envelope.View) != nil || validateCapability(capability) != nil ||
		envelope.Head.ConfigMaterial != capability.ConfigMaterial || !bytes.Equal(left, right) || envelope.Head.Index < envelope.View.Floor {
		return errors.New("invalid device view boundary")
	}
	if err := verifyHead(envelope.Head, envelope.ControlConfig); err != nil {
		return err
	}
	value, _ := viewLeaf(envelope.View)
	proof := envelope.Proof
	if proof.Size < 1 || proof.Index < 0 || proof.Index >= proof.Size {
		return errors.New("invalid device view proof")
	}
	position, width := proof.Index, proof.Size
	for _, encoded := range proof.Siblings {
		sibling, err := hex.DecodeString(encoded)
		if err != nil || len(sibling) != sha256.Size || width <= 1 {
			return errors.New("invalid device view proof")
		}
		if position%2 == 0 {
			value = viewNode(value, sibling)
		} else {
			value = viewNode(sibling, value)
		}
		position, width = position/2, (width+1)/2
	}
	if width != 1 || "sha256:"+hex.EncodeToString(value) != envelope.Head.DeviceViewsDigest {
		return errors.New("device view proof mismatch")
	}
	return nil
}

func decodeInvite(raw string) (bootstrapInvite, error) {
	var invite bootstrapInvite
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme != "loom" || parsed.Host != "enroll" || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment == "" {
		return invite, errors.New("invalid bootstrap invite")
	}
	body, err := base64.RawURLEncoding.DecodeString(parsed.Fragment)
	if err != nil || len(body) > 64<<10 || base64.RawURLEncoding.EncodeToString(body) != parsed.Fragment ||
		decodeCanonical(body, &invite) != nil || invite.Schema != 1 || validateCapability(invite.Capability) != nil {
		return bootstrapInvite{}, errors.New("invalid bootstrap invite")
	}
	return invite, nil
}

func signValue(domain string, value any, signature *string, private ed25519.PrivateKey) error {
	*signature = ""
	message, err := signingBytes(domain, value)
	if err != nil {
		return err
	}
	*signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, message))
	return nil
}

func headID(head governanceHead) string {
	copy := head
	copy.Signatures = nil
	message, _ := signingBytes(headDomain, copy)
	sum := sha256.Sum256(message)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func recordID(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func requireRFC3339(value string) error {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil || parsed.UTC().Format(time.RFC3339) != value {
		return fmt.Errorf("invalid RFC3339 time")
	}
	return nil
}
