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
	endpointSchema   = 1
	enrollmentSchema = 1
	deviceViewSchema = 1

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
	DeviceID string           `json:"device_id"`
	Name     string           `json:"name"`
	Platform string           `json:"platform"`
	Roles    []string         `json:"roles"`
	Routes   []RouteCandidate `json:"routes"`
	Runtime  *RuntimeProfile  `json:"runtime_profile,omitempty"`
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
	TransactionID   string `json:"transaction_id"`
	ClaimRequestID  string `json:"claim_request_id"`
	DevicePublicKey string `json:"device_public_key"`
	ClaimedAt       string `json:"claimed_at"`
}

type EnrollmentApprove struct {
	TransactionID string `json:"transaction_id"`
}

type EnrollmentComplete struct {
	TransactionID string              `json:"transaction_id"`
	Authorization DeviceAuthorization `json:"authorization"`
	ResultDigest  string              `json:"result_digest"`
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
	ResultDigest     string           `json:"result_digest,omitempty"`
}

type DeviceAuthorization struct {
	Schema          int              `json:"schema"`
	DeviceID        string           `json:"device_id"`
	Name            string           `json:"name"`
	Platform        string           `json:"platform"`
	Roles           []string         `json:"roles"`
	Routes          []RouteCandidate `json:"routes"`
	Runtime         *RuntimeProfile  `json:"runtime_profile,omitempty"`
	DevicePublicKey string           `json:"device_public_key"`
	Floor           uint64           `json:"floor"`
}

type DeviceView struct {
	Schema          int                 `json:"schema"`
	DeviceID        string              `json:"device_id"`
	Name            string              `json:"name"`
	Platform        string              `json:"platform"`
	Roles           []string            `json:"roles"`
	DevicePublicKey string              `json:"device_public_key"`
	Floor           uint64              `json:"floor"`
	Endpoints       []EndpointReference `json:"endpoint_generations"`
	Routes          []RouteCandidate    `json:"route_candidates"`
	Runtime         *RuntimeProfile     `json:"runtime_profile,omitempty"`
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

func validRawKey(value string) bool {
	key, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(key) == ed25519.PublicKeySize && base64.RawURLEncoding.EncodeToString(key) == value
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
	for index, candidate := range intent.Routes {
		if err := candidate.Validate(); err != nil || index > 0 && intent.Routes[index-1].ID >= candidate.ID {
			return errors.New("route candidates are not uniquely sorted")
		}
	}
	if intent.Platform == "android" {
		if intent.Runtime == nil || intent.Runtime.Validate(intent.Routes) != nil {
			return errors.New("android enrollment runtime profile is invalid")
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
	return nil
}

func (approve EnrollmentApprove) Validate() error {
	if !validName(approve.TransactionID) {
		return errors.New("enrollment approval is invalid")
	}
	return nil
}

func (authorization DeviceAuthorization) Validate() error {
	intent := EnrollmentIntent{DeviceID: authorization.DeviceID, Name: authorization.Name, Platform: authorization.Platform,
		Roles: authorization.Roles, Routes: authorization.Routes, Runtime: authorization.Runtime}
	if authorization.Schema != enrollmentSchema || intent.Validate() != nil || !validRawKey(authorization.DevicePublicKey) || authorization.Floor == 0 {
		return errors.New("device authorization is invalid")
	}
	return nil
}

func (complete EnrollmentComplete) Validate() error {
	if !validName(complete.TransactionID) || complete.Authorization.Validate() != nil || !validDigest(complete.ResultDigest) {
		return errors.New("enrollment completion is invalid")
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
		if transaction.Intent.DeviceID == open.Intent.DeviceID && transaction.State != "rejected" && transaction.State != "expired" && transaction.State != "cancelled" {
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

func reduceEnrollmentBind(projection *Projection, bind EnrollmentBind) error {
	_, transaction := findEnrollment(projection, bind.TransactionID)
	if transaction == nil {
		return errors.New("enrollment transaction does not exist")
	}
	if transaction.State != "open" {
		return errors.New("only open enrollment may bind")
	}
	transaction.State = "bound"
	transaction.ClaimRequestID = bind.ClaimRequestID
	transaction.DevicePublicKey = bind.DevicePublicKey
	transaction.ClaimedAt = bind.ClaimedAt
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
	if transaction == nil || transaction.State != "approved" {
		return errors.New("only approved enrollment may complete")
	}
	intent := transaction.Intent
	authorization := complete.Authorization
	leftRuntime, _ := canonical(authorization.Runtime)
	rightRuntime, _ := canonical(intent.Runtime)
	if authorization.DeviceID != intent.DeviceID || authorization.Name != intent.Name || authorization.Platform != intent.Platform ||
		authorization.DevicePublicKey != transaction.DevicePublicKey || !equalStrings(authorization.Roles, intent.Roles) ||
		!equalRoutes(authorization.Routes, intent.Routes) || !bytes.Equal(leftRuntime, rightRuntime) {
		return errors.New("device authorization does not match enrollment")
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

func reduceDeviceAuthorization(projection *Projection, authorization DeviceAuthorization) error {
	index := sort.Search(len(projection.DeviceAuthorizations), func(index int) bool {
		return projection.DeviceAuthorizations[index].DeviceID >= authorization.DeviceID
	})
	if index == len(projection.DeviceAuthorizations) || projection.DeviceAuthorizations[index].DeviceID != authorization.DeviceID {
		return errors.New("device authorization does not exist")
	}
	previous := projection.DeviceAuthorizations[index]
	if authorization.Name != previous.Name || authorization.Platform != previous.Platform ||
		authorization.DevicePublicKey != previous.DevicePublicKey || !equalStrings(authorization.Roles, previous.Roles) ||
		authorization.Floor <= previous.Floor {
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
	view := DeviceView{Schema: deviceViewSchema, DeviceID: authorization.DeviceID, Name: authorization.Name,
		Platform: authorization.Platform, Roles: append([]string(nil), authorization.Roles...),
		DevicePublicKey: authorization.DevicePublicKey, Floor: authorization.Floor,
		Routes: append([]RouteCandidate(nil), authorization.Routes...), Runtime: cloneRuntimeProfile(authorization.Runtime)}
	for _, generation := range projection.EndpointGenerations {
		if generation.State == "serving" || generation.State == "draining" {
			view.Endpoints = append(view.Endpoints, generation.Reference())
		}
	}
	sort.Slice(view.Endpoints, func(i, j int) bool { return endpointReferenceLess(view.Endpoints[i], view.Endpoints[j]) })
	return view, true
}

func (view DeviceView) Validate() error {
	authorization := DeviceAuthorization{Schema: enrollmentSchema, DeviceID: view.DeviceID, Name: view.Name,
		Platform: view.Platform, Roles: view.Roles, Routes: view.Routes, Runtime: view.Runtime,
		DevicePublicKey: view.DevicePublicKey, Floor: view.Floor}
	if view.Schema != deviceViewSchema || authorization.Validate() != nil || len(view.Endpoints) == 0 {
		return errors.New("device view is invalid")
	}
	for index, endpoint := range view.Endpoints {
		if endpoint.Validate() != nil || index > 0 && !endpointReferenceLess(view.Endpoints[index-1], endpoint) {
			return errors.New("device view endpoints are invalid")
		}
	}
	return nil
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
	for _, transaction := range projection.Enrollments {
		index := sort.Search(len(projection.Web.Devices), func(index int) bool {
			return projection.Web.Devices[index].ID >= transaction.Intent.DeviceID
		})
		device := Device{ID: transaction.Intent.DeviceID, Name: transaction.Intent.Name, Platform: transaction.Intent.Platform,
			Roles: append([]string(nil), transaction.Intent.Roles...), Authorized: transaction.State == "completed",
			Availability: "unknown", EnrollmentID: transaction.ID, Enrollment: transaction.State, ViewDigest: transaction.ResultDigest}
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
		for _, candidate := range transaction.Intent.Routes {
			projection.Web.Paths = append(projection.Web.Paths, Path{CandidateID: candidate.ID, Device: transaction.Intent.DeviceID,
				FinalExit: candidate.FinalExit, Chain: append([]string(nil), candidate.Chain...), Availability: "unknown"})
		}
	}
	sort.Slice(projection.Web.Paths, func(i, j int) bool {
		return projection.Web.Paths[i].Device+"\x00"+projection.Web.Paths[i].CandidateID <
			projection.Web.Paths[j].Device+"\x00"+projection.Web.Paths[j].CandidateID
	})
}
