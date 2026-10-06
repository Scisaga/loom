package control

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"sort"
)

const MaterialSchema = 3
const materialDomain = "loom-material-v3\x00"
const materialIDDomain = "loom-material-id-v3\x00"

var ErrMissingDependencies = errors.New("material dependencies are not available")
var ErrMaterialEquivocation = errors.New("issuer key signed conflicting sequence values")

type Member struct {
	ControlID string `json:"control_id"`
	NodeID    string `json:"node_id"`
	PublicKey string `json:"public_key"`
}

type ControlConfig struct {
	Schema           int                      `json:"schema"`
	NetworkID        string                   `json:"network_id"`
	PreviousConfigID string                   `json:"previous_config_id"`
	Operation        string                   `json:"operation"`
	Members          []Member                 `json:"members"`
	SealedKeys       []ControlSealedKey       `json:"sealed_keys"`
	TargetNodeID     string                   `json:"target_node_id,omitempty"`
	OriginPromises   []ControlPromise         `json:"origin_promises,omitempty"`
	Join             *ControlJoinBinding      `json:"join,omitempty"`
	Invalidation     *ControlJoinInvalidation `json:"invalidation,omitempty"`
}

type AdminCertificate struct {
	ID             string `json:"id"`
	CertificateDER string `json:"certificate_der"`
}

type Genesis struct {
	ControlConfig     ControlConfig      `json:"control_config"`
	NetworkIntent     NetworkIntent      `json:"network_intent"`
	AdminCertificates []AdminCertificate `json:"admin_certificates"`
}

// MaterialPayload is a closed domain sum. The canonical codec recognizes only
// the exact concrete values selected by operation and target kind, never an
// arbitrary implementation of this interface.
type MaterialPayload interface{ materialPayload() }

func (Genesis) materialPayload()               {}
func (Service) materialPayload()               {}
func (NetworkPolicy) materialPayload()         {}
func (DeleteTarget) materialPayload()          {}
func (BusinessProbeTarget) materialPayload()   {}
func (Invite) materialPayload()                {}
func (EnrollmentBind) materialPayload()        {}
func (EnrollmentTermination) materialPayload() {}
func (DeviceAuthorization) materialPayload()   {}
func (DevicePut) materialPayload()             {}
func (EndpointGeneration) materialPayload()    {}
func (TransportResource) materialPayload()     {}
func (NetworkLink) materialPayload()           {}
func (ExpectedComponent) materialPayload()     {}

type DevicePut struct {
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	Responsibilities []string `json:"responsibilities"`
	PolicyIDs        []string `json:"policy_ids"`
	DistributionURLs []string `json:"distribution_urls"`
	DNSServers       []string `json:"dns_servers,omitempty"`
}

func (value DevicePut) Validate() error {
	if err := validateOptionalDNS(value.DNSServers); err != nil {
		return err
	}
	if ValidateID(value.ID) != nil || value.ID == "direct" || ValidateText(value.Name) != nil || validateResponsibilities(value.Responsibilities, false) != nil || validateIDSet(value.PolicyIDs) != nil || value.DistributionURLs == nil {
		return errors.New("device management value is invalid")
	}
	if !containsString(value.Responsibilities, "access") && len(value.PolicyIDs) != 0 {
		return errors.New("non-access device cannot assign policies")
	}
	for i, address := range value.DistributionURLs {
		if ValidateHTTPSURL(address) != nil || i > 0 && value.DistributionURLs[i-1] >= address {
			return errors.New("distribution URLs are invalid or not sorted")
		}
	}
	return nil
}

type DeleteTarget struct {
	ID string `json:"id"`
}

func (target DeleteTarget) Validate() error { return ValidateID(target.ID) }

// Material has one canonical codec with the two shapes fixed by the contract.
// For genesis, Payload is Genesis and all ordinary-only fields are absent/zero.
type Material struct {
	Schema             int             `json:"schema"`
	NetworkID          string          `json:"network_id"`
	IssuerControlID    string          `json:"issuer_control_id"`
	IssuerKeyID        string          `json:"issuer_key_id"`
	ControlConfigID    string          `json:"control_config_id"`
	Sequence           U64             `json:"sequence"`
	PreviousMaterialID string          `json:"previous_material_id"`
	Dependencies       []string        `json:"dependencies"`
	RequestID          string          `json:"request_id"`
	TargetKind         string          `json:"target_kind"`
	TargetID           string          `json:"target_id"`
	Operation          string          `json:"operation"`
	Payload            MaterialPayload `json:"payload"`
	Signature          string          `json:"signature"`
}

// Operation is the administrator's public command, not a second fact or store.
// Issuer identity, sequence, key material and signatures belong to the daemon.
type Operation struct {
	Schema       int             `json:"schema"`
	RequestID    string          `json:"request_id"`
	Operation    string          `json:"operation"`
	TargetKind   string          `json:"target_kind"`
	TargetID     string          `json:"target_id"`
	Dependencies []string        `json:"dependencies"`
	Payload      MaterialPayload `json:"payload"`
}

type TargetState struct {
	TargetKind  string   `json:"target_kind"`
	TargetID    string   `json:"target_id"`
	MaterialIDs []string `json:"material_ids"`
	Conflicted  bool     `json:"conflicted"`
	Deleted     bool     `json:"deleted"`
	// Public history for explicit administrator review, never an active grant.
	DeviceForReview *DevicePut `json:"device_for_review,omitempty"`
}

// Projection and its indexes are disposable results of the same raw facts.
type MaterialRejection struct {
	MaterialID string `json:"material_id"`
	Reason     string `json:"reason"`
}

type Projection struct {
	Schema               int                   `json:"schema"`
	NetworkID            string                `json:"network_id"`
	Config               ControlConfig         `json:"control_config"`
	ControlConfigID      string                `json:"control_config_id"`
	NetworkIntent        NetworkIntent         `json:"network_intent"`
	AdminCertificates    []AdminCertificate    `json:"admin_certificates"`
	Targets              []TargetState         `json:"targets"`
	Frontier             []FactFrontier        `json:"fact_frontier"`
	PendingMaterialIDs   []string              `json:"pending_material_ids"`
	InvalidMaterials     []MaterialRejection   `json:"invalid_materials"`
	DeviceAuthorizations []DeviceAuthorization `json:"device_authorizations"`
	Invites              []Invite              `json:"invites"`
	Bindings             []EnrollmentBind      `json:"bindings"`
	EndpointGenerations  []EndpointGeneration  `json:"endpoint_generations"`
}

func (projection Projection) CurrentTarget(kind, id string) (TargetState, bool) {
	for _, target := range projection.Targets {
		if target.TargetKind == kind && target.TargetID == id {
			target.MaterialIDs = append([]string{}, target.MaterialIDs...)
			return target, true
		}
	}
	return TargetState{}, false
}

func (config ControlConfig) Validate() error {
	if config.Schema != 3 || ValidateID(config.NetworkID) != nil || len(config.Members) == 0 || config.SealedKeys == nil {
		return errors.New("ControlConfig identity or members are invalid")
	}
	nodes, keys := map[string]bool{}, map[string]bool{}
	for index, member := range config.Members {
		if ValidateID(member.ControlID) != nil || ValidateID(member.NodeID) != nil || member.NodeID == "direct" ||
			ValidatePublicKey(member.PublicKey) != nil || index > 0 && config.Members[index-1].ControlID >= member.ControlID || nodes[member.NodeID] || keys[member.PublicKey] {
			return errors.New("ControlConfig members are invalid or not uniquely sorted")
		}
		nodes[member.NodeID], keys[member.PublicKey] = true, true
	}
	if config.Operation != "genesis" {
		return validateControlConfigSuccessor(config)
	}
	if config.PreviousConfigID != "" || len(config.SealedKeys) != 0 || config.TargetNodeID != "" || config.OriginPromises != nil || config.Join != nil || config.Invalidation != nil {
		return errors.New("initial ControlConfig contains successor fields")
	}
	return nil
}

func (genesis Genesis) Validate() error {
	if genesis.ControlConfig.Validate() != nil || genesis.ControlConfig.Operation != "genesis" || genesis.NetworkIntent.Validate() != nil || genesis.AdminCertificates == nil {
		return errors.New("genesis payload is incomplete")
	}
	certificates := map[string]bool{}
	for index, item := range genesis.AdminCertificates {
		body, err := base64.RawURLEncoding.DecodeString(item.CertificateDER)
		if ValidateID(item.ID) != nil || index > 0 && genesis.AdminCertificates[index-1].ID >= item.ID || err != nil ||
			base64.RawURLEncoding.EncodeToString(body) != item.CertificateDER || certificates[item.CertificateDER] {
			return errors.New("genesis admin certificates are invalid or not uniquely sorted")
		}
		certificate, err := x509.ParseCertificate(body)
		if err != nil || !bytes.Equal(certificate.Raw, body) {
			return errors.New("genesis admin value must be one complete DER certificate")
		}
		certificates[item.CertificateDER] = true
	}
	return nil
}

func validateDigests(values []string) error {
	if values == nil {
		return errors.New("digest collection must be explicit")
	}
	for index, value := range values {
		if ValidateDigest(value) != nil || index > 0 && values[index-1] >= value {
			return errors.New("digests are invalid or not uniquely sorted")
		}
	}
	return nil
}

func validateMaterialPayload(operation, kind, id string, payload MaterialPayload) error {
	if ValidateID(id) != nil {
		return errors.New("material target is invalid")
	}
	switch operation {
	case "public_trust.put":
		value, ok := payload.(PublicTrust)
		if !ok || kind != "public_trust" || value.ID != id {
			return errors.New("public_trust.put has the wrong payload or target")
		}
		return value.Validate()
	case "admin_certificate.put":
		value, ok := payload.(AdminCertificate)
		if !ok || kind != "admin_certificate" || value.ID != id {
			return errors.New("administrator grant has the wrong payload or target")
		}
		_, err := ValidateAdminLeaf(value)
		return err
	case "dns_record.put":
		value, ok := payload.(DNSRecord)
		if !ok || kind != "dns_record" || value.ID != id {
			return errors.New("dns_record.put has the wrong payload or target")
		}
		return value.Validate()
	case "service.put":
		value, ok := payload.(Service)
		if !ok || kind != "service" || value.ID != id {
			return errors.New("service.put has the wrong payload or target")
		}
		return value.Validate()
	case "policy.put":
		value, ok := payload.(NetworkPolicy)
		if !ok || kind != "policy" || value.ID != id {
			return errors.New("policy.put has the wrong payload or target")
		}
		return value.Validate()
	case "public_trust.delete", "dns_record.delete", "service.delete", "policy.delete", "device.delete", "device.revoke", "resource.delete", "link.delete", "expected_component.delete", "admin_certificate.delete":
		value, ok := payload.(DeleteTarget)
		if !ok || operation != kind+".delete" && !(operation == "device.revoke" && kind == "device") || value.ID != id {
			return errors.New("deletion has the wrong payload or target")
		}
		return value.Validate()
	case "invite.issue":
		value, ok := payload.(Invite)
		if !ok || kind != "invite" || value.ID != id {
			return errors.New("invite payload or target is invalid")
		}
		return value.Validate()
	case "invite.bind":
		value, ok := payload.(EnrollmentBind)
		if !ok || kind != "invite" || value.TransactionID != id {
			return errors.New("binding payload or target is invalid")
		}
		return value.Validate()
	case "invite.cancel", "invite.expire":
		value, ok := payload.(EnrollmentTermination)
		if !ok || kind != "invite" || value.TransactionID != id || (operation == "invite.expire") != (value.ExpiredAt != nil) {
			return errors.New("termination payload or target is invalid")
		}
		return value.Validate()
	case "device.join", "device.put":
		value, ok := payload.(DeviceAuthorization)
		if !ok || kind != "device" || value.ID != id {
			return errors.New("device payload or target is invalid")
		}
		return value.Validate()
	case "endpoint.put":
		value, ok := payload.(EndpointGeneration)
		if !ok || kind != "endpoint" || value.ID != id {
			return errors.New("endpoint payload or target is invalid")
		}
		return value.Validate()
	case "resource.put":
		value, ok := payload.(TransportResource)
		if !ok || kind != "resource" || value.ID != id {
			return errors.New("resource payload or target is invalid")
		}
		return value.Validate()
	case "link.put":
		value, ok := payload.(NetworkLink)
		if !ok || kind != "link" || value.ID != id {
			return errors.New("link payload or target is invalid")
		}
		return value.Validate()
	case "expected_component.put":
		value, ok := payload.(ExpectedComponent)
		if !ok || kind != "expected_component" || value.ID != id {
			return errors.New("expected component has the wrong payload or target")
		}
		return value.Validate()
	case "probe_target.put":
		value, ok := payload.(BusinessProbeTarget)
		if !ok || kind != "probe_target" || value.ID != id {
			return errors.New("probe target has the wrong payload or target")
		}
		return value.Validate()
	case "probe_target.delete":
		value, ok := payload.(DeleteTarget)
		if !ok || kind != "probe_target" || value.ID != id {
			return errors.New("probe deletion has the wrong payload or target")
		}
		return value.Validate()
	default:
		return errors.New("material operation has no implemented complete payload contract")
	}
}

func (material Material) validate(signature bool) error {
	if material.Schema != 3 || ValidateID(material.NetworkID) != nil || ValidateID(material.IssuerControlID) != nil || ValidateDigest(material.IssuerKeyID) != nil {
		return errors.New("Material identity is incomplete")
	}
	if signature {
		decoded, err := base64.RawURLEncoding.DecodeString(material.Signature)
		if err != nil || len(decoded) != ed25519.SignatureSize || base64.RawURLEncoding.EncodeToString(decoded) != material.Signature {
			return errors.New("Material signature is not canonical")
		}
	} else if material.Signature != "" {
		return errors.New("unsigned Material contains its own signature")
	}
	if material.Operation == "genesis" {
		value, ok := material.Payload.(Genesis)
		if !ok || value.Validate() != nil || value.ControlConfig.NetworkID != material.NetworkID || material.ControlConfigID != "" || material.Sequence != 0 ||
			material.PreviousMaterialID != "" || material.Dependencies != nil || material.RequestID != "" || material.TargetKind != "" || material.TargetID != "" {
			return errors.New("genesis has invalid or ordinary-only fields")
		}
		for _, member := range value.ControlConfig.Members {
			keyID, _ := KeyID(member.PublicKey)
			if member.ControlID == material.IssuerControlID && keyID == material.IssuerKeyID {
				return nil
			}
		}
		return errors.New("genesis issuer is not an initial member")
	}
	if ValidateDigest(material.ControlConfigID) != nil || material.Sequence == 0 || ValidateDigest(material.PreviousMaterialID) != nil ||
		validateDigests(material.Dependencies) != nil || ValidateID(material.RequestID) != nil {
		return errors.New("ordinary Material coordinates are invalid")
	}
	if material.Sequence == 1 && material.PreviousMaterialID != EmptyMaterialChainID() {
		return errors.New("first material does not name the empty chain")
	}
	return validateMaterialPayload(material.Operation, material.TargetKind, material.TargetID, material.Payload)
}

func (material Material) Validate() error { return material.validate(true) }

func (operation Operation) Validate() error {
	if operation.Schema != 3 || ValidateID(operation.RequestID) != nil || validateDigests(operation.Dependencies) != nil {
		return errors.New("management operation coordinates are invalid")
	}
	if operation.Operation == "device.put" {
		value, ok := operation.Payload.(DevicePut)
		if !ok || operation.TargetKind != "device" || operation.TargetID != value.ID {
			return errors.New("device management payload must contain only public fields")
		}
		return value.Validate()
	}
	return validateMaterialPayload(operation.Operation, operation.TargetKind, operation.TargetID, operation.Payload)
}

func (material Material) OperationRequest() (Operation, error) {
	if material.Operation == "genesis" {
		return Operation{}, errors.New("genesis is not a management operation")
	}
	operation := Operation{Schema: 3, RequestID: material.RequestID, Operation: material.Operation, TargetKind: material.TargetKind,
		TargetID: material.TargetID, Dependencies: append([]string{}, material.Dependencies...), Payload: material.Payload}
	if material.Operation == "device.put" {
		value, ok := material.Payload.(DeviceAuthorization)
		if !ok {
			return Operation{}, errors.New("device material payload is invalid")
		}
		operation.Payload = DevicePut{ID: value.ID, Name: value.Name, Responsibilities: append([]string{}, value.Responsibilities...), PolicyIDs: append([]string{}, value.PolicyIDs...), DistributionURLs: append([]string{}, value.DistributionURLs...), DNSServers: append([]string(nil), value.DNSServers...)}
	}
	return operation, operation.Validate()
}

func digestContract(domain string, value any) (string, error) {
	body, err := CanonicalEncode(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append([]byte(domain), body...))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func EmptyMaterialChainID() string {
	sum := sha256.Sum256([]byte("loom-empty-material-chain-v3\x00"))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func KeyID(publicKey string) (string, error) {
	if err := ValidatePublicKey(publicKey); err != nil {
		return "", err
	}
	return digestContract("loom-control-key-id-v3\x00", map[string]any{"public_key": publicKey})
}

func ConfigID(config ControlConfig) (string, error) {
	if err := config.Validate(); err != nil {
		return "", err
	}
	return digestContract("loom-control-config-id-v3\x00", config)
}

func SignMaterial(material Material, key ed25519.PrivateKey) (Material, error) {
	material.Signature = ""
	if len(key) != ed25519.PrivateKeySize {
		return Material{}, errors.New("Material signing key is invalid")
	}
	keyID, _ := KeyID(base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey)))
	if keyID != material.IssuerKeyID {
		return Material{}, errors.New("Material issuer does not match signing key")
	}
	if err := material.validate(false); err != nil {
		return Material{}, err
	}
	body, err := CanonicalEncode(material.contractObject(false))
	if err != nil {
		return Material{}, err
	}
	material.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, append([]byte(materialDomain), body...)))
	return material, nil
}

func VerifyMaterial(material Material, key ed25519.PublicKey) error {
	if err := material.Validate(); err != nil {
		return err
	}
	if len(key) != ed25519.PublicKeySize {
		return errors.New("Material verification key is invalid")
	}
	keyID, _ := KeyID(base64.RawURLEncoding.EncodeToString(key))
	if keyID != material.IssuerKeyID {
		return errors.New("Material verification key does not match issuer")
	}
	body, err := CanonicalEncode(material.contractObject(false))
	if err != nil {
		return err
	}
	signature, _ := base64.RawURLEncoding.DecodeString(material.Signature)
	if !ed25519.Verify(key, append([]byte(materialDomain), body...), signature) {
		return errors.New("Material signature is invalid")
	}
	return nil
}

func EncodeMaterial(material Material) ([]byte, string, error) {
	body, err := CanonicalEncode(material)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(append([]byte(materialIDDomain), body...))
	return body, "sha256:" + hex.EncodeToString(sum[:]), nil
}

func MaterialID(material Material) (string, error) {
	_, id, err := EncodeMaterial(material)
	return id, err
}

// These are the bounded ordinary HTTP/store entry defaults. Proof delivery can
// choose larger complete-message limits without changing a business maximum.
func materialDecodeLimits() ContractDecodeLimits {
	return ContractDecodeLimits{MaxBytes: 16 << 20, MaxDepth: 128, MaxItems: 1 << 20}
}

func DecodeMaterial(body []byte) (Material, error) {
	return DecodeMaterialWithLimits(body, materialDecodeLimits())
}
func DecodeMaterialWithLimits(body []byte, limits ContractDecodeLimits) (Material, error) {
	var material Material
	err := DecodeCanonical(body, &material, limits)
	return material, err
}
func EncodeMaterialFromBytes(body []byte) (Material, string, error) {
	material, err := DecodeMaterial(body)
	if err != nil {
		return Material{}, "", err
	}
	id, err := MaterialID(material)
	return material, id, err
}
func EncodeOperation(operation Operation) ([]byte, error) { return CanonicalEncode(operation) }
func DecodeOperation(body []byte) (Operation, error) {
	var operation Operation
	err := DecodeCanonical(body, &operation, materialDecodeLimits())
	return operation, err
}

func (material Material) contractObject(signature bool) map[string]any {
	object := map[string]any{"schema": material.Schema, "network_id": material.NetworkID, "issuer_control_id": material.IssuerControlID,
		"issuer_key_id": material.IssuerKeyID, "operation": material.Operation}
	if material.Operation == "genesis" {
		genesis := material.Payload.(Genesis)
		object["control_config"], object["network_intent"], object["admin_certificates"] = genesis.ControlConfig, genesis.NetworkIntent, genesis.AdminCertificates
	} else {
		object["control_config_id"], object["sequence"], object["previous_material_id"] = material.ControlConfigID, material.Sequence, material.PreviousMaterialID
		object["dependencies"], object["request_id"] = material.Dependencies, material.RequestID
		object["target_kind"], object["target_id"], object["payload"] = material.TargetKind, material.TargetID, material.Payload
	}
	if signature {
		object["signature"] = material.Signature
	}
	return object
}

func (operation Operation) contractObject() map[string]any {
	return map[string]any{"schema": operation.Schema, "request_id": operation.RequestID, "operation": operation.Operation,
		"target_kind": operation.TargetKind, "target_id": operation.TargetID, "dependencies": operation.Dependencies, "payload": operation.Payload}
}

func decodeMaterialObject(object map[string]any) (Material, error) {
	var material Material
	operation, ok := object["operation"].(string)
	if !ok {
		return material, errors.New("Material operation is missing")
	}
	fields := map[string]any{"schema": &material.Schema, "network_id": &material.NetworkID, "issuer_control_id": &material.IssuerControlID,
		"issuer_key_id": &material.IssuerKeyID, "operation": &material.Operation, "signature": &material.Signature}
	if operation == "genesis" {
		var genesis Genesis
		fields["control_config"], fields["network_intent"], fields["admin_certificates"] = &genesis.ControlConfig, &genesis.NetworkIntent, &genesis.AdminCertificates
		if err := decodeContractObjectFields(object, fields); err != nil {
			return Material{}, err
		}
		material.Payload = genesis
	} else {
		fields["control_config_id"], fields["sequence"], fields["previous_material_id"] = &material.ControlConfigID, &material.Sequence, &material.PreviousMaterialID
		fields["dependencies"], fields["request_id"], fields["target_kind"], fields["target_id"] = &material.Dependencies, &material.RequestID, &material.TargetKind, &material.TargetID
		if err := decodeContractObjectFieldsExceptPayload(object, fields); err != nil {
			return Material{}, err
		}
		payload, err := decodeMaterialPayload(operation, material.TargetKind, object["payload"])
		if err != nil {
			return Material{}, err
		}
		material.Payload = payload
	}
	return material, material.Validate()
}

func decodeOperationObject(object map[string]any) (Operation, error) {
	var operation Operation
	fields := map[string]any{"schema": &operation.Schema, "request_id": &operation.RequestID, "operation": &operation.Operation,
		"target_kind": &operation.TargetKind, "target_id": &operation.TargetID, "dependencies": &operation.Dependencies}
	if err := decodeContractObjectFieldsExceptPayload(object, fields); err != nil {
		return Operation{}, err
	}
	var payload MaterialPayload
	var err error
	if operation.Operation == "device.put" {
		var value DevicePut
		err = assignContractJSON(object["payload"], reflect.ValueOf(&value).Elem())
		payload = value
	} else {
		payload, err = decodeMaterialPayload(operation.Operation, operation.TargetKind, object["payload"])
	}
	if err != nil {
		return Operation{}, err
	}
	operation.Payload = payload
	return operation, operation.Validate()
}

func decodeMaterialPayload(operation, kind string, value any) (MaterialPayload, error) {
	var target any
	switch operation {
	case "public_trust.put":
		target = &PublicTrust{}
	case "admin_certificate.put":
		target = &AdminCertificate{}
	case "dns_record.put":
		target = &DNSRecord{}
	case "service.put":
		target = &Service{}
	case "policy.put":
		target = &NetworkPolicy{}
	case "public_trust.delete", "dns_record.delete", "service.delete", "policy.delete", "probe_target.delete", "device.delete", "device.revoke", "resource.delete", "link.delete", "expected_component.delete", "admin_certificate.delete":
		target = &DeleteTarget{}
	case "invite.issue":
		target = &Invite{}
	case "invite.bind":
		target = &EnrollmentBind{}
	case "invite.cancel", "invite.expire":
		target = &EnrollmentTermination{}
	case "device.join", "device.put":
		target = &DeviceAuthorization{}
	case "endpoint.put":
		target = &EndpointGeneration{}
	case "resource.put":
		target = &TransportResource{}
	case "link.put":
		target = &NetworkLink{}
	case "probe_target.put":
		target = &BusinessProbeTarget{}
	case "expected_component.put":
		target = &ExpectedComponent{}
	default:
		return nil, errors.New("unsupported Material payload contract")
	}
	if err := assignContractJSON(value, reflect.ValueOf(target).Elem()); err != nil {
		return nil, err
	}
	return reflect.ValueOf(target).Elem().Interface().(MaterialPayload), nil
}

func decodeContractObjectFieldsExceptPayload(object map[string]any, fields map[string]any) error {
	if _, ok := object["payload"]; !ok || len(object) != len(fields)+1 {
		return errors.New("Material object fields are incomplete or unknown")
	}
	copy := make(map[string]any, len(fields))
	for key, value := range object {
		if key != "payload" {
			copy[key] = value
		}
	}
	return decodeContractObjectFields(copy, fields)
}

func decodeContractObjectFields(object map[string]any, fields map[string]any) error {
	if len(object) != len(fields) {
		return errors.New("contract object has missing or unknown fields")
	}
	for key, destination := range fields {
		value, found := object[key]
		if !found {
			return errors.New("contract object has missing or unknown fields")
		}
		if err := assignContractJSON(value, reflect.ValueOf(destination).Elem()); err != nil {
			return err
		}
	}
	return nil
}

func contains(values []string, value string) bool {
	index := sort.SearchStrings(values, value)
	return index < len(values) && values[index] == value
}

// Project and ValidateAdmission below share causal validation. Reception uses
// only the fact's declared ancestry; concurrent facts affect projection only.

type materialGraph struct {
	genesis   Material
	genesisID string
	config    ControlConfig
	configID  string
	facts     map[string]Material
	ordered   []string
	forks     map[string]U64
	visiting  map[string]bool
	checked   map[string]bool
	failures  map[string]error
	ancestors map[string]map[string]bool
}

func newMaterialGraph(genesis Material, configs []ControlConfig, materials []Material) (*materialGraph, error) {
	if len(configs) != 0 {
		return nil, ErrControlSuccessionUnsupported
	}
	genesisID, err := MaterialID(genesis)
	if err != nil {
		return nil, err
	}
	config, err := VerifyControlProof(ControlProof{Genesis: genesis, Successors: []ControlCertificate{}}, genesis.NetworkID, genesisID)
	if err != nil {
		return nil, err
	}
	configID, err := ConfigID(config)
	if err != nil {
		return nil, err
	}
	graph := &materialGraph{genesis: genesis, genesisID: genesisID, config: config, configID: configID, facts: map[string]Material{}, forks: map[string]U64{}, visiting: map[string]bool{}, checked: map[string]bool{}, failures: map[string]error{}, ancestors: map[string]map[string]bool{}}
	sequences := map[string]map[U64]string{}
	for _, material := range materials {
		if err := graph.verifyIdentity(material); err != nil {
			return nil, err
		}
		id, err := MaterialID(material)
		if err != nil {
			return nil, err
		}
		if _, exists := graph.facts[id]; exists {
			continue
		}
		graph.facts[id] = material
		graph.ordered = append(graph.ordered, id)
		if sequences[material.IssuerKeyID] == nil {
			sequences[material.IssuerKeyID] = map[U64]string{}
		}
		sequence := sequences[material.IssuerKeyID]
		if prior, exists := sequence[material.Sequence]; exists && prior != id {
			first, found := graph.forks[material.IssuerKeyID]
			if !found || material.Sequence < first {
				graph.forks[material.IssuerKeyID] = material.Sequence
			}
		}
		sequence[material.Sequence] = id
	}
	sort.Strings(graph.ordered)
	return graph, nil
}

func (graph *materialGraph) verifyIdentity(material Material) error {
	if material.Operation == "genesis" || material.NetworkID != graph.genesis.NetworkID || material.ControlConfigID != graph.configID {
		return errors.New("ordinary Material has no matching network or verified ControlConfig")
	}
	for _, member := range graph.config.Members {
		keyID, _ := KeyID(member.PublicKey)
		if member.ControlID != material.IssuerControlID || keyID != material.IssuerKeyID {
			continue
		}
		key, err := base64.RawURLEncoding.DecodeString(member.PublicKey)
		if err != nil {
			return err
		}
		return VerifyMaterial(material, ed25519.PublicKey(key))
	}
	return errors.New("Material issuer has no member authority")
}

func (graph *materialGraph) validate(id string) (err error) {
	if id == graph.genesisID {
		return nil
	}
	if graph.checked[id] {
		return graph.failures[id]
	}
	material, exists := graph.facts[id]
	if !exists {
		return ErrMissingDependencies
	}
	if graph.visiting[id] {
		return errors.New("Material ancestry contains a cycle")
	}
	graph.visiting[id] = true
	defer func() { delete(graph.visiting, id); graph.checked[id] = true; graph.failures[id] = err }()
	if fork, found := graph.forks[material.IssuerKeyID]; found && material.Sequence >= fork {
		return ErrMaterialEquivocation
	}
	ancestors := map[string]bool{graph.genesisID: true}
	parents := append([]string{}, material.Dependencies...)
	if material.Sequence > 1 {
		previous, found := graph.facts[material.PreviousMaterialID]
		if !found {
			return ErrMissingDependencies
		}
		if previous.IssuerKeyID != material.IssuerKeyID || previous.IssuerControlID != material.IssuerControlID || previous.Sequence != material.Sequence-1 {
			return errors.New("Material previous value is not the same key's immediate predecessor")
		}
		parents = append(parents, material.PreviousMaterialID)
	}
	for _, parent := range parents {
		if parent == id {
			return errors.New("Material depends on itself")
		}
		if err := graph.validate(parent); err != nil {
			return err
		}
		ancestors[parent] = true
		for ancestor := range graph.ancestors[parent] {
			ancestors[ancestor] = true
		}
	}
	graph.ancestors[id] = ancestors
	history := []string{}
	for ancestor := range ancestors {
		if ancestor != graph.genesisID {
			history = append(history, ancestor)
		}
	}
	sort.Strings(history)
	view := graph.projectValues(history, nil)
	return graph.validateOperation(material, view, history)
}

// ValidateAdmission uses only the signed fact's causal past. Unrelated facts
// cannot invalidate reception merely because they arrived in another order.
// The two sentinel errors occur only after identity and signature verification.
func ValidateAdmission(material Material, genesis Material, configs []ControlConfig, known []Material) error {
	values := append(append([]Material{}, known...), material)
	graph, err := newMaterialGraph(genesis, configs, values)
	if err != nil {
		return err
	}
	id, err := MaterialID(material)
	if err != nil {
		return err
	}
	return graph.validate(id)
}

func Project(genesis Material, configs []ControlConfig, materials []Material) (Projection, error) {
	graph, err := newMaterialGraph(genesis, configs, materials)
	if err != nil {
		return Projection{}, err
	}
	valid, pending := []string{}, []string{}
	invalid := []MaterialRejection{}
	suspended := map[string][]string{}
	for _, id := range graph.ordered {
		err := graph.validate(id)
		if err == nil {
			valid = append(valid, id)
			continue
		}
		material := graph.facts[id]
		key := material.TargetKind + "\x00" + material.TargetID
		suspended[key] = append(suspended[key], id)
		if errors.Is(err, ErrMissingDependencies) {
			pending = append(pending, id)
		} else {
			invalid = append(invalid, MaterialRejection{MaterialID: id, Reason: err.Error()})
		}
	}
	projection := graph.projectValues(valid, suspended)
	projection.PendingMaterialIDs, projection.InvalidMaterials = pending, invalid
	for _, member := range graph.config.Members {
		keyID, _ := KeyID(member.PublicKey)
		prefix := FactFrontier{KeyID: keyID, Sequence: 0, TipMaterialID: EmptyMaterialChainID()}
		for _, id := range valid {
			material := graph.facts[id]
			if material.IssuerKeyID == keyID && material.Sequence > prefix.Sequence {
				prefix.Sequence, prefix.TipMaterialID = material.Sequence, id
			}
		}
		projection.Frontier = append(projection.Frontier, prefix)
	}
	sort.Slice(projection.Frontier, func(i, j int) bool { return projection.Frontier[i].KeyID < projection.Frontier[j].KeyID })
	return projection, nil
}

type targetFact struct {
	id        string
	payload   MaterialPayload
	operation string
}

func (graph *materialGraph) projectValues(ids []string, suspended map[string][]string) Projection {
	genesis := graph.genesis.Payload.(Genesis)
	projection := Projection{Schema: 3, NetworkID: graph.genesis.NetworkID, Config: graph.config, ControlConfigID: graph.configID, NetworkIntent: EmptyNetworkIntent(),
		AdminCertificates: []AdminCertificate{}, Targets: []TargetState{}, Frontier: []FactFrontier{}, PendingMaterialIDs: []string{}, InvalidMaterials: []MaterialRejection{},
		DeviceAuthorizations: []DeviceAuthorization{}, Invites: []Invite{}, Bindings: []EnrollmentBind{}, EndpointGenerations: []EndpointGeneration{}}
	grouped := map[string][]targetFact{}
	add := func(kind, id, factID, operation string, payload MaterialPayload) {
		key := kind + "\x00" + id
		grouped[key] = append(grouped[key], targetFact{id: factID, payload: payload, operation: operation})
	}
	for _, value := range genesis.AdminCertificates {
		add("admin_certificate", value.ID, graph.genesisID, "admin_certificate.put", value)
	}
	for _, value := range genesis.NetworkIntent.DNSRecords {
		add("dns_record", value.ID, graph.genesisID, "dns_record.put", value)
	}
	for _, value := range genesis.NetworkIntent.PublicTrust {
		add("public_trust", value.ID, graph.genesisID, "public_trust.put", value)
	}
	for _, value := range genesis.NetworkIntent.Services {
		add("service", value.ID, graph.genesisID, "service.put", value)
	}
	for _, value := range genesis.NetworkIntent.Policies {
		add("policy", value.ID, graph.genesisID, "policy.put", value)
	}
	for _, value := range genesis.NetworkIntent.BusinessProbeTargets {
		add("probe_target", value.ID, graph.genesisID, "probe_target.put", value)
	}
	for _, id := range ids {
		material := graph.facts[id]
		add(material.TargetKind, material.TargetID, id, material.Operation, material.Payload)
		switch value := material.Payload.(type) {
		case Invite:
			projection.Invites = append(projection.Invites, value)
		case EnrollmentBind:
			projection.Bindings = append(projection.Bindings, value)
		}
	}
	for key := range suspended {
		if grouped[key] == nil {
			grouped[key] = []targetFact{}
		}
	}
	keys := make([]string, 0, len(grouped))
	for key := range grouped {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		facts := grouped[key]
		maxima := []targetFact{}
		for _, fact := range facts {
			superseded := false
			for _, other := range facts {
				if fact.id != other.id && graph.ancestors[other.id][fact.id] {
					superseded = true
					break
				}
			}
			if !superseded {
				maxima = append(maxima, fact)
			}
		}
		separator := bytes.IndexByte([]byte(key), 0)
		state := TargetState{TargetKind: key[:separator], TargetID: key[separator+1:], MaterialIDs: []string{}}
		var chosen *targetFact
		for i := range maxima {
			fact := &maxima[i]
			state.MaterialIDs = append(state.MaterialIDs, fact.id)
			if isWithdrawal(fact.operation) {
				state.Deleted = true
				chosen = fact
			}
		}
		if !state.Deleted {
			if len(maxima) == 1 {
				chosen = &maxima[0]
			} else if len(maxima) > 1 {
				state.Conflicted = true
			}
		}
		if len(suspended[key]) > 0 {
			state.Conflicted = true
			state.MaterialIDs = append(state.MaterialIDs, suspended[key]...)
		}
		sort.Strings(state.MaterialIDs)
		if state.TargetKind == "device" && state.Deleted && !state.Conflicted {
			state.DeviceForReview = graph.revokedDeviceForReview(facts, maxima)
		}
		projection.Targets = append(projection.Targets, state)
		if chosen == nil || state.Deleted || state.Conflicted {
			continue
		}
		switch value := chosen.payload.(type) {
		case PublicTrust:
			projection.NetworkIntent.PublicTrust = append(projection.NetworkIntent.PublicTrust, value)
		case AdminCertificate:
			projection.AdminCertificates = append(projection.AdminCertificates, value)
		case DNSRecord:
			projection.NetworkIntent.DNSRecords = append(projection.NetworkIntent.DNSRecords, value)
		case Service:
			projection.NetworkIntent.Services = append(projection.NetworkIntent.Services, value)
		case NetworkPolicy:
			projection.NetworkIntent.Policies = append(projection.NetworkIntent.Policies, value)
		case BusinessProbeTarget:
			projection.NetworkIntent.BusinessProbeTargets = append(projection.NetworkIntent.BusinessProbeTargets, value)
		case ExpectedComponent:
			projection.NetworkIntent.ExpectedComponents = append(projection.NetworkIntent.ExpectedComponents, value)
		case DeviceAuthorization:
			projection.DeviceAuthorizations = append(projection.DeviceAuthorizations, value)
		case EndpointGeneration:
			// Every generation is projected separately from this target history below.
		case TransportResource:
			projection.NetworkIntent.Resources = append(projection.NetworkIntent.Resources, value)
		case NetworkLink:
			projection.NetworkIntent.Links = append(projection.NetworkIntent.Links, value)
		}
	}
	sort.Slice(projection.NetworkIntent.ExpectedComponents, func(i, j int) bool {
		return expectedComponentLess(projection.NetworkIntent.ExpectedComponents[i], projection.NetworkIntent.ExpectedComponents[j])
	})
	graph.projectEndpointGenerations(&projection, ids)
	closeEnrollmentConflicts(&projection)
	sort.Slice(projection.Invites, func(i, j int) bool { return projection.Invites[i].ID < projection.Invites[j].ID })
	sort.Slice(projection.Bindings, func(i, j int) bool {
		return projection.Bindings[i].TransactionID < projection.Bindings[j].TransactionID
	})
	return projection
}

func isWithdrawal(operation string) bool {
	switch operation {
	case "public_trust.delete", "dns_record.delete", "service.delete", "policy.delete", "device.revoke", "device.delete", "resource.delete", "link.delete", "probe_target.delete", "expected_component.delete", "admin_certificate.delete", "invite.cancel", "invite.expire":
		return true
	}
	return false
}

func requireTargetDependency(material Material, view Projection, kind, id string, active bool) error {
	target, found := view.CurrentTarget(kind, id)
	if !found {
		return fmt.Errorf("%s reference does not exist", kind)
	}
	if active && (target.Deleted || target.Conflicted) {
		return fmt.Errorf("%s reference is deleted or conflicted", kind)
	}
	for _, factID := range target.MaterialIDs {
		if !contains(material.Dependencies, factID) {
			return fmt.Errorf("%s reference is not an explicit reviewed dependency", kind)
		}
	}
	return nil
}

func (graph *materialGraph) validateOperation(material Material, view Projection, history []string) error {
	for _, id := range history {
		prior := graph.facts[id]
		if prior.IssuerKeyID == material.IssuerKeyID && prior.RequestID == material.RequestID {
			return errors.New("request ID was already signed at an earlier sequence")
		}
	}
	if target, exists := view.CurrentTarget(material.TargetKind, material.TargetID); exists {
		if err := requireTargetDependency(material, view, material.TargetKind, material.TargetID, false); err != nil {
			return err
		}
		if target.Conflicted && !isWithdrawal(material.Operation) {
			return errors.New("conflicted target requires an explicit conflict resolution")
		}
	} else if isWithdrawal(material.Operation) || material.Operation == "device.put" || material.Operation == "invite.bind" {
		return errors.New("operation requires an existing target")
	}
	switch value := material.Payload.(type) {
	case PublicTrust:
		return nil // The complete immutable certificate determines its stable ID.
	case AdminCertificate:
		return graph.validateAdminCertificate(value, history)
	case DNSRecord:
		for _, record := range view.NetworkIntent.DNSRecords {
			if record.ID != value.ID && record.Name == value.Name {
				return errors.New("DNS name is already assigned to another record")
			}
		}
		return nil
	case Service:
		return nil
	case NetworkPolicy:
		if err := requireTargetDependency(material, view, "service", value.ServiceID, true); err != nil {
			return err
		}
		for _, initial := range graph.genesis.Payload.(Genesis).NetworkIntent.Policies {
			if initial.ID == value.ID && initial.ServiceID != value.ServiceID {
				return errors.New("Policy ID cannot change its original Service")
			}
		}
		for _, id := range history {
			if prior, ok := graph.facts[id].Payload.(NetworkPolicy); ok && prior.ID == value.ID && prior.ServiceID != value.ServiceID {
				return errors.New("Policy ID cannot change its historical Service")
			}
		}
		return validatePolicyNodes(material, view, value)
	case Invite:
		return graph.validateInvite(material, view, history, value)
	case EnrollmentBind:
		return graph.validateBinding(material, view, history, value)
	case EnrollmentTermination:
		return graph.validateTermination(material, view, history, value)
	case DeviceAuthorization:
		return graph.validateDevice(material, view, history, value)
	case EndpointGeneration:
		return graph.validateEndpoint(material, view, history, value)
	case ExpectedComponent:
		if err := validateExpectedNode(value, view); err != nil {
			return err
		}
		return requireTargetDependency(material, view, "device", value.NodeID, true)
	case TransportResource:
		for _, id := range history {
			if prior, ok := graph.facts[id].Payload.(TransportResource); ok && prior.ID == value.ID && (prior.OwnerNodeID != value.OwnerNodeID || prior.Kind != value.Kind || prior.ListenerID != value.ListenerID) {
				return errors.New("resource kind, owner and listener identity cannot change")
			}
		}
		var owner DeviceAuthorization
		found := false
		for _, device := range view.DeviceAuthorizations {
			if device.ID == value.OwnerNodeID {
				owner = device
				found = true
			}
		}
		if !found || !containsString(owner.Responsibilities, "forward") && !containsString(owner.Responsibilities, "internet_egress") {
			return errors.New("resource owner has no transport responsibility")
		}
		return requireTargetDependency(material, view, "device", value.OwnerNodeID, true)
	case NetworkLink:
		resources := map[string]TransportResource{}
		for _, resource := range view.NetworkIntent.Resources {
			resources[resource.ID] = resource
		}
		if _, _, _, err := linkResources(value, resources); err != nil {
			return err
		}
		for _, id := range []string{value.FromResourceID, value.ResourceID, value.ProbeTarget.ResourceID} {
			if err := requireTargetDependency(material, view, "resource", id, true); err != nil {
				return err
			}
		}
		for _, id := range []string{value.FromNodeID, value.ToNodeID} {
			found := false
			for _, device := range view.DeviceAuthorizations {
				if device.ID == id && containsString(device.Responsibilities, "forward") {
					found = true
				}
			}
			if !found {
				return errors.New("WireGuard Link endpoint has no forwarding responsibility")
			}
			if err := requireTargetDependency(material, view, "device", id, true); err != nil {
				return err
			}
		}
		for _, id := range history {
			if prior, ok := graph.facts[id].Payload.(NetworkLink); ok && prior.ID == value.ID && (prior.FromNodeID != value.FromNodeID || prior.ToNodeID != value.ToNodeID || prior.FromResourceID != value.FromResourceID || prior.ResourceID != value.ResourceID || prior.InitiatorNodeID != value.InitiatorNodeID || prior.Purpose != value.Purpose) {
				return errors.New("Link identity relationships cannot change")
			}
		}
		return nil
	case DeleteTarget:
		if material.Operation == "device.delete" {
			for _, member := range view.Config.Members {
				if member.NodeID == value.ID {
					return errors.New("control node deletion requires member rules")
				}
			}
		}
	}
	return nil
}

func validatePolicyNodes(material Material, view Projection, policy NetworkPolicy) error {
	devices := map[string]DeviceAuthorization{}
	for _, device := range view.DeviceAuthorizations {
		devices[device.ID] = device
	}
	for _, item := range []struct {
		scope PolicyScope
		role  string
	}{{policy.EntryScope, "entry"}, {policy.RelayScope, "forward"}, {policy.ExitScope, "internet_egress"}} {
		for _, id := range item.scope.NodeIDs {
			device, found := devices[id]
			eligible := containsString(device.Responsibilities, item.role)
			if item.role == "entry" {
				eligible = containsString(device.Responsibilities, "forward") || containsString(device.Responsibilities, "internet_egress")
			}
			if !found || !eligible {
				return errors.New("Policy scope node lacks the required responsibility")
			}
			if err := requireTargetDependency(material, view, "device", id, true); err != nil {
				return err
			}
		}
	}
	for _, id := range policy.LocalEgressDevices {
		device, found := devices[id]
		if !found || !containsString(device.Responsibilities, "access") || !containsString(device.Responsibilities, "internet_egress") || !policy.ExitScope.Allows(id) {
			return errors.New("Policy local egress node is not an eligible hybrid exit")
		}
		if err := requireTargetDependency(material, view, "device", id, true); err != nil {
			return err
		}
	}
	return nil
}

func (graph *materialGraph) inviteReference(material Material, id string) (Invite, error) {
	prior, found := graph.facts[id]
	value, ok := prior.Payload.(Invite)
	if !found || !ok || prior.Operation != "invite.issue" || !contains(material.Dependencies, id) || value.ID != material.TargetID && material.TargetKind == "invite" || value.IssuerControlID != material.IssuerControlID {
		return Invite{}, errors.New("operation has no matching issuer-owned Invite dependency")
	}
	return value, nil
}

func (graph *materialGraph) validateInvite(material Material, view Projection, history []string, invite Invite) error {
	if invite.GenesisDigest != graph.genesisID || invite.IssuerControlID != material.IssuerControlID {
		return errors.New("Invite is not bound to this genesis and issuer")
	}
	if _, found := view.CurrentTarget("invite", invite.ID); found {
		return errors.New("Invite transaction ID is immutable and cannot be reissued")
	}
	for _, id := range history {
		prior := graph.facts[id]
		if prior.TargetKind == "device" && prior.TargetID == invite.DeviceID {
			return errors.New("device identity has already been bound or deleted")
		}
	}
	existingMember := false
	for _, member := range view.Config.Members {
		if member.NodeID != invite.DeviceID {
			continue
		}
		if member.ControlID != material.IssuerControlID || !containsString(invite.Responsibilities, "control") {
			return errors.New("existing control identity requires its own first-binding Invite")
		}
		existingMember = true
	}
	if containsString(invite.Responsibilities, "control") && !existingMember {
		return ErrControlSuccessionUnsupported
	}
	for _, prior := range view.Invites {
		if prior.DeviceID != invite.DeviceID {
			continue
		}
		target, _ := view.CurrentTarget("invite", prior.ID)
		if !target.Deleted {
			return errors.New("device ID has another unterminated Invite")
		}
	}
	if err := requireTargetDependency(material, view, "endpoint", invite.Endpoint.ID, true); err != nil {
		return err
	}
	endpointFound := false
	for _, endpoint := range view.EndpointGenerations {
		if endpoint.ID == invite.Endpoint.ID && reflect.DeepEqual(endpoint, invite.Endpoint) {
			endpointFound = true
		}
	}
	if !endpointFound {
		return errors.New("Invite endpoint is not the authenticated current endpoint")
	}
	return validateAssignedPolicies(material, view, invite.PolicyIDs)
}

func (graph *materialGraph) validateBinding(material Material, view Projection, history []string, binding EnrollmentBind) error {
	for _, member := range view.Config.Members {
		if binding.DevicePublicKey == member.PublicKey {
			return errors.New("device identity must not reuse a control signing key")
		}
	}
	invite, err := graph.inviteReference(material, binding.InviteMaterialID)
	if err != nil {
		return err
	}
	target, found := view.CurrentTarget("invite", binding.TransactionID)
	if !found || target.Deleted || target.Conflicted || len(target.MaterialIDs) != 1 || target.MaterialIDs[0] != binding.InviteMaterialID {
		return errors.New("Invite has already bound or terminated")
	}
	for _, id := range history {
		prior := graph.facts[id]
		if device, ok := prior.Payload.(DeviceAuthorization); ok && (device.ID == invite.DeviceID || device.DevicePublicKey == binding.DevicePublicKey) {
			return errors.New("device identity is already bound")
		}
		if other, ok := prior.Payload.(EnrollmentBind); ok && other.DevicePublicKey == binding.DevicePublicKey && other.TransactionID != binding.TransactionID {
			return errors.New("device public key has another binding")
		}
	}
	return validateAssignedPolicies(material, view, invite.PolicyIDs)
}

func (graph *materialGraph) validateTermination(material Material, view Projection, history []string, termination EnrollmentTermination) error {
	invite, err := graph.inviteReference(material, termination.InviteMaterialID)
	if err != nil {
		return err
	}
	target, found := view.CurrentTarget("invite", termination.TransactionID)
	if !found || target.Deleted || target.Conflicted {
		return errors.New("Invite is already terminated or conflicted")
	}
	if termination.ExpiredAt != nil && *termination.ExpiredAt < invite.ExpiresAt {
		return errors.New("Invite expiration precedes its signed expiry")
	}
	for _, id := range history {
		if device, ok := graph.facts[id].Payload.(DeviceAuthorization); ok && device.TransactionID == termination.TransactionID {
			return errors.New("completed enrollment cannot be terminated")
		}
	}
	return nil
}

func (graph *materialGraph) validateDevice(material Material, view Projection, history []string, device DeviceAuthorization) error {
	var previous *DeviceAuthorization
	for _, id := range history {
		prior := graph.facts[id]
		if prior.TargetKind == "device" && prior.TargetID == device.ID && prior.Operation == "device.delete" {
			return errors.New("deleted device identity cannot be resurrected")
		}
		if value, ok := prior.Payload.(DeviceAuthorization); ok && value.ID == device.ID {
			if previous != nil && (previous.DevicePublicKey != value.DevicePublicKey || previous.RuntimeKey != value.RuntimeKey || previous.TransactionID != value.TransactionID || previous.InviteMaterialID != value.InviteMaterialID || previous.BindingMaterialID != value.BindingMaterialID || previous.Platform != value.Platform) {
				return errors.New("device causal history has conflicting identity bindings")
			}
			copy := value
			previous = &copy
		}
	}
	if material.Operation == "device.put" {
		if previous == nil {
			return errors.New("device update has no original authorization")
		}
		if previous.DevicePublicKey != device.DevicePublicKey || previous.RuntimeKey != device.RuntimeKey || previous.TransactionID != device.TransactionID || previous.InviteMaterialID != device.InviteMaterialID || previous.BindingMaterialID != device.BindingMaterialID || previous.Platform != device.Platform {
			return errors.New("device update changes immutable identity, key or enrollment binding")
		}
		return validateAssignedPolicies(material, view, device.PolicyIDs)
	}
	if previous != nil {
		return errors.New("device identity cannot join twice")
	}
	if len(device.DistributionURLs) != 0 {
		return errors.New("device.join distribution URLs must be empty")
	}
	bindingFact, found := graph.facts[device.BindingMaterialID]
	binding, ok := bindingFact.Payload.(EnrollmentBind)
	if !found || !ok || !contains(material.Dependencies, device.BindingMaterialID) || bindingFact.IssuerControlID != material.IssuerControlID || binding.TransactionID != device.TransactionID || binding.InviteMaterialID != device.InviteMaterialID || binding.DevicePublicKey != device.DevicePublicKey || binding.Platform != device.Platform {
		return errors.New("device.join has no matching issuer-owned binding dependency")
	}
	inviteFact, found := graph.facts[device.InviteMaterialID]
	invite, ok := inviteFact.Payload.(Invite)
	if !found || !ok || invite.IssuerControlID != material.IssuerControlID || invite.DeviceID != device.ID || invite.ID != device.TransactionID || invite.Name != device.Name {
		return errors.New("device.join does not match its Invite")
	}
	target, found := view.CurrentTarget("invite", invite.ID)
	if !found || target.Deleted || target.Conflicted || len(target.MaterialIDs) != 1 || target.MaterialIDs[0] != device.BindingMaterialID {
		return errors.New("device.join Invite is not currently bound")
	}
	expected := []string{}
	for _, role := range invite.Responsibilities {
		if role != "control" {
			expected = append(expected, role)
		}
	}
	if !reflect.DeepEqual(expected, device.Responsibilities) || !reflect.DeepEqual(invite.PolicyIDs, device.PolicyIDs) || !reflect.DeepEqual(invite.DNSServers, device.DNSServers) {
		return errors.New("device.join changes invited authorization")
	}
	if len(expected) == 0 {
		found := false
		for _, member := range view.Config.Members {
			if member.NodeID == device.ID && member.ControlID == material.IssuerControlID {
				found = true
			}
		}
		if !found {
			return errors.New("empty ordinary responsibilities require an existing control member")
		}
	}
	for _, prior := range view.DeviceAuthorizations {
		if prior.ID != device.ID && prior.DevicePublicKey == device.DevicePublicKey {
			return errors.New("device identity public key is already used")
		}
	}
	return validateAssignedPolicies(material, view, device.PolicyIDs)
}

func validateAssignedPolicies(material Material, view Projection, ids []string) error {
	policies := map[string]NetworkPolicy{}
	for _, value := range view.NetworkIntent.Policies {
		policies[value.ID] = value
	}
	services := map[string]Service{}
	for _, value := range view.NetworkIntent.Services {
		services[value.ID] = value
	}
	selected := []Service{}
	seen := map[string]bool{}
	for _, id := range ids {
		policy, found := policies[id]
		if !found {
			return errors.New("assigned Policy is unavailable")
		}
		if err := requireTargetDependency(material, view, "policy", id, true); err != nil {
			return err
		}
		service, found := services[policy.ServiceID]
		if !found || seen[service.ID] {
			return errors.New("assigned Policy has an unavailable or duplicated Service")
		}
		if err := requireTargetDependency(material, view, "service", service.ID, true); err != nil {
			return err
		}
		for _, other := range selected {
			if serviceTargetsOverlap(service, other) {
				return errors.New("assigned Services have ambiguous targets")
			}
		}
		seen[service.ID] = true
		selected = append(selected, service)
	}
	return nil
}

func serviceTargetsOverlap(left, right Service) bool {
	for _, a := range left.Matchers {
		for _, b := range right.Matchers {
			if a.Kind == "ip_prefix" || b.Kind == "ip_prefix" {
				if a.Kind != b.Kind {
					continue
				}
				x, _ := netip.ParsePrefix(a.Value)
				y, _ := netip.ParsePrefix(b.Value)
				if x.Contains(y.Addr()) || y.Contains(x.Addr()) {
					return true
				}
				continue
			}
			if a.Kind == "dns_exact" && b.Kind == "dns_exact" {
				if a.Value == b.Value {
					return true
				}
				continue
			}
			if a.Kind == "dns_exact" {
				if b.Matches(a.Value) {
					return true
				}
				continue
			}
			if b.Kind == "dns_exact" {
				if a.Matches(b.Value) {
					return true
				}
				continue
			}
			if a.Matches(b.Value) || b.Matches(a.Value) {
				return true
			}
		}
	}
	return false
}

// Transaction and device uniqueness are constraints across target IDs. These
// indexes are rebuilt from the same facts; they neither choose a winner nor
// create another identity registry.
func closeEnrollmentConflicts(projection *Projection) {
	activeInvites := map[string][]string{}
	for _, invite := range projection.Invites {
		state, found := projection.CurrentTarget("invite", invite.ID)
		if found && !state.Deleted {
			activeInvites[invite.DeviceID] = append(activeInvites[invite.DeviceID], invite.ID)
		}
	}
	conflict := func(kind, id string) {
		for i := range projection.Targets {
			if projection.Targets[i].TargetKind == kind && projection.Targets[i].TargetID == id {
				projection.Targets[i].Conflicted = true
			}
		}
	}
	for deviceID, invites := range activeInvites {
		if len(invites) > 1 {
			for _, id := range invites {
				conflict("invite", id)
			}
			conflict("device", deviceID)
		}
	}
	boundKeys := map[string][]string{}
	for _, binding := range projection.Bindings {
		boundKeys[binding.DevicePublicKey] = append(boundKeys[binding.DevicePublicKey], binding.TransactionID)
	}
	for _, transactions := range boundKeys {
		if len(transactions) > 1 {
			for _, id := range transactions {
				conflict("invite", id)
			}
		}
	}
	authorizedKeys := map[string][]string{}
	for _, device := range projection.DeviceAuthorizations {
		authorizedKeys[device.DevicePublicKey] = append(authorizedKeys[device.DevicePublicKey], device.ID)
	}
	for _, ids := range authorizedKeys {
		if len(ids) > 1 {
			for _, id := range ids {
				conflict("device", id)
			}
		}
	}
	kept := make([]DeviceAuthorization, 0, len(projection.DeviceAuthorizations))
	for _, device := range projection.DeviceAuthorizations {
		target, _ := projection.CurrentTarget("device", device.ID)
		invite, found := projection.CurrentTarget("invite", device.TransactionID)
		if !found || invite.Deleted || invite.Conflicted {
			conflict("device", device.ID)
			continue
		}
		if !target.Conflicted {
			kept = append(kept, device)
		}
	}
	projection.DeviceAuthorizations = kept
}

func (graph *materialGraph) validateEndpoint(material Material, view Projection, history []string, value EndpointGeneration) error {
	if value.State == "draining" || value.State == "retired" {
		for _, invite := range view.Invites {
			if invite.Endpoint.ID != value.ID || invite.Endpoint.Generation != value.Generation {
				continue
			}
			target, _ := view.CurrentTarget("invite", invite.ID)
			if target.Deleted {
				continue
			}
			completed := false
			for _, id := range history {
				if authorization, ok := graph.facts[id].Payload.(DeviceAuthorization); ok && authorization.TransactionID == invite.ID {
					completed = true
					break
				}
			}
			if !completed {
				return errors.New("endpoint generation still protects an unterminated enrollment")
			}
		}
	}

	if value.OwnerControlID != material.IssuerControlID {
		return errors.New("endpoint may be published only by its owning control")
	}
	highest := U64(0)
	var previous *EndpointGeneration
	previousID := ""
	for _, id := range history {
		old, ok := graph.facts[id].Payload.(EndpointGeneration)
		if !ok || old.ID != value.ID {
			continue
		}
		if old.OwnerControlID != value.OwnerControlID {
			return errors.New("endpoint cannot change its owning control")
		}
		if old.Generation > highest {
			highest = old.Generation
		}
		if old.Generation == value.Generation && (previous == nil || graph.ancestors[id][previousID]) {
			copy := old
			previous = &copy
			previousID = id
		}
	}
	if previous == nil {
		if value.Generation <= highest || value.State != "prepared" {
			return errors.New("new endpoint generation must advance and start prepared")
		}
		return nil
	}
	if value.Host != previous.Host || value.Port != previous.Port || value.ServerName != previous.ServerName || value.SPKISHA256 != previous.SPKISHA256 || value.CertificateDigest != previous.CertificateDigest || !reflect.DeepEqual(value.Modes, previous.Modes) {
		return errors.New("endpoint generation changes immutable coordinates")
	}
	stages := map[string]int{"prepared": 0, "serving": 1, "draining": 2, "retired": 3}
	before, after := stages[previous.State], stages[value.State]
	if after < before || after > before+1 {
		return errors.New("endpoint phase transition is not forward by one stage")
	}
	if before == 2 && after == 2 && value.DrainUntil != previous.DrainUntil {
		return errors.New("draining deadline cannot be extended or rewritten")
	}
	return nil
}

func (graph *materialGraph) projectEndpointGenerations(projection *Projection, ids []string) {
	type coordinate struct {
		id         string
		generation U64
	}
	selected := map[coordinate]string{}
	for _, id := range ids {
		value, ok := graph.facts[id].Payload.(EndpointGeneration)
		if !ok {
			continue
		}
		target, found := projection.CurrentTarget("endpoint", value.ID)
		if !found || target.Conflicted || target.Deleted {
			continue
		}
		key := coordinate{value.ID, value.Generation}
		prior, found := selected[key]
		if !found || graph.ancestors[id][prior] {
			selected[key] = id
		}
	}
	for _, id := range selected {
		projection.EndpointGenerations = append(projection.EndpointGenerations, graph.facts[id].Payload.(EndpointGeneration))
	}
	sort.Slice(projection.EndpointGenerations, func(i, j int) bool {
		left, right := projection.EndpointGenerations[i], projection.EndpointGenerations[j]
		return left.ID < right.ID || left.ID == right.ID && left.Generation < right.Generation
	})
}
