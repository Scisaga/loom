package control

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

const (
	claimDomain  = "loom-claim-v3\x00"
	resumeDomain = "loom-resume-v3\x00"
	reportDomain = "loom-report-v3\x00"
)

type EnrollmentClaimRequest struct {
	Schema           int    `json:"schema"`
	NetworkID        string `json:"network_id"`
	GenesisDigest    string `json:"genesis_digest"`
	TransactionID    string `json:"transaction_id"`
	InviteMaterialID string `json:"invite_material_id"`
	RequestID        string `json:"request_id"`
	DevicePublicKey  string `json:"device_public_key"`
	Platform         string `json:"platform"`
	Signature        string `json:"signature"`
}

type EnrollmentResumeRequest EnrollmentClaimRequest

func (request EnrollmentClaimRequest) unsigned() map[string]any {
	return map[string]any{"schema": request.Schema, "network_id": request.NetworkID, "genesis_digest": request.GenesisDigest,
		"transaction_id": request.TransactionID, "invite_material_id": request.InviteMaterialID, "request_id": request.RequestID,
		"device_public_key": request.DevicePublicKey, "platform": request.Platform}
}

func (request EnrollmentClaimRequest) validateFields() error {
	if request.Schema != 3 || ValidateID(request.NetworkID) != nil || ValidateDigest(request.GenesisDigest) != nil ||
		ValidateID(request.TransactionID) != nil || ValidateDigest(request.InviteMaterialID) != nil || ValidateID(request.RequestID) != nil ||
		ValidatePublicKey(request.DevicePublicKey) != nil || !validatePlatform(request.Platform) {
		return errors.New("enrollment request is invalid")
	}
	return nil
}

func signedContractBytes(domain string, value any) ([]byte, error) {
	body, err := CanonicalEncode(value)
	if err != nil {
		return nil, err
	}
	return append([]byte(domain), body...), nil
}

func verifyContractSignature(domain string, value any, encodedSignature, encodedKey string) error {
	key, err := base64.RawURLEncoding.DecodeString(encodedKey)
	if err != nil || len(key) != ed25519.PublicKeySize || base64.RawURLEncoding.EncodeToString(key) != encodedKey {
		return errors.New("signature public key is invalid")
	}
	signature, err := base64.RawURLEncoding.DecodeString(encodedSignature)
	if err != nil || len(signature) != ed25519.SignatureSize || base64.RawURLEncoding.EncodeToString(signature) != encodedSignature {
		return errors.New("signature is not canonical")
	}
	message, err := signedContractBytes(domain, value)
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(key), message, signature) {
		return errors.New("signature does not verify")
	}
	return nil
}

func (request EnrollmentClaimRequest) Validate() error {
	if err := request.validateFields(); err != nil {
		return err
	}
	return verifyContractSignature(claimDomain, request.unsigned(), request.Signature, request.DevicePublicKey)
}
func (request EnrollmentResumeRequest) Validate() error {
	value := EnrollmentClaimRequest(request)
	if err := value.validateFields(); err != nil {
		return err
	}
	return verifyContractSignature(resumeDomain, value.unsigned(), value.Signature, value.DevicePublicKey)
}

func SignEnrollmentClaim(request EnrollmentClaimRequest, private ed25519.PrivateKey) (EnrollmentClaimRequest, error) {
	if len(private) != ed25519.PrivateKeySize {
		return EnrollmentClaimRequest{}, errors.New("claim signing key is invalid")
	}
	if err := request.validateFields(); err != nil {
		return EnrollmentClaimRequest{}, err
	}
	message, err := signedContractBytes(claimDomain, request.unsigned())
	if err != nil {
		return EnrollmentClaimRequest{}, err
	}
	request.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, message))
	if err := request.Validate(); err != nil {
		return EnrollmentClaimRequest{}, err
	}
	return request, nil
}
func SignEnrollmentResume(request EnrollmentResumeRequest, private ed25519.PrivateKey) (EnrollmentResumeRequest, error) {
	if len(private) != ed25519.PrivateKeySize {
		return EnrollmentResumeRequest{}, errors.New("resume signing key is invalid")
	}
	value := EnrollmentClaimRequest(request)
	if err := value.validateFields(); err != nil {
		return EnrollmentResumeRequest{}, err
	}
	message, err := signedContractBytes(resumeDomain, value.unsigned())
	if err != nil {
		return EnrollmentResumeRequest{}, err
	}
	request.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, message))
	if err := request.Validate(); err != nil {
		return EnrollmentResumeRequest{}, err
	}
	return request, nil
}

type EnrollmentResponse struct {
	Schema        int                 `json:"schema"`
	TransactionID string              `json:"transaction_id"`
	State         string              `json:"state"`
	DeviceView    *DeviceViewEnvelope `json:"device_view,omitempty"`
}

func (response EnrollmentResponse) Validate() error {
	if response.Schema != 3 || ValidateID(response.TransactionID) != nil {
		return errors.New("enrollment response is invalid")
	}
	switch response.State {
	case "open", "bound", "completed", "cancelled", "expired":
	default:
		return errors.New("enrollment response state is invalid")
	}
	if (response.State == "completed") != (response.DeviceView != nil) {
		return errors.New("enrollment response view does not match completion")
	}
	if response.DeviceView != nil {
		return response.DeviceView.Validate()
	}
	return nil
}

type ReportSelection struct {
	ServiceID   string `json:"service_id"`
	CandidateID string `json:"candidate_id"`
}
type RuntimeReadback struct {
	State             string              `json:"state"`
	AppliedViewDigest string              `json:"applied_view_digest"`
	ErrorCode         string              `json:"error_code"`
	Resources         *[]ResourceReadback `json:"resources,omitempty"`
}

type ResourceReadback struct {
	ResourceID        string `json:"resource_id"`
	ListenerID        string `json:"listener_id"`
	Listen            string `json:"listen"`
	CertificateDigest string `json:"certificate_digest"`
	ACLDigest         string `json:"acl_digest"`
}

func (value ResourceReadback) Validate() error {
	host, port, err := net.SplitHostPort(value.Listen)
	ip, ipErr := netip.ParseAddr(host)
	number, numberErr := strconv.Atoi(port)
	if ValidateID(value.ResourceID) != nil || ValidateID(value.ListenerID) != nil || ValidateDigest(value.CertificateDigest) != nil || ValidateDigest(value.ACLDigest) != nil ||
		err != nil || ipErr != nil || ip.Zone() != "" || ip.String() != host || numberErr != nil || number < 1 || number > 65535 || net.JoinHostPort(host, strconv.Itoa(number)) != value.Listen {
		return errors.New("resource execution readback is invalid")
	}
	return nil
}

type ComponentReadback struct {
	ComponentID    string `json:"component_id"`
	Platform       string `json:"platform"`
	Version        string `json:"version"`
	ArtifactDigest string `json:"artifact_digest"`
}

func (component ComponentReadback) Validate() error {
	if ValidateID(component.ComponentID) != nil || ValidateText(component.Platform) != nil || ValidateText(component.Version) != nil || ValidateDigest(component.ArtifactDigest) != nil {
		return errors.New("component readback is invalid")
	}
	return nil
}

func (runtime RuntimeReadback) Validate() error {
	switch runtime.State {
	case "running", "error", "stopped", "unknown":
	default:
		return errors.New("runtime readback state is invalid")
	}
	if runtime.AppliedViewDigest != "" && ValidateDigest(runtime.AppliedViewDigest) != nil || runtime.ErrorCode != "" && ValidateID(runtime.ErrorCode) != nil {
		return errors.New("runtime readback value is invalid")
	}
	if runtime.State == "running" && (runtime.AppliedViewDigest == "" || runtime.ErrorCode != "") {
		return errors.New("running readback requires an applied digest and no error")
	}
	if runtime.Resources != nil {
		if runtime.State != "running" || len(*runtime.Resources) == 0 {
			return errors.New("resource readback requires actual running resources")
		}
		for index, value := range *runtime.Resources {
			if value.Validate() != nil || index > 0 && (*runtime.Resources)[index-1].ResourceID >= value.ResourceID {
				return errors.New("resource readbacks are invalid or not uniquely sorted")
			}
		}
	}
	return nil
}

type Observation struct {
	Level             string `json:"level"`
	ServiceID         string `json:"service_id"`
	CandidateID       string `json:"candidate_id"`
	ResourceID        string `json:"resource_id"`
	LinkID            string `json:"link_id"`
	Target            string `json:"target"`
	Action            string `json:"action"`
	SpecDigest        string `json:"spec_digest"`
	NetworkGeneration string `json:"network_generation"`
	Result            string `json:"result"`
	ObservedAt        int64  `json:"observed_at"`
	ValidUntil        int64  `json:"valid_until"`
	DurationMS        *int64 `json:"duration_ms,omitempty"`
}

func (observation Observation) Validate() error {
	if ValidateDigest(observation.SpecDigest) != nil || ValidateID(observation.NetworkGeneration) != nil || !validateTime(observation.ObservedAt) || !validateTime(observation.ValidUntil) || observation.ObservedAt >= observation.ValidUntil || observation.DurationMS != nil && *observation.DurationMS < 0 {
		return errors.New("observation identity or time is invalid")
	}
	switch observation.Result {
	case "available", "unavailable", "unknown":
	default:
		return errors.New("observation result is invalid")
	}
	switch observation.Level {
	case "service":
		if ValidateID(observation.ServiceID) != nil || ValidateDigest(observation.CandidateID) != nil || observation.ResourceID != "" || observation.LinkID != "" || observation.Action != "https_request" || ValidateHTTPSURL(observation.Target) != nil {
			return errors.New("service observation is invalid")
		}
	case "link":
		target, err := netip.ParseAddrPort(observation.Target)
		if ValidateID(observation.LinkID) != nil || ValidateID(observation.ResourceID) != nil || observation.ServiceID != "" || observation.CandidateID != "" ||
			observation.Action != "hysteria2_tls" || err != nil || target.Port() == 0 || target.String() != observation.Target || !target.Addr().IsGlobalUnicast() || target.Addr().Zone() != "" {
			return errors.New("Link observation is invalid")
		}
	case "resource":
		host, port, err := net.SplitHostPort(observation.Target)
		number, portErr := strconv.Atoi(port)
		if ValidateID(observation.ResourceID) != nil || observation.ServiceID != "" || observation.CandidateID != "" || observation.LinkID != "" ||
			observation.Action != "hysteria2_tls" || err != nil || !contractHost(host) || portErr != nil || number < 1 || number > 65535 ||
			net.JoinHostPort(host, strconv.Itoa(number)) != observation.Target {
			return errors.New("resource observation is invalid")
		}
	default:
		return errors.New("observation level is invalid")
	}
	return nil
}

func observationOrder(value Observation) string {
	return strings.Join([]string{value.NetworkGeneration, value.Level, value.ServiceID, value.CandidateID, value.ResourceID, value.LinkID, value.Target, value.Action, value.SpecDigest}, "\x00")
}

type DeviceReport struct {
	Schema            int                 `json:"schema"`
	NetworkID         string              `json:"network_id"`
	DeviceID          string              `json:"device_id"`
	ReportSequence    U64                 `json:"report_sequence"`
	ViewDigest        string              `json:"view_digest"`
	NetworkGeneration string              `json:"network_generation"`
	ReportedAt        int64               `json:"reported_at"`
	Selections        []ReportSelection   `json:"selections"`
	Observations      []Observation       `json:"observations"`
	Runtime           RuntimeReadback     `json:"runtime"`
	Components        []ComponentReadback `json:"components"`
	Signature         string              `json:"signature"`
}

func (report DeviceReport) unsigned() map[string]any {
	return map[string]any{"schema": report.Schema, "network_id": report.NetworkID, "device_id": report.DeviceID, "report_sequence": report.ReportSequence, "view_digest": report.ViewDigest, "network_generation": report.NetworkGeneration, "reported_at": report.ReportedAt, "selections": report.Selections, "observations": report.Observations, "runtime": report.Runtime, "components": report.Components}
}

func (report DeviceReport) validateFields() error {
	if report.Schema != 3 || ValidateID(report.NetworkID) != nil || ValidateID(report.DeviceID) != nil || report.DeviceID == "direct" || report.ReportSequence == 0 || ValidateDigest(report.ViewDigest) != nil || ValidateID(report.NetworkGeneration) != nil || !validateTime(report.ReportedAt) || report.Selections == nil || report.Observations == nil || report.Components == nil || report.Runtime.Validate() != nil {
		return errors.New("device report is invalid")
	}
	for index, selection := range report.Selections {
		if ValidateID(selection.ServiceID) != nil || ValidateDigest(selection.CandidateID) != nil || index > 0 && report.Selections[index-1].ServiceID >= selection.ServiceID {
			return errors.New("report selections are invalid or not uniquely sorted")
		}
	}
	for index, observation := range report.Observations {
		if observation.Validate() != nil || observation.NetworkGeneration != report.NetworkGeneration || index > 0 && observationOrder(report.Observations[index-1]) >= observationOrder(observation) {
			return errors.New("report observations are invalid or not uniquely sorted")
		}
	}
	for index, component := range report.Components {
		if component.Validate() != nil {
			return errors.New("report component is invalid")
		}
		if index > 0 {
			previous := report.Components[index-1]
			if previous.ComponentID > component.ComponentID || previous.ComponentID == component.ComponentID && previous.Platform >= component.Platform {
				return errors.New("report components are not uniquely sorted")
			}
		}
	}
	return nil
}

func (report DeviceReport) Validate() error {
	if err := report.validateFields(); err != nil {
		return err
	}
	signature, err := base64.RawURLEncoding.DecodeString(report.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || base64.RawURLEncoding.EncodeToString(signature) != report.Signature {
		return errors.New("report signature is not canonical")
	}
	return nil
}
func (report DeviceReport) Verify(publicKey string) error {
	if err := report.Validate(); err != nil {
		return err
	}
	return verifyContractSignature(reportDomain, report.unsigned(), report.Signature, publicKey)
}
func SignDeviceReport(report DeviceReport, private ed25519.PrivateKey) (DeviceReport, error) {
	if len(private) != ed25519.PrivateKeySize {
		return DeviceReport{}, errors.New("report signing key is invalid")
	}
	if err := report.validateFields(); err != nil {
		return DeviceReport{}, err
	}
	message, err := signedContractBytes(reportDomain, report.unsigned())
	if err != nil {
		return DeviceReport{}, err
	}
	report.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, message))
	return report, nil
}

type DeviceReportResponse struct {
	Schema         int    `json:"schema"`
	ReportSequence U64    `json:"report_sequence"`
	Status         string `json:"status"`
}

func (response DeviceReportResponse) Validate() error {
	if response.Schema != 3 || response.ReportSequence == 0 || response.Status != "accepted" {
		return errors.New("report response is invalid")
	}
	return nil
}
