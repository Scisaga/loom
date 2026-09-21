package control

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/netip"
	"sort"
	"time"

	"loom/internal/clientmodel"
)

const (
	claimDomain    = "loom-enrollment-claim-v1\n"
	claimDomainV2  = "loom-enrollment-claim-v2\n"
	resumeDomain   = "loom-enrollment-resume-v1\n"
	resumeDomainV2 = "loom-enrollment-resume-v2\n"
	reportDomain   = "loom-device-report-v1\n"
	reportDomainV2 = "loom-device-report-v2\n"
)

type EnrollmentClaimRequest struct {
	Schema          int                 `json:"schema"`
	Capability      BootstrapCapability `json:"capability"`
	RequestID       string              `json:"request_id"`
	DevicePublicKey string              `json:"device_public_key"`
	Server          *ServerClaimV2      `json:"server,omitempty"`
	Signature       string              `json:"signature"`
}

type EnrollmentResumeRequest struct {
	Schema          int    `json:"schema"`
	TransactionID   string `json:"transaction_id"`
	RequestID       string `json:"request_id"`
	DevicePublicKey string `json:"device_public_key"`
	Signature       string `json:"signature"`
}

type EnrollmentResponse struct {
	Schema      int                   `json:"schema"`
	Transaction EnrollmentTransaction `json:"transaction"`
	DeviceView  *DeviceViewEnvelope   `json:"device_view,omitempty"`
}

type Observation = clientmodel.Observation

type DeviceReport struct {
	Schema       int                 `json:"schema"`
	DeviceID     string              `json:"device_id"`
	ViewDigest   string              `json:"view_digest"`
	Selection    string              `json:"selection,omitempty"`
	ReportedAt   string              `json:"reported_at"`
	Observations []Observation       `json:"observations"`
	Signature    string              `json:"signature"`
	Selections   []ReportSelection   `json:"selections,omitempty"`
	Runtime      *RuntimeReadback    `json:"runtime,omitempty"`
	Components   []ComponentReadback `json:"components,omitempty"`
	Links        []LinkReadback      `json:"links,omitempty"`
	Deployment   *DeploymentReadback `json:"deployment,omitempty"`
}

type ReportSelection struct {
	Scope       string `json:"scope"`
	CandidateID string `json:"candidate_id"`
}

type RuntimeReadback struct {
	State             string `json:"state"`
	AppliedViewDigest string `json:"applied_view_digest"`
	Exact             bool   `json:"exact"`
	StartedAt         string `json:"started_at,omitempty"`
	ErrorCode         string `json:"error_code,omitempty"`
}

type ComponentReadback struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Digest  string `json:"digest,omitempty"`
}

type LinkReadback struct {
	LinkID            string `json:"link_id"`
	Peer              string `json:"peer"`
	Interface         string `json:"interface"`
	Epoch             string `json:"epoch"`
	ProbeTarget       string `json:"probe_target"`
	Result            string `json:"result"`
	LatencyMS         int64  `json:"latency_ms,omitempty"`
	LatestHandshakeAt string `json:"latest_handshake_at,omitempty"`
	TXBytes           uint64 `json:"tx_bytes"`
	RXBytes           uint64 `json:"rx_bytes"`
}

type DeploymentReadback struct {
	Generation       uint64 `json:"generation"`
	PayloadSHA256    string `json:"payload_sha256"`
	SelectedSnapshot string `json:"selected_snapshot"`
	AppliedSnapshot  string `json:"applied_snapshot"`
	Version          string `json:"version"`
	RolloutVerified  bool   `json:"rollout_verified"`
}

func signedBytes(domain string, value any) ([]byte, error) {
	body, err := canonical(value)
	if err != nil {
		return nil, err
	}
	return append([]byte(domain), body...), nil
}

func (request EnrollmentClaimRequest) signingBytes() ([]byte, error) {
	copy := request
	copy.Signature = ""
	domain := claimDomain
	if request.Schema == enrollmentSchemaV2 {
		domain = claimDomainV2
	}
	return signedBytes(domain, copy)
}

func SignEnrollmentClaim(request EnrollmentClaimRequest, private ed25519.PrivateKey) (EnrollmentClaimRequest, error) {
	request.Signature = ""
	if err := request.validate(false); err != nil {
		return request, err
	}
	body, err := request.signingBytes()
	if err != nil {
		return request, err
	}
	request.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, body))
	return request, request.Validate()
}

func (request EnrollmentClaimRequest) validate(requireSignature bool) error {
	if request.Schema != enrollmentSchema && request.Schema != enrollmentSchemaV2 || request.Capability.Validate() != nil ||
		!validName(request.RequestID) || !validRawKey(request.DevicePublicKey) {
		return errors.New("enrollment claim is invalid")
	}
	if request.Schema == enrollmentSchema && request.Server != nil {
		return errors.New("legacy enrollment claim cannot carry schema-2 server facts")
	}
	if request.Server != nil && request.Server.Validate() != nil {
		return errors.New("enrollment server claim is invalid")
	}
	if requireSignature {
		key, _ := base64.RawURLEncoding.DecodeString(request.DevicePublicKey)
		signature, err := base64.RawURLEncoding.DecodeString(request.Signature)
		body, bodyErr := request.signingBytes()
		if err != nil || bodyErr != nil || !ed25519.Verify(key, body, signature) {
			return errors.New("enrollment claim signature is invalid")
		}
	}
	return nil
}

func (request EnrollmentClaimRequest) Validate() error { return request.validate(true) }

func (request EnrollmentResumeRequest) signingBytes() ([]byte, error) {
	copy := request
	copy.Signature = ""
	domain := resumeDomain
	if request.Schema == enrollmentSchemaV2 {
		domain = resumeDomainV2
	}
	return signedBytes(domain, copy)
}

func SignEnrollmentResume(request EnrollmentResumeRequest, private ed25519.PrivateKey) (EnrollmentResumeRequest, error) {
	request.Signature = ""
	if err := request.validate(false); err != nil {
		return request, err
	}
	body, err := request.signingBytes()
	if err != nil {
		return request, err
	}
	request.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, body))
	return request, request.Validate()
}

func (request EnrollmentResumeRequest) validate(requireSignature bool) error {
	if request.Schema != enrollmentSchema && request.Schema != enrollmentSchemaV2 || !validName(request.TransactionID) ||
		!validName(request.RequestID) || !validRawKey(request.DevicePublicKey) {
		return errors.New("enrollment resume is invalid")
	}
	if requireSignature {
		key, _ := base64.RawURLEncoding.DecodeString(request.DevicePublicKey)
		signature, err := base64.RawURLEncoding.DecodeString(request.Signature)
		body, bodyErr := request.signingBytes()
		if err != nil || bodyErr != nil || !ed25519.Verify(key, body, signature) {
			return errors.New("enrollment resume signature is invalid")
		}
	}
	return nil
}

func (request EnrollmentResumeRequest) Validate() error { return request.validate(true) }

func (report DeviceReport) signingBytes() ([]byte, error) {
	copy := report
	copy.Signature = ""
	domain := reportDomain
	if report.Schema == enrollmentSchemaV2 {
		domain = reportDomainV2
	}
	return signedBytes(domain, copy)
}

func SignDeviceReport(report DeviceReport, private ed25519.PrivateKey) (DeviceReport, error) {
	report.Signature = ""
	if err := report.validate(false, ""); err != nil {
		return report, err
	}
	body, err := report.signingBytes()
	if err != nil {
		return report, err
	}
	report.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, body))
	return report, nil
}

func (report DeviceReport) validate(requireSignature bool, publicKey string) error {
	if report.Schema != enrollmentSchema && report.Schema != enrollmentSchemaV2 || !validName(report.DeviceID) || !validDigest(report.ViewDigest) {
		return errors.New("device report is incomplete")
	}
	if _, err := time.Parse(time.RFC3339, report.ReportedAt); err != nil {
		return errors.New("device report time is invalid")
	}
	if report.Selection != "" && !validName(report.Selection) {
		return errors.New("device report selection is invalid")
	}
	if report.Schema == enrollmentSchemaV2 {
		if report.Selection != "" || report.Runtime == nil {
			return errors.New("schema-2 device report contains legacy selection or no runtime readback")
		}
		for index, selection := range report.Selections {
			if !validName(selection.Scope) || !validName(selection.CandidateID) ||
				index > 0 && report.Selections[index-1].Scope >= selection.Scope {
				return errors.New("device report selections are not uniquely sorted")
			}
		}
		if report.Runtime.AppliedViewDigest != report.ViewDigest {
			return errors.New("device runtime readback does not cover report view")
		}
		switch report.Runtime.State {
		case "running", "stopped", "error":
		default:
			return errors.New("device runtime state is invalid")
		}
		if report.Runtime.StartedAt != "" {
			started, err := time.Parse(time.RFC3339, report.Runtime.StartedAt)
			if err != nil || started.UTC().Format(time.RFC3339) != report.Runtime.StartedAt {
				return errors.New("device runtime start time is invalid")
			}
		}
		if report.Runtime.ErrorCode != "" && !validName(report.Runtime.ErrorCode) {
			return errors.New("device runtime error code is invalid")
		}
		if report.Runtime.State != "error" && report.Runtime.ErrorCode != "" {
			return errors.New("device runtime error is inconsistent")
		}
		if err := validateComponentReadbacks(report.Components); err != nil {
			return err
		}
		for index, link := range report.Links {
			probe, probeErr := netip.ParseAddr(link.ProbeTarget)
			if !validName(link.LinkID) || !validName(link.Peer) || !validName(link.Interface) || !validName(link.Epoch) ||
				probeErr != nil || probe.String() != link.ProbeTarget || link.LatencyMS < 0 || index > 0 && report.Links[index-1].LinkID >= link.LinkID {
				return errors.New("device link readbacks are not uniquely sorted")
			}
			if link.LatestHandshakeAt != "" {
				handshake, err := time.Parse(time.RFC3339, link.LatestHandshakeAt)
				if err != nil || handshake.UTC().Format(time.RFC3339) != link.LatestHandshakeAt {
					return errors.New("device link handshake time is invalid")
				}
			}
			switch link.Result {
			case "available", "unavailable", "unknown":
			default:
				return errors.New("device link result is invalid")
			}
		}
		if report.Deployment != nil {
			deployment := report.Deployment
			if deployment.Generation == 0 || !validLowerHex(deployment.PayloadSHA256, sha256.Size) ||
				!validLowerHex(deployment.SelectedSnapshot, 6) || !validLowerHex(deployment.AppliedSnapshot, 6) ||
				!validName(deployment.Version) {
				return errors.New("device deployment readback is invalid")
			}
		}
	} else if len(report.Selections) != 0 || report.Runtime != nil || len(report.Components) != 0 || len(report.Links) != 0 || report.Deployment != nil {
		return errors.New("schema-1 device report contains schema-2 fields")
	}
	for index, observation := range report.Observations {
		if observation.Validate() != nil || index > 0 && report.Observations[index-1].CandidateID >= observation.CandidateID {
			return errors.New("device report observations are not uniquely sorted")
		}
	}
	if requireSignature {
		if !validRawKey(publicKey) {
			return errors.New("device report key is invalid")
		}
		key, _ := base64.RawURLEncoding.DecodeString(publicKey)
		signature, err := base64.RawURLEncoding.DecodeString(report.Signature)
		body, bodyErr := report.signingBytes()
		if err != nil || bodyErr != nil || !ed25519.Verify(key, body, signature) {
			return errors.New("device report signature is invalid")
		}
	}
	return nil
}

func validateComponentReadbacks(values []ComponentReadback) error {
	if !sort.SliceIsSorted(values, func(i, j int) bool { return values[i].Name < values[j].Name }) {
		return errors.New("device component readbacks are not sorted")
	}
	for index, component := range values {
		if !validName(component.Name) || !validName(component.Version) || index > 0 && values[index-1].Name == component.Name ||
			component.Digest != "" && !validDigest(component.Digest) {
			return errors.New("device component readbacks are invalid")
		}
	}
	return nil
}

func (report DeviceReport) Verify(publicKey string) error { return report.validate(true, publicKey) }

func SelectRoute(routes []RouteCandidate, observations []Observation, finalExit, current string, now time.Time) (string, error) {
	preference := clientmodel.Preference{Schema: 1, Mode: clientmodel.ModeAuto}
	if finalExit == "direct" {
		preference.Mode = clientmodel.ModeDirect
	} else if finalExit != "" && finalExit != "auto" {
		preference.Mode, preference.Exit = clientmodel.ModeFixed, finalExit
	}
	generation := "unknown"
	if len(observations) > 0 {
		generation = observations[0].NetworkGeneration
	}
	selection, err := clientmodel.Select(routes, observations, preference, current, generation, now)
	return selection.CandidateID, err
}
