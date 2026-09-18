package control

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"sort"
	"time"
)

const (
	claimDomain  = "loom-enrollment-claim-v1\n"
	resumeDomain = "loom-enrollment-resume-v1\n"
	reportDomain = "loom-device-report-v1\n"
)

type EnrollmentClaimRequest struct {
	Schema          int                 `json:"schema"`
	Capability      BootstrapCapability `json:"capability"`
	RequestID       string              `json:"request_id"`
	DevicePublicKey string              `json:"device_public_key"`
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

type Observation struct {
	CandidateID       string `json:"candidate_id"`
	NetworkGeneration string `json:"network_generation"`
	Scope             string `json:"scope"`
	Result            string `json:"result"`
	Action            string `json:"action"`
	ObservedAt        string `json:"observed_at"`
	ValidUntil        string `json:"valid_until"`
	MetricMillis      int64  `json:"metric_millis,omitempty"`
}

type DeviceReport struct {
	Schema       int           `json:"schema"`
	DeviceID     string        `json:"device_id"`
	ViewDigest   string        `json:"view_digest"`
	Selection    string        `json:"selection,omitempty"`
	ReportedAt   string        `json:"reported_at"`
	Observations []Observation `json:"observations"`
	Signature    string        `json:"signature"`
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
	return signedBytes(claimDomain, copy)
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
	if request.Schema != enrollmentSchema || request.Capability.Validate() != nil || !validName(request.RequestID) || !validRawKey(request.DevicePublicKey) {
		return errors.New("enrollment claim is invalid")
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
	return signedBytes(resumeDomain, copy)
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
	if request.Schema != enrollmentSchema || !validName(request.TransactionID) || !validName(request.RequestID) || !validRawKey(request.DevicePublicKey) {
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

func (observation Observation) Validate() error {
	if !validName(observation.CandidateID) || !validName(observation.NetworkGeneration) || !validName(observation.Scope) ||
		!validName(observation.Action) || observation.MetricMillis < 0 {
		return errors.New("device observation is incomplete")
	}
	switch observation.Result {
	case "available", "unavailable", "unknown":
	default:
		return errors.New("device observation result is invalid")
	}
	observed, err := time.Parse(time.RFC3339, observation.ObservedAt)
	if err != nil {
		return errors.New("device observation time is invalid")
	}
	until, err := time.Parse(time.RFC3339, observation.ValidUntil)
	if err != nil || !until.After(observed) {
		return errors.New("device observation validity is invalid")
	}
	return nil
}

func (report DeviceReport) signingBytes() ([]byte, error) {
	copy := report
	copy.Signature = ""
	return signedBytes(reportDomain, copy)
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
	if report.Schema != enrollmentSchema || !validName(report.DeviceID) || !validDigest(report.ViewDigest) {
		return errors.New("device report is incomplete")
	}
	if _, err := time.Parse(time.RFC3339, report.ReportedAt); err != nil {
		return errors.New("device report time is invalid")
	}
	if report.Selection != "" && !validName(report.Selection) {
		return errors.New("device report selection is invalid")
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

func (report DeviceReport) Verify(publicKey string) error { return report.validate(true, publicKey) }

func SelectRoute(routes []RouteCandidate, observations []Observation, finalExit, current string, now time.Time) (string, error) {
	byID := map[string]Observation{}
	for _, observation := range observations {
		if err := observation.Validate(); err != nil {
			return "", err
		}
		until, _ := time.Parse(time.RFC3339, observation.ValidUntil)
		if now.Before(until) {
			byID[observation.CandidateID] = observation
		}
	}
	allowed := make([]RouteCandidate, 0, len(routes))
	for _, route := range routes {
		if err := route.Validate(); err != nil {
			return "", err
		}
		if finalExit == "direct" && len(route.Chain) != 0 || finalExit != "" && finalExit != "auto" && finalExit != "direct" && route.FinalExit != finalExit {
			continue
		}
		if observation, found := byID[route.ID]; found && observation.Result == "unavailable" {
			continue
		}
		allowed = append(allowed, route)
	}
	if len(allowed) == 0 {
		return "", errors.New("no authorized route candidate is usable")
	}
	rank := func(candidate RouteCandidate) int {
		if observation, found := byID[candidate.ID]; found && observation.Result == "available" {
			return 0
		}
		return 1
	}
	sort.SliceStable(allowed, func(i, j int) bool {
		left, right := rank(allowed[i]), rank(allowed[j])
		if left != right {
			return left < right
		}
		if allowed[i].ID == current {
			return true
		}
		if allowed[j].ID == current {
			return false
		}
		return allowed[i].ID < allowed[j].ID
	})
	return allowed[0].ID, nil
}
