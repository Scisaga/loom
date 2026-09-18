package control

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"time"

	"loom/internal/clientmodel"
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

type Observation = clientmodel.Observation

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
