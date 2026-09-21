//go:build !windows

package publish

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"

	"loom/internal/version"
)

const (
	PublisherObservationSchema = 2
	publisherObservationDomain = "loom-publisher-observation-v2\x00"

	PublisherErrorPublishFailed        = "publish_failed"
	PublisherErrorDistributionFailed   = "distribution_failed"
	PublisherErrorAuthorityUnavailable = "authority_unavailable"
	PublisherErrorVerifyFailed         = "verify_failed"
)

// PublisherDistributionCheck is the Web/control-safe subset of a local
// distribution diagnostic.  Health may retain a detailed operator error on
// the publisher host; signed observations expose only a finite code.
type PublisherDistributionCheck struct {
	URL          string `json:"url"`
	Snapshot     string `json:"snapshot"`
	SourceDigest string `json:"source_digest"`
	CheckedAt    string `json:"checked_at"`
	Success      bool   `json:"success"`
	ErrorCode    string `json:"error_code,omitempty"`
}

// PublisherObservation authenticates publisher liveness and distribution
// evidence. DeploymentCurrent remains the only desired deployment pointer;
// this value can prove what the publisher observed but can never replace it.
type PublisherObservation struct {
	Schema             int                          `json:"schema"`
	Current            DeploymentCurrent            `json:"current"`
	ObservedAt         string                       `json:"observed_at"`
	IntervalSeconds    int64                        `json:"interval_seconds"`
	Version            version.Coordinate           `json:"version"`
	Success            bool                         `json:"success"`
	ErrorCode          string                       `json:"error_code,omitempty"`
	DistributionChecks []PublisherDistributionCheck `json:"distribution_checks"`
	Signature          string                       `json:"signature"`
}

func (observation PublisherObservation) signingBytes() ([]byte, error) {
	copy := observation
	copy.Signature = ""
	body, err := json.Marshal(copy)
	if err != nil {
		return nil, err
	}
	return append([]byte(publisherObservationDomain), body...), nil
}

func (observation PublisherObservation) validate(requireSignature bool) error {
	if observation.Schema != PublisherObservationSchema || observation.Current.validate(true) != nil ||
		observation.IntervalSeconds < 1 || observation.Version.Commit == "" || observation.Version.Platform == "" {
		return errors.New("publisher observation is incomplete")
	}
	if !sort.SliceIsSorted(observation.Current.Assignments, func(i, j int) bool {
		return observation.Current.Assignments[i].Node < observation.Current.Assignments[j].Node
	}) {
		return errors.New("publisher deployment assignments are not sorted")
	}
	observed, err := time.Parse(time.RFC3339Nano, observation.ObservedAt)
	if err != nil || observed.UTC().Format(time.RFC3339Nano) != observation.ObservedAt {
		return errors.New("publisher observation time is invalid")
	}
	if observation.Success == (observation.ErrorCode != "") || !validPublisherErrorCode(observation.ErrorCode, true) {
		return errors.New("publisher observation result is inconsistent")
	}
	for index, check := range observation.DistributionChecks {
		checked, parseErr := time.Parse(time.RFC3339Nano, check.CheckedAt)
		if check.URL == "" || check.Snapshot != observation.Current.Snapshot || !validSHA256Coordinate(check.SourceDigest) || parseErr != nil ||
			checked.UTC().Format(time.RFC3339Nano) != check.CheckedAt || check.Success == (check.ErrorCode != "") ||
			!validPublisherErrorCode(check.ErrorCode, false) ||
			index > 0 && observation.DistributionChecks[index-1].URL >= check.URL {
			return errors.New("publisher distribution checks are invalid")
		}
	}
	if requireSignature {
		signature, err := base64.RawURLEncoding.DecodeString(observation.Signature)
		if err != nil || len(signature) != ed25519.SignatureSize || base64.RawURLEncoding.EncodeToString(signature) != observation.Signature {
			return errors.New("publisher observation signature is invalid")
		}
	}
	return nil
}

func validPublisherErrorCode(code string, topLevel bool) bool {
	if code == "" {
		return true
	}
	if topLevel {
		return code == PublisherErrorPublishFailed || code == PublisherErrorDistributionFailed ||
			code == PublisherErrorAuthorityUnavailable
	}
	return code == PublisherErrorVerifyFailed
}

func (observation *PublisherObservation) Sign(privateKey ed25519.PrivateKey) error {
	if observation == nil || len(privateKey) != ed25519.PrivateKeySize {
		return errors.New("publisher observation signing key is invalid")
	}
	observation.DistributionChecks = append([]PublisherDistributionCheck(nil), observation.DistributionChecks...)
	sort.Slice(observation.DistributionChecks, func(i, j int) bool {
		return observation.DistributionChecks[i].URL < observation.DistributionChecks[j].URL
	})
	observation.Signature = ""
	if err := observation.validate(false); err != nil {
		return err
	}
	body, err := observation.signingBytes()
	if err != nil {
		return err
	}
	observation.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, body))
	return observation.validate(true)
}

func (observation PublisherObservation) Verify(publicKey ed25519.PublicKey) error {
	if len(publicKey) != ed25519.PublicKeySize {
		return errors.New("publisher observation verification key is invalid")
	}
	if err := observation.validate(true); err != nil {
		return err
	}
	signature, _ := base64.RawURLEncoding.DecodeString(observation.Signature)
	body, err := observation.signingBytes()
	if err != nil || !ed25519.Verify(publicKey, body, signature) {
		return errors.New("publisher observation signature is invalid")
	}
	return observation.Current.Verify(publicKey)
}

func (observation PublisherObservation) Bytes() ([]byte, error) {
	if err := observation.validate(true); err != nil {
		return nil, err
	}
	body, err := json.Marshal(observation)
	if err != nil {
		return nil, err
	}
	return append(body, '\n'), nil
}

func DecodePublisherObservation(body []byte) (*PublisherObservation, error) {
	if err := rejectDuplicateJSONKeys(body); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var observation PublisherObservation
	if err := decoder.Decode(&observation); err != nil {
		return nil, fmt.Errorf("decode publisher observation: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("publisher observation has trailing content")
	}
	if err := observation.validate(true); err != nil {
		return nil, err
	}
	canonical, _ := observation.Bytes()
	if !bytes.Equal(body, canonical) {
		return nil, errors.New("publisher observation is not canonical")
	}
	return &observation, nil
}

func (observation PublisherObservation) Write(path string) error {
	if path == "" {
		return nil
	}
	body, err := observation.Bytes()
	if err != nil {
		return err
	}
	return writeFileAtomic(path, body, 0o644)
}
