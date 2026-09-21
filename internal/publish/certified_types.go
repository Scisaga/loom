package publish

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"

	"loom/internal/model"
)

const CertifiedPublisherInputSchema = 2

// CertifiedPublisherInput is the narrow, secret-free boundary between the
// control authority and the publisher. It is obtained from the local root
// admin socket and is never reconstructed from WebSnapshot or legacy SSOT.
type CertifiedPublisherInput struct {
	Schema           int                        `json:"schema"`
	Head             string                     `json:"head"`
	Index            uint64                     `json:"index"`
	ProjectionDigest string                     `json:"projection_digest"`
	DistributionURLs []string                   `json:"distribution_urls"`
	Devices          []CertifiedPublisherDevice `json:"devices"`
}

type CertifiedPublisherDevice struct {
	ID         string                        `json:"id"`
	Platform   string                        `json:"platform"`
	Roles      []string                      `json:"roles"`
	Components []CertifiedPublisherComponent `json:"components"`
}

type CertifiedPublisherComponent struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Digest  string `json:"digest,omitempty"`
}

func (input CertifiedPublisherInput) Validate() error {
	if input.Schema != CertifiedPublisherInputSchema || input.Index == 0 ||
		!validSHA256Coordinate(input.Head) || !validSHA256Coordinate(input.ProjectionDigest) {
		return errors.New("certified publisher input identity is incomplete")
	}
	for index, value := range input.DistributionURLs {
		parsed, err := url.Parse(value)
		if err != nil || parsed.Scheme != "https" && parsed.Scheme != "http" || parsed.Host == "" ||
			parsed.User != nil || parsed.Fragment != "" || index > 0 && input.DistributionURLs[index-1] >= value {
			return errors.New("certified publisher distribution URLs are invalid or unsorted")
		}
	}
	for i, device := range input.Devices {
		if !model.ValidNodeID(device.ID) || i > 0 && input.Devices[i-1].ID >= device.ID ||
			device.Platform != "android" && device.Platform != "linux" && device.Platform != "windows" {
			return errors.New("certified publisher devices are invalid or unsorted")
		}
		for j, role := range device.Roles {
			if role != "access" && role != "server" || j > 0 && device.Roles[j-1] >= role {
				return errors.New("certified publisher device roles are invalid or unsorted")
			}
		}
		for j, component := range device.Components {
			if !validPublisherToken(component.Name) || !validPublisherToken(component.Version) ||
				j > 0 && device.Components[j-1].Name >= component.Name ||
				component.Digest != "" && !validSHA256Coordinate(component.Digest) {
				return errors.New("certified publisher components are invalid or unsorted")
			}
		}
	}
	return nil
}

func validSHA256Coordinate(value string) bool {
	raw, ok := strings.CutPrefix(value, "sha256:")
	if !ok || len(raw) != sha256.Size*2 || raw != strings.ToLower(raw) {
		return false
	}
	_, err := hex.DecodeString(raw)
	return err == nil
}

func validPublisherToken(value string) bool {
	if value == "" || strings.TrimSpace(value) != value || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if r < 0x21 || r > 0x7e {
			return false
		}
	}
	return true
}

func DecodeCertifiedPublisherInput(body []byte) (CertifiedPublisherInput, error) {
	var input CertifiedPublisherInput
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		return input, fmt.Errorf("decode certified publisher input: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return input, errors.New("certified publisher input has trailing content")
	}
	if err := input.Validate(); err != nil {
		return input, err
	}
	canonical, err := json.Marshal(input)
	if err != nil {
		return input, err
	}
	if !bytes.Equal(body, canonical) {
		return input, errors.New("certified publisher input is not canonical")
	}
	return input, nil
}
