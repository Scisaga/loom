package control

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"time"
)

// EndpointCertificateReadback diagnoses authenticated public certificate bytes.
// It does not attest listener readiness, key possession or reachability, and
// never changes a signed endpoint stage.
type EndpointCertificateReadback struct {
	EndpointID       string   `json:"endpoint_id"`
	Generation       U64      `json:"generation"`
	OwnerControlID   string   `json:"owner_control_id"`
	Modes            []string `json:"modes"`
	Status           string   `json:"status"`
	Reason           string   `json:"reason,omitempty"`
	LeafNotBefore    string   `json:"leaf_not_before,omitempty"`
	LeafNotAfter     string   `json:"leaf_not_after,omitempty"`
	RootNotBefore    string   `json:"root_not_before,omitempty"`
	RootNotAfter     string   `json:"root_not_after,omitempty"`
	RemainingSeconds *int64   `json:"remaining_seconds,omitempty"`
}

func EndpointCertificateReadbacks(root, owner string, projection Projection, now time.Time) []EndpointCertificateReadback {
	result := []EndpointCertificateReadback{}
	for _, endpoint := range projection.EndpointGenerations {
		if endpoint.State != "serving" {
			continue
		}
		value := EndpointCertificateReadback{EndpointID: endpoint.ID, Generation: endpoint.Generation, OwnerControlID: endpoint.OwnerControlID, Modes: append([]string{}, endpoint.Modes...), Status: "unknown"}
		if endpoint.OwnerControlID != owner {
			value.Reason = "inspect_owning_control"
			result = append(result, value)
			continue
		}
		result = append(result, readEndpointCertificate(root, projection, endpoint, now, value))
	}
	return result
}

func readEndpointCertificate(root string, projection Projection, endpoint EndpointGeneration, now time.Time, value EndpointCertificateReadback) EndpointCertificateReadback {
	inputs, err := loadEndpointInputs(root, endpoint)
	if err != nil {
		value.Reason = "material_unavailable"
		return value
	}
	certificate, err := readControlPublicFile(inputs.CertificateFile)
	if err != nil {
		value.Reason = "material_unavailable"
		return value
	}
	block, rest := pem.Decode(certificate)
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
		value.Reason = "certificate_invalid"
		return value
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !leaf.NotAfter.After(leaf.NotBefore) || validateEndpointCertificate(leaf, endpoint, leaf.NotBefore) != nil {
		value.Reason = "certificate_invalid"
		return value
	}
	// Validate the authenticated bytes and chain within their common validity,
	// then compare the caller's clock. This can report an expired local leaf
	// even when runtime correctly stopped its listener at expiration.
	start, end := leaf.NotBefore, leaf.NotAfter
	if endpoint.WebsiteTrustID != "" {
		trust, err := endpointWebsiteTrust(projection, endpoint)
		if err != nil {
			value.Reason = "root_not_authorized"
			return value
		}
		ca, err := trust.certificate()
		if err != nil || len(bytes.TrimSpace(rest)) != 0 {
			value.Reason = "certificate_invalid"
			return value
		}
		if ca.NotBefore.After(start) {
			start = ca.NotBefore
		}
		if ca.NotAfter.Before(end) {
			end = ca.NotAfter
		}
		if _, err := verifyWebsiteLeaf(leaf.Raw, ca.Raw, start); err != nil {
			value.Reason = "certificate_invalid"
			return value
		}
		value.RootNotBefore, value.RootNotAfter = ca.NotBefore.UTC().Format(time.RFC3339), ca.NotAfter.UTC().Format(time.RFC3339)
	}
	remaining := int64(end.Sub(now) / time.Second)
	value.LeafNotBefore, value.LeafNotAfter, value.RemainingSeconds = leaf.NotBefore.UTC().Format(time.RFC3339), leaf.NotAfter.UTC().Format(time.RFC3339), &remaining
	switch {
	case now.Before(start):
		value.Status = "not_yet_valid"
	case !now.Before(end):
		value.Status = "expired"
	case end.Sub(now) <= 30*24*time.Hour:
		value.Status = "renewal_due"
	default:
		value.Status = "valid"
	}
	return value
}
