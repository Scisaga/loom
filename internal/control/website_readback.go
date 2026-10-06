package control

import "time"

// WebsiteCertificateReadback is a local diagnostic, not endpoint stage or
// reachability authority. Remote controls need not possess another owner's key.
type WebsiteCertificateReadback struct {
	EndpointID       string `json:"endpoint_id"`
	Generation       U64    `json:"generation"`
	OwnerControlID   string `json:"owner_control_id"`
	Status           string `json:"status"`
	Reason           string `json:"reason,omitempty"`
	LeafNotAfter     string `json:"leaf_not_after,omitempty"`
	RootNotAfter     string `json:"root_not_after,omitempty"`
	RemainingSeconds *int64 `json:"remaining_seconds,omitempty"`
}

func WebsiteCertificateReadbacks(root, owner string, projection Projection, now time.Time) []WebsiteCertificateReadback {
	result := []WebsiteCertificateReadback{}
	for _, endpoint := range projection.EndpointGenerations {
		if endpoint.WebsiteTrustID == "" || endpoint.State != "serving" {
			continue
		}
		value := WebsiteCertificateReadback{EndpointID: endpoint.ID, Generation: endpoint.Generation, OwnerControlID: endpoint.OwnerControlID, Status: "unknown"}
		if endpoint.OwnerControlID != owner {
			value.Reason = "inspect_owning_control"
			result = append(result, value)
			continue
		}
		result = append(result, readWebsiteCertificate(root, projection, endpoint, now, value))
	}
	return result
}

func readWebsiteCertificate(root string, projection Projection, endpoint EndpointGeneration, now time.Time, value WebsiteCertificateReadback) WebsiteCertificateReadback {
	trust, err := endpointWebsiteTrust(projection, endpoint)
	if err != nil {
		value.Reason = "root_not_authorized"
		return value
	}
	ca, err := trust.certificate()
	if err != nil {
		value.Reason = "certificate_invalid"
		return value
	}
	inputs, err := loadEndpointInputs(root, endpoint)
	if err != nil {
		value.Reason = "material_unavailable"
		return value
	}
	certificate, err := LoadTLSCertificate(inputs.CertificateFile, inputs.KeyFile)
	if err != nil || len(certificate.Certificate) != 1 {
		value.Reason = "material_unavailable"
		return value
	}
	leaf := certificate.Leaf
	// Validate the authenticated bytes and chain within their common validity,
	// then compare the caller's clock. This can report an expired local leaf
	// even when runtime correctly stopped its listener at expiration.
	start, end := leaf.NotBefore, leaf.NotAfter
	if ca.NotBefore.After(start) {
		start = ca.NotBefore
	}
	if ca.NotAfter.Before(end) {
		end = ca.NotAfter
	}
	if validateEndpointCertificate(leaf, endpoint, start) != nil {
		value.Reason = "certificate_invalid"
		return value
	}
	if _, err := verifyWebsiteLeaf(leaf.Raw, ca.Raw, start); err != nil {
		value.Reason = "certificate_invalid"
		return value
	}
	remaining := int64(end.Sub(now) / time.Second)
	value.LeafNotAfter, value.RootNotAfter, value.RemainingSeconds = leaf.NotAfter.UTC().Format(time.RFC3339), ca.NotAfter.UTC().Format(time.RFC3339), &remaining
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
