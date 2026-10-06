package control

import (
	"crypto/tls"
	"errors"
	"sort"
	"time"
)

func endpointLess(left, right EndpointGeneration) bool {
	return left.ID < right.ID || left.ID == right.ID && left.Generation < right.Generation
}

func validateWebsiteEndpoints(endpoints []EndpointGeneration, roots []PublicTrust) error {
	if endpoints != nil && len(endpoints) == 0 {
		return errors.New("empty website endpoints must be omitted")
	}
	for index, endpoint := range endpoints {
		if endpoint.Validate() != nil || endpoint.WebsiteTrustID == "" || endpoint.State != "serving" ||
			index > 0 && (!endpointLess(endpoints[index-1], endpoint) || endpoint.Port != endpoints[0].Port) {
			return errors.New("website endpoints must be serving, uniquely sorted and share one client port")
		}
		if _, err := endpointWebsiteTrust(Projection{NetworkIntent: NetworkIntent{PublicTrust: roots}}, endpoint); err != nil {
			return err
		}
	}
	return nil
}

// WebsiteEndpoints is a pure projection, not an assertion of network reachability.
// Conflicting client ports cannot be represented by one DNS name and URL.
func WebsiteEndpoints(projection Projection) ([]EndpointGeneration, error) {
	var result []EndpointGeneration
	for _, endpoint := range projection.EndpointGenerations {
		if endpoint.WebsiteTrustID == "" || endpoint.State != "serving" || !endpointOwnerActive(projection, endpoint.OwnerControlID) {
			continue
		}
		if _, err := endpointWebsiteTrust(projection, endpoint); err != nil {
			continue
		}
		result = append(result, endpoint)
	}
	sort.Slice(result, func(i, j int) bool { return endpointLess(result[i], result[j]) })
	if err := validateWebsiteEndpoints(result, projection.NetworkIntent.PublicTrust); err != nil {
		return nil, err
	}
	return result, nil
}

func endpointWebsiteTrust(projection Projection, endpoint EndpointGeneration) (PublicTrust, error) {
	for _, trust := range projection.NetworkIntent.PublicTrust {
		if trust.ID == endpoint.WebsiteTrustID {
			return trust, trust.Validate()
		}
	}
	return PublicTrust{}, errors.New("website endpoint has no current public trust grant")
}

func loadAuthorizedEndpointCertificate(projection Projection, endpoint EndpointGeneration, inputs EndpointLocalInputs, now time.Time) (tls.Certificate, error) {
	certificate, err := loadEndpointCertificate(endpoint, inputs, now)
	if err != nil || endpoint.WebsiteTrustID == "" {
		return certificate, err
	}
	trust, err := endpointWebsiteTrust(projection, endpoint)
	if err != nil {
		return tls.Certificate{}, err
	}
	root, err := trust.certificate()
	if err != nil {
		return tls.Certificate{}, err
	}
	if len(certificate.Certificate) != 1 {
		return tls.Certificate{}, errors.New("website endpoint requires the single leaf signed by its authorized root")
	}
	if _, err := verifyWebsiteLeaf(certificate.Certificate[0], root.Raw, now); err != nil {
		return tls.Certificate{}, err
	}
	return certificate, nil
}
