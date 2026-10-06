package control

import (
	"crypto/tls"
	"errors"
	"time"
)

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
