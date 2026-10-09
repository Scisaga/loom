//go:build !linux

package control

import (
	"errors"
	"time"
)

func localWebsiteRequest(string, NodeConfig, Projection, string, U64) (WebsiteRequest, error) {
	return WebsiteRequest{}, errors.New("website requests remain on the owning Linux control")
}
func localWebsiteRequests(string, NodeConfig, Projection) ([]WebsiteRequestSummary, error) {
	return []WebsiteRequestSummary{}, nil
}
func installWebsiteCertificate(string, NodeConfig, Projection, websiteInstallInput, time.Time) (EndpointGeneration, error) {
	return EndpointGeneration{}, errors.New("website certificates must be installed on the owning Linux control")
}
