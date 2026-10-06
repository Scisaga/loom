//go:build !linux

package control

import (
	"errors"
	"time"
)

func PrepareWebsiteRequest(string, string, U64) (WebsiteRequest, error) {
	return WebsiteRequest{}, errors.New("website leaf keys must be generated on the owning Linux control")
}

func verifyLocalWebsiteRequest(string, Projection, EndpointGeneration, EndpointLocalInputs, time.Time) error {
	return errors.New("website leaf keys remain on the owning Linux control")
}
