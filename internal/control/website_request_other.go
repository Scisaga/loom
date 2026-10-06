//go:build !linux

package control

import (
	"errors"
)

func PrepareWebsiteRequest(string, string, U64) (WebsiteRequest, error) {
	return WebsiteRequest{}, errors.New("website leaf keys must be generated on the owning Linux control")
}
