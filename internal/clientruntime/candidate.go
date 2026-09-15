// Package clientruntime validates and activates certified client data-plane artifacts.
package clientruntime

import (
	"errors"
	"fmt"
	"path/filepath"
)

type CandidateVersion struct {
	Generation    uint64 `json:"generation"`
	PayloadSHA256 string `json:"payload_sha256"`
	Snapshot      string `json:"snapshot"`
	BundleSHA256  string `json:"bundle_sha256"`
	ConfigSHA256  string `json:"config_sha256"`
}

func (v CandidateVersion) Validate() error {
	if v.Generation == 0 || !validLowerHex(v.PayloadSHA256, 64) || !validLowerHex(v.Snapshot, 12) ||
		!validLowerHex(v.BundleSHA256, 64) || !validLowerHex(v.ConfigSHA256, 64) {
		return errors.New("candidate has invalid generation or content coordinates")
	}
	return nil
}

func validateRoot(root string) error {
	if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return fmt.Errorf("client state root must be absolute and clean: %q", root)
	}
	return nil
}

func validLowerHex(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for _, character := range []byte(value) {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}
