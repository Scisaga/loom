package loomcore

import (
	"errors"

	"loom/internal/control"
	"loom/internal/deviceclient"
)

// Explicit file import only. The host preserves the old bytes in its Keystore
// evidence slot before atomically committing this one forward replacement.
func ReplaceAndroidTransport(original, replacement []byte) ([]byte, error) {
	var envelope control.DeviceViewEnvelope
	if err := control.DecodeCanonical(replacement, &envelope, control.ContractDecodeLimits{MaxBytes: 8 << 20, MaxDepth: 128, MaxItems: 1 << 20}); err != nil {
		return nil, err
	}
	if envelope.View.Platform != "android" {
		return nil, errors.New("replacement belongs to another platform")
	}
	next, err := deviceclient.ReplaceTransportLKG(original, envelope)
	if err != nil {
		return nil, err
	}
	return deviceclient.EncodeIdentityState(next)
}
