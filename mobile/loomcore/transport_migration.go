package loomcore

import (
	"errors"

	"loom/internal/control"
	"loom/internal/deviceclient"
)

// AcceptAndroidCertifiedView imports a current View through the same identity
// and frontier checks as private synchronization. It does not migrate evidence.
func AcceptAndroidCertifiedView(original, replacement []byte) ([]byte, error) {
	state, err := decodeState(original)
	if err != nil {
		return nil, err
	}
	var envelope control.DeviceViewEnvelope
	if err := control.DecodeCanonical(replacement, &envelope, control.ContractDecodeLimits{MaxBytes: 8 << 20, MaxDepth: 128, MaxItems: 1 << 20}); err != nil {
		return nil, err
	}
	next, err := deviceclient.AcceptLKG(state, envelope)
	if err != nil {
		return nil, err
	}
	return deviceclient.EncodeIdentityState(next)
}

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

// ReplaceAndroidPolicySelection is reachable only from explicit certified-file
// import. Historical execution is evidence, never a runtime fallback.
func ReplaceAndroidPolicySelection(original, replacement, previousPreference []byte) ([]byte, error) {
	var envelope control.DeviceViewEnvelope
	if err := control.DecodeCanonical(replacement, &envelope, control.ContractDecodeLimits{MaxBytes: 8 << 20, MaxDepth: 128, MaxItems: 1 << 20}); err != nil {
		return nil, err
	}
	if envelope.View.Platform != "android" {
		return nil, errors.New("replacement belongs to another platform")
	}
	state, _, err := deviceclient.ReplacePolicySelectionLKG(original, envelope, previousPreference)
	if err != nil {
		return nil, err
	}
	return deviceclient.EncodeIdentityState(state)
}

func MigrateAndroidPolicyPreference(original, replacement, previousPreference []byte) ([]byte, error) {
	var envelope control.DeviceViewEnvelope
	if err := control.DecodeCanonical(replacement, &envelope, control.ContractDecodeLimits{MaxBytes: 8 << 20, MaxDepth: 128, MaxItems: 1 << 20}); err != nil {
		return nil, err
	}
	if envelope.View.Platform != "android" {
		return nil, errors.New("replacement belongs to another platform")
	}
	_, preference, err := deviceclient.ReplacePolicySelectionLKG(original, envelope, previousPreference)
	if err != nil {
		return nil, err
	}
	return control.CanonicalEncode(preference)
}
