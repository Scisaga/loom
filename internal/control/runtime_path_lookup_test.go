package control

import (
	"testing"
)

func TestStableViewRejectsRuntimeInjectionAndUnqualifiedAuthentication(t *testing.T) {
	projection := relayProjectionFixture(t)
	view, err := ProjectDeviceView(projection, "demo-access")
	if err != nil {
		t.Fatal(err)
	}
	body, err := CanonicalEncode(view)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"routes", "links", "runtime_profile", "inbound_credentials", "access_grants", "policy_exits"} {
		raw := append([]byte{}, body[:len(body)-1]...)
		// DecodeCanonical rejects noncanonical field ordering as well as unknown
		// fields; the map encoding makes this specifically an unknown-field check.
		parsed, err := parseContractJSON(body, ContractDecodeLimits{MaxBytes: 8 << 20, MaxDepth: 128, MaxItems: 100000})
		if err != nil {
			t.Fatal(err)
		}
		object := parsed.(map[string]any)
		object[key] = []any{}
		raw = appendContractJSON(nil, object)
		if err != nil {
			t.Fatal(err)
		}
		var decoded DeviceView
		if DecodeCanonical(raw, &decoded, ContractDecodeLimits{MaxBytes: 8 << 20, MaxDepth: 128, MaxItems: 100000}) == nil {
			t.Fatal("runtime expansion entered signed authority", key)
		}
	}
	receiver, err := ProjectDeviceView(projection, "demo-entry")
	if err != nil {
		t.Fatal(err)
	}
	if len(receiver.TransportCredentials) == 0 {
		t.Fatal("missing transport credential fixture")
	}
	for _, sender := range []string{"demo-ungranted", "demo-entry"} {
		changed := receiver
		changed.TransportCredentials = append([]TransportCredential{}, receiver.TransportCredentials...)
		changed.TransportCredentials[0].SenderID = sender
		if changed.Validate() == nil {
			t.Fatal("invalid actual sender admitted")
		}
	}
	if _, err := CanonicalEncode(testDeviceExecution(view)); err == nil {
		t.Fatal("execution projection became writable authority")
	}
}
