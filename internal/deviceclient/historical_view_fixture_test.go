package deviceclient

import (
	"bytes"
	"encoding/json"
	"loom/internal/control"
	"strconv"
	"testing"
)

// These finite retired bytes are test evidence for explicit migration only.
// They cannot be read as current authorization or executed by any test runtime.
func testHistoricalView(t testing.TB, view control.DeviceView) map[string]json.RawMessage {
	t.Helper()
	body, err := control.CanonicalEncode(view)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err = json.Unmarshal(body, &fields); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"nodes", "transport_credentials", "wireguard_private_key", "wireguard_public_key"} {
		delete(fields, key)
	}
	execution := testDeviceExecution(view)
	add := func(key string, value any) {
		body, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		fields[key] = body
	}
	add("routes", execution.Routes)
	add("links", execution.Links)
	add("business_probe_targets", execution.BusinessProbeTargets)
	add("inbound_credentials", []any{})
	if len(execution.WireGuardPeers) > 0 {
		add("wireguard_peers", execution.WireGuardPeers)
	}
	if execution.RuntimeProfile != nil {
		add("runtime_profile", execution.RuntimeProfile)
	}
	return fields
}
func testCanonicalHistoricalJSON(t testing.TB, value any) []byte {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var object any
	if err = decoder.Decode(&object); err != nil {
		t.Fatal(err)
	}
	body, err = control.CanonicalEncode(testHistoricalNumbers(t, object))
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func testHistoricalNumbers(t testing.TB, value any) any {
	switch value := value.(type) {
	case json.Number:
		n, err := strconv.ParseInt(string(value), 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		return n
	case map[string]any:
		for key, child := range value {
			value[key] = testHistoricalNumbers(t, child)
		}
		return value
	case []any:
		for i, child := range value {
			value[i] = testHistoricalNumbers(t, child)
		}
		return value
	default:
		return value
	}
}
