package wire

import "testing"

func TestDeviceHealthPayloadRequiresExplicitKnownFields(t *testing.T) {
	for _, raw := range []string{`{"healthy":true,"version":"demo-build"}`, `{"healthy":false,"version":"demo-build"}`} {
		if _, err := DecodeDeviceHealthPayload("health", 1, []byte(raw)); err != nil {
			t.Fatal(err)
		}
	}
	for _, raw := range []string{
		`{"version":"demo-build"}`, `{"healthy":null,"version":"demo-build"}`,
		`{"healthy":true}`, `{"healthy":true,"version":""}`,
		`{"healthy":true,"version":" demo-build"}`, `{"healthy":true,"version":"demo\n"}`,
		`{"healthy":true,"online":true,"version":"demo-build"}`,
		`{ "healthy": true, "version": "demo-build" }`,
	} {
		if _, err := DecodeDeviceHealthPayload("health", 1, []byte(raw)); err == nil {
			t.Fatalf("accepted invalid health: %s", raw)
		}
	}
	for _, pair := range []struct {
		kind   string
		schema int64
	}{{"runtime", 1}, {"health", 2}} {
		if _, err := DecodeDeviceHealthPayload(pair.kind, pair.schema, []byte(`{"healthy":true,"version":"demo-build"}`)); err == nil {
			t.Fatal("accepted unknown contract")
		}
	}
}
