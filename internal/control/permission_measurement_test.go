package control

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"testing"
	"time"
)

func TestPartialPermissionProofIsOptionalCanonicalAndPreservedInCache(t *testing.T) {
	legacy := RuntimeReadback{State: "unknown", ErrorCode: "runtime_apply_pending"}
	body, err := CanonicalEncode(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != `{"applied_view_digest":"","error_code":"runtime_apply_pending","state":"unknown"}` {
		t.Fatal("absent permission proof changed historical runtime bytes", string(body))
	}
	key := testKey(t)
	public := base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
	digest := ReleaseDigest([]byte("demo-view"))
	value := DeviceReport{Schema: 3, NetworkID: "demo-network", DeviceID: "demo-source", ReportSequence: 1, ViewDigest: digest, NetworkGeneration: "demo-generation", ReportedAt: 1000, Selections: []ReportSelection{}, Observations: []Observation{}, Components: []ComponentReadback{}, Runtime: RuntimeReadback{State: "unknown", ErrorCode: "resources_pending", PermissionViewDigest: digest}}
	signed, err := SignDeviceReport(value, key)
	if err != nil {
		t.Fatal(err)
	}
	body, err = CanonicalEncode(signed)
	if err != nil {
		t.Fatal(err)
	}
	var decoded DeviceReport
	if err := DecodeCanonical(body, &decoded, contractTestLimits); err != nil {
		t.Fatal(err)
	}
	if err := decoded.Verify(public); err != nil {
		t.Fatal(err)
	}
	if decoded.Runtime.AppliedViewDigest != "" || decoded.Runtime.PermissionViewDigest != digest {
		t.Fatal("partial readback became complete or lost its permission proof")
	}
	store := new(ObservationStore)
	for range 2 {
		_, runtime, err := store.originalRuntime(body, public)
		if err != nil || runtime.PermissionViewDigest != digest {
			t.Fatal("cold or cached runtime dropped the permission proof", err)
		}
	}
	changed := decoded
	changed.Runtime.PermissionViewDigest = ReleaseDigest([]byte("demo-other-view"))
	if changed.validateFields() == nil {
		t.Fatal("permission proof for another report View was accepted")
	}
	for _, state := range []string{"stopped", "error"} {
		invalid := value.Runtime
		invalid.State = state
		if invalid.Validate() == nil {
			t.Fatal("nonexecuting runtime retained permission proof", state)
		}
	}
	legacyBody, err := CanonicalEncode(legacy)
	if err != nil || !bytes.Equal(legacyBody, []byte(`{"applied_view_digest":"","error_code":"runtime_apply_pending","state":"unknown"}`)) {
		t.Fatal("old runtime bytes no longer reproduce", err)
	}
}

func TestPartialPermissionsRetainIndependentMeasurementsWithoutRenewingThem(t *testing.T) {
	store, _, at, sample, query, _ := sharedMeasurementFixture(t)
	key := testKey(t)
	query.publicKey = base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
	digest := ReleaseDigest([]byte("demo-view"))
	put := func(sequence U64, generation string, runtime RuntimeReadback, values []Observation) {
		t.Helper()
		report, err := SignDeviceReport(DeviceReport{Schema: 3, NetworkID: "demo-network", DeviceID: query.source, ReportSequence: sequence, ViewDigest: digest, NetworkGeneration: generation, ReportedAt: at.Add(time.Duration(sequence) * time.Second).UnixMilli(), Selections: []ReportSelection{}, Observations: append([]Observation{}, values...), Components: []ComponentReadback{}, Runtime: runtime}, key)
		if err != nil {
			t.Fatal(err)
		}
		if err := store.Put(report, query.publicKey); err != nil {
			t.Fatal(err)
		}
	}
	read := func(want int) {
		t.Helper()
		for _, bytes := range []int{0, MeasurementDeliveryLimit} {
			rows, _, _, err := store.latestMeasurementWindow(context.Background(), "demo-network", []reportMeasurementQuery{query}, at.Add(20*time.Second), bytes)
			if err != nil || len(rows) != want {
				t.Fatal("incorrect partial measurement delivery", err, len(rows), want)
			}
			if want != 0 && (rows[0].ReportSequence != 1 || rows[0].CurrentUntil != sample.ValidUntil || rows[0].Observation.ObservedAt != sample.ObservedAt) {
				t.Fatal("partial head changed original sample identity or deadline")
			}
		}
	}
	put(1, sample.NetworkGeneration, RuntimeReadback{State: "running", AppliedViewDigest: digest}, []Observation{sample})
	put(2, sample.NetworkGeneration, RuntimeReadback{State: "unknown", PermissionViewDigest: digest, ErrorCode: "resources_pending"}, nil)
	read(1)
	put(3, sample.NetworkGeneration, RuntimeReadback{State: "unknown", ErrorCode: "authorization_pending"}, nil)
	read(0)
	put(4, sample.NetworkGeneration, RuntimeReadback{State: "stopped"}, nil)
	read(0)
	put(5, "demo-other-network", RuntimeReadback{State: "unknown", PermissionViewDigest: digest, ErrorCode: "resources_pending"}, nil)
	read(0)
}
