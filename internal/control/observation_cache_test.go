package control

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReportPositionsRequireExactOriginalAndPublicKey(t *testing.T) {
	key, other := testKey(t), testKey(t)
	public := func(key ed25519.PrivateKey) string {
		return base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
	}
	digest := "sha256:" + strings.Repeat("0", 64)
	sign := func(sequence U64, key ed25519.PrivateKey) DeviceReport {
		t.Helper()
		value, err := SignDeviceReport(DeviceReport{Schema: 3, NetworkID: "demo-network", DeviceID: "demo-device", ReportSequence: sequence,
			ViewDigest: digest, NetworkGeneration: "demo-underlay", ReportedAt: 1, Selections: []ReportSelection{}, Observations: []Observation{},
			Runtime: RuntimeReadback{State: "stopped"}, Components: []ComponentReadback{}}, key)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := testOpenObservationStore(t, root)
	if err != nil {
		t.Fatal(err)
	}
	first, next := sign(1, key), sign(2, key)
	if err := store.Put(first, public(key)); err != nil {
		t.Fatal(err)
	}
	if err := store.Put(first, public(key)); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "observations.db")
	original, _ := os.ReadFile(path)
	if store.Put(sign(2, other), public(other)) == nil {
		t.Fatal("cached verification accepted another public key for immutable history")
	}
	unchanged, _ := os.ReadFile(path)
	if !bytes.Equal(original, unchanged) {
		t.Fatal("rejected key changed original history")
	}
	testSetObservationReports(t, store, []DeviceReport{sign(1, other)})
	forged, _ := os.ReadFile(path)
	if store.Put(next, public(key)) == nil {
		t.Fatal("same position with changed signature bypassed cached-file verification")
	}
	unchanged, _ = os.ReadFile(path)
	if !bytes.Equal(forged, unchanged) {
		t.Fatal("failed verification silently repaired the changed file")
	}
	testSetObservationReports(t, store, []DeviceReport{first})
	if err := store.Put(next, public(key)); err != nil {
		t.Fatal(err)
	}
	want, _ := CanonicalEncode(observationState{Schema: 3, Reports: []DeviceReport{first, next}})
	actual := testObservationBytes(t, store)
	if !bytes.Equal(actual, want) {
		t.Fatal("resumed write changed the original schema or bytes")
	}
}

func TestEventRuntimeMessagePreservesSignedCanonicalFields(t *testing.T) {
	key := testKey(t)
	public := base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
	digest := "sha256:" + strings.Repeat("0", 64)
	base := DeviceReport{Schema: 3, NetworkID: "demo-network", DeviceID: "demo-device", ReportSequence: 18446744073709551615,
		ViewDigest: digest, NetworkGeneration: "demo-underlay", ReportedAt: 1, Selections: []ReportSelection{}, Observations: []Observation{},
		Runtime: RuntimeReadback{State: "running", AppliedViewDigest: digest}, Components: []ComponentReadback{}}
	optional := base
	optional.WireGuardCounters = &WireGuardCounters{Interface: wireGuardSharedCredential, Epoch: strings.Repeat("0", 32), ObservedAt: 1, Peers: []WireGuardPeerCounter{}}
	optional.Preference = &ReportPreference{Mode: "fixed_exit", Exit: "demo-exit"}
	networks := []LocalNetworkPrefix{{Prefix: "192.0.2.0/24", LAN: true}}
	optional.LocalNetworks = &networks
	for _, item := range []struct {
		name   string
		report DeviceReport
	}{{"required", base}, {"optional", optional}} {
		t.Run(item.name, func(t *testing.T) {
			report, err := SignDeviceReport(item.report, key)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := CanonicalEncode(report)
			var decoded DeviceReport
			if err != nil || decodeStoredReport(raw, &decoded) != nil || decoded.Validate() != nil {
				t.Fatal("canonical report did not validate", err)
			}
			got, err := reportMessageFromCanonical(raw, decoded.Signature)
			want, encodeErr := signedContractBytes(reportDomain, decoded.unsigned())
			if err != nil || encodeErr != nil || !bytes.Equal(got, want) {
				t.Fatal("original-byte signature message differs from canonical unsigned value", err, encodeErr)
			}
			store := &ObservationStore{}
			if _, _, err := store.originalRuntimeKeys(raw, []string{public}); err != nil {
				t.Fatal("cold original-byte verification rejected a valid signature", err)
			}
			store.cache.clear()
			if _, err := store.decodedReport(raw); err != nil {
				t.Fatal(err)
			}
			if _, _, err := store.originalRuntimeKeys(raw, []string{public}); err != nil {
				t.Fatal("canonical-only validation cache changed signature verification", err)
			}
			invalidRuntime := bytes.Replace(raw, []byte(`"state":"running"`), []byte(`"state":"invalid"`), 1)
			if _, err := store.decodedReport(invalidRuntime); err == nil {
				t.Fatal("canonical decode skipped static nested report validation")
			}
			if store.cache.items[ReleaseDigest(invalidRuntime)] != nil {
				t.Fatal("failed static validation entered the canonical proof cache")
			}
			for _, tamper := range []func(*DeviceReport){
				func(value *DeviceReport) {
					value.Signature = base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
				},
				func(value *DeviceReport) { value.ReportedAt++ },
			} {
				changed := report
				tamper(&changed)
				body, err := CanonicalEncode(changed)
				if err != nil {
					t.Fatal(err)
				}
				if _, _, err := store.originalRuntimeKeys(body, []string{public}); err == nil {
					t.Fatal("original-byte verification accepted a changed signature or signed field")
				}
			}
			nested := bytes.Replace(raw, []byte(`"state":"running"`), []byte(`"signature":"`+report.Signature+`","state":"running"`), 1)
			if _, _, err := store.originalRuntimeKeys(nested, []string{public}); err == nil {
				t.Fatal("signature extraction bypassed canonical rejection of an unknown nested signature")
			}
		})
	}
}

func TestEventRuntimePreferredKeyKeepsHistoricalAcceptance(t *testing.T) {
	first, second, other := testKey(t), testKey(t), testKey(t)
	public := func(key ed25519.PrivateKey) string {
		return base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
	}
	firstKey, secondKey, otherKey := public(first), public(second), public(other)
	keys := []string{otherKey, firstKey, secondKey}
	preferred := append([]string(nil), keys...)
	store := &ObservationStore{}
	codec := newContractCodec()
	var firstRaw []byte
	for i, key := range []ed25519.PrivateKey{first, second, first} {
		report, err := SignDeviceReport(DeviceReport{Schema: 3, NetworkID: "demo-network", DeviceID: "demo-device", ReportSequence: U64(i + 1),
			ViewDigest: "sha256:" + strings.Repeat("0", 64), NetworkGeneration: "demo-underlay", ReportedAt: int64(i + 1),
			Selections: []ReportSelection{}, Observations: []Observation{}, Components: []ComponentReadback{}, Runtime: RuntimeReadback{State: "stopped"}}, key)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := CanonicalEncode(report)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			firstRaw = raw
		}
		_, _, verified, err := store.originalRuntimeKeysWithCodecAndKey(raw, ReleaseDigest(raw), preferred, codec)
		if err != nil || verified != public(key) {
			t.Fatal("a previously preferred different key changed cold signature verification", err)
		}
		preferHistoricalReportKey(preferred, verified)
		if preferred[0] != verified || keys[0] != otherKey || keys[1] != firstKey || keys[2] != secondKey {
			t.Fatal("query key ordering changed the shared historical key slice")
		}
	}
	_, _, verified, err := store.originalRuntimeKeysWithCodecAndKey(firstRaw, ReleaseDigest(firstRaw), preferred, codec)
	if err != nil || verified != firstKey {
		t.Fatal("cached verification did not return its exact accepted key", err)
	}
	for _, cold := range []bool{false, true} {
		if cold {
			store.cache.clear()
		}
		if _, _, verified, err := store.originalRuntimeKeysWithCodecAndKey(firstRaw, ReleaseDigest(firstRaw), []string{secondKey, otherKey}, codec); err == nil || verified != "" {
			t.Fatal("a successful key hint supplied a removed historical identity")
		}
	}
}

func TestCanonicalReportMessageRemovesOnlyItsTopLevelSignature(t *testing.T) {
	for _, item := range []struct{ raw, unsigned string }{
		{`{"signature":"top","z":{"signature":"nested"}}`, `{"z":{"signature":"nested"}}`},
		{`{"a":"{\"signature\":\"top\"}","signature":"top","z":[{"signature":"nested"}]}`, `{"a":"{\"signature\":\"top\"}","z":[{"signature":"nested"}]}`},
		{`{"a":{"signature":"nested"},"signature":"top"}`, `{"a":{"signature":"nested"}}`},
		{`{"signature":"top"}`, `{}`},
	} {
		got, err := reportMessageFromCanonical([]byte(item.raw), "top")
		if err != nil || !bytes.Equal(got, append([]byte(reportDomain), []byte(item.unsigned)...)) {
			t.Fatal("top-level signature removal changed a nested value, escaped string or comma", err)
		}
	}
	for _, raw := range []string{`{"a":{"signature":"top"}}`, `{"a":"\"signature\":\"top\""}`, `{"signature":"different"}`} {
		if _, err := reportMessageFromCanonical([]byte(raw), "top"); err == nil {
			t.Fatal("a nested, string-like or different signature replaced the decoded top-level value")
		}
	}
}
