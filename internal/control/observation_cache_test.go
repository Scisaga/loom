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
	store, err := OpenObservationStore(root)
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
	testSetObservationReports(t, root, []DeviceReport{sign(1, other)})
	forged, _ := os.ReadFile(path)
	if store.Put(next, public(key)) == nil {
		t.Fatal("same position with changed signature bypassed cached-file verification")
	}
	unchanged, _ = os.ReadFile(path)
	if !bytes.Equal(forged, unchanged) {
		t.Fatal("failed verification silently repaired the changed file")
	}
	testSetObservationReports(t, root, []DeviceReport{first})
	if err := store.Put(next, public(key)); err != nil {
		t.Fatal(err)
	}
	want, _ := CanonicalEncode(observationState{Schema: 3, Reports: []DeviceReport{first, next}})
	actual := testObservationBytes(t, root)
	if !bytes.Equal(actual, want) {
		t.Fatal("resumed write changed the original schema or bytes")
	}
}
