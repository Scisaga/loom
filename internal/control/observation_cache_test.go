package control

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Cancel at an actual verified-original boundary, without relying on machine
// speed or racing a timer against cryptographic work.
type cancelDuringHistoryVerification struct {
	context.Context
	cancel context.CancelFunc
	store  *ObservationStore
}

func (ctx cancelDuringHistoryVerification) Err() error {
	if len(ctx.store.verified) != 0 {
		ctx.cancel()
	}
	return ctx.Context.Err()
}

func TestObservationHistoryVerificationCancellationPreservesOriginals(t *testing.T) {
	key := testKey(t)
	public := base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := OpenObservationStore(root)
	if err != nil {
		t.Fatal(err)
	}
	reports := []DeviceReport{}
	for sequence := U64(1); sequence <= 4; sequence++ {
		report, err := SignDeviceReport(DeviceReport{Schema: 3, NetworkID: "demo-network", DeviceID: "demo-device", ReportSequence: sequence,
			ViewDigest: "sha256:" + strings.Repeat("0", 64), NetworkGeneration: "demo-underlay", ReportedAt: 1,
			Selections: []ReportSelection{}, Observations: []Observation{}, Runtime: RuntimeReadback{State: "stopped"}, Components: []ComponentReadback{}}, key)
		if err != nil {
			t.Fatal(err)
		}
		reports = append(reports, report)
	}
	testSetObservationReports(t, root, reports[:3])
	store, err = OpenObservationStore(root)
	if err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(store.path)
	if err != nil {
		t.Fatal(err)
	}
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx := cancelDuringHistoryVerification{parent, cancel, store}
	err = store.mergeReports(ctx, reports[3:], map[reportOwner]string{{"demo-network", "demo-device"}: public}, false)
	if !errors.Is(err, context.Canceled) || len(store.verified) != 1 {
		t.Fatal("cancellation did not stop between verified originals", err, len(store.verified))
	}
	after, err := os.ReadFile(store.path)
	if err != nil || !bytes.Equal(original, after) {
		t.Fatal("cancelled verification changed the database", err)
	}
	if err := store.Put(reports[3], public); err != nil {
		t.Fatal("same original could not resume after cancellation", err)
	}
	want, _ := CanonicalEncode(observationState{Schema: 3, Reports: reports})
	if !bytes.Equal(testObservationBytes(t, root), want) {
		t.Fatal("retry changed the original signed history")
	}
}

func TestObservationSignatureMemoRequiresExactOriginalAndPublicKey(t *testing.T) {
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
