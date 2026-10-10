package control

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"os"
	"sort"
	"strings"
	"testing"

	bolt "go.etcd.io/bbolt"
)

func TestReportPositionBatchIsAtomicAndIndependentOfUnqueriedHistory(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	private := map[string]ed25519.PrivateKey{"demo-a": testKey(t), "demo-b": testKey(t)}
	keys := map[reportOwner]string{}
	for device, key := range private {
		keys[reportOwner{"demo-network", device}] = base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
	}
	sign := func(device string, seq U64, at int64) DeviceReport {
		t.Helper()
		r, err := SignDeviceReport(DeviceReport{Schema: 3, NetworkID: "demo-network", DeviceID: device, ReportSequence: seq, ViewDigest: "sha256:" + strings.Repeat("0", 64), NetworkGeneration: "demo-underlay", ReportedAt: at, Selections: []ReportSelection{}, Observations: []Observation{}, Components: []ComponentReadback{}, Runtime: RuntimeReadback{State: "stopped"}}, private[device])
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	originals := []DeviceReport{sign("demo-a", 1, 1), sign("demo-a", 3, 3), sign("demo-b", 1, 1), sign("demo-b", 3, 3)}
	testSetObservationReports(t, root, originals)
	store, err := testOpenObservationStore(t, root)
	if err != nil {
		t.Fatal(err)
	}
	oldRaw, _ := CanonicalEncode(originals[0])
	oldID := ReleaseDigest(oldRaw)
	oldKey := referenceOf(originals[0]).key(oldID)
	corrupt := append(bytes.Clone(oldRaw), '\n')
	if err := store.withDatabase(context.Background(), true, func(tx *bolt.Tx) error { return tx.Bucket(observationBucket).Put(oldKey, corrupt) }); err != nil {
		t.Fatal(err)
	}
	// Current state and new positions do not certify unrelated old bytes.
	latest, err := store.Latest(context.Background())
	if err != nil || len(latest) != 2 {
		t.Fatal("current state rescanned unqueried history", err)
	}
	batch := []DeviceReport{sign("demo-a", 5, 5), sign("demo-b", 5, 5)}
	before, err := os.ReadFile(store.path)
	if err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := store.mergeReports(canceled, batch, keys, true); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	badKeys := map[reportOwner]string{}
	for owner, key := range keys {
		badKeys[owner] = key
	}
	badKeys[reportOwner{"demo-network", "demo-b"}] = keys[reportOwner{"demo-network", "demo-a"}]
	if err := store.mergeReports(context.Background(), batch, badKeys, true); err == nil {
		t.Fatal("mixed invalid batch accepted")
	}
	after, _ := os.ReadFile(store.path)
	if !bytes.Equal(before, after) {
		t.Fatal("rejected batch changed original bytes")
	}
	if err := store.mergeReports(context.Background(), batch, keys, true); err != nil {
		t.Fatal(err)
	}
	if err := store.Put(sign("demo-a", 2, 2), keys[reportOwner{"demo-network", "demo-a"}]); !errors.Is(err, ErrReportReplay) {
		t.Fatal("unknown lower position accepted", err)
	}
	if _, err := store.readReports(context.Background(), []string{oldID}); err == nil {
		t.Fatal("directory hint authenticated a corrupt requested original")
	}
	// Repair only this test fixture, then prove a late old fork remains evidence.
	if err := store.withDatabase(context.Background(), true, func(tx *bolt.Tx) error { return tx.Bucket(observationBucket).Put(oldKey, oldRaw) }); err != nil {
		t.Fatal(err)
	}
	fork := sign("demo-a", 1, 2)
	if err := store.Put(fork, keys[reportOwner{"demo-network", "demo-a"}]); !errors.Is(err, ErrReportEquivocation) {
		t.Fatal("old fork was lost", err)
	}
	store.cache.clear()
	latest, err = store.Latest(context.Background())
	if err != nil || len(latest) != 2 || latest[0].ReportSequence != 5 || latest[1].ReportSequence != 5 {
		t.Fatal("latest positions changed after cache loss", err)
	}
	// Compare canonical sorted history; insertion order is not an authority.
	expected := append(append(originals, batch...), fork)
	sort.Slice(expected, func(i, j int) bool {
		a, _ := CanonicalEncode(expected[i])
		b, _ := CanonicalEncode(expected[j])
		return reportBefore(expected[i], a, expected[j], b)
	})
	want, err := CanonicalEncode(observationState{Schema: 3, Reports: expected})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(want, testObservationBytes(t, store)) {
		t.Fatal("batch or fork changed or missing after reopening")
	}
}
