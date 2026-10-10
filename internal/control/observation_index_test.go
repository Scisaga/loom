package control

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"path/filepath"
	"testing"

	bolt "go.etcd.io/bbolt"
)

func TestReportIndexesRebuildWithoutChangingOriginals(t *testing.T) {
	store, reports, public := admissionReports(t)
	if err := store.Put(reports[1], public); err != nil {
		t.Fatal(err)
	}
	before := testObservationBytes(t, store)
	raw, _ := CanonicalEncode(reports[1])
	if _, err := store.verifiedReport(raw, public); err != nil {
		t.Fatal(err)
	}
	other := testKey(t)
	if _, err := store.verifiedReport(raw, base64.RawURLEncoding.EncodeToString(other.Public().(ed25519.PublicKey))); err == nil {
		t.Fatal("cached signature accepted a different key")
	}
	if _, err := store.verifiedReport(raw, ""); err == nil {
		t.Fatal("cached parse became a signature")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if err := withReportDatabase(context.Background(), store.path, true, func(tx *bolt.Tx) error { return tx.DeleteBucket(reportIndexBucket) }); err != nil {
		t.Fatal(err)
	}
	rebuilt, err := testOpenObservationStore(t, filepath.Dir(store.path))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, testObservationBytes(t, rebuilt)) {
		t.Fatal("index rebuild changed signed originals")
	}
	known, err := rebuilt.knownReports(context.Background(), []string{ReleaseDigest(raw)})
	if err != nil || len(known) != 1 || known[ReleaseDigest(raw)].ReportSequence != 2 {
		t.Fatal("content location was not rebuilt", err)
	}
	seen := []U64{}
	err = rebuilt.walkDeviceHistorySnapshot(context.Background(), "demo-network", "demo-device", func(_ U64, ref reportReference, _ []byte) error { seen = append(seen, ref.ReportSequence); return nil }, reportHistoryWindow{kind: reportTime, from: 2, until: 2})
	if err != nil || len(seen) != 1 || seen[0] != 2 {
		t.Fatal("time window was not rebuilt", seen, err)
	}
}

func TestReportWindowDoesNotReadUnrelatedHistoricalBodies(t *testing.T) {
	store, reports, public := admissionReports(t)
	if err := store.Put(reports[1], public); err != nil {
		t.Fatal(err)
	}
	old, _ := CanonicalEncode(reports[0])
	key := referenceOf(reports[0]).key(ReleaseDigest(old))
	if err := store.withDatabase(context.Background(), true, func(tx *bolt.Tx) error { return tx.Bucket(observationBucket).Put(key, append(bytes.Clone(old), '\n')) }); err != nil {
		t.Fatal(err)
	}
	seen := 0
	err := store.walkDeviceHistorySnapshot(context.Background(), "demo-network", "demo-device", func(_ U64, ref reportReference, raw []byte) error {
		seen++
		if ref.ReportSequence != 2 {
			t.Fatal("window included unrelated history")
		}
		_, err := store.verifiedReport(raw, public)
		return err
	}, reportHistoryWindow{kind: reportTime, from: 2, until: 2})
	if err != nil || seen != 1 {
		t.Fatal("window audited unrelated historical bytes", seen, err)
	}
	if _, err := store.readReports(context.Background(), []string{ReleaseDigest(old)}); err == nil {
		t.Fatal("explicit old-original read ignored corruption")
	}
	if err := store.withDatabase(context.Background(), true, func(tx *bolt.Tx) error { return tx.Bucket(observationBucket).Put(key, old) }); err != nil {
		t.Fatal(err)
	}
}
