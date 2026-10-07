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

	bolt "go.etcd.io/bbolt"
)

func TestObservationTransactionsExceedFormerAggregateCapacity(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
	public := base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
	digest := "sha256:" + strings.Repeat("0", 64)
	report := DeviceReport{Schema: 3, NetworkID: "demo-network", DeviceID: "demo-device", ViewDigest: digest, NetworkGeneration: "demo-underlay", ReportedAt: 1,
		Selections: []ReportSelection{{ServiceID: "demo-a", CandidateID: digest}, {ServiceID: "demo-b", CandidateID: digest}, {ServiceID: "demo-c", CandidateID: digest}, {ServiceID: "demo-d", CandidateID: digest}}, Observations: []Observation{}, Runtime: RuntimeReadback{State: "running", AppliedViewDigest: digest}, Components: []ComponentReadback{}}
	sign := func(sequence U64) DeviceReport {
		t.Helper()
		report.ReportSequence = sequence
		value, err := SignDeviceReport(report, key)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "observations.db")
	if err := initializeObservationDB(path); err != nil {
		t.Fatal(err)
	}
	originals := map[string]bool{}
	total := 0
	var high U64
	// Build a real signed history beyond the former total-file bound without a
	// second whole-history byte buffer. This is fixture setup, not a runtime gate.
	db, err := bolt.Open(path, 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	err = db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(observationBucket)
		for total <= maxControlInputBytes+4096 {
			high += 2
			value := sign(high)
			raw, err := CanonicalEncode(value)
			if err != nil {
				return err
			}
			id := ReleaseDigest(raw)
			originals[id] = true
			total += len(raw)
			if err := b.Put(referenceOf(value).key(id), raw); err != nil {
				return err
			}
		}
		return nil
	})
	err = errors.Join(err, db.Close())
	if err != nil {
		t.Fatal(err)
	}
	store, err := OpenObservationStore(root)
	if err != nil {
		t.Fatal("large accepted history prevented restart", err)
	}
	if latest := store.All(); len(latest) != 1 || latest[0].ReportSequence != high {
		t.Fatal("restart lost the original high-water report")
	}
	if err := store.Put(sign(2), public); err != nil {
		t.Fatal("exact original retry lost idempotence", err)
	}
	if err := store.Put(sign(3), public); !errors.Is(err, ErrReportReplay) {
		t.Fatal("unknown lower sequence was accepted", err)
	}
	report.NetworkGeneration = "demo-another-underlay"
	fork := sign(2)
	if err := store.Put(fork, public); !errors.Is(err, ErrReportEquivocation) {
		t.Fatal("old fork was not preserved", err)
	}
	next := sign(high + 2)
	if err := store.Put(next, public); err != nil {
		t.Fatal("valid report beyond former capacity was rejected", err)
	}
	restarted, err := OpenObservationStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if latest := restarted.All(); len(latest) != 1 || latest[0].ReportSequence != high+2 {
		t.Fatal("large history append was not durable")
	}
	index, err := restarted.reportIndexSnapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(index.reports) != len(originals)+2 {
		t.Fatal("old fork or latest append was lost")
	}
	for id := range originals {
		if _, ok := index.reports[id]; !ok {
			t.Fatal("an original signed report changed")
		}
	}
	before := index
	sentinel := errors.New("demo transaction failure")
	err = withObservationDB(context.Background(), path, true, func(tx *bolt.Tx) error {
		value := sign(high + 4)
		raw, _ := CanonicalEncode(value)
		if err := tx.Bucket(observationBucket).Put(referenceOf(value).key(ReleaseDigest(raw)), raw); err != nil {
			return err
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatal(err)
	}
	after, err := restarted.reportIndexSnapshot(context.Background())
	if err != nil || len(before.reports) != len(after.reports) {
		t.Fatal("failed transaction partially committed", err)
	}
	for id := range before.reports {
		if _, ok := after.reports[id]; !ok {
			t.Fatal("failed transaction changed original bytes")
		}
	}
}
