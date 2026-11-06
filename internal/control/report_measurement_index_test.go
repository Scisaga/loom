package control

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"os"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func sharedMeasurementFixture(t *testing.T) (*ObservationStore, string, time.Time, Observation, reportMeasurementQuery, func(U64, string, string, []Observation) DeviceReport) {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	store, err := testOpenObservationStore(t, root)
	if err != nil {
		t.Fatal(err)
	}
	key := testKey(t)
	public := base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
	at := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	sample := Observation{Level: "egress", Target: "https://demo-service.example/health", Action: "https_request",
		SpecDigest: ReleaseDigest([]byte("demo-egress-spec")), NetworkGeneration: "demo-network-a", Result: "available",
		ObservedAt: at.UnixMilli(), ValidUntil: at.Add(10 * time.Minute).UnixMilli(), DurationMS: new(int64(10))}
	query := reportMeasurementQuery{"demo-egress", public, sample}
	sign := func(sequence U64, generation, runtime string, values []Observation) DeviceReport {
		t.Helper()
		digest := ReleaseDigest([]byte("demo-view"))
		readback := RuntimeReadback{State: runtime}
		if runtime == "running" {
			readback.AppliedViewDigest = digest
		}
		report, err := SignDeviceReport(DeviceReport{Schema: 3, NetworkID: "demo-network", DeviceID: query.source,
			ReportSequence: sequence, ViewDigest: digest, NetworkGeneration: generation,
			ReportedAt: at.Add(time.Duration(sequence) * time.Second).UnixMilli(), Runtime: readback,
			Selections: []ReportSelection{}, Observations: append([]Observation{}, values...), Components: []ComponentReadback{}}, key)
		if err != nil {
			t.Fatal(err)
		}
		return report
	}
	return store, root, at, sample, query, sign
}

func TestSharedMeasurementsSurviveOmissionDuplicatesAndOutOfOrderReports(t *testing.T) {
	store, _, at, first, query, sign := sharedMeasurementFixture(t)
	put := func(report DeviceReport) {
		t.Helper()
		if err := store.Put(report, query.publicKey); err != nil {
			t.Fatal(err)
		}
	}
	original := sign(1, first.NetworkGeneration, "running", []Observation{first})
	put(original)
	put(sign(3, first.NetworkGeneration, "running", nil))
	read := func(want U64, sample Observation) {
		t.Helper()
		rows, err := store.latestMeasurements(context.Background(), "demo-network", []reportMeasurementQuery{query, query}, at.Add(20*time.Second))
		if err != nil || len(rows) != 1 || rows[0].ReportSequence != want || rows[0].Observation.ObservedAt != sample.ObservedAt ||
			rows[0].CurrentUntil != sample.ValidUntil || rows[0].Observation.ValidUntil != sample.ValidUntil {
			t.Fatal("measurement was lost, duplicated or renewed", err, rows)
		}
	}
	read(1, first)
	second := first
	second.ObservedAt += 2000
	second.ValidUntil += 2000
	second.DurationMS = new(int64(5))
	late := sign(2, first.NetworkGeneration, "running", []Observation{second})
	if err := store.mergeReports(context.Background(), []DeviceReport{late}, map[reportOwner]string{{"demo-network", query.source}: query.publicKey}, true); err != nil {
		t.Fatal(err)
	}
	read(2, second)
	put(sign(4, first.NetworkGeneration, "running", []Observation{first}))
	read(2, second)
	put(sign(5, first.NetworkGeneration, "running", []Observation{second}))
	read(2, second)
	// A new metadata-only report outlives the original report's UI window,
	// while the sample still has its unchanged original ten-minute window.
	put(sign(240, first.NetworkGeneration, "running", nil))
	rows, err := store.latestMeasurements(context.Background(), "demo-network", []reportMeasurementQuery{query}, at.Add(250*time.Second))
	if err != nil || len(rows) != 1 || rows[0].ReportSequence != 2 || rows[0].Observation.ObservedAt != second.ObservedAt {
		t.Fatal("a fresh runtime report required remeasuring an unchanged sample", err)
	}
}

func TestSharedMeasurementsDoNotReviveExpiredConflictingOrOtherNetworkResults(t *testing.T) {
	for _, scenario := range []string{"expired failure", "equal-time conflict", "network changed", "source stopped", "highest fork", "sample fork"} {
		t.Run(scenario, func(t *testing.T) {
			store, _, at, sample, query, sign := sharedMeasurementFixture(t)
			if err := store.Put(sign(1, sample.NetworkGeneration, "running", []Observation{sample}), query.publicKey); err != nil {
				t.Fatal(err)
			}
			changed := sample
			changed.DurationMS = new(int64(5))
			if scenario == "expired failure" || scenario == "equal-time conflict" {
				changed.Result = "unavailable"
				changed.ValidUntil = changed.ObservedAt + 30_000
			}
			if scenario != "equal-time conflict" {
				changed.ObservedAt += 1000
				changed.ValidUntil += 1000
			}
			if err := store.Put(sign(2, sample.NetworkGeneration, "running", []Observation{changed}), query.publicKey); err != nil {
				t.Fatal(err)
			}
			generation, state := sample.NetworkGeneration, "running"
			if scenario == "network changed" {
				generation = "demo-network-b"
			}
			if scenario == "source stopped" {
				state = "stopped"
			}
			head := sign(3, generation, state, nil)
			if err := store.Put(head, query.publicKey); err != nil {
				t.Fatal(err)
			}
			if scenario == "highest fork" || scenario == "sample fork" {
				sequence := U64(3)
				if scenario == "sample fork" {
					sequence = 2
				}
				fork := sign(sequence, sample.NetworkGeneration, "stopped", nil)
				if err := store.Put(fork, query.publicKey); !errors.Is(err, ErrReportEquivocation) {
					t.Fatal("fork evidence did not survive", err)
				}
			}
			rows, err := store.latestMeasurements(context.Background(), "demo-network", []reportMeasurementQuery{query}, at.Add(40*time.Second))
			if err != nil || len(rows) != 0 {
				t.Fatal("an older success or another generation replaced unknown", scenario, err, rows)
			}
		})
	}
}

func TestSharedMeasurementLocationsRebuildWithoutChangingOriginals(t *testing.T) {
	store, root, at, sample, query, sign := sharedMeasurementFixture(t)
	if err := store.Put(sign(1, sample.NetworkGeneration, "running", []Observation{sample}), query.publicKey); err != nil {
		t.Fatal(err)
	}
	originals := testObservationBytes(t, store)
	if err := store.withDatabase(context.Background(), true, func(tx *bolt.Tx) error {
		return tx.Bucket(reportIndexBucket).DeleteBucket(reportMeasurementBucket)
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.latestMeasurements(context.Background(), "demo-network", []reportMeasurementQuery{query}, at.Add(time.Second)); err == nil {
		t.Fatal("missing locations silently used a history scanning fallback")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := testOpenObservationStore(t, root)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := restarted.latestMeasurements(context.Background(), "demo-network", []reportMeasurementQuery{query}, at.Add(time.Second))
	if err != nil || len(rows) != 1 || rows[0].ReportSequence != 1 || !bytes.Equal(originals, testObservationBytes(t, restarted)) {
		t.Fatal("index reconstruction changed originals or lost the sample", err)
	}
}

func TestSharedMeasurementLookupChecksOnlyItsOriginalAndRejectsTampering(t *testing.T) {
	store, _, at, sample, query, sign := sharedMeasurementFixture(t)
	report := sign(1, sample.NetworkGeneration, "running", []Observation{sample})
	if err := store.Put(report, query.publicKey); err != nil {
		t.Fatal(err)
	}
	key := testKey(t)
	other := report
	other.DeviceID = "demo-unrelated-source"
	other, err := SignDeviceReport(other, key)
	if err != nil {
		t.Fatal(err)
	}
	otherPublic := base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
	if err := store.Put(other, otherPublic); err != nil {
		t.Fatal(err)
	}
	corrupt := func(value DeviceReport) {
		t.Helper()
		body, _ := CanonicalEncode(value)
		if err := store.withDatabase(context.Background(), true, func(tx *bolt.Tx) error {
			return tx.Bucket(observationBucket).Put(referenceOf(value).key(ReleaseDigest(body)), []byte("damaged"))
		}); err != nil {
			t.Fatal(err)
		}
	}
	corrupt(other)
	rows, err := store.latestMeasurements(context.Background(), "demo-network", []reportMeasurementQuery{query}, at.Add(time.Second))
	if err != nil || len(rows) != 1 {
		t.Fatal("a scoped lookup decoded unrelated report history", err)
	}
	corrupt(report)
	if _, err := store.latestMeasurements(context.Background(), "demo-network", []reportMeasurementQuery{query}, at.Add(time.Second)); err == nil {
		t.Fatal("a cached verification hid a changed original")
	}
}
