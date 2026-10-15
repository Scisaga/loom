package control

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

type eventIndexSample struct {
	sequence U64
	at       int64 // zero denotes an existing original without reception metadata
	runtime  RuntimeReadback
	variant  int64
}

func eventIndexReport(t *testing.T, private ed25519.PrivateKey, sample eventIndexSample) DeviceReport {
	t.Helper()
	runtime := sample.runtime
	if runtime.State == "" {
		runtime.State = "stopped"
	}
	report, err := SignDeviceReport(DeviceReport{
		Schema: 3, NetworkID: "demo-network", DeviceID: "demo-device", ReportSequence: sample.sequence,
		ViewDigest: "sha256:" + strings.Repeat("0", 64), NetworkGeneration: "demo-underlay", ReportedAt: sample.variant + 1,
		Selections: []ReportSelection{}, Observations: []Observation{}, Components: []ComponentReadback{}, Runtime: runtime,
	}, private)
	if err != nil {
		t.Fatal(err)
	}
	return report
}

func eventIndexFixture(t *testing.T, samples []eventIndexSample) (*ObservationStore, []DeviceReport, string) {
	t.Helper()
	private := testKey(t)
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	reports := make([]DeviceReport, len(samples))
	for i, sample := range samples {
		reports[i] = eventIndexReport(t, private, sample)
	}
	testSetObservationReports(t, root, reports)
	store, err := testOpenObservationStore(t, root)
	if err != nil {
		t.Fatal(err)
	}
	err = store.withDatabase(context.Background(), true, func(tx *bolt.Tx) error {
		for i, sample := range samples {
			if sample.at == 0 {
				continue
			}
			raw, _ := CanonicalEncode(reports[i])
			if err := receiveReport(tx, referenceOf(reports[i]).key(ReleaseDigest(raw)), time.Unix(0, sample.at)); err != nil {
				return err
			}
		}
		return rebuildReportEventIndex(context.Background(), tx)
	})
	if err != nil {
		t.Fatal(err)
	}
	return store, reports, base64.RawURLEncoding.EncodeToString(private.Public().(ed25519.PublicKey))
}

func eventIndexLocations(t *testing.T, store *ObservationStore) map[string]string {
	t.Helper()
	result := map[string]string{}
	err := store.withDatabase(context.Background(), false, func(tx *bolt.Tx) error {
		index := tx.Bucket(reportIndexBucket).Bucket(reportEventIndexBucket)
		if index == nil {
			return errors.New("missing candidate index")
		}
		return index.ForEach(func(key, value []byte) error {
			result[string(key)] = string(value)
			return nil
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func eventIndexSequences(t *testing.T, store *ObservationStore) []U64 {
	t.Helper()
	sequences := []U64{}
	for key, value := range eventIndexLocations(t, store) {
		if key[0] != 'e' {
			continue
		}
		prefix := receptionIndexPrefix("demo-network")
		if value != "" || !strings.HasPrefix(key, string(prefix)) {
			t.Fatal("candidate contains data rather than a location")
		}
		_, ref, err := locateReportKey([]byte(key)[len(prefix)+8:])
		if err != nil {
			t.Fatal(err)
		}
		sequences = append(sequences, ref.ReportSequence)
	}
	sort.Slice(sequences, func(i, j int) bool { return sequences[i] < sequences[j] })
	return sequences
}

func TestReportEventIndexUniqueIntervals(t *testing.T) {
	digest := "sha256:" + strings.Repeat("1", 64)
	running := RuntimeReadback{State: "running", AppliedViewDigest: digest}
	failed := RuntimeReadback{State: "error", ErrorCode: "demo-failure"}
	tests := []struct {
		name    string
		samples []eventIndexSample
		want    []U64
	}{
		{"unchanged", []eventIndexSample{{1, 100, RuntimeReadback{}, 0}, {2, 200, RuntimeReadback{}, 1}}, []U64{1}},
		{"three-scalars", []eventIndexSample{{1, 100, RuntimeReadback{}, 0}, {2, 200, running, 1}, {3, 300, RuntimeReadback{State: "running", AppliedViewDigest: "sha256:" + strings.Repeat("2", 64)}, 2}, {4, 400, failed, 3}}, []U64{1, 2, 3, 4}},
		{"fork-overlap", []eventIndexSample{{1, 100, RuntimeReadback{}, 0}, {1, 150, failed, 1}, {2, 140, running, 2}}, []U64{1, 2}},
		{"touching-is-empty", []eventIndexSample{{1, 100, RuntimeReadback{}, 0}, {1, 150, failed, 1}, {2, 150, running, 2}}, []U64{1}},
		{"earliest-tie", []eventIndexSample{{1, 100, RuntimeReadback{}, 0}, {1, 100, failed, 1}, {2, 200, running, 2}}, []U64{}},
		{"legacy-prior", []eventIndexSample{{1, 0, RuntimeReadback{}, 0}, {2, 200, running, 1}}, []U64{2}},
		{"legacy-annotated-overlap", []eventIndexSample{{1, 0, RuntimeReadback{}, 0}, {1, 150, failed, 1}, {2, 140, running, 2}}, []U64{2}},
		{"legacy-touching-is-empty", []eventIndexSample{{1, 0, RuntimeReadback{}, 0}, {1, 150, failed, 1}, {2, 150, running, 2}}, []U64{}},
		{"legacy-fork", []eventIndexSample{{1, 0, RuntimeReadback{}, 0}, {1, 0, failed, 1}, {2, 200, running, 2}}, []U64{}},
		{"gap", []eventIndexSample{{1, 100, RuntimeReadback{}, 0}, {3, 200, running, 1}}, []U64{1}},
		{"clock-backward", []eventIndexSample{{1, 100, RuntimeReadback{}, 0}, {1, 40, failed, 1}, {2, 50, RuntimeReadback{}, 2}}, []U64{1, 2}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store, _, _ := eventIndexFixture(t, test.samples)
			if got := eventIndexSequences(t, store); !reflect.DeepEqual(got, test.want) {
				t.Fatalf("candidate positions %v, want %v", got, test.want)
			}
		})
	}
}

func TestReportEventIndexBatchMaintenanceAndRebuild(t *testing.T) {
	private := testKey(t)
	public := base64.RawURLEncoding.EncodeToString(private.Public().(ed25519.PublicKey))
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	store, err := testOpenObservationStore(t, root)
	if err != nil {
		t.Fatal(err)
	}
	owner := reportOwner{"demo-network", "demo-device"}
	merge := func(at int64, samples ...eventIndexSample) {
		t.Helper()
		store.now = func() time.Time { return time.Unix(0, at) }
		reports := make([]DeviceReport, len(samples))
		for i, sample := range samples {
			reports[i] = eventIndexReport(t, private, sample)
		}
		err := store.mergeReports(context.Background(), reports, map[reportOwner]string{owner: public}, true)
		if err != nil && !errors.Is(err, ErrReportEquivocation) {
			t.Fatal(err)
		}
		before := eventIndexLocations(t, store)
		err = store.withDatabase(context.Background(), true, func(tx *bolt.Tx) error { return rebuildReportEventIndex(context.Background(), tx) })
		if err != nil || !reflect.DeepEqual(before, eventIndexLocations(t, store)) {
			t.Fatal("incremental locations differ from rebuild", err)
		}
	}
	merge(100, eventIndexSample{5, 0, RuntimeReadback{}, 0})
	if got := eventIndexSequences(t, store); !reflect.DeepEqual(got, []U64{5}) {
		t.Fatal("first accepted position was not a baseline", got)
	}
	merge(200, eventIndexSample{2, 0, RuntimeReadback{}, 1})
	if got := eventIndexSequences(t, store); !reflect.DeepEqual(got, []U64{2}) {
		t.Fatal("late lowest position did not remove distant old baseline", got)
	}
	merge(300, eventIndexSample{4, 0, RuntimeReadback{State: "error", ErrorCode: "demo-failure"}, 2}, eventIndexSample{3, 0, RuntimeReadback{}, 3})
	if got := eventIndexSequences(t, store); !reflect.DeepEqual(got, []U64{2, 4, 5}) {
		t.Fatal("batch did not use final predecessor set", got)
	}
	merge(40, eventIndexSample{2, 0, RuntimeReadback{State: "error", ErrorCode: "demo-failure"}, 4})
	if got := eventIndexSequences(t, store); !reflect.DeepEqual(got, []U64{2, 4, 5}) {
		t.Fatal("clock-backward fork maintenance differs", got)
	}
	merge(400, eventIndexSample{^U64(0), 0, RuntimeReadback{}, 5})
	before := eventIndexLocations(t, store)
	originals := testObservationBytes(t, store)
	receptions := eventIndexReceptionBytes(t, store)
	// An idempotent delivery cannot annotate legacy originals or rewrite times.
	merge(500, eventIndexSample{2, 0, RuntimeReadback{}, 1})
	if !reflect.DeepEqual(before, eventIndexLocations(t, store)) || !bytes.Equal(receptions, eventIndexReceptionBytes(t, store)) {
		t.Fatal("duplicate changed locations or reception annotations")
	}
	err = store.withDatabase(context.Background(), true, func(tx *bolt.Tx) error {
		return tx.Bucket(reportIndexBucket).DeleteBucket(reportEventIndexBucket)
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := testOpenObservationStore(t, filepath.Dir(store.path))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, eventIndexLocations(t, reopened)) || !bytes.Equal(originals, testObservationBytes(t, reopened)) || !bytes.Equal(receptions, eventIndexReceptionBytes(t, reopened)) {
		t.Fatal("startup rebuild changed locations, originals or reception annotations")
	}
}

func eventIndexReceptionBytes(t *testing.T, store *ObservationStore) []byte {
	t.Helper()
	var result []byte
	err := store.withDatabase(context.Background(), false, func(tx *bolt.Tx) error {
		return tx.Bucket(reportReceptionBucket).ForEach(func(key, value []byte) error {
			result = binary.BigEndian.AppendUint64(result, uint64(len(key)))
			result = append(result, key...)
			result = append(result, value...)
			return nil
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestReportEventIndexLateForkRecomputesSuccessor(t *testing.T) {
	private := testKey(t)
	public := base64.RawURLEncoding.EncodeToString(private.Public().(ed25519.PublicKey))
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	store, err := testOpenObservationStore(t, root)
	if err != nil {
		t.Fatal(err)
	}
	for _, sample := range []eventIndexSample{{1, 100, RuntimeReadback{}, 0}, {2, 50, RuntimeReadback{}, 1}, {1, 40, RuntimeReadback{State: "error", ErrorCode: "demo-failure"}, 2}} {
		store.now = func() time.Time { return time.Unix(0, sample.at) }
		err := store.Put(eventIndexReport(t, private, sample), public)
		if err != nil && !errors.Is(err, ErrReportEquivocation) {
			t.Fatal(err)
		}
	}
	if got := eventIndexSequences(t, store); !reflect.DeepEqual(got, []U64{1, 2}) {
		t.Fatal("clock-backward fork did not create successor candidate", got)
	}
	before := eventIndexLocations(t, store)
	err = store.withDatabase(context.Background(), true, func(tx *bolt.Tx) error { return rebuildReportEventIndex(context.Background(), tx) })
	if err != nil || !reflect.DeepEqual(before, eventIndexLocations(t, store)) {
		t.Fatal("late fork incremental candidates differ from rebuild", err)
	}
}

func TestReportEventIndexCancellationAndOriginalFailureAreAtomic(t *testing.T) {
	store, _, _ := eventIndexFixture(t, []eventIndexSample{{1, 100, RuntimeReadback{}, 0}})
	before := eventIndexLocations(t, store)
	ctx, cancel := context.WithCancel(context.Background())
	err := store.withDatabase(context.Background(), true, func(tx *bolt.Tx) error {
		cancel()
		return rebuildReportEventIndex(ctx, tx)
	})
	if !errors.Is(err, context.Canceled) || !reflect.DeepEqual(before, eventIndexLocations(t, store)) {
		t.Fatal("cancellation committed a partial candidate index", err)
	}
	err = store.withDatabase(context.Background(), true, func(tx *bolt.Tx) error {
		key, raw := tx.Bucket(observationBucket).Cursor().First()
		changed := bytes.Replace(raw, []byte(`"state":"stopped"`), []byte(`"state":"error"`), 1)
		return tx.Bucket(observationBucket).Put(key, changed)
	})
	if err != nil {
		t.Fatal(err)
	}
	err = store.withDatabase(context.Background(), true, func(tx *bolt.Tx) error { return rebuildReportEventIndex(context.Background(), tx) })
	if err == nil || !reflect.DeepEqual(before, eventIndexLocations(t, store)) {
		t.Fatal("changed original was accepted or replaced the old index", err)
	}
}
