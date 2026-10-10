package control

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"testing"

	bolt "go.etcd.io/bbolt"
)

func (store *ObservationStore) All() []DeviceReport {
	result, err := store.Latest(context.Background())
	if err != nil {
		return nil
	}
	return result
}
func (store *ObservationStore) History() []DeviceReport {
	result := []DeviceReport{}
	err := store.withDatabase(context.Background(), false, func(tx *bolt.Tx) error {
		return tx.Bucket(observationBucket).ForEach(func(_, raw []byte) error {
			var report DeviceReport
			if err := decodeStoredReport(raw, &report); err != nil {
				return err
			}
			result = append(result, report)
			return nil
		})
	})
	if err != nil {
		return nil
	}
	sort.Slice(result, func(i, j int) bool {
		a, _ := CanonicalEncode(result[i])
		b, _ := CanonicalEncode(result[j])
		return reportBefore(result[i], a, result[j], b)
	})
	return result
}
func (store *ObservationStore) Verified(projection Projection, releases ...ReleaseSet) []DeviceReport {
	result := []DeviceReport{}
	for _, report := range store.All() {
		if verifyCurrentReport(report, projection, releases...) == nil {
			result = append(result, report)
		}
	}
	return result
}

func testOpenObservationStore(t *testing.T, root string) (*ObservationStore, error) {
	t.Helper()
	store, err := OpenObservationStore(root)
	if err == nil {
		t.Cleanup(func() {
			if err := store.Close(); err != nil {
				t.Error(err)
			}
		})
	}
	return store, err
}
func testObservationBytes(t *testing.T, source any) []byte {
	t.Helper()
	var store *ObservationStore
	switch value := source.(type) {
	case *ObservationStore:
		store = value
	case string:
		var err error
		store, err = OpenObservationStore(value)
		if err != nil {
			t.Fatal(err)
		}
		defer store.Close()
	default:
		t.Fatal("invalid report fixture source")
	}
	body, err := CanonicalEncode(observationState{Schema: 3, Reports: store.History()})
	if err != nil {
		t.Fatal(err)
	}
	return body
}
func testSetObservationReports(t *testing.T, source any, reports []DeviceReport) {
	t.Helper()
	write := func(tx *bolt.Tx) error {
		if err := tx.DeleteBucket(observationBucket); err != nil {
			return err
		}
		if tx.Bucket(reportIndexBucket) != nil {
			if err := tx.DeleteBucket(reportIndexBucket); err != nil {
				return err
			}
		}
		b, err := tx.CreateBucket(observationBucket)
		if err != nil {
			return err
		}
		for _, report := range reports {
			raw, err := CanonicalEncode(report)
			if err != nil {
				return err
			}
			if err := b.Put(referenceOf(report).key(ReleaseDigest(raw)), raw); err != nil {
				return err
			}
		}
		return ensureReportIndexes(tx)
	}
	var err error
	switch value := source.(type) {
	case *ObservationStore:
		err = value.withDatabase(context.Background(), true, write)
	case string:
		path := filepath.Join(value, "observations.db")
		if _, statErr := os.Stat(path); os.IsNotExist(statErr) {
			if err := initializeObservationDB(path); err != nil {
				t.Fatal(err)
			}
		}
		err = withReportDatabase(context.Background(), path, true, write)
	default:
		t.Fatal("invalid report fixture source")
	}
	if err != nil {
		t.Fatal(err)
	}
}
func testCorruptReport(t *testing.T, store *ObservationStore, transform func([]byte) []byte) {
	t.Helper()
	err := store.withDatabase(context.Background(), true, func(tx *bolt.Tx) error {
		b := tx.Bucket(observationBucket)
		key, raw := b.Cursor().First()
		return b.Put(append([]byte{}, key...), transform(append([]byte{}, raw...)))
	})
	if err != nil {
		t.Fatal(err)
	}
}

// Full scans are confined to fixture assertions; production queries use indexes.
type testReportCollection struct {
	reports map[string]reportReference
	groups  map[storedReportRange][]string
	digests map[storedReportRange]string
}

func testCollectReports(t *testing.T, store *ObservationStore) *testReportCollection {
	t.Helper()
	result := &testReportCollection{reports: map[string]reportReference{}, groups: map[storedReportRange][]string{}, digests: map[storedReportRange]string{}}
	err := store.withDatabase(context.Background(), false, func(tx *bolt.Tx) error {
		return tx.Bucket(observationBucket).ForEach(func(key, raw []byte) error {
			id, ref, err := reportRecord(key, raw)
			if err != nil {
				return err
			}
			result.reports[id] = ref
			group := storedReportRange{ref.NetworkID, reportScope{ref.DeviceID, reportRangeStart(ref.ReportSequence)}}
			result.groups[group] = append(result.groups[group], id)
			return nil
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	for group, ids := range result.groups {
		sort.Strings(ids)
		raw, err := CanonicalEncode(ids)
		if err != nil {
			t.Fatal(err)
		}
		result.digests[group] = ReleaseDigest(raw)
	}
	return result
}
