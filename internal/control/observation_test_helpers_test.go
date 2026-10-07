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
	err := withObservationDB(context.Background(), store.path, false, func(tx *bolt.Tx) error {
		if _, err := scanObservationIndex(context.Background(), tx, store.index.Load()); err != nil {
			return err
		}
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

func testObservationBytes(t *testing.T, root string) []byte {
	t.Helper()
	store, err := OpenObservationStore(root)
	if err != nil {
		t.Fatal(err)
	}
	body, err := CanonicalEncode(observationState{Schema: 3, Reports: store.History()})
	if err != nil {
		t.Fatal(err)
	}
	return body
}
func testSetObservationReports(t *testing.T, root string, reports []DeviceReport) {
	t.Helper()
	path := filepath.Join(root, "observations.db")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		if err := initializeObservationDB(path); err != nil {
			t.Fatal(err)
		}
	}
	err := withReportDatabase(context.Background(), path, true, func(tx *bolt.Tx) error {
		if err := tx.DeleteBucket(observationBucket); err != nil {
			return err
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
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
func testCorruptReport(t *testing.T, path string, transform func([]byte) []byte) {
	t.Helper()
	err := withReportDatabase(context.Background(), path, true, func(tx *bolt.Tx) error {
		b := tx.Bucket(observationBucket)
		key, raw := b.Cursor().First()
		return b.Put(append([]byte{}, key...), transform(append([]byte{}, raw...)))
	})
	if err != nil {
		t.Fatal(err)
	}
}
