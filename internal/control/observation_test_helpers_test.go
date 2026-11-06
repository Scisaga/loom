package control

import (
	"bytes"
	"context"
	"errors"
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
	type original struct {
		report DeviceReport
		body   []byte
	}
	originals := []original{}
	codec := newContractCodec()
	err := store.withDatabase(context.Background(), false, func(tx *bolt.Tx) error {
		return tx.Bucket(observationBucket).ForEach(func(_, raw []byte) error {
			var report DeviceReport
			if err := decodeStoredReportWithCodec(raw, &report, codec); err != nil {
				return err
			}
			// Decode still validates every original. Its exact canonical bytes
			// determine fork order without re-encoding on every comparison.
			originals = append(originals, original{report, bytes.Clone(raw)})
			return nil
		})
	})
	if err != nil {
		return nil
	}
	sort.Slice(originals, func(i, j int) bool {
		return reportBefore(originals[i].report, originals[i].body, originals[j].report, originals[j].body)
	})
	result := make([]DeviceReport, len(originals))
	for i, original := range originals {
		result[i] = original.report
	}
	return result
}

// Progress assertions need the number actually committed, independently of a
// derived index. Final history assertions still decode and compare all originals.
func testReportCount(t *testing.T, store *ObservationStore) int {
	t.Helper()
	count := 0
	err := store.withDatabase(context.Background(), false, func(tx *bolt.Tx) error {
		return tx.Bucket(observationBucket).ForEach(func(_, raw []byte) error {
			if raw == nil {
				return errors.New("original report bucket contains a child bucket")
			}
			count++
			return nil
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	return count
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

func testOpenObservationStore(t *testing.T, root string, keys ...map[reportOwner]string) (*ObservationStore, error) {
	t.Helper()
	var store *ObservationStore
	var err error
	if len(keys) == 0 {
		store, err = OpenObservationStore(root)
	} else {
		store, err = openObservationStore(root, func() (map[reportOwner]string, error) { return keys[0], nil })
	}
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
func testSetObservationReports(t *testing.T, source any, reports []DeviceReport, publicKeys ...string) {
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
		if err := ensureReportIndexes(tx); err != nil {
			return err
		}
		if err := ensureReportMeasurementIndex(context.Background(), tx); err != nil {
			return err
		}
		if _, err := tx.Bucket(reportIndexBucket).CreateBucket(reportCountersBucket); err != nil {
			return err
		}
		for _, report := range reports {
			verified := ""
			for _, public := range publicKeys {
				if report.Verify(public) == nil {
					verified = public
					break
				}
			}
			if verified == "" {
				t.Fatal("report fixture requires its explicit signing public key")
			}
			raw, err := CanonicalEncode(report)
			if err != nil {
				return err
			}
			if err := indexReportCounters(tx, referenceOf(report).key(ReleaseDigest(raw)), report, verified); err != nil {
				return err
			}
		}
		if tx.Bucket(reportReceptionBucket) != nil {
			return ensureReportEventIndex(context.Background(), tx)
		}
		return nil
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
	codec := newContractCodec()
	err := store.withDatabase(context.Background(), false, func(tx *bolt.Tx) error {
		return tx.Bucket(observationBucket).ForEach(func(key, raw []byte) error {
			var report DeviceReport
			if err := decodeStoredReportWithCodec(raw, &report, codec); err != nil {
				return err
			}
			id, ref := ReleaseDigest(raw), referenceOf(report)
			if !bytes.Equal(ref.key(id), key) {
				return errors.New("report storage key does not match its canonical signed value")
			}
			result.reports[id] = ref
			group := storedReportRange{ref.NetworkID, reportScope{ref.DeviceID, reportRangeStart(ref.ReportSequence), reportLeafHeight}}
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
