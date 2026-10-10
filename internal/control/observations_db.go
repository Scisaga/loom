package control

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"
	"golang.org/x/sync/semaphore"
)

var observationBucket = []byte("reports")

// A disposable location in the original report collection. No report body,
// independent high-water mark, authority or lifecycle is stored here.
type reportReference struct {
	CounterAt      *int64 // Original sample time, only a deletable query hint.
	NetworkID      string
	DeviceID       string
	ReportSequence U64
	ReportedAt     int64 // Original signed timestamp; disposable query hint.
	LinkSamples    []linkSampleReference
}

// Only original scope and time, used to decide which bodies need decoding.
type linkSampleReference struct {
	LinkID     string
	SpecDigest string
	ObservedAt int64
}

func referenceOf(report DeviceReport) reportReference {
	ref := reportReference{NetworkID: report.NetworkID, DeviceID: report.DeviceID, ReportSequence: report.ReportSequence, ReportedAt: report.ReportedAt}
	if report.WireGuardCounters != nil {
		at := report.WireGuardCounters.ObservedAt
		ref.CounterAt = &at
	}
	for _, sample := range report.Observations {
		if sample.Level == "link" {
			ref.LinkSamples = append(ref.LinkSamples, linkSampleReference{sample.LinkID, sample.SpecDigest, sample.ObservedAt})
		}
	}
	return ref
}

func (ref reportReference) equal(other reportReference) bool {
	return ((ref.CounterAt == nil && other.CounterAt == nil) || (ref.CounterAt != nil && other.CounterAt != nil && *ref.CounterAt == *other.CounterAt)) && ref.NetworkID == other.NetworkID && ref.DeviceID == other.DeviceID && ref.ReportSequence == other.ReportSequence && ref.ReportedAt == other.ReportedAt && slices.Equal(ref.LinkSamples, other.LinkSamples)
}

func (ref reportReference) key(id string) []byte {
	key := append([]byte(ref.NetworkID+"\x00"+ref.DeviceID+"\x00"), make([]byte, 8)...)
	binary.BigEndian.PutUint64(key[len(key)-8:], uint64(ref.ReportSequence))
	digest, _ := hex.DecodeString(strings.TrimPrefix(id, "sha256:"))
	return append(key, digest...)
}

func decodeStoredReport(raw []byte, report *DeviceReport) error {
	return DecodeCanonical(raw, report, ContractDecodeLimits{MaxBytes: controlHTTPBodyLimit, MaxDepth: 128, MaxItems: 1 << 20})
}

func reportRecord(key, raw []byte, cached *reportIndex) (string, reportReference, error) {
	var empty reportReference
	if len(raw) == 0 || len(raw) > controlHTTPBodyLimit {
		return "", empty, errors.New("stored report exceeds its input boundary")
	}
	id := ReleaseDigest(raw)
	if cached != nil {
		if ref, ok := cached.reports[id]; ok && bytes.Equal(ref.key(id), key) {
			return id, ref, nil
		}
	}
	var report DeviceReport
	if err := decodeStoredReport(raw, &report); err != nil {
		return "", empty, err
	}
	ref := referenceOf(report)
	if !bytes.Equal(ref.key(id), key) {
		return "", empty, errors.New("report storage key does not match its canonical signed value")
	}
	return id, ref, nil
}

func rejectObservationJSON(root string) error {
	if _, err := os.Lstat(filepath.Join(root, "observations.json")); !errors.Is(err, os.ErrNotExist) {
		return errors.New("JSON observation container still exists; explicit verified report migration is required")
	}
	return nil
}

func observationStructure(tx *bolt.Tx) error {
	count := 0
	err := tx.ForEach(func(name []byte, bucket *bolt.Bucket) error {
		count++
		if !bytes.Equal(name, observationBucket) || bucket.Sequence() != 0 {
			return errors.New("unknown observation bucket or independent sequence")
		}
		return nil
	})
	if err != nil {
		return err
	}
	if count != 1 {
		return errors.New("original report bucket is missing")
	}
	return nil
}

// No process-lifetime DB registry: each bounded operation opens and closes its
// own handle. OpenFile removes CREATE and checks the same protected inode before
// bbolt can initialize, map or mutate it. The DB file lock serializes independent
// processes; the existing report writer lock also covers migration.
func withObservationDB(ctx context.Context, path string, writable bool, fn func(*bolt.Tx) error) (retErr error) {
	if err := rejectObservationJSON(filepath.Dir(path)); err != nil {
		return err
	}
	return withReportDatabase(ctx, path, writable, fn)
}

func (store *ObservationStore) withDatabase(ctx context.Context, writable bool, fn func(*bolt.Tx) error) error {
	if err := rejectObservationJSON(filepath.Dir(store.path)); err != nil {
		return err
	}
	return withReportDatabaseAccess(ctx, store.path, writable, store.databaseAccess, fn)
}

func withReportDatabase(ctx context.Context, path string, writable bool, fn func(*bolt.Tx) error) (retErr error) {
	return withReportDatabaseAccess(ctx, path, writable, nil, fn)
}

func withReportDatabaseAccess(ctx context.Context, path string, writable bool, access *semaphore.Weighted, fn func(*bolt.Tx) error) (retErr error) {
	entry, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !controlPrivateRegular(entry) || entry.Size() == 0 {
		return errors.New("observation database must be a nonempty protected regular file")
	}
	lockContext, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if access != nil {
		weight := int64(1)
		if writable {
			weight = math.MaxInt64
		}
		// A queued writer prevents later readers from overtaking it. Admission
		// and the file lock share the original timeout; neither extends it.
		if err := access.Acquire(lockContext, weight); err != nil {
			return err
		}
		defer access.Release(weight)
	}
	options := &bolt.Options{ReadOnly: !writable, Timeout: 50 * time.Millisecond}
	options.OpenFile = func(name string, flags int, mode os.FileMode) (*os.File, error) {
		file, err := os.OpenFile(name, flags&^os.O_CREATE, mode)
		if err != nil {
			return nil, err
		}
		info, a := file.Stat()
		current, b := os.Lstat(name)
		if a != nil || b != nil || !controlPrivateRegular(info) || !controlPrivateRegular(current) || !os.SameFile(entry, info) || !os.SameFile(info, current) {
			file.Close()
			return nil, errors.New("observation database changed while opening")
		}
		return file, nil
	}
	var db *bolt.DB
	for {
		if err := lockContext.Err(); err != nil {
			return err
		}
		db, err = bolt.Open(path, 0o600, options)
		if !errors.Is(err, bolt.ErrTimeout) {
			break
		}
		// bbolt may return immediately when its timeout is no greater than
		// its own retry interval. Do not turn contention into an open loop.
		select {
		case <-lockContext.Done():
			return lockContext.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
	if err != nil {
		return err
	}
	defer func() { retErr = errors.Join(retErr, db.Close()) }()
	operation := func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := observationStructure(tx); err != nil {
			return err
		}
		if err := fn(tx); err != nil {
			return err
		}
		return ctx.Err()
	}
	if writable {
		return db.Update(operation)
	}
	return db.View(operation)
}

func initializeObservationDB(path string) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".observations-*")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if err := file.Close(); err != nil {
		return err
	}
	db, err := bolt.Open(temporary, 0o600, nil)
	if err != nil {
		return err
	}
	err = db.Update(func(tx *bolt.Tx) error { _, err := tx.CreateBucket(observationBucket); return err })
	err = errors.Join(err, db.Close())
	if err != nil {
		return err
	}
	if err := os.Link(temporary, path); err != nil {
		return err
	}
	if err := os.Remove(temporary); err != nil {
		return err
	}
	return syncControlDirectory(filepath.Dir(path))
}

func scanObservationIndex(ctx context.Context, tx *bolt.Tx, cached *reportIndex) (*reportIndex, error) {
	if cached != nil {
		count, unchanged := 0, true
		err := tx.Bucket(observationBucket).ForEach(func(key, raw []byte) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			id, ref, err := reportRecord(key, raw, cached)
			if err != nil {
				return err
			}
			count++
			if prior, ok := cached.reports[id]; !ok || !prior.equal(ref) {
				unchanged = false
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		if unchanged && count == len(cached.reports) {
			return cached, nil
		}
	}
	// Rebuild only after a content change, in the same committed snapshot.
	// The checked fast path still hashes and checks every original and key.
	result := emptyReportIndex()
	err := tx.Bucket(observationBucket).ForEach(func(key, raw []byte) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		id, ref, err := reportRecord(key, raw, cached)
		if err != nil {
			return err
		}
		result.reports[id] = ref
		return nil
	})
	if err != nil {
		return nil, err
	}
	if err := result.rebuildGroups(); err != nil {
		return nil, err
	}
	return result, nil
}

func (store *ObservationStore) readReports(ctx context.Context, ids []string) (map[string]DeviceReport, error) {
	result := map[string]DeviceReport{}
	err := store.withDatabase(ctx, false, func(tx *bolt.Tx) error {
		index, err := scanObservationIndex(ctx, tx, store.index.Load())
		if err != nil {
			return err
		}
		used := len(observationPrefix) + len(observationSuffix)
		for _, id := range ids {
			ref, found := index.reports[id]
			if !found {
				return errors.New("requested report is absent")
			}
			raw := tx.Bucket(observationBucket).Get(ref.key(id))
			if used+len(raw)+1 > reportBatchBytes {
				break
			}
			used += len(raw) + 1
			var report DeviceReport
			if err := decodeStoredReport(raw, &report); err != nil {
				return err
			}
			result[id] = report
		}
		store.index.Store(index)
		return nil
	})
	return result, err
}
