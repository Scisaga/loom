package control

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"
)

var observationBucket = []byte("reports")
var reportIndexBucket = []byte("report-index")

// Original scope and time only; never authorization or a durable high-water mark.
type reportReference struct {
	CounterAt      *int64
	NetworkID      string
	DeviceID       string
	ReportSequence U64
	ReportedAt     int64
	LinkSamples    []linkSampleReference
}
type linkSampleReference struct {
	LinkID, SpecDigest string
	ObservedAt         int64
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
func (ref reportReference) key(id string) []byte {
	key := binary.BigEndian.AppendUint64(reportOwnerPrefix(reportOwner{ref.NetworkID, ref.DeviceID}), uint64(ref.ReportSequence))
	digest, _ := hex.DecodeString(strings.TrimPrefix(id, "sha256:"))
	return append(key, digest...)
}
func decodeStoredReport(raw []byte, report *DeviceReport) error {
	return DecodeCanonical(raw, report, ContractDecodeLimits{MaxBytes: controlHTTPBodyLimit, MaxDepth: 128, MaxItems: 1 << 20})
}
func reportRecord(key, raw []byte) (string, reportReference, error) {
	var report DeviceReport
	if err := decodeStoredReport(raw, &report); err != nil {
		return "", reportReference{}, err
	}
	id, ref := ReleaseDigest(raw), referenceOf(report)
	if !bytes.Equal(ref.key(id), key) {
		return "", ref, errors.New("report storage key does not match its canonical signed value")
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
	if tx.Bucket(observationBucket) == nil {
		return errors.New("original report bucket is missing")
	}
	return tx.ForEach(func(name []byte, bucket *bolt.Bucket) error {
		if (!bytes.Equal(name, observationBucket) && !bytes.Equal(name, reportIndexBucket)) || bucket.Sequence() != 0 {
			return errors.New("unknown observation bucket or independent sequence")
		}
		return nil
	})
}

// One daemon owns the handle. Maintenance opens it only after that owner stops.
func openReportDatabase(ctx context.Context, path string, readOnly bool) (*bolt.DB, os.FileInfo, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	entry, err := os.Lstat(path)
	if err != nil {
		return nil, nil, err
	}
	if !controlPrivateRegular(entry) || entry.Size() == 0 {
		return nil, nil, errors.New("observation database must be a nonempty protected regular file")
	}
	// bbolt subtracts its 50 ms retry interval before deciding to retry. A
	// 50 ms timeout therefore fails on the first contention, including the
	// kernel's deferred file release immediately after a killed owner exits.
	// Allow bounded startup recovery while still refusing a second live owner.
	options := &bolt.Options{ReadOnly: readOnly, Timeout: 250 * time.Millisecond}
	options.OpenFile = func(name string, flags int, mode os.FileMode) (*os.File, error) {
		f, err := os.OpenFile(name, flags&^os.O_CREATE, mode)
		if err != nil {
			return nil, err
		}
		info, a := f.Stat()
		current, b := os.Lstat(name)
		if a != nil || b != nil || !controlPrivateRegular(info) || !controlPrivateRegular(current) || !os.SameFile(entry, info) || !os.SameFile(info, current) {
			f.Close()
			return nil, errors.New("observation database changed while opening")
		}
		return f, nil
	}
	db, err := bolt.Open(path, 0600, options)
	if err != nil {
		return nil, nil, err
	}
	if err := db.View(observationStructure); err != nil {
		db.Close()
		return nil, nil, err
	}
	return db, entry, nil
}
func (store *ObservationStore) Close() error {
	store.lifetime.Lock()
	defer store.lifetime.Unlock()
	if store.db == nil {
		return nil
	}
	err := store.db.Close()
	store.db = nil
	store.cache.clear()
	return err
}
func (store *ObservationStore) withDatabase(ctx context.Context, writable bool, fn func(*bolt.Tx) error) error {
	if writable {
		select {
		case store.write <- struct{}{}:
		case <-ctx.Done():
			return ctx.Err()
		}
		defer func() { <-store.write }()
	}
	store.lifetime.RLock()
	defer store.lifetime.RUnlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if store.db == nil {
		return errors.New("observation database is closed")
	}
	current, err := os.Lstat(store.path)
	if err != nil {
		return err
	}
	if !controlPrivateRegular(current) || !os.SameFile(store.entry, current) {
		return errors.New("observation database was replaced")
	}
	operation := func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := fn(tx); err != nil {
			return err
		}
		return ctx.Err()
	}
	if writable {
		return store.db.Update(operation)
	}
	return store.db.View(operation)
}
func withObservationDB(ctx context.Context, path string, writable bool, fn func(*bolt.Tx) error) error {
	if err := rejectObservationJSON(filepath.Dir(path)); err != nil {
		return err
	}
	return withReportDatabase(ctx, path, writable, fn)
}
func withReportDatabase(ctx context.Context, path string, writable bool, fn func(*bolt.Tx) error) (retErr error) {
	db, _, err := openReportDatabase(ctx, path, !writable)
	if err != nil {
		return err
	}
	defer func() { retErr = errors.Join(retErr, db.Close()) }()
	operation := func(tx *bolt.Tx) error {
		if err := ctx.Err(); err != nil {
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
	f, err := os.CreateTemp(filepath.Dir(path), ".observations-*")
	if err != nil {
		return err
	}
	temporary := f.Name()
	defer os.Remove(temporary)
	if err := f.Close(); err != nil {
		return err
	}
	db, err := bolt.Open(temporary, 0600, nil)
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

func (store *ObservationStore) readReports(ctx context.Context, ids []string) (map[string]DeviceReport, error) {
	result := map[string]DeviceReport{}
	var originals, locations [][]byte
	err := store.withDatabase(ctx, false, func(tx *bolt.Tx) error {
		used := len(observationPrefix) + len(observationSuffix)
		for _, id := range ids {
			if err := ctx.Err(); err != nil {
				return err
			}
			key := tx.Bucket(reportIndexBucket).Get(reportIDKey(id))
			actual, _, err := locateReportKey(key)
			if err != nil || actual != id {
				return errors.New("requested report has no valid original location")
			}
			raw := tx.Bucket(observationBucket).Get(key)
			if len(raw) == 0 || len(raw) > controlHTTPBodyLimit || ReleaseDigest(raw) != id {
				return errors.New("requested original differs from its directory location")
			}
			if used+len(raw)+1 > reportBatchBytes {
				break
			}
			used += len(raw) + 1
			originals = append(originals, bytes.Clone(raw))
			locations = append(locations, bytes.Clone(key))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	for i, raw := range originals {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		report, err := store.decodedReport(raw)
		if err != nil {
			return nil, err
		}
		// Do not let a damaged secondary location relabel a signed original.
		if !bytes.Equal(referenceOf(report).key(ids[i]), locations[i]) {
			return nil, errors.New("report location mismatch")
		}
		result[ids[i]] = report
	}
	return result, nil
}
