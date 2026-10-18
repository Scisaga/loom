package control

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"sort"
	"strings"

	bolt "go.etcd.io/bbolt"
)

const reportTime byte = 1
const counterTime byte = 2
const observationTime byte = 3
const linkTime byte = 4

func reportIDKey(id string) []byte {
	digest, _ := hex.DecodeString(strings.TrimPrefix(id, "sha256:"))
	return append([]byte{'i'}, digest...)
}
func reportLinkTimePrefix(owner reportOwner, link, spec string) []byte {
	return append(reportTimePrefix(owner, linkTime), []byte(link+"\x00"+spec+"\x00")...)
}
func reportTimePrefix(owner reportOwner, kind byte) []byte {
	return append(append([]byte{'t'}, reportOwnerPrefix(owner)...), kind)
}

// Secondary locations commit in the same transaction as the original bytes.
func indexReport(tx *bolt.Tx, key []byte, report DeviceReport) error {
	return reportIndexEntries(key, report, tx.Bucket(reportIndexBucket).Put)
}

func reportIndexEntries(key []byte, report DeviceReport, put func([]byte, []byte) error) error {
	if err := put(append([]byte{'i'}, key[len(key)-32:]...), key); err != nil {
		return err
	}
	times := map[byte]map[int64]bool{reportTime: {report.ReportedAt: true}, observationTime: {}}
	if report.WireGuardCounters != nil {
		times[counterTime] = map[int64]bool{report.WireGuardCounters.ObservedAt: true}
	}
	for _, sample := range report.Observations {
		times[observationTime][sample.ObservedAt] = true
		if sample.Level == "link" {
			prefix := reportLinkTimePrefix(reportOwner{report.NetworkID, report.DeviceID}, sample.LinkID, sample.SpecDigest)
			location := binary.BigEndian.AppendUint64(prefix, uint64(sample.ObservedAt))
			location = append(location, key[len(key)-40:]...)
			if err := put(location, nil); err != nil {
				return err
			}
		}
	}
	for kind, values := range times {
		prefix := reportTimePrefix(reportOwner{report.NetworkID, report.DeviceID}, kind)
		for at := range values {
			location := binary.BigEndian.AppendUint64(bytes.Clone(prefix), uint64(at))
			location = append(location, key[len(key)-40:]...)
			if err := put(location, nil); err != nil {
				return err
			}
		}
	}
	return nil
}
func rangeIDs(tx *bolt.Tx, group storedReportRange) ([]string, error) {
	owner := reportOwner{group.network, group.scope.DeviceID}
	prefix := reportOwnerPrefix(owner)
	first := binary.BigEndian.AppendUint64(bytes.Clone(prefix), uint64(group.scope.FirstSequence))
	cursor := tx.Bucket(observationBucket).Cursor()
	type item struct {
		id       string
		sequence U64
	}
	items := []item{}
	for key, _ := cursor.Seek(first); key != nil && bytes.HasPrefix(key, prefix); key, _ = cursor.Next() {
		id, ref, err := locateReportKey(key)
		if err != nil {
			return nil, err
		}
		if reportRangeStart(ref.ReportSequence) != group.scope.FirstSequence {
			break
		}
		items = append(items, item{id, ref.ReportSequence})
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].sequence > items[j].sequence || items[i].sequence == items[j].sequence && items[i].id < items[j].id
	})
	ids := make([]string, len(items))
	for i, value := range items {
		ids[i] = value.id
	}
	return ids, nil
}
func ensureReportIndexes(tx *bolt.Tx) error {
	if tx.Bucket(reportIndexBucket) != nil {
		return ensureReportTreeIndex(tx)
	}
	if _, err := tx.CreateBucket(reportIndexBucket); err != nil {
		return err
	}
	// bbolt splits nodes at commit. Inserting a large unsorted initial index
	// repeatedly shifts one growing leaf; sort locations before the first spill.
	type location struct{ key, value []byte }
	var entries []location
	collect := func(key, value []byte) error {
		entries = append(entries, location{key, value})
		return nil
	}
	err := tx.Bucket(observationBucket).ForEach(func(key, raw []byte) error {
		var report DeviceReport
		if err := decodeStoredReport(raw, &report); err != nil {
			return err
		}
		ref := referenceOf(report)
		if !bytes.Equal(ref.key(ReleaseDigest(raw)), key) {
			return errors.New("original differs from its storage key")
		}
		if err := reportIndexEntries(key, report, collect); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return err
	}
	sort.Slice(entries, func(i, j int) bool { return bytes.Compare(entries[i].key, entries[j].key) < 0 })
	index := tx.Bucket(reportIndexBucket)
	for _, entry := range entries {
		if err := index.Put(entry.key, entry.value); err != nil {
			return err
		}
	}
	return ensureReportTreeIndex(tx)
}

// Membership in the local original collection is a transport hint, not verification.
func (store *ObservationStore) knownReports(ctx context.Context, ids []string) (map[string]reportReference, error) {
	result := map[string]reportReference{}
	err := store.withDatabase(ctx, false, func(tx *bolt.Tx) error {
		index, originals := tx.Bucket(reportIndexBucket), tx.Bucket(observationBucket)
		for _, id := range ids {
			if err := ctx.Err(); err != nil {
				return err
			}
			key := index.Get(reportIDKey(id))
			if key == nil {
				continue
			}
			actual, ref, err := locateReportKey(key)
			if err != nil || actual != id || originals.Get(key) == nil {
				return errors.New("report location has no matching original")
			}
			result[id] = ref
		}
		return nil
	})
	return result, err
}
