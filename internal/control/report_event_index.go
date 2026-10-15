package control

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"sort"

	bolt "go.etcd.io/bbolt"
)

var reportEventIndexBucket = []byte("event-candidates")

// The interval describes cutoffs at which exactly one original is visible.
// A zero lower/upper bound means negative/positive infinity respectively.
type reportEventInterval struct {
	key          []byte
	lower, upper uint64
}

type reportEventPosition struct {
	position            reportPosition
	firstKey, legacyKey []byte
	firstAt, secondAt   uint64
	legacyCount         int
}

func reportEventPositionPrefix(position reportPosition) []byte {
	return binary.BigEndian.AppendUint64(reportOwnerPrefix(position.owner), uint64(position.sequence))
}

func lowestReportPosition(bucket *bolt.Bucket, owner reportOwner) (U64, error) {
	key, _ := bucket.Cursor().Seek(reportOwnerPrefix(owner))
	if !bytes.HasPrefix(key, reportOwnerPrefix(owner)) {
		return 0, nil
	}
	_, ref, err := locateReportKey(key)
	return ref.ReportSequence, err
}

// Only location and reception metadata are retained while walking positions.
// In particular, old unannotated report bodies are not decoded speculatively.
func scanReportEventPosition(ctx context.Context, tx *bolt.Tx, cursor *bolt.Cursor, key []byte) (reportEventPosition, []byte, error) {
	var result reportEventPosition
	_, ref, err := locateReportKey(key)
	if err != nil {
		return result, nil, err
	}
	result.position = reportPosition{reportOwner{ref.NetworkID, ref.DeviceID}, ref.ReportSequence}
	prefix := reportEventPositionPrefix(result.position)
	receptions := tx.Bucket(reportReceptionBucket)
	if receptions == nil {
		return result, nil, errors.New("report reception metadata unavailable")
	}
	for ; bytes.HasPrefix(key, prefix); key, _ = cursor.Next() {
		if err := ctx.Err(); err != nil {
			return result, nil, err
		}
		if _, _, err := locateReportKey(key); err != nil {
			return result, nil, err
		}
		rawAt := receptions.Get(key)
		if rawAt == nil {
			if result.legacyCount == 0 {
				result.legacyKey = bytes.Clone(key)
			}
			if result.legacyCount < 2 {
				result.legacyCount++
			}
			continue
		}
		if _, err := receptionTime(rawAt); err != nil {
			return result, nil, err
		}
		at := binary.BigEndian.Uint64(rawAt)
		if result.firstAt == 0 || at < result.firstAt {
			result.secondAt, result.firstAt = result.firstAt, at
			result.firstKey = bytes.Clone(key)
		} else if result.secondAt == 0 || at < result.secondAt {
			result.secondAt = at
		}
	}
	return result, key, nil
}

func (position reportEventPosition) uniqueInterval() reportEventInterval {
	if position.legacyCount == 1 {
		return reportEventInterval{position.legacyKey, 0, position.firstAt}
	}
	if position.legacyCount != 0 || position.firstAt == 0 || position.firstAt == position.secondAt {
		return reportEventInterval{}
	}
	return reportEventInterval{position.firstKey, position.firstAt, position.secondAt}
}

func reportEventIntervalsOverlap(left, right reportEventInterval) bool {
	if left.key == nil || right.key == nil {
		return false
	}
	lower := max(left.lower, right.lower)
	return (left.upper == 0 || lower < left.upper) && (right.upper == 0 || lower < right.upper)
}

// An index location is not a verification receipt. The query independently
// checks the actual original against the historical identity at its cutoff.
func reportEventRuntime(tx *bolt.Tx, key []byte, codec *contractCodec) (RuntimeReadback, error) {
	raw := tx.Bucket(observationBucket).Get(key)
	var report DeviceReport
	if err := decodeStoredReportWithCodec(raw, &report, codec); err != nil {
		return RuntimeReadback{}, err
	}
	if !bytes.Equal(referenceOf(report).key(ReleaseDigest(raw)), key) {
		return RuntimeReadback{}, errors.New("event candidate original differs from its storage key")
	}
	return RuntimeReadback{State: report.Runtime.State, AppliedViewDigest: report.Runtime.AppliedViewDigest, ErrorCode: report.Runtime.ErrorCode}, nil
}

func reportEventCandidate(tx *bolt.Tx, current, prior reportEventPosition, earliest U64, codec *contractCodec) ([]byte, error) {
	interval := current.uniqueInterval()
	if current.legacyCount != 0 || interval.key == nil {
		return nil, nil
	}
	baseline := current.position.sequence == earliest
	previous := prior.uniqueInterval()
	if !baseline && (current.position.sequence <= 1 || prior.position.owner != current.position.owner ||
		prior.position.sequence != current.position.sequence-1 || !reportEventIntervalsOverlap(interval, previous)) {
		return nil, nil
	}
	runtime, err := reportEventRuntime(tx, interval.key, codec)
	if err != nil {
		return nil, err
	}
	if !baseline {
		before, err := reportEventRuntime(tx, previous.key, codec)
		if err != nil {
			return nil, err
		}
		if runtime.State == before.State && runtime.AppliedViewDigest == before.AppliedViewDigest && runtime.ErrorCode == before.ErrorCode {
			return nil, nil
		}
	}
	location := binary.BigEndian.AppendUint64(receptionIndexPrefix(current.position.owner.network), current.firstAt)
	return append(location, interval.key...), nil
}

func replaceReportEventCandidate(index *bolt.Bucket, position reportPosition, location []byte) error {
	reverse := append([]byte{'p'}, reportEventPositionPrefix(position)...)
	if previous := index.Get(reverse); previous != nil {
		if err := index.Delete(previous); err != nil {
			return err
		}
		if err := index.Delete(reverse); err != nil {
			return err
		}
	}
	if location == nil {
		return nil
	}
	if err := index.Put(location, nil); err != nil {
		return err
	}
	return index.Put(reverse, location)
}

// A missing child is rebuilt atomically; interrupted construction is never
// visible to readers. Original bytes and reception annotations are untouched.
func ensureReportEventIndex(ctx context.Context, tx *bolt.Tx) error {
	index := tx.Bucket(reportIndexBucket)
	if index == nil {
		return errors.New("report locations unavailable")
	}
	if child := index.Bucket(reportEventIndexBucket); child != nil {
		if child.Sequence() != 0 {
			return errors.New("event candidate locations have an independent sequence")
		}
		return ctx.Err()
	}
	return rebuildReportEventIndex(ctx, tx)
}

func rebuildReportEventIndex(ctx context.Context, tx *bolt.Tx) error {
	parent := tx.Bucket(reportIndexBucket)
	if parent == nil || tx.Bucket(reportReceptionBucket) == nil {
		return errors.New("report locations or reception metadata unavailable")
	}
	if parent.Bucket(reportEventIndexBucket) != nil {
		if err := parent.DeleteBucket(reportEventIndexBucket); err != nil {
			return err
		}
	}
	index, err := parent.CreateBucket(reportEventIndexBucket)
	if err != nil {
		return err
	}
	codec := newContractCodec()
	cursor := tx.Bucket(observationBucket).Cursor()
	key, _ := cursor.First()
	var prior reportEventPosition
	var earliest U64
	for key != nil {
		current, next, err := scanReportEventPosition(ctx, tx, cursor, key)
		if err != nil {
			return err
		}
		if earliest == 0 || current.position.owner != prior.position.owner {
			earliest = current.position.sequence
		}
		location, err := reportEventCandidate(tx, current, prior, earliest, codec)
		if err != nil {
			return err
		}
		if err := replaceReportEventCandidate(index, current.position, location); err != nil {
			return err
		}
		prior, key = current, next
	}
	return ctx.Err()
}

func updateReportEventPositions(ctx context.Context, tx *bolt.Tx, positions map[reportPosition]bool) error {
	parent := tx.Bucket(reportIndexBucket)
	if parent == nil {
		return errors.New("report locations unavailable")
	}
	index := parent.Bucket(reportEventIndexBucket)
	if index == nil || index.Sequence() != 0 {
		return errors.New("event candidate locations unavailable")
	}
	ordered := make([]reportPosition, 0, len(positions))
	for position := range positions {
		if position.sequence != 0 {
			ordered = append(ordered, position)
		}
	}
	sort.Slice(ordered, func(i, j int) bool {
		return bytes.Compare(reportEventPositionPrefix(ordered[i]), reportEventPositionPrefix(ordered[j])) < 0
	})
	codec := newContractCodec()
	reports := tx.Bucket(observationBucket)
	for _, position := range ordered {
		if err := ctx.Err(); err != nil {
			return err
		}
		cursor := reports.Cursor()
		key, _ := cursor.Seek(reportEventPositionPrefix(position))
		if !bytes.HasPrefix(key, reportEventPositionPrefix(position)) {
			continue
		}
		current, _, err := scanReportEventPosition(ctx, tx, cursor, key)
		if err != nil {
			return err
		}
		var prior reportEventPosition
		if position.sequence > 1 {
			prefix := reportEventPositionPrefix(reportPosition{position.owner, position.sequence - 1})
			key, _ := cursor.Seek(prefix)
			if bytes.HasPrefix(key, prefix) {
				prior, _, err = scanReportEventPosition(ctx, tx, cursor, key)
				if err != nil {
					return err
				}
			}
		}
		earliest, err := lowestReportPosition(reports, position.owner)
		if err != nil {
			return err
		}
		location, err := reportEventCandidate(tx, current, prior, earliest, codec)
		if err != nil {
			return err
		}
		if err := replaceReportEventCandidate(index, position, location); err != nil {
			return err
		}
	}
	return ctx.Err()
}
