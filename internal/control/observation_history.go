package control

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"sort"

	bolt "go.etcd.io/bbolt"
)

type reportHistoryWindow struct {
	kind        byte
	from, until int64
	link, spec  string
	include     func(reportReference) bool
}

// Pin only the requested time window and highest original position. Forks are
// checked against originals. No read transaction survives into projection work.
func (store *ObservationStore) walkDeviceHistorySnapshot(ctx context.Context, network, device string, visit func(U64, reportReference, []byte) error, window ...reportHistoryWindow) error {
	if ValidateID(network) != nil || ValidateID(device) != nil || len(window) > 1 {
		return errors.New("invalid report history scope")
	}
	owner := reportOwner{network, device}
	prefix := reportOwnerPrefix(owner)
	type location struct {
		key  []byte
		fork bool
		ref  reportReference
	}
	var positions []location
	var highest U64
	err := store.withDatabase(ctx, false, func(tx *bolt.Tx) error {
		bucket := tx.Bucket(observationBucket)
		var err error
		highest, err = highestReportPosition(bucket, owner)
		if err != nil || highest == 0 {
			return err
		}
		sequences := map[U64]bool{highest: true}
		references := map[string]reportReference{}
		if len(window) == 0 {
			cursor := bucket.Cursor()
			for key, _ := cursor.Seek(prefix); key != nil && bytes.HasPrefix(key, prefix); key, _ = cursor.Next() {
				if err := ctx.Err(); err != nil {
					return err
				}
				_, ref, err := locateReportKey(key)
				if err != nil {
					return err
				}
				sequences[ref.ReportSequence] = true
			}
		} else {
			w := window[0]
			if w.kind < reportTime || w.kind > linkTime || w.from < 0 || w.until < w.from {
				return errors.New("invalid report history window")
			}
			timePrefix := reportTimePrefix(owner, w.kind)
			if w.kind == linkTime {
				if ValidateID(w.link) != nil || ValidateDigest(w.spec) != nil {
					return errors.New("invalid Link history scope")
				}
				timePrefix = reportLinkTimePrefix(owner, w.link, w.spec)
			}
			first := binary.BigEndian.AppendUint64(bytes.Clone(timePrefix), uint64(w.from))
			cursor := tx.Bucket(reportIndexBucket).Cursor()
			for key, _ := cursor.Seek(first); key != nil && bytes.HasPrefix(key, timePrefix); key, _ = cursor.Next() {
				if err := ctx.Err(); err != nil {
					return err
				}
				if len(key) != len(timePrefix)+8+40 {
					return errors.New("invalid report time location")
				}
				at := binary.BigEndian.Uint64(key[len(timePrefix):])
				if at > uint64(w.until) {
					break
				}
				original := append(bytes.Clone(prefix), key[len(timePrefix)+8:]...)
				if bucket.Get(original) == nil {
					return errors.New("indexed original is absent")
				}
				_, ref, err := locateReportKey(original)
				if err != nil {
					return err
				}
				sequences[ref.ReportSequence] = true
				prior := references[string(original)]
				switch w.kind {
				case reportTime:
					ref.ReportedAt = int64(at)
				case counterTime:
					ref.CounterAt = new(int64(at))
				case linkTime:
					ref.LinkSamples = append(prior.LinkSamples, linkSampleReference{w.link, w.spec, int64(at)})
				}
				references[string(original)] = ref
			}
		}
		// Include every fork at selected positions even if only one is in the time index.
		cursor := bucket.Cursor()
		for sequence := range sequences {
			if err := ctx.Err(); err != nil {
				return err
			}
			position := binary.BigEndian.AppendUint64(bytes.Clone(prefix), uint64(sequence))
			start := len(positions)
			for key, _ := cursor.Seek(position); key != nil && bytes.HasPrefix(key, position); key, _ = cursor.Next() {
				_, ref, err := locateReportKey(key)
				if err != nil {
					return err
				}
				if indexed, found := references[string(key)]; found {
					ref = indexed
				}
				positions = append(positions, location{key: bytes.Clone(key), ref: ref})
			}
			if len(positions) == start {
				return errors.New("pinned original position is absent")
			}
			if len(positions)-start > 1 {
				for i := start; i < len(positions); i++ {
					positions[i].fork = true
				}
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	sort.Slice(positions, func(i, j int) bool { return bytes.Compare(positions[i].key, positions[j].key) > 0 })
	var previous U64
	include := func(position location) bool {
		return len(window) == 0 || window[0].include == nil || position.fork || position.ref.ReportSequence == highest || window[0].include(position.ref)
	}
	batchLimit := 64
	if len(window) != 0 && window[0].include != nil {
		batchLimit = 1
	}
	for offset := 0; offset < len(positions); {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !include(positions[offset]) {
			offset++
			continue
		}
		first := offset
		var originals [][]byte
		copied := 0
		err := store.withDatabase(ctx, false, func(tx *bolt.Tx) error {
			for offset < len(positions) && len(originals) < batchLimit {
				if err := ctx.Err(); err != nil {
					return err
				}
				position := positions[offset]
				raw := tx.Bucket(observationBucket).Get(position.key)
				if len(raw) == 0 || len(raw) > controlHTTPBodyLimit {
					return errors.New("pinned report is missing or exceeds its input boundary")
				}
				if copied > 0 && copied+len(raw) > 1<<20 {
					break
				}
				originals = append(originals, bytes.Clone(raw))
				copied += len(raw)
				offset++
			}
			return nil
		})
		if err != nil {
			return err
		}
		for i, raw := range originals {
			if err := ctx.Err(); err != nil {
				return err
			}
			position := positions[first+i]
			report, err := store.decodedReport(raw)
			if err != nil {
				return err
			}
			ref := referenceOf(report)
			if !bytes.Equal(ref.key(ReleaseDigest(raw)), position.key) {
				return errors.New("pinned report differs from its original location")
			}
			if position.fork {
				continue
			}
			// Skipping an out-of-window sequence must break repeated counter samples too.
			if len(window) != 0 && window[0].kind == counterTime && previous != 0 && previous-1 != ref.ReportSequence {
				if err := visit(highest, reportReference{}, nil); err != nil {
					return err
				}
			}
			previous = ref.ReportSequence
			if err := visit(highest, ref, raw); err != nil {
				return err
			}
		}
	}
	return ctx.Err()
}
