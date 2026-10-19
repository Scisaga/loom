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

// One freshly read, canonical original and its actual content digest. History
// callbacks receive it only after its physical position was checked. The value
// is immutable during consumption and is never cached.
type reportHistoryOriginal struct {
	id     string
	raw    []byte
	report DeviceReport
}

// Only the traffic consumer accepts this one-way projection. It is never a
// complete report or a writable report value. verifiedKey records the exact
// verification key of its transactionally maintained source, not permission.
type reportCounterProjection struct {
	NetworkID         string             `json:"network_id"`
	DeviceID          string             `json:"device_id"`
	ReportSequence    U64                `json:"report_sequence"`
	NetworkGeneration string             `json:"network_generation"`
	ReportedAt        int64              `json:"reported_at"`
	WireGuardCounters *WireGuardCounters `json:"wireguard_counters"`
	verifiedKey       string
}

func (report reportCounterProjection) reference() reportReference {
	ref := reportReference{NetworkID: report.NetworkID, DeviceID: report.DeviceID, ReportSequence: report.ReportSequence, ReportedAt: report.ReportedAt}
	if report.WireGuardCounters != nil {
		at := report.WireGuardCounters.ObservedAt
		ref.CounterAt = &at
	}
	return ref
}

type reportHistoryLocation struct {
	key  []byte
	fork bool
	ref  reportReference
}

// Pin only the requested time window and highest original position. Forks are
// checked against original keys. No transaction survives into projection work.
func (store *ObservationStore) pinDeviceHistoryLocations(ctx context.Context, network, device string, window []reportHistoryWindow) (U64, []reportHistoryLocation, error) {
	if ValidateID(network) != nil || ValidateID(device) != nil || len(window) > 1 {
		return 0, nil, errors.New("invalid report history scope")
	}
	owner := reportOwner{network, device}
	prefix := reportOwnerPrefix(owner)
	var positions []reportHistoryLocation
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
				positions = append(positions, reportHistoryLocation{key: bytes.Clone(key), ref: ref})
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
		return 0, nil, err
	}
	sort.Slice(positions, func(i, j int) bool { return bytes.Compare(positions[i].key, positions[j].key) > 0 })
	return highest, positions, nil
}

func (store *ObservationStore) walkDeviceHistorySnapshot(ctx context.Context, network, device string, visit func(U64, reportReference, *reportHistoryOriginal) error, window ...reportHistoryWindow) error {
	highest, positions, err := store.pinDeviceHistoryLocations(ctx, network, device, window)
	if err != nil {
		return err
	}
	var previous U64
	codec := newContractCodec()
	include := func(position reportHistoryLocation) bool {
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
			id := ReleaseDigest(raw)
			original, err := store.decodedHistoryOriginal(raw, id, codec)
			if err != nil {
				return err
			}
			ref := referenceOf(original.report)
			if !bytes.Equal(ref.key(id), position.key) {
				return errors.New("pinned report differs from its original location")
			}
			if position.fork {
				// Report-window consumers must see both the real highest and
				// in-window forks, including forks with unequal original times.
				if len(window) != 0 && window[0].kind == reportTime {
					if err := visit(highest, ref, nil); err != nil {
						return err
					}
				}
				continue
			}
			// Skipping an out-of-window sequence must break repeated counter samples too.
			if len(window) != 0 && window[0].kind == counterTime && previous != 0 && previous-1 != ref.ReportSequence {
				if err := visit(highest, reportReference{}, nil); err != nil {
					return err
				}
			}
			previous = ref.ReportSequence
			if err := visit(highest, ref, original); err != nil {
				return err
			}
		}
	}
	return ctx.Err()
}
