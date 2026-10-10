package control

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"

	bolt "go.etcd.io/bbolt"
)

// Pin locations and forks. An optional query filter can exclude a known content
// ID's immutable metadata. Exclusions are delivered with nil raw bytes so that
// counters still break adjacency; they cannot supply a projected sample.
// Every selected original, and the highest position, is read and checked.
func (store *ObservationStore) walkDeviceHistorySnapshot(ctx context.Context, network, device string, visit func(U64, reportReference, []byte) error, include ...func(reportReference) bool) error {
	if ValidateID(network) != nil || ValidateID(device) != nil {
		return errors.New("invalid report history scope")
	}
	cached := store.index.Load()
	prefix := []byte(network + "\x00" + device + "\x00")
	end := bytes.Clone(prefix)
	end[len(end)-1]++
	var keys [][]byte
	err := store.withDatabase(ctx, false, func(tx *bolt.Tx) error {
		cursor := tx.Bucket(observationBucket).Cursor()
		key, _ := cursor.Seek(end)
		if key == nil {
			key, _ = cursor.Last()
		} else {
			key, _ = cursor.Prev()
		}
		for ; key != nil && bytes.HasPrefix(key, prefix); key, _ = cursor.Prev() {
			if err := ctx.Err(); err != nil {
				return err
			}
			if len(key) != len(prefix)+8+32 {
				return errors.New("report history key has invalid shape")
			}
			keys = append(keys, bytes.Clone(key))
		}
		return nil
	})
	if err != nil {
		return err
	}
	sequence := func(key []byte) U64 { return U64(binary.BigEndian.Uint64(key[len(prefix) : len(prefix)+8])) }
	var highest U64
	if len(keys) != 0 {
		highest = sequence(keys[0])
	}
	for offset := 0; offset < len(keys); {
		// Skip a run outside the query without repeatedly opening the database.
		// These notifications can only break adjacency, never supply a sample.
		if len(include) != 0 && cached != nil && sequence(keys[offset]) != highest {
			if err := ctx.Err(); err != nil {
				return err
			}
			id, _, err := locateReportKey(keys[offset])
			if err != nil {
				return err
			}
			if ref, found := cached.reports[id]; found && bytes.Equal(ref.key(id), keys[offset]) && !include[0](ref) {
				if err := visit(highest, ref, nil); err != nil {
					return err
				}
				offset++
				continue
			}
		}
		first := offset
		var originals [][]byte
		copied := 0
		err := store.withDatabase(ctx, false, func(tx *bolt.Tx) error {
			for offset < len(keys) && len(originals) < 64 {
				if err := ctx.Err(); err != nil {
					return err
				}
				if len(include) != 0 && cached != nil && sequence(keys[offset]) != highest {
					id, _, err := locateReportKey(keys[offset])
					if err != nil {
						return err
					}
					if ref, found := cached.reports[id]; found && bytes.Equal(ref.key(id), keys[offset]) && !include[0](ref) {
						originals = append(originals, nil)
						offset++
						continue
					}
				}
				raw := tx.Bucket(observationBucket).Get(keys[offset])
				if len(raw) == 0 || len(raw) > controlHTTPBodyLimit {
					return errors.New("pinned report is missing or exceeds its input boundary")
				}
				// At most 1 MiB, except one original may use its existing input limit.
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
			position := first + i
			if raw == nil {
				id, _, err := locateReportKey(keys[position])
				if err != nil {
					return err
				}
				if err := visit(highest, cached.reports[id], nil); err != nil {
					return err
				}
				continue
			}
			_, ref, err := reportRecord(keys[position], raw, cached)
			if err != nil {
				return err
			}
			// Look across batch boundaries. No original at a fork becomes a winner.
			if position > 0 && sequence(keys[position-1]) == ref.ReportSequence || position+1 < len(keys) && sequence(keys[position+1]) == ref.ReportSequence {
				continue
			}
			if err := visit(highest, ref, raw); err != nil {
				return err
			}
		}
	}
	return ctx.Err()
}
