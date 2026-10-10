package control

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"

	bolt "go.etcd.io/bbolt"
)

// Pin only locations while holding the read handle. Keys do not authenticate
// their values: every pinned original is copied and checked before projection,
// including forks and originals the caller excludes from its time window.
func (store *ObservationStore) walkDeviceHistorySnapshot(ctx context.Context, network, device string, visit func(U64, reportReference, []byte) error) error {
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
		first := offset
		var originals [][]byte
		copied := 0
		err := store.withDatabase(ctx, false, func(tx *bolt.Tx) error {
			for offset < len(keys) && len(originals) < 64 {
				if err := ctx.Err(); err != nil {
					return err
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
