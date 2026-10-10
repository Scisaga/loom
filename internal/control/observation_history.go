package control

import (
	"bytes"
	"context"

	bolt "go.etcd.io/bbolt"
)

// Read inside the caller's original-report snapshot. A fork at this position
// cannot be replaced with an older report by the history walker.
func highestDeviceReportSequence(tx *bolt.Tx, cached *reportIndex, network, device string) (U64, error) {
	cursor := tx.Bucket(observationBucket).Cursor()
	prefix := []byte(network + "\x00" + device + "\x00")
	end := append([]byte{}, prefix...)
	end[len(end)-1]++
	key, raw := cursor.Seek(end)
	if key == nil {
		key, raw = cursor.Last()
	} else {
		key, raw = cursor.Prev()
	}
	if !bytes.HasPrefix(key, prefix) {
		return 0, nil
	}
	_, ref, err := reportRecord(key, raw, cached)
	return ref.ReportSequence, err
}

// Walk the original device range newest sequence first, excluding every fork.
// Read-only bbolt values stay valid until the caller's transaction ends.
func walkDeviceReportHistory(ctx context.Context, tx *bolt.Tx, cached *reportIndex, network, device string, visit func(string, reportReference, []byte) error) error {
	cursor := tx.Bucket(observationBucket).Cursor()
	prefix := []byte(network + "\x00" + device + "\x00")
	var pending reportReference
	var pendingRaw []byte
	var pendingID string
	count := 0
	consume := func() error {
		if count == 1 {
			return visit(pendingID, pending, pendingRaw)
		}
		return nil
	}
	end := append([]byte{}, prefix...)
	end[len(end)-1]++
	key, raw := cursor.Seek(end)
	if key == nil {
		key, raw = cursor.Last()
	} else {
		key, raw = cursor.Prev()
	}
	for ; key != nil && bytes.HasPrefix(key, prefix); key, raw = cursor.Prev() {
		if err := ctx.Err(); err != nil {
			return err
		}
		id, ref, err := reportRecord(key, raw, cached)
		if err != nil {
			return err
		}
		if count > 0 && ref.ReportSequence == pending.ReportSequence {
			count++
			continue
		}
		if err := consume(); err != nil {
			return err
		}
		pending, pendingRaw, pendingID, count = ref, raw, id, 1
	}
	return consume()
}

func (store *ObservationStore) walkDeviceHistorySnapshot(ctx context.Context, network, device string, keep func(reportReference) bool, visit func(U64, []byte) error) error {
	// Pin the original input set, not a long-lived DB transaction. A nil key
	// retains an excluded sample's adjacency break. Forks remain excluded by
	// the same range walker, including a fork at the highest sequence.
	cached := store.index.Load()
	var highest U64
	var keys [][]byte
	err := withObservationDB(ctx, store.path, false, func(tx *bolt.Tx) error {
		var err error
		highest, err = highestDeviceReportSequence(tx, cached, network, device)
		if err != nil {
			return err
		}
		return walkDeviceReportHistory(ctx, tx, cached, network, device, func(id string, ref reportReference, _ []byte) error {
			if !keep(ref) {
				if len(keys) == 0 || keys[len(keys)-1] != nil {
					keys = append(keys, nil)
				}
			} else {
				keys = append(keys, ref.key(id))
			}
			return nil
		})
	})
	if err != nil {
		return err
	}
	for offset := 0; offset < len(keys); {
		// At most 64 entries and 1 MiB per batch, except that one original may
		// use its existing single-report limit. Never retain all report bodies.
		var originals [][]byte
		copied := 0
		err := withObservationDB(ctx, store.path, false, func(tx *bolt.Tx) error {
			for offset < len(keys) && len(originals) < 64 {
				if err := ctx.Err(); err != nil {
					return err
				}
				key := keys[offset]
				if key == nil {
					originals = append(originals, nil)
					offset++
					continue
				}
				raw := tx.Bucket(observationBucket).Get(key)
				if _, _, err := reportRecord(key, raw, cached); err != nil {
					return err
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
		for _, raw := range originals {
			if err := ctx.Err(); err != nil {
				return err
			}
			// Decoding, signature verification and aggregation run only after
			// the read handle closes, so a pending report writer can proceed.
			if err := visit(highest, raw); err != nil {
				return err
			}
		}
	}
	return ctx.Err()
}
