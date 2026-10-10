package control

import (
	"bytes"
	"context"

	bolt "go.etcd.io/bbolt"
)

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
