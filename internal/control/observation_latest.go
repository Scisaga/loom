package control

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"sort"

	bolt "go.etcd.io/bbolt"
)

// LatestForDevices limits actual highest-original reads to the caller's exact
// source set. Supplied keys prove signatures, never grant current permission.
// A highest fork has no winner; every original at that position is checked.
func (store *ObservationStore) LatestForDevices(ctx context.Context, network string, devices map[string]string) ([]DeviceReport, error) {
	if ValidateID(network) != nil {
		return nil, errors.New("invalid latest report network")
	}
	ids := make([]string, 0, len(devices))
	for device, key := range devices {
		if ValidateID(device) != nil || ValidatePublicKey(key) != nil {
			return nil, errors.New("invalid latest report source")
		}
		ids = append(ids, device)
	}
	sort.Strings(ids)
	var positions []reportHistoryLocation
	err := store.withDatabase(ctx, false, func(tx *bolt.Tx) error {
		bucket := tx.Bucket(observationBucket)
		for _, device := range ids {
			if err := ctx.Err(); err != nil {
				return err
			}
			owner := reportOwner{network, device}
			highest, err := highestReportPosition(bucket, owner)
			if err != nil {
				return err
			}
			if highest == 0 {
				continue
			}
			prefix := binary.BigEndian.AppendUint64(reportOwnerPrefix(owner), uint64(highest))
			start := len(positions)
			cursor := bucket.Cursor()
			for key, _ := cursor.Seek(prefix); bytes.HasPrefix(key, prefix); key, _ = cursor.Next() {
				_, ref, err := locateReportKey(key)
				if err != nil {
					return err
				}
				positions = append(positions, reportHistoryLocation{key: bytes.Clone(key), ref: ref})
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
		return nil, err
	}
	result := []DeviceReport{}
	for offset := 0; offset < len(positions); {
		first, copied := offset, 0
		var originals [][]byte
		err := store.withDatabase(ctx, false, func(tx *bolt.Tx) error {
			for offset < len(positions) && len(originals) < 64 {
				if err := ctx.Err(); err != nil {
					return err
				}
				raw := tx.Bucket(observationBucket).Get(positions[offset].key)
				if len(raw) == 0 || len(raw) > controlHTTPBodyLimit {
					return errors.New("pinned latest original is absent or exceeds its input boundary")
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
			return nil, err
		}
		for i, raw := range originals {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			position := positions[first+i]
			report, err := store.verifiedReport(raw, devices[position.ref.DeviceID])
			if err != nil {
				return nil, err
			}
			if !bytes.Equal(referenceOf(report).key(ReleaseDigest(raw)), position.key) {
				return nil, errors.New("latest original differs from its pinned position")
			}
			if !position.fork {
				result = append(result, report)
			}
		}
	}
	return result, ctx.Err()
}
