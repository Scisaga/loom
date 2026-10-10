package control

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"

	bolt "go.etcd.io/bbolt"
)

// Physical keys locate originals. Their contents never authenticate a report.
func locateReportKey(key []byte) (string, reportReference, error) {
	var ref reportReference
	a := bytes.IndexByte(key, 0)
	if a < 0 {
		return "", ref, errors.New("invalid report network key")
	}
	b := bytes.IndexByte(key[a+1:], 0)
	if b < 0 || len(key) != a+b+2+8+32 {
		return "", ref, errors.New("invalid report position key")
	}
	end := a + b + 2
	ref.NetworkID, ref.DeviceID = string(key[:a]), string(key[a+1:end-1])
	ref.ReportSequence = U64(binary.BigEndian.Uint64(key[end : end+8]))
	if ValidateID(ref.NetworkID) != nil || ValidateID(ref.DeviceID) != nil || ref.ReportSequence == 0 {
		return "", ref, errors.New("invalid report owner or sequence")
	}
	return "sha256:" + hex.EncodeToString(key[end+8:]), ref, nil
}

func reportOwnerPrefix(owner reportOwner) []byte {
	return []byte(owner.network + "\x00" + owner.device + "\x00")
}

func reportOwnerEnd(owner reportOwner) []byte {
	end := reportOwnerPrefix(owner)
	end[len(end)-1]++
	return end
}

func highestReportPosition(bucket *bolt.Bucket, owner reportOwner) (U64, error) {
	cursor := bucket.Cursor()
	key, _ := cursor.Seek(reportOwnerEnd(owner))
	if key == nil {
		key, _ = cursor.Last()
	} else {
		key, _ = cursor.Prev()
	}
	if !bytes.HasPrefix(key, reportOwnerPrefix(owner)) {
		return 0, nil
	}
	_, ref, err := locateReportKey(key)
	return ref.ReportSequence, err
}

func readReportPosition(ctx context.Context, bucket *bolt.Bucket, owner reportOwner, sequence U64, cached *reportIndex, visit func(string, reportReference, []byte) error) error {
	prefix := binary.BigEndian.AppendUint64(reportOwnerPrefix(owner), uint64(sequence))
	cursor := bucket.Cursor()
	for key, raw := cursor.Seek(prefix); bytes.HasPrefix(key, prefix); key, raw = cursor.Next() {
		if err := ctx.Err(); err != nil {
			return err
		}
		id, ref, err := reportRecord(key, raw, cached)
		if err != nil {
			return err
		}
		if err := visit(id, ref, raw); err != nil {
			return err
		}
	}
	return ctx.Err()
}
