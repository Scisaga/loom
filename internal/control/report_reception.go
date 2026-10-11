package control

import (
	"bytes"
	"encoding/binary"
	"errors"
	"time"

	bolt "go.etcd.io/bbolt"
)

var receptionSinceKey = []byte("since")
var receptionIndexedKey = []byte("receptions-indexed")

func receptionTime(raw []byte) (time.Time, error) {
	if len(raw) != 8 || binary.BigEndian.Uint64(raw) == 0 || binary.BigEndian.Uint64(raw) > uint64(1<<63-1) {
		return time.Time{}, errors.New("invalid original reception time")
	}
	return time.Unix(0, int64(binary.BigEndian.Uint64(raw))).UTC(), nil
}
func receptionIndexPrefix(network string) []byte { return []byte("e" + network + "\x00") }
func indexReception(tx *bolt.Tx, key, at []byte) error {
	_, ref, err := locateReportKey(key)
	if err != nil {
		return err
	}
	index := append(receptionIndexPrefix(ref.NetworkID), at...)
	return tx.Bucket(reportIndexBucket).Put(append(index, key...), nil)
}
func ensureReportReceptions(tx *bolt.Tx, now time.Time) error {
	bucket := tx.Bucket(reportReceptionBucket)
	if bucket == nil {
		var err error
		bucket, err = tx.CreateBucket(reportReceptionBucket)
		if err != nil {
			return err
		}
		if err := bucket.Put(receptionSinceKey, binary.BigEndian.AppendUint64(nil, uint64(now.UnixNano()))); err != nil {
			return err
		}
	}
	if _, err := receptionTime(bucket.Get(receptionSinceKey)); err != nil {
		return err
	}
	index := tx.Bucket(reportIndexBucket)
	if index.Get(receptionIndexedKey) != nil {
		return nil
	}
	if err := bucket.ForEach(func(key, at []byte) error {
		if bytes.Equal(key, receptionSinceKey) {
			return nil
		}
		if _, err := receptionTime(at); err != nil {
			return err
		}
		if tx.Bucket(observationBucket).Get(key) == nil {
			return errors.New("reception refers to a missing original")
		}
		return indexReception(tx, key, at)
	}); err != nil {
		return err
	}
	return index.Put(receptionIndexedKey, []byte{1})
}
func receiveReport(tx *bolt.Tx, key []byte, at time.Time) error {
	bucket := tx.Bucket(reportReceptionBucket)
	if bucket == nil {
		return errors.New("report reception metadata unavailable")
	}
	if bucket.Get(key) != nil {
		return nil
	}
	if at.UnixNano() <= 0 {
		return errors.New("invalid report reception clock")
	}
	raw := binary.BigEndian.AppendUint64(nil, uint64(at.UnixNano()))
	if err := bucket.Put(key, raw); err != nil {
		return err
	}
	return indexReception(tx, key, raw)
}
