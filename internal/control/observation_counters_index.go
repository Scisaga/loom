package control

import (
	"bytes"
	"context"
	"errors"

	bolt "go.etcd.io/bbolt"
)

// A disposable, one-way projection of each accepted original, including reports
// without counters. Keys are the complete original keys, never a latest pointer.
var reportCountersBucket = []byte("wg-counters")

type reportCounterIndexValue struct {
	NetworkGeneration string             `json:"network_generation"`
	ReportedAt        int64              `json:"reported_at"`
	VerifiedPublicKey string             `json:"verified_public_key"`
	Counters          *WireGuardCounters `json:"wireguard_counters,omitempty"`
}

func (value reportCounterIndexValue) Validate() error {
	if ValidateID(value.NetworkGeneration) != nil || !validateTime(value.ReportedAt) || ValidatePublicKey(value.VerifiedPublicKey) != nil {
		return errors.New("invalid report counter projection")
	}
	if value.Counters != nil {
		return value.Counters.Validate()
	}
	return nil
}

func counterIndexValue(report DeviceReport, key string) reportCounterIndexValue {
	return reportCounterIndexValue{report.NetworkGeneration, report.ReportedAt, key, report.WireGuardCounters}
}

func indexReportCounters(tx *bolt.Tx, location []byte, report DeviceReport, key string) error {
	index := tx.Bucket(reportIndexBucket).Bucket(reportCountersBucket)
	if index == nil {
		return errors.New("report counter projections unavailable")
	}
	body, err := CanonicalEncode(counterIndexValue(report, key))
	if err != nil {
		return err
	}
	return index.Put(location, body)
}

// Every original is checked before its derived row is trusted or replaced.
// No cached proof or current permission substitutes for the historical binding.
func verifyReportCounterOriginal(raw, location []byte, keys map[reportOwner]string, codec *contractCodec) (DeviceReport, string, error) {
	var report DeviceReport
	if err := decodeStoredReportWithCodec(raw, &report, codec); err != nil {
		return report, "", err
	}
	if !bytes.Equal(referenceOf(report).key(ReleaseDigest(raw)), location) {
		return report, "", errors.New("report original differs from its storage key")
	}
	key := keys[reportOwner{report.NetworkID, report.DeviceID}]
	if key == "" || report.Verify(key) != nil {
		return report, "", errors.New("report original does not verify against its accepted historical device binding")
	}
	return report, key, nil
}

func rebuildReportCounters(ctx context.Context, tx *bolt.Tx, keys map[reportOwner]string) error {
	index := tx.Bucket(reportIndexBucket)
	if index == nil {
		return errors.New("report index unavailable")
	}
	if index.Bucket(reportCountersBucket) != nil {
		if err := index.DeleteBucket(reportCountersBucket); err != nil {
			return err
		}
	}
	if _, err := index.CreateBucket(reportCountersBucket); err != nil {
		return err
	}
	codec := newContractCodec()
	return tx.Bucket(observationBucket).ForEach(func(location, raw []byte) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		report, key, err := verifyReportCounterOriginal(raw, location, keys, codec)
		if err != nil {
			return err
		}
		return indexReportCounters(tx, location, report, key)
	})
}

func verifyReportCounters(ctx context.Context, tx *bolt.Tx, keys map[reportOwner]string) error {
	parent := tx.Bucket(reportIndexBucket)
	if parent == nil || parent.Bucket(reportCountersBucket) == nil {
		return errors.New("report counter projections unavailable")
	}
	index := parent.Bucket(reportCountersBucket)
	if index.Sequence() != 0 {
		return errors.New("report counter projection has an independent sequence")
	}
	codec := newContractCodec()
	if err := tx.Bucket(observationBucket).ForEach(func(location, raw []byte) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		report, key, err := verifyReportCounterOriginal(raw, location, keys, codec)
		if err != nil {
			return err
		}
		expected, err := CanonicalEncode(counterIndexValue(report, key))
		if err != nil || !bytes.Equal(index.Get(location), expected) {
			return errors.New("report counter projection differs from its verified original")
		}
		return nil
	}); err != nil {
		return err
	}
	return index.ForEach(func(location, raw []byte) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if raw == nil || tx.Bucket(observationBucket).Get(location) == nil {
			return errors.New("counter projection has no original")
		}
		return nil
	})
}

// Historical rows come from the same committed original set. Only the highest
// position still consumes complete originals here; ordinary historical body
// corruption is detected by explicit verification/rebuild, not each graph read.
func (store *ObservationStore) walkDeviceCounterHistory(ctx context.Context, network, device, publicKey string, from, until int64, visit func(U64, reportReference, *reportCounterProjection) error) error {
	if ValidatePublicKey(publicKey) != nil {
		return errors.New("invalid counter history verification key")
	}
	highest, positions, err := store.pinDeviceCounterHistoryLocations(ctx, network, device, from, until)
	if err != nil {
		return err
	}
	codec := newContractCodec()
	var previous U64
	for offset := 0; offset < len(positions); {
		if err := ctx.Err(); err != nil {
			return err
		}
		first, copied := offset, 0
		type row struct{ value, highestRaw []byte }
		var rows []row
		err := store.withDatabase(ctx, false, func(tx *bolt.Tx) error {
			index := tx.Bucket(reportIndexBucket).Bucket(reportCountersBucket)
			if index == nil || index.Sequence() != 0 {
				return errors.New("report counter projections unavailable")
			}
			for offset < len(positions) && len(rows) < 64 {
				if err := ctx.Err(); err != nil {
					return err
				}
				position := positions[offset]
				value := index.Get(position.key)
				if len(value) == 0 || len(value) > controlHTTPBodyLimit {
					return errors.New("pinned counter projection is absent or exceeds its input boundary")
				}
				var raw []byte
				if position.ref.ReportSequence == highest {
					raw = tx.Bucket(observationBucket).Get(position.key)
					if len(raw) == 0 || len(raw) > controlHTTPBodyLimit {
						return errors.New("pinned highest original is absent or exceeds its input boundary")
					}
				}
				if copied > 0 && copied+len(value)+len(raw) > 1<<20 {
					break
				}
				rows = append(rows, row{bytes.Clone(value), bytes.Clone(raw)})
				copied += len(value) + len(raw)
				offset++
			}
			return nil
		})
		if err != nil {
			return err
		}
		for i, row := range rows {
			if err := ctx.Err(); err != nil {
				return err
			}
			position := positions[first+i]
			var value reportCounterIndexValue
			if err := codec.decode(row.value, &value, ContractDecodeLimits{MaxBytes: controlHTTPBodyLimit, MaxDepth: 128, MaxItems: 1 << 20}); err != nil {
				return err
			}
			if value.VerifiedPublicKey != publicKey {
				return errors.New("counter projection belongs to a different device verification key")
			}
			id, ref, err := locateReportKey(position.key)
			if err != nil {
				return err
			}
			if row.highestRaw != nil {
				actual := ReleaseDigest(row.highestRaw)
				original, err := store.decodedHistoryOriginal(row.highestRaw, actual, codec)
				if err != nil {
					return err
				}
				if actual != id || !bytes.Equal(referenceOf(original.report).key(actual), position.key) {
					return errors.New("highest original differs from its pinned position")
				}
				report, err := store.verifiedHistoryOriginal(original, publicKey)
				if err != nil {
					return err
				}
				expected, err := CanonicalEncode(counterIndexValue(report, publicKey))
				if err != nil || !bytes.Equal(row.value, expected) {
					return errors.New("highest counter projection differs from its original")
				}
			}
			if position.fork {
				continue
			}
			if previous != 0 && previous-1 != ref.ReportSequence {
				if err := visit(highest, reportReference{}, nil); err != nil {
					return err
				}
			}
			previous = ref.ReportSequence
			projection := reportCounterProjection{NetworkID: ref.NetworkID, DeviceID: ref.DeviceID, ReportSequence: ref.ReportSequence,
				NetworkGeneration: value.NetworkGeneration, ReportedAt: value.ReportedAt, WireGuardCounters: value.Counters, verifiedKey: publicKey}
			if err := visit(highest, projection.reference(), &projection); err != nil {
				return err
			}
		}
	}
	return ctx.Err()
}
