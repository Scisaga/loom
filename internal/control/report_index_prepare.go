package control

import (
	"context"
	"errors"
	"path/filepath"
	"time"

	bolt "go.etcd.io/bbolt"
)

// PrepareReportIndex builds the same disposable locations used at startup, with
// the formal owner stopped. It never initializes a missing original database.
type ReportIndexOptions struct {
	Verify  bool
	Rebuild bool
	Stats   *ReportIndexStats
}

type ReportIndexStats struct {
	Originals     int   `json:"originals"`
	WGRows        int   `json:"wg_rows"`
	OriginalBytes int64 `json:"original_bytes"`
	WGBytes       int64 `json:"wg_bytes"`
}

func PrepareReportIndex(ctx context.Context, root, adminSocket string, options ...ReportIndexOptions) error {
	if len(options) > 1 || len(options) == 1 && options[0].Verify && options[0].Rebuild {
		return errors.New("report index verify and rebuild are mutually exclusive")
	}
	mode := ReportIndexOptions{}
	if len(options) == 1 {
		mode = options[0]
	}
	if err := validateControlRoot(root); err != nil {
		return err
	}
	if !absoluteControlPath(adminSocket) {
		return errors.New("report index preparation requires the actual canonical admin socket path")
	}
	listener, err := lockProtectedControlPath(ctx, adminSocket+".listen.lock")
	if err != nil {
		return err
	}
	defer listener.Close()
	lock, err := lockProtectedControlPath(ctx, filepath.Join(root, ".observations.lock"))
	if err != nil {
		return err
	}
	defer lock.Close()
	var stats ReportIndexStats
	err = withObservationDB(ctx, filepath.Join(root, "observations.db"), !mode.Verify, func(tx *bolt.Tx) (operationErr error) {
		defer func() {
			if operationErr != nil || mode.Stats == nil {
				return
			}
			operationErr = tx.Bucket(observationBucket).ForEach(func(_, raw []byte) error {
				stats.Originals++
				stats.OriginalBytes += int64(len(raw))
				return ctx.Err()
			})
			if operationErr == nil {
				operationErr = tx.Bucket(reportIndexBucket).Bucket(reportCountersBucket).ForEach(func(key, raw []byte) error {
					if !isReportCounterLayoutKey(key) {
						stats.WGRows++
					}
					stats.WGBytes += int64(len(raw))
					return ctx.Err()
				})
			}
		}()
		var keys map[reportOwner]string
		first, _ := tx.Bucket(observationBucket).Cursor().First()
		if first != nil {
			var err error
			keys, err = loadReportVerificationKeys(ctx, root)
			if err != nil {
				return err
			}
		}
		if mode.Verify {
			if err := verifyReportCounters(ctx, tx, keys); err != nil {
				return err
			}
			return verifyReportMeasurements(ctx, tx, keys)
		}
		if mode.Rebuild {
			if err := rebuildReportCounters(ctx, tx, keys); err != nil {
				return err
			}
			return rebuildReportMeasurements(ctx, tx, keys)
		}
		if err := ensureReportIndexes(tx); err != nil {
			return err
		}
		if err := ensureReportReceptions(tx, time.Now()); err != nil {
			return err
		}
		if err := ensureReportEventIndex(ctx, tx); err != nil {
			return err
		}
		if err := ensureReportMeasurementIndex(ctx, tx); err != nil {
			return err
		}
		child := tx.Bucket(reportIndexBucket).Bucket(reportCountersBucket)
		if child == nil {
			return rebuildReportCounters(ctx, tx, keys)
		}
		return reportCountersReady(child)
	})
	if err == nil && mode.Stats != nil {
		*mode.Stats = stats
	}
	return err
}
