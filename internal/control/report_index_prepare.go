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
func PrepareReportIndex(ctx context.Context, root, adminSocket string) error {
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
	return withObservationDB(ctx, filepath.Join(root, "observations.db"), true, func(tx *bolt.Tx) error {
		if err := ensureReportIndexes(tx); err != nil {
			return err
		}
		if err := ensureReportReceptions(tx, time.Now()); err != nil {
			return err
		}
		return ensureReportEventIndex(ctx, tx)
	})
}
