package control

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func TestPrepareReportIndexRequiresStoppedExistingOwner(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(root, "admin.sock")
	if err := PrepareReportIndex(context.Background(), root, socket); err == nil {
		t.Fatal("preparation initialized missing original history")
	}
	if _, err := os.Lstat(filepath.Join(root, "observations.db")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("missing database was recreated", err)
	}
	if err := initializeObservationDB(filepath.Join(root, "observations.db")); err != nil {
		t.Fatal(err)
	}
	listener, err := lockProtectedControlPath(context.Background(), socket+".listen.lock")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	err = PrepareReportIndex(ctx, root, socket)
	cancel()
	listener.Close()
	if err == nil {
		t.Fatal("preparation ignored the formal listener owner")
	}
	db, _, err := openReportDatabase(context.Background(), filepath.Join(root, "observations.db"), false)
	if err != nil {
		t.Fatal(err)
	}
	if err := PrepareReportIndex(context.Background(), root, socket); err == nil {
		t.Fatal("preparation ignored the actual live database owner")
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := PrepareReportIndex(context.Background(), root, socket); err != nil {
		t.Fatal(err)
	}
	if err := withObservationDB(context.Background(), filepath.Join(root, "observations.db"), false, func(tx *bolt.Tx) error {
		if tx.Bucket(reportIndexBucket).Bucket(reportEventIndexBucket) == nil {
			t.Fatal("candidate locations were not initialized")
		}
		if tx.Bucket(observationBucket).Stats().KeyN != 0 {
			t.Fatal("preparation manufactured a report")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
