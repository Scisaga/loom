package control

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func admissionReports(t *testing.T) (*ObservationStore, []DeviceReport, string) {
	t.Helper()
	key := testKey(t)
	public := base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	reports := make([]DeviceReport, 2)
	for i := range reports {
		value, err := SignDeviceReport(DeviceReport{Schema: 3, NetworkID: "demo-network", DeviceID: "demo-device", ReportSequence: U64(i + 1), ViewDigest: "sha256:" + strings.Repeat("0", 64), NetworkGeneration: "demo-underlay", ReportedAt: int64(i + 1), Selections: []ReportSelection{}, Observations: []Observation{}, Components: []ComponentReadback{}, Runtime: RuntimeReadback{State: "stopped"}}, key)
		if err != nil {
			t.Fatal(err)
		}
		reports[i] = value
	}
	testSetObservationReports(t, root, reports[:1])
	store, err := testOpenObservationStore(t, root)
	if err != nil {
		t.Fatal(err)
	}
	return store, reports, public
}
func TestReportReadersUseCommittedSnapshotWhileWriterWaits(t *testing.T) {
	store, reports, public := admissionReports(t)
	store.write <- struct{}{}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- store.mergeReports(ctx, reports[1:], map[reportOwner]string{{"demo-network", "demo-device"}: public}, false)
	}()
	latest, err := store.Latest(ctx)
	if err != nil || len(latest) != 1 || latest[0].ReportSequence != 1 {
		t.Fatal("read blocked behind uncommitted writer", err)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal("waiting writer did not cancel", err)
	}
	<-store.write
	if err := store.Put(reports[1], public); err != nil {
		t.Fatal(err)
	}
	before := testObservationBytes(t, store)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := testOpenObservationStore(t, filepath.Dir(store.path))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, testObservationBytes(t, reopened)) {
		t.Fatal("restart changed originals")
	}
}
func TestReportFailedTransactionLeavesOriginalsAndIndexesUnchanged(t *testing.T) {
	store, reports, public := admissionReports(t)
	before := testObservationBytes(t, store)
	failure := errors.New("demo transaction failure")
	err := store.withDatabase(context.Background(), true, func(tx *bolt.Tx) error {
		raw, _ := CanonicalEncode(reports[1])
		key := referenceOf(reports[1]).key(ReleaseDigest(raw))
		if err := tx.Bucket(observationBucket).Put(key, raw); err != nil {
			return err
		}
		if err := indexReport(tx, key, reports[1]); err != nil {
			return err
		}
		return failure
	})
	if !errors.Is(err, failure) || !bytes.Equal(before, testObservationBytes(t, store)) {
		t.Fatal("transaction changed originals", err)
	}
	raw, _ := CanonicalEncode(reports[1])
	known, err := store.knownReports(context.Background(), []string{ReleaseDigest(raw)})
	if err != nil || len(known) != 0 {
		t.Fatal("failed transaction left an index", err)
	}
	if err := store.Put(reports[1], public); err != nil {
		t.Fatal(err)
	}
}
