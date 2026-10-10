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
	"sync"
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
		value, err := SignDeviceReport(DeviceReport{Schema: 3, NetworkID: "demo-network", DeviceID: "demo-device", ReportSequence: U64(i + 1),
			ViewDigest: "sha256:" + strings.Repeat("0", 64), NetworkGeneration: "demo-underlay", ReportedAt: 1,
			Selections: []ReportSelection{}, Observations: []Observation{}, Components: []ComponentReadback{}, Runtime: RuntimeReadback{State: "stopped"}}, key)
		if err != nil {
			t.Fatal(err)
		}
		reports[i] = value
	}
	testSetObservationReports(t, root, reports[:1])
	store, err := OpenObservationStore(root)
	if err != nil {
		t.Fatal(err)
	}
	return store, reports, public
}

func holdReportOperation(t *testing.T, store *ObservationStore, write bool) func() {
	t.Helper()
	entered, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- store.withDatabase(context.Background(), write, func(*bolt.Tx) error {
			close(entered)
			<-release
			return nil
		})
	}()
	select {
	case <-entered:
	case err := <-done:
		t.Fatal("operation never entered original database", err)
	case <-time.After(5 * time.Second):
		t.Fatal("operation did not start")
	}
	var once sync.Once
	finish := func() {
		once.Do(func() {
			close(release)
			if err := <-done; err != nil {
				t.Error(err)
			}
		})
	}
	t.Cleanup(finish)
	return finish
}

func waitForReportOperation(t *testing.T, store *ObservationStore) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	// Observe a queued operation without consuming any read/write permission.
	for store.databaseAccess.TryAcquire(0) {
		if time.Now().After(deadline) {
			t.Fatal("report operation did not queue")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestPendingReportCommitPrecedesLaterSnapshot(t *testing.T) {
	store, reports, public := admissionReports(t)
	release := holdReportOperation(t, store, false)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	written := make(chan error, 1)
	go func() {
		written <- store.mergeReports(ctx, reports[1:], map[reportOwner]string{{"demo-network", "demo-device"}: public}, false)
	}()
	waitForReportOperation(t, store)
	type readback struct {
		reports []DeviceReport
		err     error
	}
	read := make(chan readback, 1)
	go func() {
		values, err := store.Latest(ctx)
		read <- readback{values, err}
	}()
	release()
	if err := <-written; err != nil {
		t.Fatal("pending original could not commit", err)
	}
	value := <-read
	if value.err != nil || len(value.reports) != 1 || value.reports[0].ReportSequence != 2 {
		t.Fatal("later snapshot overtook pending report commit", value)
	}
	reopened, err := OpenObservationStore(filepath.Dir(store.path))
	if err != nil {
		t.Fatal(err)
	}
	want, _ := CanonicalEncode(observationState{Schema: 3, Reports: reports})
	if !bytes.Equal(testObservationBytes(t, filepath.Dir(reopened.path)), want) {
		t.Fatal("read/write scheduling changed originals or restart recovery")
	}
}

func TestReportOperationCancellationAndFailureReleaseAdmission(t *testing.T) {
	for _, write := range []bool{false, true} {
		t.Run(map[bool]string{false: "reader", true: "writer"}[write], func(t *testing.T) {
			store, reports, public := admissionReports(t)
			before := testObservationBytes(t, filepath.Dir(store.path))
			release := holdReportOperation(t, store, !write)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan error, 1)
			go func() {
				if write {
					done <- store.mergeReports(ctx, reports[1:], map[reportOwner]string{{"demo-network", "demo-device"}: public}, false)
				} else {
					_, err := store.Latest(ctx)
					done <- err
				}
			}()
			waitForReportOperation(t, store)
			cancel()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatal("cancelled request did not fail explicitly", err)
				}
			case <-time.After(time.Second):
				t.Fatal("cancelled request waited for unrelated database operation")
			}
			release()
			failure := errors.New("demo transaction failure")
			if err := store.withDatabase(context.Background(), true, func(*bolt.Tx) error { return failure }); !errors.Is(err, failure) {
				t.Fatal("transaction error was lost", err)
			}
			if !bytes.Equal(before, testObservationBytes(t, filepath.Dir(store.path))) {
				t.Fatal("cancelled or failed operation changed signed originals")
			}
			if err := store.Put(reports[1], public); err != nil {
				t.Fatal("cancelled or failed operation retained admission", err)
			}
		})
	}
}
