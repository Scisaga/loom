package control

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func TestTrafficHistoryProjectionDoesNotBlockReportCommit(t *testing.T) {
	key := testKey(t)
	public := base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	reports := make([]DeviceReport, 4)
	for i := range reports {
		value, err := SignDeviceReport(DeviceReport{Schema: 3, NetworkID: "demo-network", DeviceID: "demo-device", ReportSequence: U64(i + 1), ViewDigest: "sha256:" + strings.Repeat("0", 64), NetworkGeneration: "demo-underlay", ReportedAt: 1, Selections: []ReportSelection{}, Observations: []Observation{}, Components: []ComponentReadback{}, Runtime: RuntimeReadback{State: "stopped"}}, key)
		if err != nil {
			t.Fatal(err)
		}
		reports[i] = value
	}
	testSetObservationReports(t, root, []DeviceReport{reports[0], reports[2]})
	store, err := OpenObservationStore(root)
	if err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	seen := []U64{}
	readCtx, readCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer readCancel()
	go func() {
		done <- store.walkDeviceHistorySnapshot(readCtx, "demo-network", "demo-device", func(highest U64, _ reportReference, raw []byte) error {
			if len(seen) == 0 {
				close(entered)
				<-release
			}
			if highest != 3 {
				return fmt.Errorf("query highest changed to %d", highest)
			}
			var report DeviceReport
			if err := decodeStoredReport(raw, &report); err != nil {
				return err
			}
			seen = append(seen, report.ReportSequence)
			return report.Verify(public)
		})
	}()
	select {
	case <-entered:
	case err := <-done:
		t.Fatalf("history did not reach projection: %v", err)
	case <-readCtx.Done():
		t.Fatal("history never reached projection")
	}
	writeCtx, writeCancel := context.WithTimeout(context.Background(), 2*time.Second)
	writeErr := store.mergeReports(writeCtx, []DeviceReport{reports[1], reports[3]}, map[reportOwner]string{{"demo-network", "demo-device"}: public}, true)
	writeCancel()
	close(release)
	readErr := <-done
	if writeErr != nil {
		t.Fatalf("new reports could not commit while history projection was pending: %v", writeErr)
	}
	if readErr != nil || !reflect.DeepEqual(seen, []U64{3, 1}) {
		t.Fatal("query did not retain its original input set", seen, readErr)
	}
	latest, err := store.Latest(context.Background())
	if err != nil || len(latest) != 1 || latest[0].ReportSequence != 4 {
		t.Fatal("concurrent report was not durably accepted", latest, err)
	}
	original := testObservationBytes(t, root)
	want, err := CanonicalEncode(observationState{Schema: 3, Reports: reports})
	if err != nil || string(original) != string(want) {
		t.Fatal("history query changed signed originals", err)
	}
}

func TestTrafficHistorySnapshotRejectsChangedOriginalsAndCancellation(t *testing.T) {
	for _, action := range []string{"delete", "replace", "cancel"} {
		t.Run(action, func(t *testing.T) {
			key := testKey(t)
			public := base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
			root := t.TempDir()
			if err := os.Chmod(root, 0700); err != nil {
				t.Fatal(err)
			}
			reports := make([]DeviceReport, 65)
			for i := range reports {
				value, err := SignDeviceReport(DeviceReport{Schema: 3, NetworkID: "demo-network", DeviceID: "demo-device", ReportSequence: U64(i + 1),
					ViewDigest: "sha256:" + strings.Repeat("0", 64), NetworkGeneration: "demo-underlay", ReportedAt: 1,
					Selections: []ReportSelection{}, Observations: []Observation{}, Components: []ComponentReadback{}, Runtime: RuntimeReadback{State: "stopped"}}, key)
				if err != nil {
					t.Fatal(err)
				}
				reports[i] = value
			}
			testSetObservationReports(t, root, reports)
			store, err := OpenObservationStore(root)
			if err != nil {
				t.Fatal(err)
			}
			before := testObservationBytes(t, root)
			original, err := CanonicalEncode(reports[0])
			if err != nil {
				t.Fatal(err)
			}
			storageKey := referenceOf(reports[0]).key(ReleaseDigest(original))
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			visited := 0
			err = store.walkDeviceHistorySnapshot(ctx, "demo-network", "demo-device", func(_ U64, _ reportReference, raw []byte) error {
				if visited == 0 {
					if action == "cancel" {
						cancel()
					} else if err := withObservationDB(context.Background(), store.path, true, func(tx *bolt.Tx) error {
						if action == "delete" {
							return tx.Bucket(observationBucket).Delete(storageKey)
						}
						replacement, err := CanonicalEncode(reports[1])
						if err != nil {
							return err
						}
						return tx.Bucket(observationBucket).Put(storageKey, replacement)
					}); err != nil {
						return err
					}
				}
				var report DeviceReport
				if err := decodeStoredReport(raw, &report); err != nil {
					return err
				}
				if report.ReportSequence == 1 {
					t.Error("changed or removed original reached projection")
				}
				visited++
				return report.Verify(public)
			})
			if err == nil {
				t.Fatal("query returned success after its original changed or cancellation")
			}
			if action == "cancel" && (!errors.Is(err, context.Canceled) || visited != 1 || !bytes.Equal(before, testObservationBytes(t, root))) {
				t.Fatal("cancelled projection continued or changed originals", visited, err)
			}
		})
	}
}

func TestHistorySnapshotExcludesForksAcrossBatchesAndAtHighestSequence(t *testing.T) {
	key := testKey(t)
	public := base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
	for _, forkSequence := range []U64{2, 65} {
		t.Run(fmt.Sprint(forkSequence), func(t *testing.T) {
			root := t.TempDir()
			if err := os.Chmod(root, 0700); err != nil {
				t.Fatal(err)
			}
			reports := make([]DeviceReport, 65)
			for i := range reports {
				value, err := SignDeviceReport(DeviceReport{Schema: 3, NetworkID: "demo-network", DeviceID: "demo-device", ReportSequence: U64(i + 1),
					ViewDigest: "sha256:" + strings.Repeat("0", 64), NetworkGeneration: "demo-underlay", ReportedAt: 1,
					Selections: []ReportSelection{}, Observations: []Observation{}, Components: []ComponentReadback{}, Runtime: RuntimeReadback{State: "stopped"}}, key)
				if err != nil {
					t.Fatal(err)
				}
				reports[i] = value
			}
			fork := reports[int(forkSequence)-1]
			fork.ReportedAt = 2
			fork, err := SignDeviceReport(fork, key)
			if err != nil {
				t.Fatal(err)
			}
			testSetObservationReports(t, root, append(reports, fork))
			store, err := OpenObservationStore(root)
			if err != nil {
				t.Fatal(err)
			}
			original := testObservationBytes(t, root)
			seen := map[U64]bool{}
			err = store.walkDeviceHistorySnapshot(context.Background(), "demo-network", "demo-device", func(highest U64, ref reportReference, raw []byte) error {
				if highest != 65 || ref.ReportSequence == forkSequence || seen[ref.ReportSequence] {
					return fmt.Errorf("fork became a winner, highest changed, or original repeated")
				}
				var report DeviceReport
				if err := decodeStoredReport(raw, &report); err != nil {
					return err
				}
				if report.ReportSequence != ref.ReportSequence {
					return fmt.Errorf("reference differs from original")
				}
				seen[ref.ReportSequence] = true
				return report.Verify(public)
			})
			if err != nil || len(seen) != 64 || !bytes.Equal(original, testObservationBytes(t, root)) {
				t.Fatal("fork exclusion changed valid history or original bytes", len(seen), err)
			}
		})
	}
}

func TestHistorySnapshotRejectsMalformedPhysicalKey(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	testSetObservationReports(t, root, nil)
	store, err := OpenObservationStore(root)
	if err != nil {
		t.Fatal(err)
	}
	err = store.withDatabase(context.Background(), true, func(tx *bolt.Tx) error {
		return tx.Bucket(observationBucket).Put([]byte("demo-network\x00demo-device\x00invalid"), []byte("{}"))
	})
	if err != nil {
		t.Fatal(err)
	}
	visited := false
	err = store.walkDeviceHistorySnapshot(context.Background(), "demo-network", "demo-device", func(U64, reportReference, []byte) error {
		visited = true
		return nil
	})
	if err == nil || visited {
		t.Fatal("malformed physical key reached history projection", err)
	}
}
