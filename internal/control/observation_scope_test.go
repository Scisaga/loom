package control

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"os"
	"strings"
	"testing"

	bolt "go.etcd.io/bbolt"
)

func TestReportCommitReadsActualOwnerHistory(t *testing.T) {
	for _, scenario := range []string{"restarted-highest-and-fork", "unrelated-corruption"} {
		t.Run(scenario, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Chmod(root, 0700); err != nil {
				t.Fatal(err)
			}
			keys := map[string]ed25519.PrivateKey{"demo-a": testKey(t), "demo-b": testKey(t)}
			public := func(device string) string {
				return base64.RawURLEncoding.EncodeToString(keys[device].Public().(ed25519.PublicKey))
			}
			sign := func(device string, sequence U64, at int64) DeviceReport {
				t.Helper()
				value, err := SignDeviceReport(DeviceReport{Schema: 3, NetworkID: "demo-network", DeviceID: device, ReportSequence: sequence,
					ViewDigest: "sha256:" + strings.Repeat("0", 64), NetworkGeneration: "demo-underlay", ReportedAt: at,
					Selections: []ReportSelection{}, Observations: []Observation{}, Components: []ComponentReadback{}, Runtime: RuntimeReadback{State: "stopped"}}, keys[device])
				if err != nil {
					t.Fatal(err)
				}
				return value
			}
			firstA, firstB := sign("demo-a", 1, 1), sign("demo-b", 1, 1)
			testSetObservationReports(t, root, []DeviceReport{firstA, firstB})
			store, err := testOpenObservationStore(t, root)
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "restarted-highest-and-fork" {
				if err := store.Put(sign("demo-a", 3, 1), public("demo-a")); err != nil {
					t.Fatal(err)
				}
				if err := store.Close(); err != nil {
					t.Fatal(err)
				}
				store, err = testOpenObservationStore(t, root)
				if err != nil {
					t.Fatal(err)
				}
				if err := store.Put(sign("demo-a", 2, 1), public("demo-a")); !errors.Is(err, ErrReportReplay) {
					t.Fatal("stale metadata hid the durable higher sequence", err)
				}
				if err := store.Put(sign("demo-b", 2, 1), public("demo-b")); err != nil {
					t.Fatal("another device's sequence blocked an independent owner", err)
				}
				store.cache.clear()
				if err := store.Put(sign("demo-a", 3, 2), public("demo-a")); !errors.Is(err, ErrReportEquivocation) {
					t.Fatal("discarded metadata hid a durable fork", err)
				}
				latest, err := store.Latest(context.Background())
				if err != nil || len(latest) != 1 || latest[0].DeviceID != "demo-b" || latest[0].ReportSequence != 2 {
					t.Fatal("fork acquired a winner or independent owner was lost", latest, err)
				}
				want, err := CanonicalEncode(observationState{Schema: 3, Reports: []DeviceReport{firstA, sign("demo-a", 3, 1), sign("demo-a", 3, 2), firstB, sign("demo-b", 2, 1)}})
				if err != nil || !bytes.Equal(want, testObservationBytes(t, store)) {
					t.Fatal("reopen lost or changed original signed history", err)
				}
				return
			}
			body, _ := CanonicalEncode(firstB)
			physical := referenceOf(firstB).key(ReleaseDigest(body))
			corrupt := append(bytes.Clone(body), '\n')
			if err := store.withDatabase(context.Background(), true, func(tx *bolt.Tx) error { return tx.Bucket(observationBucket).Put(physical, corrupt) }); err != nil {
				t.Fatal(err)
			}
			if err := store.Put(sign("demo-a", 2, 1), public("demo-a")); err != nil {
				t.Fatal("independent owner could not submit its valid next original", err)
			}
			if err := store.Put(sign("demo-b", 2, 1), public("demo-b")); err == nil {
				t.Fatal("owner commit ignored corruption in its own history")
			}
			if _, err := store.Latest(context.Background()); err == nil {
				t.Fatal("independent commit manufactured whole-database validity")
			}
			for _, device := range []string{"demo-a", "demo-b"} {
				err := store.walkDeviceHistorySnapshot(context.Background(), "demo-network", device, func(U64, reportReference, []byte) error { return nil })
				if (err != nil) != (device == "demo-b") {
					t.Fatal("history reader did not validate its own originals", device, err)
				}
			}
			if err := store.withDatabase(context.Background(), false, func(tx *bolt.Tx) error {
				if !bytes.Equal(tx.Bucket(observationBucket).Get(physical), corrupt) {
					t.Error("independent commit rewrote unrelated evidence")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
