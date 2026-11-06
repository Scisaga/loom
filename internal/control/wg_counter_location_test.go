package control

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"strings"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func TestCounterLocationsKeepOutsideWindowForksAndRejectMissingRows(t *testing.T) {
	for _, scenario := range []string{"missing historical row", "outside-window historical fork", "missing highest fork row", "damaged highest fork original", "missing historical original"} {
		t.Run(scenario, func(t *testing.T) {
			key := testKey(t)
			public := base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
			identity := projectedDeviceIdentity{ID: "demo-device", DevicePublicKey: public}
			peer := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("a", 32)))
			digest := "sha256:" + strings.Repeat("0", 64)
			now := time.Date(2030, 1, 2, 12, 30, 0, 0, time.UTC)
			makeReport := func(seq U64, at time.Time) DeviceReport {
				r, err := SignDeviceReport(DeviceReport{Schema: 3, NetworkID: "demo-network", DeviceID: identity.ID, ReportSequence: seq, ViewDigest: digest, NetworkGeneration: "demo-underlay", ReportedAt: at.UnixMilli(), Selections: []ReportSelection{}, Observations: []Observation{}, Components: []ComponentReadback{}, Runtime: RuntimeReadback{State: "running", AppliedViewDigest: digest}, WireGuardCounters: &WireGuardCounters{Interface: "resource:demo-wg", Epoch: strings.Repeat("a", 32), ObservedAt: at.UnixMilli(), Peers: []WireGuardPeerCounter{{PublicKey: peer, RXBytes: seq * 100, TXBytes: seq * 200, Links: []WireGuardCounterLink{}}}}}, key)
				if err != nil {
					t.Fatal(err)
				}
				return r
			}
			reports := []DeviceReport{}
			for i := 1; i <= 4; i++ {
				reports = append(reports, makeReport(U64(i), now.Add(time.Duration(i-4)*time.Minute)))
			}
			if scenario == "outside-window historical fork" {
				reports = append(reports, makeReport(2, now.Add(-25*time.Hour)))
			}
			if scenario == "missing highest fork row" || scenario == "damaged highest fork original" {
				reports = append(reports, makeReport(4, now.Add(-25*time.Hour)))
			}
			root := t.TempDir()
			if err := os.Chmod(root, 0700); err != nil {
				t.Fatal(err)
			}
			testSetObservationReports(t, root, reports, public)
			store, err := testOpenObservationStore(t, root)
			if err != nil {
				t.Fatal(err)
			}
			which := 1
			if scenario == "missing highest fork row" || scenario == "damaged highest fork original" {
				which = len(reports) - 1
			}
			raw, err := CanonicalEncode(reports[which])
			if err != nil {
				t.Fatal(err)
			}
			location := referenceOf(reports[which]).key(ReleaseDigest(raw))
			if scenario != "outside-window historical fork" {
				err = store.withDatabase(context.Background(), true, func(tx *bolt.Tx) error {
					switch scenario {
					case "missing historical row", "missing highest fork row":
						return tx.Bucket(reportIndexBucket).Bucket(reportCountersBucket).Delete(location)
					case "damaged highest fork original":
						return tx.Bucket(observationBucket).Put(location, append(bytes.Clone(raw), '\n'))
					default:
						return tx.Bucket(observationBucket).Delete(location)
					}
				})
				if err != nil {
					t.Fatal(err)
				}
			}
			got, err := store.deviceTrafficHistory(context.Background(), "demo-network", identity, nil, now)
			if scenario == "outside-window historical fork" || scenario == "missing historical original" {
				if err != nil {
					t.Fatal(err)
				}
				intervals := 0
				for _, b := range got.Buckets {
					if b.Delta != nil {
						intervals += b.Delta.Intervals
					}
				}
				want := 3
				if scenario == "outside-window historical fork" {
					want = 1
				}
				if intervals != want {
					t.Fatalf("fork/source integrity boundary changed intervals: got %d want %d", intervals, want)
				}
				if scenario == "missing historical original" {
					keys := map[reportOwner]string{{"demo-network", identity.ID}: public}
					if err := store.withDatabase(context.Background(), false, func(tx *bolt.Tx) error { return verifyReportCounters(context.Background(), tx, keys) }); err == nil {
						t.Fatal("maintenance missed an absent historical original")
					}
				}
			} else if err == nil {
				t.Fatal("missing counter row or damaged highest fork acquired a usable winner")
			}
		})
	}
}
