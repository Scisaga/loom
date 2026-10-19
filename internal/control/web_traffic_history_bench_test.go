package control

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

// Exercise the real window/index/original/signature/aggregation chain, with a
// full day's reports rather than using the small response size as input size.
func BenchmarkDeviceTrafficHistory(b *testing.B) {
	for _, scenario := range []struct {
		name         string
		observations int
	}{{"simple", 4}, {"dense", 128}} {
		b.Run(scenario.name, func(b *testing.B) {
			benchmarkDeviceTrafficHistory(b, scenario.observations)
		})
	}
}

func benchmarkDeviceTrafficHistory(b *testing.B, observations int) {
	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		b.Fatal(err)
	}
	root := b.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		b.Fatal(err)
	}
	store, err := OpenObservationStore(root)
	if err != nil {
		b.Fatal(err)
	}
	defer store.Close()
	identity := projectedDeviceIdentity{ID: "demo-device", DevicePublicKey: base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))}
	now := time.Date(2030, 1, 2, 23, 59, 30, 0, time.UTC)
	digest := "sha256:" + strings.Repeat("0", 64)
	var originals, compact, highestBytes int64
	err = store.withDatabase(context.Background(), true, func(tx *bolt.Tx) error {
		if err := tx.DeleteBucket(reportIndexBucket); err != nil {
			return err
		}
		for i := 0; i < 24*120; i++ {
			at := now.Add(time.Duration(i-(24*120-1)) * 30 * time.Second).UnixMilli()
			report := DeviceReport{Schema: 3, NetworkID: "demo-network", DeviceID: identity.ID, ReportSequence: U64(i + 1), ViewDigest: digest,
				NetworkGeneration: "demo-underlay", ReportedAt: at, Selections: []ReportSelection{}, Observations: []Observation{},
				Components: []ComponentReadback{}, Runtime: RuntimeReadback{State: "running", AppliedViewDigest: digest},
				WireGuardCounters: &WireGuardCounters{Interface: "resource:demo-wg", Epoch: strings.Repeat("a", 32), ObservedAt: at, Peers: []WireGuardPeerCounter{}}}
			for j := 0; j < 4; j++ {
				link := fmt.Sprintf("demo-link-%d", j)
				peer := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat(string(rune('a'+j)), 32)))
				report.WireGuardCounters.Peers = append(report.WireGuardCounters.Peers, WireGuardPeerCounter{PublicKey: peer, RXBytes: U64(i * 1024), TXBytes: U64(i * 2048), Links: []WireGuardCounterLink{{LinkID: link, SpecDigest: digest}}})
			}
			for j := 0; j < observations; j++ {
				report.Observations = append(report.Observations, Observation{Level: "service", ServiceID: fmt.Sprintf("demo-service-%d", j), CandidateID: digest, SpecDigest: digest,
					Target: "https://demo.example/probe", Action: "https_request", NetworkGeneration: report.NetworkGeneration, Result: "available", ObservedAt: at, ValidUntil: at + 30000, DurationMS: new(int64(10))})
			}
			sort.Slice(report.WireGuardCounters.Peers, func(i, j int) bool {
				return report.WireGuardCounters.Peers[i].PublicKey < report.WireGuardCounters.Peers[j].PublicKey
			})
			sort.Slice(report.Observations, func(i, j int) bool {
				return compareObservationOrder(report.Observations[i], report.Observations[j]) < 0
			})
			report, err := SignDeviceReport(report, key)
			if err != nil {
				return err
			}
			raw, err := CanonicalEncode(report)
			if err != nil {
				return err
			}
			originals += int64(len(raw))
			highestBytes = int64(len(raw))
			if err := tx.Bucket(observationBucket).Put(referenceOf(report).key(ReleaseDigest(raw)), raw); err != nil {
				return err
			}
		}
		if err := ensureReportIndexes(tx); err != nil {
			return err
		}
		if err := rebuildReportCounters(context.Background(), tx, map[reportOwner]string{{"demo-network", identity.ID}: identity.DevicePublicKey}); err != nil {
			return err
		}
		return tx.Bucket(reportIndexBucket).Bucket(reportCountersBucket).ForEach(func(_, raw []byte) error {
			compact += int64(len(raw))
			return nil
		})
	})
	if err != nil {
		b.Fatal(err)
	}
	read := func(b *testing.B) {
		b.Helper()
		history, err := store.deviceTrafficHistory(context.Background(), "demo-network", identity, nil, now)
		if err != nil || len(history.Buckets) != 24 || history.Recent == nil || history.Recent.TXBytes != 4*10*2048 || history.Recent.CoveredMS != 5*time.Minute.Milliseconds() {
			b.Fatal("full-day traffic history lost actual recent bytes or coverage", err, history.Recent)
		}
	}
	for _, cold := range []bool{true, false} {
		name := "warm"
		if cold {
			name = "cold"
		}
		b.Run(name, func(b *testing.B) {
			read(b)
			b.SetBytes(compact + highestBytes)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if cold {
					b.StopTimer()
					store.cache.clear()
					b.StartTimer()
				}
				read(b)
			}
			b.ReportMetric(float64(originals)/float64(24*120), "original-bytes/report")
			b.ReportMetric(float64(compact)/float64(24*120), "index-bytes/report")
		})
	}
}
