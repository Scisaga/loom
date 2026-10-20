package control

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func layoutTrafficTotals(value WebDeviceTraffic) (rx, tx U64, covered int64) {
	for _, bucket := range value.Buckets {
		if bucket.Delta != nil {
			rx += bucket.Delta.RXBytes
			tx += bucket.Delta.TXBytes
			covered += bucket.Delta.CoveredMS
		}
	}
	return
}

func TestCounterLayoutLinkChangesPreserveDeviceIntervals(t *testing.T) {
	for _, change := range []string{"link", "spec"} {
		t.Run(change, func(t *testing.T) {
			key := testKey(t)
			public := base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
			identity := projectedDeviceIdentity{ID: "demo-device", DevicePublicKey: public}
			peer := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{'a'}, 32))
			digest := "sha256:" + strings.Repeat("0", 64)
			now := time.Date(2030, 1, 2, 12, 30, 0, 0, time.UTC)
			reports := make([]DeviceReport, 3)
			for i := range reports {
				at := now.Add(time.Duration(i-2) * time.Minute).UnixMilli()
				link := WireGuardCounterLink{LinkID: "demo-link", SpecDigest: digest}
				if i == 2 && change == "link" {
					link.LinkID = "demo-other-link"
				}
				if i == 2 && change == "spec" {
					link.SpecDigest = "sha256:" + strings.Repeat("1", 64)
				}
				report := DeviceReport{Schema: 3, NetworkID: "demo-network", DeviceID: identity.ID, ReportSequence: U64(i + 1), ViewDigest: digest,
					NetworkGeneration: "demo-underlay", ReportedAt: at, Selections: []ReportSelection{}, Observations: []Observation{}, Components: []ComponentReadback{},
					Runtime: RuntimeReadback{State: "running", AppliedViewDigest: digest},
					WireGuardCounters: &WireGuardCounters{Interface: "resource:demo-wg", Epoch: strings.Repeat("a", 32), ObservedAt: at,
						Peers: []WireGuardPeerCounter{{PublicKey: peer, RXBytes: []U64{100, 1100, 3100}[i], TXBytes: []U64{200, 2200, 5200}[i], Links: []WireGuardCounterLink{link}}}}}
				var err error
				reports[i], err = SignDeviceReport(report, key)
				if err != nil {
					t.Fatal(err)
				}
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
			before := testObservationBytes(t, store)
			device, err := store.deviceTrafficHistory(context.Background(), "demo-network", identity, nil, now)
			if rx, tx, covered := layoutTrafficTotals(device); err != nil || rx != 3000 || tx != 5000 || covered != 120000 {
				t.Fatal("a static Link-only change cut an otherwise continuous device interval", rx, tx, covered, err)
			}
			oldScope := &trafficLinkScope{id: "demo-link", spec: digest, endpoint: "resource:demo-wg", peer: peer}
			oldLink, err := store.deviceTrafficHistory(context.Background(), "demo-network", identity, oldScope, now)
			if rx, tx, covered := layoutTrafficTotals(oldLink); err != nil || rx != 1000 || tx != 2000 || covered != 60000 {
				t.Fatal("Link history ignored one endpoint's changed binding", rx, tx, covered, err)
			}
			latest := reports[2].WireGuardCounters.Peers[0].Links[0]
			newScope := &trafficLinkScope{id: latest.LinkID, spec: latest.SpecDigest, endpoint: "resource:demo-wg", peer: peer}
			newLink, err := store.deviceTrafficHistory(context.Background(), "demo-network", identity, newScope, now)
			if rx, tx, covered := layoutTrafficTotals(newLink); err != nil || rx != 0 || tx != 0 || covered != 0 {
				t.Fatal("a new Link binding acquired an interval from the older layout", rx, tx, covered, err)
			}
			if !bytes.Equal(before, testObservationBytes(t, store)) {
				t.Fatal("layout-backed history changed signed originals")
			}
		})
	}
}

func TestCounterLayoutDistinguishesAbsentCountersAndEmptyPeers(t *testing.T) {
	absent := counterIndexEncodingFixture()
	absent.Counters = nil
	empty := absent
	empty.Counters = &WireGuardCounters{Interface: "wg-shared", Epoch: strings.Repeat("a", 32), ObservedAt: 1, Peers: []WireGuardPeerCounter{}}
	var keys [][]byte
	for _, value := range []reportCounterIndexValue{absent, empty} {
		row, layout, err := encodeReportCounterIndex(value)
		if err != nil {
			t.Fatal(err)
		}
		var actual reportCounterIndexValue
		if err := decodeReportCounterIndex(row, layout, &actual); err != nil || !reflect.DeepEqual(actual, value) {
			t.Fatal("optional counters or explicit empty peers changed meaning", actual, err)
		}
		key, err := reportCounterLayoutKey(row)
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, key)
	}
	if bytes.Equal(keys[0], keys[1]) {
		t.Fatal("absent counters and a real empty-peer observation share a layout")
	}
}

func TestCounterLayoutDamageFailsCurrentHistoryQuery(t *testing.T) {
	for _, damage := range []string{"missing", "changed"} {
		t.Run(damage, func(t *testing.T) {
			store, reports, public := admissionReports(t)
			raw, err := CanonicalEncode(reports[0])
			if err != nil {
				t.Fatal(err)
			}
			location := referenceOf(reports[0]).key(ReleaseDigest(raw))
			before := testObservationBytes(t, store)
			if err := store.withDatabase(context.Background(), true, func(tx *bolt.Tx) error {
				bucket := tx.Bucket(reportIndexBucket).Bucket(reportCountersBucket)
				layout, err := reportCounterLayoutKey(bucket.Get(location))
				if err != nil {
					return err
				}
				if damage == "missing" {
					return bucket.Delete(layout)
				}
				return bucket.Put(layout, append(bytes.Clone(bucket.Get(layout)), 0))
			}); err != nil {
				t.Fatal(err)
			}
			if err := store.walkDeviceCounterHistory(context.Background(), "demo-network", "demo-device", public, 0, 10, func(U64, reportReference, *reportCounterProjection) error { return nil }); err == nil {
				t.Fatal("history hid a missing or hash-mismatched referenced layout")
			}
			if !bytes.Equal(before, testObservationBytes(t, store)) {
				t.Fatal("failed history repaired or changed signed originals")
			}
		})
	}
}

func TestCounterLayoutCollisionRollsBackOriginalAndRows(t *testing.T) {
	root, _, reports, public := reportIndexFixture(t)
	report := reports[0]
	raw, err := CanonicalEncode(report)
	if err != nil {
		t.Fatal(err)
	}
	location := referenceOf(report).key(ReleaseDigest(raw))
	path := filepath.Join(root, "observations.db")
	if err := withReportDatabase(context.Background(), path, true, func(tx *bolt.Tx) error {
		index := tx.Bucket(reportIndexBucket).Bucket(reportCountersBucket)
		key, err := reportCounterLayoutKey(index.Get(location))
		if err != nil {
			return err
		}
		return index.Put(key, append(bytes.Clone(index.Get(key)), 0))
	}); err != nil {
		t.Fatal(err)
	}
	originals := reportBucketSnapshot(t, root, observationBucket)
	rows := reportBucketSnapshot(t, root, reportCountersBucket)
	err = withReportDatabase(context.Background(), path, true, func(tx *bolt.Tx) error {
		if err := tx.Bucket(observationBucket).Put([]byte("demo-new-original"), raw); err != nil {
			return err
		}
		if err := tx.Bucket(reportIndexBucket).Bucket(reportCountersBucket).Put([]byte("demo-new-row"), []byte("demo-pending-row")); err != nil {
			return err
		}
		return indexReportCounters(tx, location, report, public)
	})
	if err == nil || !strings.Contains(err.Error(), "collides") {
		t.Fatal("writer replaced conflicting layout bytes instead of failing", err)
	}
	if !reflect.DeepEqual(originals, reportBucketSnapshot(t, root, observationBucket)) || !reflect.DeepEqual(rows, reportBucketSnapshot(t, root, reportCountersBucket)) {
		t.Fatal("layout collision committed a partial original or projection write")
	}
}

func TestCounterLayoutOfflineVerificationRejectsReferenceSetDamage(t *testing.T) {
	for _, damage := range []string{"missing-layout", "changed-layout", "extra-row", "orphan-layout"} {
		t.Run(damage, func(t *testing.T) {
			root, socket, reports, _ := reportIndexFixture(t)
			originals := reportBucketSnapshot(t, root, observationBucket)
			receptions := reportBucketSnapshot(t, root, reportReceptionBucket)
			raw, _ := CanonicalEncode(reports[0])
			location := referenceOf(reports[0]).key(ReleaseDigest(raw))
			if err := withReportDatabase(context.Background(), filepath.Join(root, "observations.db"), true, func(tx *bolt.Tx) error {
				bucket := tx.Bucket(reportIndexBucket).Bucket(reportCountersBucket)
				row := bytes.Clone(bucket.Get(location))
				layout, err := reportCounterLayoutKey(row)
				if err != nil {
					return err
				}
				switch damage {
				case "missing-layout":
					return bucket.Delete(layout)
				case "changed-layout":
					return bucket.Put(layout, append(bytes.Clone(bucket.Get(layout)), 0))
				case "extra-row":
					return bucket.Put([]byte("demo-extra-original-position"), row)
				default:
					value := counterIndexEncodingFixture()
					row, body, err := encodeReportCounterIndex(value)
					if err != nil {
						return err
					}
					key, err := reportCounterLayoutKey(row)
					if err != nil {
						return err
					}
					return bucket.Put(key, body)
				}
			}); err != nil {
				t.Fatal(err)
			}
			damaged := reportBucketSnapshot(t, root, reportCountersBucket)
			if err := PrepareReportIndex(context.Background(), root, socket, ReportIndexOptions{Verify: true}); err == nil {
				t.Fatal("offline verification accepted a damaged row/layout reference set")
			}
			if !reflect.DeepEqual(damaged, reportBucketSnapshot(t, root, reportCountersBucket)) {
				t.Fatal("read-only verification changed damaged projection evidence")
			}
			if err := PrepareReportIndex(context.Background(), root, socket, ReportIndexOptions{Rebuild: true}); err != nil {
				t.Fatal(err)
			}
			if err := PrepareReportIndex(context.Background(), root, socket, ReportIndexOptions{Verify: true}); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(originals, reportBucketSnapshot(t, root, observationBucket)) || !reflect.DeepEqual(receptions, reportBucketSnapshot(t, root, reportReceptionBucket)) {
				t.Fatal("verification/rebuild changed original reports or reception annotations")
			}
		})
	}
}

type counterLayoutCancelContext struct {
	context.Context
	cancel context.CancelFunc
	checks int
}

func (ctx *counterLayoutCancelContext) Err() error {
	ctx.checks++
	if ctx.checks == 2 {
		ctx.cancel()
	}
	return ctx.Context.Err()
}

func TestCounterLayoutRebuildRollsBackCancellationAndTransactionFailure(t *testing.T) {
	for _, failure := range []string{"cancel-after-first-original", "transaction-error"} {
		t.Run(failure, func(t *testing.T) {
			root, socket, reports, public := reportIndexFixture(t)
			originals := reportBucketSnapshot(t, root, observationBucket)
			receptions := reportBucketSnapshot(t, root, reportReceptionBucket)
			projection := reportBucketSnapshot(t, root, reportCountersBucket)
			keys := map[reportOwner]string{{reports[0].NetworkID, reports[0].DeviceID}: public}
			parent, cancel := context.WithCancel(context.Background())
			defer cancel()
			ctx := &counterLayoutCancelContext{Context: parent, cancel: cancel}
			injected := errors.New("demo transaction aborted after rebuilding the projection")
			err := withReportDatabase(context.Background(), filepath.Join(root, "observations.db"), true, func(tx *bolt.Tx) error {
				if failure == "cancel-after-first-original" {
					return rebuildReportCounters(ctx, tx, keys)
				}
				if err := rebuildReportCounters(context.Background(), tx, keys); err != nil {
					return err
				}
				return injected
			})
			if failure == "cancel-after-first-original" && (!errors.Is(err, context.Canceled) || ctx.checks < 2) || failure == "transaction-error" && !errors.Is(err, injected) {
				t.Fatal("the rebuild did not reach its intended transactional failure", err)
			}
			if !reflect.DeepEqual(originals, reportBucketSnapshot(t, root, observationBucket)) || !reflect.DeepEqual(receptions, reportBucketSnapshot(t, root, reportReceptionBucket)) || !reflect.DeepEqual(projection, reportBucketSnapshot(t, root, reportCountersBucket)) {
				t.Fatal("failed/cancelled rebuild committed partial rows/layouts or changed originals")
			}
			if err := PrepareReportIndex(context.Background(), root, socket, ReportIndexOptions{Verify: true}); err != nil {
				t.Fatal("the prior complete projection was not usable after rollback", err)
			}
		})
	}
}
