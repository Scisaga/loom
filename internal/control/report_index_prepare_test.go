package control

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
)

func reportIndexFixture(t *testing.T) (string, string, []DeviceReport, string) {
	t.Helper()
	server, invite, _, claim, key, _ := enrollmentAuthorityFixture(t)
	if _, err := server.Runtime.Authority.CompleteEnrollment(context.Background(), claim, false, enrollmentTunnel(invite), server.now(), server.Runtime.Config); err != nil {
		t.Fatal(err)
	}
	reports := make([]DeviceReport, 2)
	for i := range reports {
		report := DeviceReport{Schema: 3, NetworkID: claim.NetworkID, DeviceID: invite.DeviceID, ReportSequence: U64(i + 1),
			ViewDigest: claim.GenesisDigest, NetworkGeneration: "demo-underlay", ReportedAt: int64(i + 1),
			Selections: []ReportSelection{}, Observations: []Observation{}, Components: []ComponentReadback{}, Runtime: RuntimeReadback{State: "stopped"}}
		if i == 1 {
			report.Runtime = RuntimeReadback{State: "running", AppliedViewDigest: report.ViewDigest}
			report.WireGuardCounters = &WireGuardCounters{Interface: "wg-shared", Epoch: strings.Repeat("a", 32), ObservedAt: 2, Peers: []WireGuardPeerCounter{}}
		}
		var err error
		reports[i], err = SignDeviceReport(report, key)
		if err != nil || server.Runtime.Reports.Put(reports[i], claim.DevicePublicKey) != nil {
			t.Fatal("could not admit report fixture", err)
		}
	}
	target, _ := server.Runtime.Authority.Snapshot().CurrentTarget("device", invite.DeviceID)
	submitAuthority(t, server.Runtime, Operation{Schema: 3, RequestID: "demo-index-revoke", Operation: "device.revoke", TargetKind: "device", TargetID: invite.DeviceID, Dependencies: target.MaterialIDs, Payload: DeleteTarget{ID: invite.DeviceID}})
	keys, err := server.Runtime.Authority.reportVerificationKeys()
	if err != nil || keys[reportOwner{claim.NetworkID, invite.DeviceID}] != claim.DevicePublicKey {
		t.Fatal("revocation erased the accepted historical report key", err)
	}
	if _, found := identityFor(server.Runtime.Authority.Snapshot(), invite.DeviceID); found {
		t.Fatal("historical key lookup restored a revoked permission")
	}
	root := server.Runtime.Authority.root
	if err := server.Runtime.Close(); err != nil {
		t.Fatal(err)
	}
	return root, filepath.Join(root, "admin.sock"), reports, claim.DevicePublicKey
}

func reportBucketSnapshot(t *testing.T, root string, child []byte) map[string][]byte {
	t.Helper()
	result := map[string][]byte{}
	err := withReportDatabase(context.Background(), filepath.Join(root, "observations.db"), false, func(tx *bolt.Tx) error {
		bucket := tx.Bucket(child)
		if bytes.Equal(child, reportCountersBucket) {
			bucket = tx.Bucket(reportIndexBucket).Bucket(child)
		}
		return bucket.ForEach(func(key, raw []byte) error {
			result[string(key)] = bytes.Clone(raw)
			return nil
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestPrepareReportIndexVerifiesReadOnlyAndRebuildsAtomically(t *testing.T) {
	root, socket, reports, _ := reportIndexFixture(t)
	path := filepath.Join(root, "observations.db")
	originals := reportBucketSnapshot(t, root, observationBucket)
	receptions := reportBucketSnapshot(t, root, reportReceptionBucket)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var stats ReportIndexStats
	if err := PrepareReportIndex(context.Background(), root, socket, ReportIndexOptions{Verify: true, Stats: &stats}); err != nil || stats.Originals != 2 || stats.WGRows != 2 || stats.WGBytes >= stats.OriginalBytes {
		t.Fatal("verified historical rows or successful counts were lost", stats, err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("verify modified the database", err)
	}
	locations := make([][]byte, len(reports))
	for i, report := range reports {
		raw, _ := CanonicalEncode(report)
		locations[i] = referenceOf(report).key(ReleaseDigest(raw))
	}
	if err := withReportDatabase(context.Background(), path, true, func(tx *bolt.Tx) error {
		return tx.Bucket(reportIndexBucket).Bucket(reportCountersBucket).Delete(locations[0])
	}); err != nil {
		t.Fatal(err)
	}
	if err := PrepareReportIndex(context.Background(), root, socket, ReportIndexOptions{Verify: true}); err == nil {
		t.Fatal("verify accepted a missing no-counter row")
	}
	if err := PrepareReportIndex(context.Background(), root, socket, ReportIndexOptions{Rebuild: true}); err != nil {
		t.Fatal(err)
	}
	if err := PrepareReportIndex(context.Background(), root, socket, ReportIndexOptions{Verify: true}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(originals, reportBucketSnapshot(t, root, observationBucket)) || !reflect.DeepEqual(receptions, reportBucketSnapshot(t, root, reportReceptionBucket)) {
		t.Fatal("rebuild changed signed originals or reception annotations")
	}
	if err := withReportDatabase(context.Background(), path, true, func(tx *bolt.Tx) error {
		index := tx.Bucket(reportIndexBucket).Bucket(reportCountersBucket)
		if err := index.Put(locations[0], []byte("demo-damaged-projection")); err != nil {
			return err
		}
		bucket := tx.Bucket(observationBucket)
		return bucket.Put(locations[1], append(bytes.Clone(bucket.Get(locations[1])), '\n'))
	}); err != nil {
		t.Fatal(err)
	}
	damaged := reportBucketSnapshot(t, root, reportCountersBucket)
	stats.Originals = 99
	if err := PrepareReportIndex(context.Background(), root, socket, ReportIndexOptions{Rebuild: true, Stats: &stats}); err == nil || stats.Originals != 99 {
		t.Fatal("rebuild accepted a changed original or exposed uncommitted stats", err)
	}
	if !reflect.DeepEqual(damaged, reportBucketSnapshot(t, root, reportCountersBucket)) {
		t.Fatal("failed rebuild changed an earlier row or erased the prior projection")
	}
	if err := PrepareReportIndex(context.Background(), root, socket, ReportIndexOptions{Verify: true, Rebuild: true}); err == nil {
		t.Fatal("mutually exclusive maintenance operations were accepted")
	}
}

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
