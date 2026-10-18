package control

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"path/filepath"
	"reflect"
	"testing"

	bolt "go.etcd.io/bbolt"
)

func TestReportTreeSparseForksAndRebuildPreserveOriginals(t *testing.T) {
	server, invite, _, claim, key, _ := enrollmentAuthorityFixture(t)
	if response := enrollmentHTTP(t, server, "/enrollment/claim", claim, enrollmentTunnel(invite)); response.Code != 200 {
		t.Fatal(response.Code)
	}
	p := server.Runtime.Authority.Snapshot()
	view, err := server.deviceEnvelope(invite.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	reports := []DeviceReport{}
	for _, sequence := range []U64{1, 17, 4097, 1 << 63, ^U64(0)} {
		report, err := SignDeviceReport(DeviceReport{Schema: 3, NetworkID: p.NetworkID, DeviceID: invite.DeviceID, ReportSequence: sequence, ViewDigest: view.ViewDigest, NetworkGeneration: "demo-underlay", ReportedAt: 1, Selections: []ReportSelection{}, Observations: []Observation{}, Runtime: RuntimeReadback{State: "stopped"}, Components: []ComponentReadback{}}, key)
		if err != nil {
			t.Fatal(err)
		}
		reports = append(reports, report)
	}
	store := server.Runtime.Reports
	if err := store.mergeReportHistory(context.Background(), reports, p); err != nil {
		t.Fatal(err)
	}
	fork := reports[1]
	fork.Runtime.State = "error"
	fork.Signature = ""
	fork, err = SignDeviceReport(fork, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.mergeReportHistory(context.Background(), []DeviceReport{fork}, p); !errors.Is(err, ErrReportEquivocation) {
		t.Fatal("old fork not retained", err)
	}
	roots, err := store.reportRanges(context.Background(), p)
	if err != nil || roots.Validate() != nil || len(roots.Ranges) != 1 || roots.Heads[0].FirstSequence != reportRangeStart(^U64(0)) {
		t.Fatal("invalid sparse roots", roots, err)
	}
	all := func(s *ObservationStore) map[string]string {
		result := map[string]string{}
		if err := s.withDatabase(context.Background(), false, func(tx *bolt.Tx) error {
			return tx.Bucket(reportIndexBucket).Bucket(reportTreeBucket).ForEach(func(k, v []byte) error { result[string(k)] = string(v); return nil })
		}); err != nil {
			t.Fatal(err)
		}
		return result
	}
	beforeTree := all(store)
	before := testObservationBytes(t, store)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	retiredKey := append([]byte{'r'}, reportOwnerPrefix(reportOwner{p.NetworkID, invite.DeviceID})...)
	retiredKey = binary.BigEndian.AppendUint64(retiredKey, 1)
	if err := withReportDatabase(context.Background(), store.path, true, func(tx *bolt.Tx) error {
		index := tx.Bucket(reportIndexBucket)
		if err := index.DeleteBucket(reportTreeBucket); err != nil {
			return err
		}
		return index.Put(retiredKey, []byte(roots.Ranges[0].Digest))
	}); err != nil {
		t.Fatal(err)
	}
	rebuilt, err := testOpenObservationStore(t, filepath.Dir(store.path))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(beforeTree, all(rebuilt)) || !bytes.Equal(before, testObservationBytes(t, rebuilt)) {
		t.Fatal("derived tree rebuild changed original bytes or tree")
	}
	after, err := rebuilt.reportRanges(context.Background(), p)
	if err != nil || !reflect.DeepEqual(roots, after) {
		t.Fatal("rebuild changed roots/heads", err)
	}
	if err := rebuilt.withDatabase(context.Background(), false, func(tx *bolt.Tx) error {
		index := tx.Bucket(reportIndexBucket)
		if index.Get(retiredKey) != nil || index.Get(receptionIndexedKey) == nil {
			return errors.New("retired range cleanup touched reception index")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
func TestReportTreeRejectsAmbiguousScopesAndChildren(t *testing.T) {
	digest := ReleaseDigest([]byte("demo-value"))
	for _, scope := range []reportScope{{"demo-device", 1, 0}, {"demo-device", 1, 3}, {"demo-device", 1, 65}, {"demo-device", 17, 5}, {"demo-device", 17, 64}, {"demo-device", 0, 4}} {
		if scope.Validate() == nil {
			t.Fatal("ambiguous scope accepted", scope)
		}
	}
	parent := reportScope{"demo-device", 1, 64}
	valid := reportRangeIDs{parent.DeviceID, parent.FirstSequence, parent.Height, []reportRangeSummary{summaryOf(reportScope{"demo-device", 1, 4}, digest), summaryOf(reportScope{"demo-device", 1 + (1 << 63), 4}, digest)}, []string{}}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, children := range [][]reportRangeSummary{{summaryOf(parent, digest)}, {summaryOf(reportScope{"demo-other", 1, 4}, digest)}, {valid.Children[0], valid.Children[0]}, {valid.Children[1], valid.Children[0]}} {
		invalid := valid
		invalid.Children = children
		if invalid.Validate() == nil {
			t.Fatal("invalid child accepted", children)
		}
	}
	leaf := valid
	leaf.Height = reportLeafHeight
	if leaf.Validate() == nil {
		t.Fatal("leaf accepted children")
	}
	branch := valid
	branch.ReportIDs = []string{digest}
	if branch.Validate() == nil {
		t.Fatal("branch accepted leaf IDs")
	}
}
