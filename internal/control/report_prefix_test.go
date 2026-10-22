package control

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func TestReportPrefixKeepsOldGapsAndForksWhileIgnoringOnlyTheLatestLeafAndSuffix(t *testing.T) {
	server, invite, _, claim, key, _ := enrollmentAuthorityFixture(t)
	if response := enrollmentHTTP(t, server, "/enrollment/claim", claim, enrollmentTunnel(invite)); response.Code != http.StatusOK {
		t.Fatal(response.Code)
	}
	p := server.Runtime.Authority.Snapshot()
	view, _ := server.deviceEnvelope(invite.DeviceID)
	type sample struct {
		sequence U64
		fork     bool
	}
	makeReport := func(value sample) DeviceReport {
		t.Helper()
		state := "stopped"
		if value.fork {
			state = "error"
		}
		report, err := SignDeviceReport(DeviceReport{Schema: 3, NetworkID: p.NetworkID, DeviceID: invite.DeviceID, ReportSequence: value.sequence, ViewDigest: view.ViewDigest, NetworkGeneration: "demo-underlay", ReportedAt: 1, Selections: []ReportSelection{}, Observations: []Observation{}, Runtime: RuntimeReadback{State: state}, Components: []ComponentReadback{}}, key)
		if err != nil {
			t.Fatal(err)
		}
		return report
	}
	for _, test := range []struct {
		name          string
		local, remote []sample
		matches       bool
	}{
		{"equal", []sample{{1, false}, {17, false}}, []sample{{1, false}, {17, false}}, true},
		{"new-in-leaf", []sample{{1, false}, {17, false}}, []sample{{1, false}, {17, false}, {18, false}}, true},
		{"new-leaf", []sample{{1, false}, {17, false}, {32, false}}, []sample{{1, false}, {17, false}, {32, false}, {33, false}}, true},
		{"local-newer-suffix", []sample{{1, false}, {17, false}, {33, false}, {65, false}}, []sample{{1, false}, {17, false}, {33, false}}, true},
		{"old-hole", []sample{{1, false}, {33, false}}, []sample{{1, false}, {17, false}, {33, false}}, false},
		{"new-leaf-with-old-hole", []sample{{1, false}, {17, false}}, []sample{{1, false}, {17, false}, {32, false}, {33, false}}, false},
		{"old-fork", []sample{{1, false}, {17, false}, {33, false}}, []sample{{1, false}, {17, false}, {17, true}, {33, false}}, false},
		{"head-fork-still-needs-leaf-reconciliation", []sample{{1, false}, {17, false}}, []sample{{1, false}, {17, false}, {17, true}}, true},
		{"sparse-u64-head", []sample{{1, false}, {1 << 63, false}}, []sample{{1, false}, {1 << 63, false}, {^U64(0), false}}, true},
		{"sparse-u64-old-hole", []sample{{1, false}, {^U64(0), false}}, []sample{{1, false}, {1 << 63, false}, {^U64(0), false}}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			stores := []*ObservationStore{}
			for _, values := range [][]sample{test.local, test.remote} {
				root := filepath.Join(t.TempDir(), "demo-reports")
				if err := os.Mkdir(root, 0700); err != nil {
					t.Fatal(err)
				}
				store, err := testOpenObservationStore(t, root, map[reportOwner]string{{p.NetworkID, invite.DeviceID}: claim.DevicePublicKey})
				if err != nil {
					t.Fatal(err)
				}
				reports := []DeviceReport{}
				for _, value := range values {
					reports = append(reports, makeReport(value))
				}
				if err := store.mergeReportHistory(context.Background(), reports, p); err != nil && !errors.Is(err, ErrReportEquivocation) {
					t.Fatal(err)
				}
				stores = append(stores, store)
			}
			remote, err := stores[1].reportRanges(context.Background(), p)
			if err != nil || len(remote.Ranges) != 1 {
				t.Fatal("remote tree unavailable", err)
			}
			before := testObservationBytes(t, stores[0])
			got, err := stores[0].reportPrefixMatches(context.Background(), p.NetworkID, remote.Ranges[0], remote.Heads[0])
			if err != nil || got != test.matches {
				t.Fatal("prefix comparison hid or invented an old difference", got, err)
			}
			if !bytes.Equal(before, testObservationBytes(t, stores[0])) {
				t.Fatal("prefix comparison changed original history")
			}
		})
	}
}
