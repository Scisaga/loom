package control

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestTrafficHistoryUsesOnlyOriginalAdjacentScopedCounters(t *testing.T) {
	key := testKey(t)
	public := base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
	identity := projectedDeviceIdentity{ID: "demo-device", DevicePublicKey: public}
	peer := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("a", 32)))
	digest := "sha256:" + strings.Repeat("0", 64)
	now := time.Date(2030, 1, 2, 12, 30, 0, 0, time.UTC)
	makeReport := func(seq U64, at time.Time, rx, tx U64) DeviceReport {
		return DeviceReport{Schema: 3, NetworkID: "demo-network", DeviceID: identity.ID, ReportSequence: seq, ViewDigest: digest, NetworkGeneration: "demo-underlay", ReportedAt: at.UnixMilli(), Selections: []ReportSelection{}, Observations: []Observation{}, Components: []ComponentReadback{}, Runtime: RuntimeReadback{State: "running", AppliedViewDigest: digest}, WireGuardCounters: &WireGuardCounters{Interface: "resource:demo-wg", Epoch: strings.Repeat("a", 32), ObservedAt: at.UnixMilli(), Peers: []WireGuardPeerCounter{{PublicKey: peer, RXBytes: rx, TXBytes: tx, Links: []WireGuardCounterLink{{LinkID: "demo-link", SpecDigest: digest}}}}}}
	}
	base := func() []DeviceReport {
		return []DeviceReport{makeReport(1, now.Add(-2*time.Minute), 100, 200), makeReport(2, now.Add(-time.Minute), 1100, 2200), makeReport(3, now, 3100, 5200)}
	}
	for _, tc := range []struct {
		name     string
		change   func([]DeviceReport) []DeviceReport
		rx, tx   U64
		coverage int64
	}{
		{"normal", func(v []DeviceReport) []DeviceReport { return v }, 3000, 5000, 120000},
		{"actual zero", func(v []DeviceReport) []DeviceReport {
			for i := range v {
				v[i].WireGuardCounters.Peers[0].RXBytes = 0
				v[i].WireGuardCounters.Peers[0].TXBytes = 0
			}
			return v
		}, 0, 0, 120000},
		{"latest fork", func(v []DeviceReport) []DeviceReport {
			other := makeReport(3, now, 4000, 6000)
			return append(v, other)
		}, 1000, 2000, 60000},
		{"future report", func(v []DeviceReport) []DeviceReport { v[2].ReportedAt = now.Add(time.Second).UnixMilli(); return v }, 1000, 2000, 60000},
		{"counter ahead of report", func(v []DeviceReport) []DeviceReport {
			v[2].ReportedAt = now.Add(-10 * time.Second).UnixMilli()
			return v
		}, 3000, 5000, 120000},
		{"latest missing", func(v []DeviceReport) []DeviceReport { v[2].WireGuardCounters = nil; return v }, 1000, 2000, 60000},
		{"missing sample", func(v []DeviceReport) []DeviceReport { v[1].WireGuardCounters = nil; return v }, 0, 0, 0},
		{"counter reset", func(v []DeviceReport) []DeviceReport { v[2].WireGuardCounters.Peers[0].RXBytes = 0; return v }, 1000, 2000, 60000},
		{"new owner", func(v []DeviceReport) []DeviceReport {
			v[2].WireGuardCounters.Epoch = strings.Repeat("b", 32)
			return v
		}, 1000, 2000, 60000},
		{"new network", func(v []DeviceReport) []DeviceReport { v[2].NetworkGeneration = "demo-other-underlay"; return v }, 1000, 2000, 60000},
		{"sequence gap", func(v []DeviceReport) []DeviceReport { return []DeviceReport{v[0], v[2]} }, 0, 0, 0},
		{"time rollback", func(v []DeviceReport) []DeviceReport {
			v[2].WireGuardCounters.ObservedAt = now.Add(-90 * time.Second).UnixMilli()
			return v
		}, 1000, 2000, 60000},
		{"same sample time contradiction", func(v []DeviceReport) []DeviceReport {
			v[2].WireGuardCounters.ObservedAt = v[1].WireGuardCounters.ObservedAt
			return v
		}, 0, 0, 0},
		{"large gap", func(v []DeviceReport) []DeviceReport {
			v[0].WireGuardCounters.ObservedAt = now.Add(-5 * time.Minute).UnixMilli()
			return v
		}, 2000, 3000, 60000},
		{"hour boundary", func(v []DeviceReport) []DeviceReport {
			v = v[:2]
			v[0].WireGuardCounters.ObservedAt = now.Truncate(time.Hour).Add(-time.Minute).UnixMilli()
			v[1].WireGuardCounters.ObservedAt = now.Truncate(time.Hour).Add(time.Minute).UnixMilli()
			return v
		}, 0, 0, 0},
		{"same sequence fork", func(v []DeviceReport) []DeviceReport {
			other := makeReport(2, now.Add(-time.Minute), 1200, 2300)
			return append(v, other)
		}, 0, 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reports := tc.change(base())
			for i := range reports {
				var err error
				reports[i], err = SignDeviceReport(reports[i], key)
				if err != nil {
					t.Fatal(err)
				}
			}
			root := t.TempDir()
			if err := os.Chmod(root, 0700); err != nil {
				t.Fatal(err)
			}
			testSetObservationReports(t, root, reports)
			original := testObservationBytes(t, root)
			var first WebDeviceTraffic
			for i := 0; i < 2; i++ {
				store, err := testOpenObservationStore(t, root)
				if err != nil {
					t.Fatal(err)
				}
				got, err := store.deviceTrafficHistory(context.Background(), "demo-network", identity, nil, now)
				if err != nil {
					t.Fatal(err)
				}
				var rx, tx U64
				var coverage int64
				for _, bucket := range got.Buckets {
					if bucket.Delta != nil {
						rx += bucket.Delta.RXBytes
						tx += bucket.Delta.TXBytes
						coverage += bucket.Delta.CoveredMS
					}
				}
				if rx != tc.rx || tx != tc.tx || coverage != tc.coverage {
					t.Fatalf("got rx=%d tx=%d ms=%d", rx, tx, coverage)
				}
				if i == 0 {
					first = got
				} else if !reflect.DeepEqual(first, got) {
					t.Fatal("restart changed derived history")
				}
				if !bytes.Equal(original, testObservationBytes(t, store)) {
					t.Fatal("query rewrote signed samples")
				}
				if tc.coverage == 0 {
					for _, bucket := range got.Buckets {
						if bucket.Delta != nil {
							t.Fatal("unknown became zero")
						}
					}
				}
				if tc.name == "future report" || tc.name == "counter ahead of report" || tc.name == "new owner" || tc.name == "new network" || tc.name == "time rollback" || tc.name == "latest fork" || tc.name == "latest missing" {
					if got.Recent != nil {
						t.Fatal("prior owner or clock range became a current rate")
					}
				}
				if tc.name == "normal" {
					if got.Recent == nil || got.Recent.TXBytes != 5000 || got.Recent.CoveredMS != 120000 {
						t.Fatal("recent rate lost actual coverage")
					}
					wrong := &trafficLinkScope{id: "demo-link", spec: "sha256:" + strings.Repeat("1", 64), endpoint: "resource:demo-wg", peer: peer}
					hidden, err := store.deviceTrafficHistory(context.Background(), "demo-network", identity, wrong, now)
					if err != nil || hidden.Recent != nil {
						t.Fatal("old link scope leaked into new one", err)
					}
				}
				if err := store.Close(); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestTrafficHistoryFormalScopesAndAuthentication(t *testing.T) {
	p := relayProjectionFixture(t)
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	store, err := testOpenObservationStore(t, root)
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{Runtime: &Runtime{Authority: &Authority{root: root, projection: p}, Reports: store}}
	for _, tc := range []struct {
		query  string
		status int
	}{
		{"device=demo-entry", 200}, {"link=demo-link", 200}, {"network=" + p.NetworkID, 200},
		{"device=demo-absent", 404}, {"link=demo-absent", 404}, {"network=demo-absent", 404},
		{"", 400}, {"device=demo-entry&link=demo-link", 400}, {"device=demo-entry&device=demo-entry", 400}, {"peer=demo-entry", 400},
	} {
		req := httptest.NewRequest(http.MethodGet, "/api/control/ui/traffic-history?"+tc.query, nil)
		response := httptest.NewRecorder()
		server.AdminHandler().ServeHTTP(response, req)
		if response.Code != tc.status {
			t.Fatalf("%s: %d %s", tc.query, response.Code, response.Body.String())
		}
	}
	request := httptest.NewRequest(http.MethodGet, "/api/control/ui/traffic-history?device=demo-entry", nil)
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("untrusted request accepted: %d", response.Code)
	}
	for i := range p.DeviceAuthorizations {
		if p.DeviceAuthorizations[i].ID == "demo-entry" {
			p.DeviceAuthorizations = append(p.DeviceAuthorizations[:i], p.DeviceAuthorizations[i+1:]...)
			break
		}
	}
	server.Runtime.Authority.projection = p
	for _, query := range []string{"device=demo-entry", "link=demo-link"} {
		response := httptest.NewRecorder()
		server.AdminHandler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/control/ui/traffic-history?"+query, nil))
		if response.Code != http.StatusNotFound {
			t.Fatalf("revoked scope retained: %s %d", query, response.Code)
		}
	}
}
