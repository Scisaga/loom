package control

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestWebLinkHistoryKeepsOriginalDirectionScopeAndSampleTime(t *testing.T) {
	p := relayProjectionFixture(t)
	f := newMaterialFixture(t)
	for index := range p.DeviceAuthorizations {
		if p.DeviceAuthorizations[index].ID == "demo-entry" {
			p.DeviceAuthorizations[index].DevicePublicKey = base64.RawURLEncoding.EncodeToString(f.keys[0].Public().(ed25519.PublicKey))
		}
	}
	identity, _ := authorizationFor(p, "demo-entry")
	view, err := ProjectDeviceView(p, identity.ID)
	if err != nil {
		t.Fatal(err)
	}
	link := view.Links[0]
	spec, _ := LinkSpecDigest(view, link.ID)
	digest, _ := DeviceViewDigest(view)
	now := time.Date(2026, 1, 2, 12, 30, 0, 0, time.UTC)
	hour := now.Truncate(time.Hour)
	zero := int64(0)
	base := Observation{Level: "link", LinkID: link.ID, ResourceID: link.ResourceID, SpecDigest: spec, Target: net.JoinHostPort(link.ProbeTarget.Host, "53"), Action: "wireguard_dns", NetworkGeneration: "demo-generation", Result: "available", DurationMS: &zero}
	reports := []DeviceReport{}
	add := func(hours int, change func(*Observation)) {
		t.Helper()
		value := base
		value.ObservedAt = hour.Add(-time.Duration(hours)*time.Hour + time.Minute).UnixMilli()
		if change != nil {
			change(&value)
		}
		value.ValidUntil = value.ObservedAt + time.Minute.Milliseconds()
		report := DeviceReport{Schema: 3, NetworkID: p.NetworkID, DeviceID: identity.ID, ReportSequence: U64(len(reports) + 1), ViewDigest: digest, NetworkGeneration: value.NetworkGeneration,
			ReportedAt: now.UnixMilli(), Selections: []ReportSelection{}, Observations: []Observation{value}, Runtime: RuntimeReadback{State: "running", AppliedViewDigest: digest}, Components: []ComponentReadback{}}
		report, err = SignDeviceReport(report, f.keys[0])
		if err != nil {
			t.Fatal(err)
		}
		reports = append(reports, report)
	}
	resign := func() {
		t.Helper()
		reports[len(reports)-1], err = SignDeviceReport(reports[len(reports)-1], f.keys[0])
		if err != nil {
			t.Fatal(err)
		}
	}
	add(0, nil)
	add(0, nil) // Retransmitting one sample does not create another observation.
	add(1, func(v *Observation) { v.Result, v.DurationMS = "unavailable", nil })
	add(2, func(v *Observation) { v.Result, v.DurationMS = "unknown", nil })
	add(3, func(v *Observation) { v.SpecDigest = "sha256:" + strings.Repeat("f", 64) })
	add(4, nil)
	add(4, func(v *Observation) { v.Result, v.DurationMS = "unavailable", nil })
	add(5, nil)
	fork := reports[len(reports)-1]
	fork.Observations = append([]Observation{}, fork.Observations...)
	fork.Observations[0].Result = "unknown"
	fork, err = SignDeviceReport(fork, f.keys[0])
	if err != nil {
		t.Fatal(err)
	}
	reports = append(reports, fork)
	add(6, nil)
	reports[len(reports)-1], err = SignDeviceReport(reports[len(reports)-1], f.keys[1])
	if err != nil {
		t.Fatal(err)
	}
	add(7, nil)
	reports[len(reports)-1].ReportedAt = hour.Add(-25 * time.Hour).UnixMilli()
	reports[len(reports)-1].ViewDigest = "sha256:" + strings.Repeat("a", 64)
	resign() // Report time and a changed unrelated View cannot erase this Link sample.
	add(8, func(v *Observation) { v.ObservedAt += time.Minute.Milliseconds() })
	add(8, func(v *Observation) { v.Result, v.DurationMS = "unavailable", nil })
	add(9, func(v *Observation) { v.NetworkGeneration = "demo-earlier-network" })
	add(10, func(v *Observation) { v.ResourceID = link.FromResourceID })
	add(11, func(v *Observation) { v.Action = "hysteria2_tls" })
	add(12, func(v *Observation) {
		v.Target = net.JoinHostPort(netip.MustParseAddr(link.ProbeTarget.Host).Next().String(), "53")
	})
	add(13, nil)
	reports[len(reports)-1].DeviceID = link.ToNodeID
	resign()
	add(23, func(v *Observation) { v.ObservedAt = hour.Add(-23 * time.Hour).UnixMilli() })
	add(24, nil)
	add(0, func(v *Observation) { v.ObservedAt = now.Add(time.Millisecond).UnixMilli() })
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	testSetObservationReports(t, root, reports)
	original := testObservationBytes(t, root)
	var previous WebLinkHistory
	for attempt := 0; attempt < 2; attempt++ {
		store, err := testOpenObservationStore(t, root)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.Latest(context.Background()); err != nil {
			t.Fatal(err)
		}
		got, err := store.linkHistory(context.Background(), view.NetworkID, identity, link, spec, now)
		if err != nil {
			t.Fatal(err)
		}
		store.cache.clear()
		cold, err := store.linkHistory(context.Background(), view.NetworkID, identity, link, spec, now)
		if err != nil || !reflect.DeepEqual(cold, got) {
			t.Fatal("discarding the original position index changed Link history", err)
		}
		if len(got.Buckets) != 24 || got.FromNodeID != identity.ID || got.ToNodeID != link.ToNodeID || got.SpecDigest != spec || got.From != hour.Add(-23*time.Hour).UnixMilli() || got.Until != now.UnixMilli() {
			t.Fatal("history lost its exact direction, specification or window")
		}
		for index, result := range map[int]string{23: "available", 22: "unavailable", 21: "unknown", 16: "available", 15: "available", 14: "available", 0: "available"} {
			if sample := got.Buckets[index].Observation; sample == nil || sample.Result != result || sample.SpecDigest != spec || sample.LinkID != link.ID {
				t.Fatal("original Link sample lost", index, sample)
			}
		}
		if got.Buckets[23].Observation.DurationMS == nil || *got.Buckets[23].Observation.DurationMS != 0 || got.Buckets[14].Observation.NetworkGeneration != "demo-earlier-network" || !got.Buckets[19].Ambiguous {
			t.Fatal("zero probe duration, original generation or equal-time conflict lost")
		}
		for _, index := range []int{20, 19, 18, 17, 13, 12, 11, 10, 1} {
			if got.Buckets[index].Observation != nil {
				t.Fatal("wrong scope, fork, conflict, identity or missing input entered history", index)
			}
		}
		if attempt > 0 && !reflect.DeepEqual(got, previous) || !bytes.Equal(original, testObservationBytes(t, store)) {
			t.Fatal("reopening history changed original signed bytes or samples")
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
		previous = got
	}
	for i := range p.NetworkIntent.Resources {
		if p.NetworkIntent.Resources[i].ID == link.FromResourceID {
			p.NetworkIntent.Resources[i].DialPort++
		}
	}
	changed, err := ProjectDeviceView(p, identity.ID)
	if err != nil {
		t.Fatal(err)
	}
	store, err := testOpenObservationStore(t, root)
	if err != nil {
		t.Fatal(err)
	}
	changedSpec, err := LinkSpecDigest(changed, link.ID)
	if err != nil {
		t.Fatal(err)
	}
	changedHistory, err := store.linkHistory(context.Background(), changed.NetworkID, identity, link, changedSpec, now)
	if err != nil || changedHistory.SpecDigest == spec {
		t.Fatal("changed resource did not replace the history scope", err)
	}
	for _, bucket := range changedHistory.Buckets {
		if bucket.Observation != nil || bucket.Ambiguous {
			t.Fatal("old native resource filled the new Link specification")
		}
	}
}

func TestWebLinkHistoryQueryCannotExpandEndpointPermission(t *testing.T) {
	p := relayProjectionFixture(t)
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := testOpenObservationStore(t, root)
	if err != nil {
		t.Fatal(err)
	}
	a := &Authority{projection: p}
	server := &Server{Runtime: &Runtime{Authority: a, Reports: store}}
	check := func(query string, want int) {
		t.Helper()
		response := httptest.NewRecorder()
		server.linkHistory(response, httptest.NewRequest(http.MethodGet, "/api/control/ui/link-history?"+query, nil))
		if response.Code != want {
			t.Fatal(query, response.Code, response.Body.String())
		}
	}
	check("link=demo-link", http.StatusOK)
	for _, query := range []string{"", "link=demo-link&link=demo-link", "link=demo-link&device=demo-exit", "link=%zz", "link="} {
		check(query, http.StatusBadRequest)
	}
	check("link=demo-missing", http.StatusNotFound)
	// Production devices have component expectations. Missing release material
	// blocks their executable View, but is unrelated to the authorized Link.
	componentID, _ := ExpectedComponentID("demo-entry", "agent", "linux-amd64")
	a.projection.NetworkIntent.ExpectedComponents = []ExpectedComponent{{ID: componentID, NodeID: "demo-entry", ComponentID: "agent", Platform: "linux-amd64", CatalogDigest: "sha256:" + strings.Repeat("c", 64), ManifestDigest: "sha256:" + strings.Repeat("d", 64)}}
	if _, err := ProjectDeviceView(a.Snapshot(), "demo-entry"); err == nil {
		t.Fatal("fixture must expose the missing release dependency of a full View")
	}
	check("link=demo-link", http.StatusOK)
	// Native WG may terminate at an Internet egress without a forwarding role.
	a.projection.DeviceAuthorizations[1].Responsibilities = []string{"internet_egress"}
	check("link=demo-link", http.StatusOK)
	if links := projectWebLinks(a.Snapshot()); len(links) != 1 || links[0].ID != "demo-link" {
		t.Fatal("authorized Internet-only receiver disappeared from the topology")
	}
	for _, change := range []func(*Projection){
		func(p *Projection) { p.NetworkIntent.Links = []NetworkLink{} },
		func(p *Projection) { p.DeviceAuthorizations[2].Responsibilities = []string{"internet_egress"} },
		func(p *Projection) { p.DeviceAuthorizations[1].Responsibilities = []string{"access"} },
	} {
		a.projection = cloneAuthorityProjection(p)
		change(&a.projection)
		check("link=demo-link", http.StatusNotFound)
	}
}
