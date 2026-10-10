package control

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// The production SPA and query handler consume original signed report fixtures.
// Production enrollment and transport execution are verified during deployment.
func TestWebChromeLinkHistoryScopeRefreshAndNavigation(t *testing.T) {
	if os.Getenv("LOOM_WEB_CHROME_TEST") != "1" {
		t.Skip("set LOOM_WEB_CHROME_TEST=1 for browser history acceptance")
	}
	p := relayProjectionFixture(t)
	p.DeviceAuthorizations[1].Responsibilities = []string{"internet_egress"}
	f := newMaterialFixture(t)
	for i := range p.DeviceAuthorizations {
		if p.DeviceAuthorizations[i].ID == "demo-entry" {
			p.DeviceAuthorizations[i].DevicePublicKey = base64.RawURLEncoding.EncodeToString(f.keys[0].Public().(ed25519.PublicKey))
		}
	}
	view, err := ProjectDeviceView(p, "demo-entry")
	if err != nil {
		t.Fatal(err)
	}
	link := view.Links[0]
	spec, _ := LinkSpecDigest(view, link.ID)
	digest, _ := DeviceViewDigest(view)
	now := time.Now().UTC().Truncate(time.Millisecond)
	resources := []ResourceReadback{}
	for _, resource := range view.Resources {
		if resource.OwnerNodeID != view.DeviceID {
			continue
		}
		acl, err := InboundACLDigest(view, resource.ID)
		if err != nil {
			t.Fatal(err)
		}
		value := ResourceReadback{ResourceID: resource.ID, ListenerID: resource.ListenerID, Listen: net.JoinHostPort(resource.DialHost, strconv.Itoa(resource.DialPort)), ACLDigest: acl, CertificateDigest: "sha256:" + strings.Repeat("0", 64)}
		if resource.Kind == "wireguard" {
			value.CertificateDigest = ""
			value.PublicKey = *resource.Authentication.PublicKey
		}
		resources = append(resources, value)
	}
	sort.Slice(resources, func(i, j int) bool { return resources[i].ResourceID < resources[j].ResourceID })
	reports := []DeviceReport{}
	for index, state := range []string{"unavailable", "available", "available"} {
		at := now.Add(-[]time.Duration{time.Hour, 5 * time.Second, 0}[index])
		sample := Observation{Level: "link", LinkID: link.ID, ResourceID: link.ResourceID, SpecDigest: spec, Target: net.JoinHostPort(link.ProbeTarget.Host, "53"), Action: "wireguard_dns",
			NetworkGeneration: "demo-generation", Result: state, ObservedAt: at.UnixMilli(), ValidUntil: at.Add(30 * time.Second).UnixMilli(), DurationMS: new(int64(100))}
		if state == "available" {
			sample.RoundTripMS = new(int64(0))
		}
		report, err := SignDeviceReport(DeviceReport{Schema: 3, NetworkID: p.NetworkID, DeviceID: view.DeviceID, ViewDigest: digest, ReportSequence: U64(index + 1), ReportedAt: at.UnixMilli(), NetworkGeneration: sample.NetworkGeneration,
			Selections: []ReportSelection{}, Observations: []Observation{sample}, Runtime: RuntimeReadback{State: "running", AppliedViewDigest: digest, Resources: &resources}, Components: []ComponentReadback{{ComponentID: "agent", Version: strings.Repeat("a", 40), ArtifactDigest: "sha256:" + strings.Repeat("b", 64), Platform: "linux-amd64"}}}, f.keys[0])
		if err != nil {
			t.Fatal(err)
		}
		reports = append(reports, report)
	}
	if err := verifyCurrentReport(reports[len(reports)-1], p); err != nil {
		t.Fatal("current fixture must obey the resource execution contract", err)
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	testSetObservationReports(t, root, reports)
	store, err := OpenObservationStore(root)
	if err != nil {
		t.Fatal(err)
	}
	a := &Authority{root: root, projection: p}
	var clock atomic.Int64
	clock.Store(now.UnixMilli())
	server := &Server{Runtime: &Runtime{Authority: a, Reports: store}, Now: func() time.Time { return time.UnixMilli(clock.Load()) }}
	var refuse atomic.Bool
	handler := server.AdminHandler()
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/control/ui/link-history" && refuse.Load() {
			http.Error(w, "demo history unavailable", http.StatusServiceUnavailable)
			return
		}
		handler.ServeHTTP(w, r)
	}))
	defer httpServer.Close()
	debug := openCommandChrome(t, httpServer.URL+"/topology")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := debug.call(ctx, "Emulation.setDeviceMetricsOverride", map[string]any{"width": 1600, "height": 1100, "deviceScaleFactor": 1, "mobile": false}, nil); err != nil {
		t.Fatal(err)
	}
	waitChromeEvaluation(t, debug, `document.querySelectorAll('[data-link-history="demo-link"] .link-hour').length===24`)
	if chromeDo(t, debug, `(()=>{const row=document.querySelector('[data-link-row="demo-link"]');return row.querySelectorAll('.link-hour.available').length===1&&row.querySelectorAll('.link-hour.unavailable').length===1&&row.querySelectorAll('.link-hour.missing').length===22&&row.textContent.includes('demo-entry → demo-exit')&&row.textContent.includes('not uptime')&&row.lastElementChild.textContent.includes('Unknown')&&row.querySelector('.link-hour.available').title.includes('demo-generation')})()`) != true {
		t.Fatal("Link row confused direction, traffic, absence or original sample state")
	}
	waitChromeEvaluation(t, debug, `document.querySelector('[data-link-rtt="demo-link"]')?.textContent.includes('WG DNS RTT: 0 ms')&&document.querySelector('[data-link-spread="demo-link"]')?.textContent.includes('P95−P50: 0 ms')`)
	chromeDo(t, debug, `(()=>{document.querySelector('#topology [data-node="demo-entry"]').dispatchEvent(new MouseEvent('click',{bubbles:true}));document.querySelector('[data-link-history-retry]').click();return true})()`)
	waitChromeEvaluation(t, debug, `document.querySelectorAll('.link-hour').length===24&&document.querySelector('#topology').dataset.locked==='demo-entry'`)
	refuse.Store(true)
	chromeDo(t, debug, `(()=>{document.querySelector('[data-link-history-retry]').click();return true})()`)
	waitChromeEvaluation(t, debug, `document.querySelector('[data-link-history]')?.textContent.includes('could not be read')`)
	refuse.Store(false)
	chromeDo(t, debug, `(()=>{document.querySelector('[data-link-history-retry]').click();return true})()`)
	waitChromeEvaluation(t, debug, `document.querySelectorAll('.link-hour').length===24`)
	chromeDo(t, debug, `(()=>{history.pushState({},'','/devices/demo-entry');dispatchEvent(new PopStateEvent('popstate'));return true})()`)
	waitChromeEvaluation(t, debug, `document.querySelectorAll('[data-runtime-history] .runtime-hour').length===24`)
	if chromeDo(t, debug, `(()=>{const cell=[...document.querySelectorAll('.device-status .step')].find(v=>v.textContent.includes('Agent version')),version=cell.querySelector('b'),range=document.createRange();range.selectNodeContents(version);return version.textContent==='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'&&[...range.getClientRects()].every(rect=>rect.right<=cell.getBoundingClientRect().right&&rect.left>=cell.getBoundingClientRect().left)})()`) != true {
		t.Fatal("full agent commit escaped its summary column")
	}
	chromeDo(t, debug, `(()=>{history.pushState({},'','/topology');dispatchEvent(new PopStateEvent('popstate'));return true})()`)
	waitChromeEvaluation(t, debug, `document.querySelectorAll('.link-hour').length===24`)
	// Report sequences change while the device wall-clock timestamp is unchanged.
	// Missing newest RTT cannot retain the older current distribution.
	latest := reports[len(reports)-1]
	for _, rtt := range []*int64{nil, new(int64(40))} {
		latest.ReportSequence++
		latest.Observations = append([]Observation{}, latest.Observations...)
		latest.Observations[0].ObservedAt++
		latest.Observations[0].ValidUntil++
		latest.Observations[0].RoundTripMS = rtt
		clock.Store(latest.Observations[0].ObservedAt)
		latest, err = SignDeviceReport(latest, f.keys[0])
		if err != nil || verifyCurrentReport(latest, p) != nil {
			t.Fatal("changed RTT fixture rejected", err)
		}
		if err := store.Put(latest, p.DeviceAuthorizations[0].DevicePublicKey); err != nil {
			t.Fatal(err)
		}
		if rtt == nil {
			waitChromeEvaluation(t, debug, `document.querySelector('[data-link-rtt="demo-link"]')?.textContent.includes('Unknown')&&document.querySelector('[data-link-spread="demo-link"]')?.textContent.includes('Unknown')`)
		} else {
			waitChromeEvaluation(t, debug, `document.querySelector('[data-link-rtt="demo-link"]')?.textContent.includes('40 ms')&&document.querySelector('[data-link-spread="demo-link"]')?.textContent.includes('40 ms')`)
		}
	}
	componentID, _ := ExpectedComponentID("demo-entry", "agent", "linux-amd64")
	a.mu.Lock()
	a.projection.NetworkIntent.ExpectedComponents = []ExpectedComponent{{ID: componentID, NodeID: "demo-entry", ComponentID: "agent", Platform: "linux-amd64", CatalogDigest: "sha256:" + strings.Repeat("c", 64), ManifestDigest: "sha256:" + strings.Repeat("d", 64)}}
	a.mu.Unlock()
	if _, err := ProjectDeviceView(a.Snapshot(), "demo-entry"); err == nil {
		t.Fatal("component fixture must reject full View generation without its release")
	}
	if chromeDo(t, debug, `(async()=>{const r=await fetch('/api/control/ui/link-history?link=demo-link');const value=await r.json();return r.status===200&&value.buckets.filter(v=>v.observation).length===2})()`) != true {
		t.Fatal("component expectations erased original Link observations")
	}
	chromeDo(t, debug, `(()=>{document.querySelector('[data-link-history-retry]').click();return true})()`)
	waitChromeEvaluation(t, debug, `document.querySelectorAll('.link-hour').length===24&&document.querySelectorAll('.link-hour.available').length===1`)
	a.mu.Lock()
	a.projection.NetworkIntent.Links = []NetworkLink{}
	a.mu.Unlock()
	waitChromeEvaluation(t, debug, `(async()=>{const r=await fetch('/api/control/ui/link-history?link=demo-link');return r.status===404&&!document.querySelector('[data-link-history="demo-link"]')})()`)
}
