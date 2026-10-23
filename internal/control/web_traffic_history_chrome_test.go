package control

import (
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

func TestWebChromeTrafficOriginalCountersUnknownAndRetry(t *testing.T) {
	if os.Getenv("LOOM_WEB_CHROME_TEST") != "1" {
		t.Skip("set LOOM_WEB_CHROME_TEST=1 for actual traffic browser acceptance")
	}
	p := relayProjectionFixture(t)
	key := testKey(t)
	reverseKey := testKey(t)
	for i := range p.DeviceAuthorizations {
		if p.DeviceAuthorizations[i].ID == "demo-entry" {
			p.DeviceAuthorizations[i].Responsibilities = []string{"access", "forward"}
			p.DeviceAuthorizations[i].PolicyIDs = []string{"demo-policy"}
			p.DeviceAuthorizations[i].DevicePublicKey = base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
		}
		if p.DeviceAuthorizations[i].ID == "demo-exit" {
			p.DeviceAuthorizations[i].DevicePublicKey = base64.RawURLEncoding.EncodeToString(reverseKey.Public().(ed25519.PublicKey))
		}
	}
	view, err := ProjectDeviceView(p, "demo-entry")
	if err != nil {
		t.Fatal(err)
	}
	link := webRelayLink(t, p, "demo-entry", "demo-exit")
	reverse := webRelayLink(t, p, "demo-exit", "demo-entry")
	sharedID := link.ID
	if reverse.ID < sharedID {
		sharedID = reverse.ID
	}
	linkSpec, err := LinkSpecDigest(view, link.ID)
	if err != nil {
		t.Fatal(err)
	}
	digest, _ := DeviceViewDigest(view)
	tag, peers, err := WireGuardCounterBindings(view)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Millisecond)
	sampleEnd := now
	if sampleEnd.Add(-time.Minute).Truncate(time.Hour) != sampleEnd.Truncate(time.Hour) {
		// Hour boundaries deliberately have no interpolated counter delta.
		// Keep this display fixture in one hour, still within current freshness.
		sampleEnd = sampleEnd.Truncate(time.Hour).Add(-time.Millisecond)
	}
	resourcesFor := func(view DeviceView) []ResourceReadback {
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
		return resources
	}
	resources := resourcesFor(view)
	reports := []DeviceReport{}
	for i := 0; i < 2; i++ {
		at := sampleEnd.Add(time.Duration(i-1) * time.Minute)
		observed := now.Add(time.Duration(i-1) * time.Minute)
		values := append([]WireGuardPeerCounter{}, peers...)
		for j := range values {
			values[j].TXBytes = U64(i) * 1048576
		}
		observations := []Observation{{Level: "link", LinkID: link.ID, ResourceID: link.ResourceID, SpecDigest: linkSpec, Target: net.JoinHostPort(link.ProbeTarget.Host, "53"), Action: "wireguard_dns", NetworkGeneration: "demo-underlay", Result: "unavailable", ObservedAt: observed.UnixMilli(), ValidUntil: observed.Add(30 * time.Second).UnixMilli(), DurationMS: new(int64(3000))}}
		report, err := SignDeviceReport(DeviceReport{Schema: 3, NetworkID: p.NetworkID, DeviceID: view.DeviceID, ReportSequence: U64(i + 1), ViewDigest: digest, NetworkGeneration: "demo-underlay", ReportedAt: observed.UnixMilli(), Selections: []ReportSelection{}, Observations: observations, Components: []ComponentReadback{}, Runtime: RuntimeReadback{State: "running", AppliedViewDigest: digest, Resources: &resources}, WireGuardCounters: &WireGuardCounters{Interface: tag, Epoch: strings.Repeat("a", 32), ObservedAt: at.UnixMilli(), Peers: values}}, key)
		if err != nil {
			t.Fatal(err)
		}
		if verifyCurrentReport(report, p) != nil {
			t.Fatal("fixture does not match actual counter View")
		}
		reports = append(reports, report)
	}
	reverseView, err := ProjectDeviceView(p, reverse.FromNodeID)
	if err != nil {
		t.Fatal(err)
	}
	reverseSpec, err := LinkSpecDigest(reverseView, reverse.ID)
	if err != nil {
		t.Fatal(err)
	}
	reverseDigest, _ := DeviceViewDigest(reverseView)
	reverseResources := resourcesFor(reverseView)
	reverseReport, err := SignDeviceReport(DeviceReport{Schema: 3, NetworkID: p.NetworkID, DeviceID: reverseView.DeviceID, ReportSequence: 1, ViewDigest: reverseDigest, NetworkGeneration: "demo-reverse-underlay", ReportedAt: now.UnixMilli(), Selections: []ReportSelection{}, Components: []ComponentReadback{},
		Observations: []Observation{{Level: "link", LinkID: reverse.ID, ResourceID: reverse.ResourceID, SpecDigest: reverseSpec, Target: net.JoinHostPort(reverse.ProbeTarget.Host, "53"), Action: "wireguard_dns", NetworkGeneration: "demo-reverse-underlay", Result: "available", ObservedAt: now.UnixMilli(), ValidUntil: now.Add(30 * time.Second).UnixMilli(), DurationMS: new(int64(100)), RoundTripMS: new(int64(57))}},
		Runtime:      RuntimeReadback{State: "running", AppliedViewDigest: reverseDigest, Resources: &reverseResources}}, reverseKey)
	if err != nil || verifyCurrentReport(reverseReport, p) != nil {
		t.Fatal("reverse fixture must be a separately authenticated direction", err)
	}
	reports = append(reports, reverseReport)
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	testSetObservationReports(t, root, reports, base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey)), base64.RawURLEncoding.EncodeToString(reverseKey.Public().(ed25519.PublicKey)))
	store, err := testOpenObservationStore(t, root)
	if err != nil {
		t.Fatal(err)
	}
	authority := &Authority{root: root, projection: p}
	var clock atomic.Int64
	clock.Store(now.UnixMilli())
	server := &Server{Runtime: &Runtime{Authority: authority, Reports: store}, Now: func() time.Time { return time.UnixMilli(clock.Load()) }}
	var refused atomic.Bool
	normal := server.AdminHandler()
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if refused.Load() && r.URL.Path == "/api/control/ui/traffic-history" {
			http.Error(w, "demo read unavailable", http.StatusServiceUnavailable)
			return
		}
		normal.ServeHTTP(w, r)
	}))
	defer httpServer.Close()
	debug := openCommandChrome(t, httpServer.URL+"/devices/demo-entry")
	waitChromeEvaluation(t, debug, `document.querySelectorAll('[data-traffic-scope="device:demo-entry"] .wg-traffic-hour').length===48`)
	if chromeDo(t, debug, `(()=>{const root=document.querySelector('[data-traffic-scope="device:demo-entry"]');return root.querySelectorAll('[data-traffic-metric="rx"][data-traffic-value="0"]').length===1&&root.querySelectorAll('[data-traffic-value="unknown"]').length===46&&root.textContent.includes('1.0 MiB')})()`) != true {
		t.Fatal("measured zero, unknown hours, or exact deltas were lost")
	}
	refused.Store(true)
	chromeDo(t, debug, `history.pushState({},'','/topology');dispatchEvent(new PopStateEvent('popstate'));true`)
	chromeDo(t, debug, `history.pushState({},'','/devices/demo-entry');dispatchEvent(new PopStateEvent('popstate'));true`)
	waitChromeEvaluation(t, debug, `document.querySelector('[data-traffic-scope="device:demo-entry"]').textContent.includes('could not be read')`)
	refused.Store(false)
	chromeDo(t, debug, `document.querySelector('[data-traffic-retry]').click();true`)
	waitChromeEvaluation(t, debug, `document.querySelectorAll('.wg-traffic-hour').length===48`)
	chromeDo(t, debug, `history.pushState({},'','/topology');dispatchEvent(new PopStateEvent('popstate'));true`)
	waitChromeEvaluation(t, debug, `document.querySelector('[data-link-row="`+sharedID+`"] [data-traffic-rate="demo-entry"]')?.textContent.includes('0.139 Mbps')`)
	if chromeDo(t, debug, `document.querySelector('[data-link-row="`+sharedID+`"]').textContent.includes('Shared WG peer')`) != true {
		t.Fatal("shared Link counters look like exclusive service bytes")
	}
	if chromeDo(t, debug, `(()=>{const row=document.querySelector('[data-link-row="`+sharedID+`"]'),ids=JSON.parse(row.dataset.linkIds);return document.querySelectorAll('[data-connection-row]').length===1&&ids.includes('`+link.ID+`')&&ids.includes('`+reverse.ID+`')&&row.querySelectorAll('.link-total').length===1&&row.querySelector('.link-total').textContent==='1.0 MiB'&&row.querySelectorAll('[data-shared-peer-traffic]').length===1&&row.querySelectorAll('[data-traffic-scope]').length===1&&row.lastElementChild.textContent.includes('counted once')&&row.querySelector('[data-link-status="`+link.ID+`"]').textContent.includes('unavailable')&&row.querySelector('[data-link-status="`+reverse.ID+`"]').textContent.includes('available')&&document.querySelector('.topology-heading .topology-observation-summary').textContent.includes('1 connections')&&document.querySelector('.topology-heading .topology-observation-summary').textContent.includes('2 directions')&&document.querySelector('.topology-edge-card thead').textContent.includes('WG SENT')&&!document.querySelector('.topology-edge-card thead').textContent.includes('TRANSFER')})()`) != true {
		t.Fatal("relay candidates, failed WG DNS and shared sent packet totals lost their independent scopes")
	}
	chromeDo(t, debug, `document.querySelector('[data-topology-link="`+sharedID+`"]').dispatchEvent(new PointerEvent('pointerover',{bubbles:true}));true`)
	waitChromeEvaluation(t, debug, `document.querySelector('.topology-traffic-card').dataset.selectedLink==='`+sharedID+`'`)
	if chromeDo(t, debug, `!new URLSearchParams(location.search).has('link')`) != true {
		t.Fatal("hover preview changed the pinned selection")
	}
	chromeDo(t, debug, `document.querySelector('#topology').dispatchEvent(new PointerEvent('pointerleave'));true`)
	waitChromeEvaluation(t, debug, `document.querySelector('.topology-traffic-card').dataset.selectedLink===''`)
	chromeDo(t, debug, `document.querySelector('[data-topology-link="`+sharedID+`"]').dispatchEvent(new KeyboardEvent('keydown',{key:'Enter',bubbles:true}));document.querySelector('button[data-topology-direction="`+link.ID+`"]').click();true`)
	waitChromeEvaluation(t, debug, `document.querySelector('[data-selected-link="`+sharedID+`"].topology-traffic-card .wg-endpoint-hours')?.querySelectorAll('[data-traffic-endpoint]').length===48`)
	if chromeDo(t, debug, `(()=>{const card=document.querySelector('.topology-traffic-card'),forward=document.querySelector('[data-link-direction="`+link.ID+`"]'),reverse=document.querySelector('[data-link-direction="`+reverse.ID+`"]');return forward.querySelector('[data-link-probe-scope]').textContent.includes('WG DNS probe failed')&&reverse.querySelector('[data-link-probe-scope]').textContent.includes('WG DNS round trip succeeded')&&forward.querySelector('[data-link-rtt]').textContent==='Unknown'&&reverse.querySelector('[data-link-rtt]').textContent==='57 ms'&&forward.querySelectorAll('.link-hour').length===24&&reverse.querySelectorAll('.link-hour').length===24&&card.querySelector('h2').textContent==='WG sent packets'&&card.textContent.includes('handshakes, keepalives')&&card.textContent.includes('count this peer pair once')&&card.textContent.includes('Sent bytes do not confirm delivery')})()`) != true {
		t.Fatal("a failed WG DNS result was explained as delivered business traffic or an invented failure stage")
	}
	if chromeDo(t, debug, `(()=>{const card=document.querySelector('.topology-traffic-card');return new URLSearchParams(location.search).get('link')==='`+link.ID+`'&&card.querySelectorAll('[data-traffic-endpoint="demo-exit"][data-traffic-value="unknown"]').length===24&&card.querySelectorAll('[data-traffic-endpoint="demo-entry"][data-traffic-value="1048576"]').length===1&&card.querySelector('.metric').textContent==='1.0 MiB'&&document.querySelector('.topology-metrics').textContent.includes('57 ms')})()`) != true {
		t.Fatal("selected Link mixed endpoint scopes or lost exact shared rate")
	}
	if chromeDo(t, debug, `(()=>{const edge=document.querySelector('#topology .topology-edge'),line=edge.querySelector('.edge-stroke');return !edge.querySelector('circle')&&line.dataset.observationPattern==='dashed'&&line.dataset.observationFrom==='demo-exit'&&line.dataset.observationTo==='demo-entry'&&line.hasAttribute('marker-start')&&!line.hasAttribute('marker-end')})()`) != true {
		t.Fatal("confirmed directional WG DNS results lost their line pattern or point toward the failed direction")
	}
	topologyDemoScreenshotChrome(t, debug)
	if chromeDo(t, debug, `(()=>{window.demoSharedScope=document.querySelector('.topology-traffic-card [data-traffic-scope]').dataset.trafficScope;document.querySelector('button[data-topology-direction="`+reverse.ID+`"]').click();return document.querySelector('.topology-traffic-card [data-traffic-scope]').dataset.trafficScope===demoSharedScope&&document.querySelector('.topology-traffic-card .metric').textContent==='1.0 MiB'&&new URLSearchParams(location.search).get('link')==='`+reverse.ID+`'})()`) != true {
		t.Fatal("direction switching duplicated or re-scoped the shared peer counters")
	}
	if chromeDo(t, debug, `!document.querySelector('[data-traffic-retry],[data-link-history-retry]')`) != true {
		t.Fatal("successful topology history retained manual refresh controls")
	}
	if chromeDo(t, debug, `(async()=>{const {trafficHistoryRequest,trafficSummary,trafficRates}=await import('/assets/traffic-history.js'),p=await(await fetch('/api/control/ui/snapshot')).json(),scope='link:`+link.ID+`',request=trafficHistoryRequest(p,scope),data=await(await fetch(request.url)).json(),entry={key:request.key,version:request.version,data},initial=trafficSummary(p,scope,entry),device=p.devices.find(d=>d.id==='demo-entry');device.last_report_at=new Date(Date.parse(device.last_report_at)+1).toISOString();const pending=trafficSummary(p,scope,entry);p.links.find(l=>l.id==='`+link.ID+`').spec_digest='sha256:'+ 'f'.repeat(64);return trafficRates(initial,Date.now()).some(v=>v.text.includes('0.139 Mbps'))&&pending.known&&trafficRates(pending,Date.now()).every(v=>v.text.includes('Unknown'))&&trafficSummary(p,scope,entry).data===null})()`) != true {
		t.Fatal("refreshing a report must preserve scoped history without reusing a current rate or a replaced Link")
	}
	if chromeDo(t, debug, `(async()=>{const {routingHTML}=await import('/assets/routing.js'),{trafficRates}=await import('/assets/traffic-history.js');const p=await(await fetch('/api/control/ui/snapshot')).json();const doc=new DOMParser().parseFromString(routingHTML(p,new URLSearchParams({service:'demo-service',device:'demo-entry',candidate:p.paths.find(v=>v.device==='demo-entry'&&v.link_ids.includes('`+link.ID+`')).candidate_id}),Date.now()),'text/html');const hops=[...doc.querySelectorAll('.paths-hop b')].map(v=>v.textContent),first=doc.querySelector('.paths-edge'),at=Date.now();const rate=bytes=>trafficRates({data:{devices:[{device_id:'demo-entry',recent:{tx_bytes:bytes,covered_ms:1000,last_at:at}}]}},at)[0].text;return hops.length===3&&hops[0]===p.devices.find(d=>d.id==='demo-entry').name&&hops[1]===p.devices.find(d=>d.id==='demo-exit').name&&first.querySelector('[data-traffic-scope="link:`+link.ID+`"]')!==null&&rate('1').includes('<0.001 Mbps')&&rate('0').includes('0.000 Mbps')})()`) != true {
		t.Fatal("hybrid route duplicated its source, misplaced the shared Link, or rounded traffic into measured zero")
	}
	// A new original forward report changes its RTT without borrowing the
	// reverse value or changing the peer counter identity.
	current := reports[1]
	current.ReportSequence++
	at := time.Now().UTC().Truncate(time.Millisecond)
	current.ReportedAt = at.UnixMilli()
	current.Observations = append([]Observation{}, current.Observations...)
	current.Observations[0].Result = "available"
	current.Observations[0].ObservedAt = at.UnixMilli()
	current.Observations[0].ValidUntil = at.Add(30 * time.Second).UnixMilli()
	current.Observations[0].DurationMS, current.Observations[0].RoundTripMS = new(int64(100)), new(int64(13))
	current.WireGuardCounters = &WireGuardCounters{Interface: tag, Epoch: strings.Repeat("a", 32), ObservedAt: at.UnixMilli(), Peers: current.WireGuardCounters.Peers}
	current, err = SignDeviceReport(current, key)
	if err != nil || verifyCurrentReport(current, p) != nil {
		t.Fatal("new original forward RTT report rejected", err)
	}
	clock.Store(at.UnixMilli())
	if err := store.Put(current, base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))); err != nil {
		t.Fatal(err)
	}
	waitChromeEvaluation(t, debug, `document.querySelector('[data-link-direction="`+link.ID+`"] [data-link-rtt]')?.textContent==='13 ms'&&document.querySelector('[data-link-direction="`+reverse.ID+`"] [data-link-rtt]')?.textContent==='57 ms'`)
	if chromeDo(t, debug, `(()=>{const line=document.querySelector('#topology .edge-stroke');return line.dataset.observationPattern==='solid'&&getComputedStyle(line).strokeDasharray==='none'&&!line.hasAttribute('marker-start')&&!line.hasAttribute('marker-end')})()`) != true {
		t.Fatal("two original successful WG DNS directions were not displayed as a solid line")
	}
	chromeDo(t, debug, `window.demoRealNow=Date.now;Date.now=()=>window.demoRealNow()+181000;document.querySelector('button[data-topology-direction="`+reverse.ID+`"]').click();true`)
	waitChromeEvaluation(t, debug, `document.querySelector('[data-link-row="`+sharedID+`"] [data-traffic-rate="demo-entry"]')?.textContent.includes('Unknown')&&[...document.querySelectorAll('.topology-direction [data-link-rtt]')].every(value=>value.textContent==='Unknown')`)
	if chromeDo(t, debug, `(()=>{const line=document.querySelector('#topology .edge-stroke');return line.dataset.observationPattern==='unknown'&&!line.hasAttribute('marker-start')&&!line.hasAttribute('marker-end')})()`) != true {
		t.Fatal("expired directions were represented as confirmed success, failure or a one-way observation")
	}
	if chromeDo(t, debug, `document.querySelector('[data-link-row="`+sharedID+`"] [data-traffic-value="1048576"]')!==null`) != true {
		t.Fatal("current rate expiry erased original traffic history")
	}
}
