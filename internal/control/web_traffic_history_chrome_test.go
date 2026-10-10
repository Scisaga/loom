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
	for i := range p.DeviceAuthorizations {
		if p.DeviceAuthorizations[i].ID == "demo-entry" {
			p.DeviceAuthorizations[i].DevicePublicKey = base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
		}
	}
	view, err := ProjectDeviceView(p, "demo-entry")
	if err != nil {
		t.Fatal(err)
	}
	digest, _ := DeviceViewDigest(view)
	tag, peers, err := WireGuardCounterBindings(view)
	if err != nil {
		t.Fatal(err)
	}
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
	for i := 0; i < 2; i++ {
		at := now.Add(time.Duration(i-1) * time.Minute)
		values := append([]WireGuardPeerCounter{}, peers...)
		for j := range values {
			values[j].TXBytes = U64(i) * 1048576
		}
		report, err := SignDeviceReport(DeviceReport{Schema: 3, NetworkID: p.NetworkID, DeviceID: view.DeviceID, ReportSequence: U64(i + 1), ViewDigest: digest, NetworkGeneration: "demo-underlay", ReportedAt: at.UnixMilli(), Selections: []ReportSelection{}, Observations: []Observation{}, Components: []ComponentReadback{}, Runtime: RuntimeReadback{State: "running", AppliedViewDigest: digest, Resources: &resources}, WireGuardCounters: &WireGuardCounters{Interface: tag, Epoch: strings.Repeat("a", 32), ObservedAt: at.UnixMilli(), Peers: values}}, key)
		if err != nil {
			t.Fatal(err)
		}
		if verifyCurrentReport(report, p) != nil {
			t.Fatal("fixture does not match actual counter View")
		}
		reports = append(reports, report)
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	testSetObservationReports(t, root, reports)
	store, err := OpenObservationStore(root)
	if err != nil {
		t.Fatal(err)
	}
	authority := &Authority{root: root, projection: p}
	server := &Server{Runtime: &Runtime{Authority: authority, Reports: store}, Now: func() time.Time { return now }}
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
	chromeDo(t, debug, `document.querySelector('[data-traffic-retry]').click();true`)
	waitChromeEvaluation(t, debug, `document.querySelector('[data-traffic-scope="device:demo-entry"]').textContent.includes('could not be read')`)
	refused.Store(false)
	chromeDo(t, debug, `document.querySelector('[data-traffic-retry]').click();true`)
	waitChromeEvaluation(t, debug, `document.querySelectorAll('.wg-traffic-hour').length===48`)
	chromeDo(t, debug, `history.pushState({},'','/topology');dispatchEvent(new PopStateEvent('popstate'));true`)
	waitChromeEvaluation(t, debug, `document.querySelector('[data-link-row="demo-link"] [data-traffic-rate="demo-entry"]')?.textContent.includes('0.139 Mbps')`)
	if chromeDo(t, debug, `document.querySelector('[data-link-row="demo-link"]').textContent.includes('Shared peer')`) != true {
		t.Fatal("shared Link counters look like exclusive service bytes")
	}
	chromeDo(t, debug, `document.querySelector('[data-topology-link="demo-link"]').dispatchEvent(new KeyboardEvent('keydown',{key:'Enter',bubbles:true}));true`)
	waitChromeEvaluation(t, debug, `document.querySelector('[data-selected-link="demo-link"].topology-traffic-card .wg-endpoint-hours')?.querySelectorAll('[data-traffic-endpoint]').length===48`)
	if chromeDo(t, debug, `(()=>{const card=document.querySelector('.topology-traffic-card');return new URLSearchParams(location.search).get('link')==='demo-link'&&card.querySelectorAll('[data-traffic-endpoint="demo-exit"][data-traffic-value="unknown"]').length===24&&card.querySelectorAll('[data-traffic-endpoint="demo-entry"][data-traffic-value="1048576"]').length===1&&document.querySelector('.topology-metrics').textContent.includes('0.139 Mbps')})()`) != true {
		t.Fatal("selected Link mixed endpoint scopes or lost exact shared rate")
	}
	chromeDo(t, debug, `document.querySelector('.topology-traffic-card [data-traffic-retry]').click();true`)
	waitChromeEvaluation(t, debug, `document.querySelector('.topology-traffic-card [data-traffic-endpoint="demo-entry"][data-traffic-value="1048576"]')!==null`)
	chromeDo(t, debug, `window.demoRealNow=Date.now;Date.now=()=>window.demoRealNow()+181000;document.querySelector('[data-traffic-retry="link:demo-link"]').click();true`)
	waitChromeEvaluation(t, debug, `document.querySelector('[data-link-row="demo-link"] [data-traffic-rate="demo-entry"]')?.textContent.includes('Unknown')`)
	if chromeDo(t, debug, `document.querySelector('[data-link-row="demo-link"] [data-traffic-value="1048576"]')!==null`) != true {
		t.Fatal("current rate expiry erased original traffic history")
	}
}
