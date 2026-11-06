package control

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// Layout acceptance uses the unmodified /topology SPA and its real snapshot,
// directional history and shared-counter handlers. Reports are signed against
// the same projected views that those handlers verify; there is no DOM fixture.
func TestWebChromeTopologyViewportKeepsFullDetailsAndStableDiagram(t *testing.T) {
	if os.Getenv("LOOM_WEB_CHROME_TEST") != "1" {
		t.Skip("set LOOM_WEB_CHROME_TEST=1 for topology viewport acceptance")
	}
	p := relayProjectionFixture(t)
	// Existing controls share two of these devices, rather than adding two
	// unrelated member-only nodes to the six-device layout fixture.
	for i := range p.Config.Members {
		p.Config.Members[i].NodeID = []string{"demo-entry", "demo-exit"}[i]
	}
	for _, id := range []string{"demo-delta", "demo-echo", "demo-foxtrot"} {
		device := p.DeviceAuthorizations[1]
		device.ID, device.Name = id, id
		device.Responsibilities, device.PolicyIDs = []string{"forward", "internet_egress"}, []string{}
		p.DeviceAuthorizations = append(p.DeviceAuthorizations, device)
	}
	keys := map[string]ed25519.PrivateKey{}
	publicKeys := []string{}
	for i := range p.DeviceAuthorizations {
		device := &p.DeviceAuthorizations[i]
		device.Name = device.ID
		if device.ID == "demo-access" || device.ID == "demo-entry" {
			device.Responsibilities, device.PolicyIDs = []string{"access", "forward"}, []string{"demo-policy"}
		}
		key := testKey(t)
		keys[device.ID] = key
		device.DevicePublicKey = base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
		publicKeys = append(publicKeys, device.DevicePublicKey)
		if device.ID == "demo-entry" || device.ID == "demo-exit" {
			continue
		}
		wgKey := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat(string(rune('c'+i)), 32)))
		addresses := []string{fmt.Sprintf("198.51.100.%d/32", i+10)}
		p.NetworkIntent.Resources = append(p.NetworkIntent.Resources, TransportResource{ID: device.ID + "-wg", Kind: "wireguard", OwnerNodeID: device.ID, ListenerID: device.ID + "-wg", DialHost: fmt.Sprintf("192.0.2.%d", i+20), DialPort: 51820, Authentication: ResourceAuthentication{PublicKey: &wgKey, LocalAddresses: &addresses}})
	}
	sort.Slice(p.NetworkIntent.Resources, func(i, j int) bool { return p.NetworkIntent.Resources[i].ID < p.NetworkIntent.Resources[j].ID })
	links, err := DerivedNetworkLinks(p)
	if err != nil {
		t.Fatal(err)
	}
	forward := webRelayLink(t, p, "demo-entry", "demo-exit")
	reverse := webRelayLink(t, p, "demo-exit", "demo-entry")
	unknown := webRelayLink(t, p, "demo-echo", "demo-entry")
	now := time.Now().UTC().Truncate(time.Millisecond)
	counterEnd := now
	if counterEnd.Add(-2*time.Minute).Truncate(time.Hour) != counterEnd.Truncate(time.Hour) {
		counterEnd = counterEnd.Truncate(time.Hour).Add(-time.Millisecond)
	}
	reports := []DeviceReport{}
	for _, device := range p.DeviceAuthorizations {
		view, err := ProjectDeviceView(p, device.ID)
		if err != nil {
			t.Fatal(err)
		}
		digest, err := DeviceViewDigest(view)
		if err != nil {
			t.Fatal(err)
		}
		tag, peers, err := WireGuardCounterBindings(view)
		if err != nil {
			t.Fatal(err)
		}
		resources := []ResourceReadback{}
		for _, resource := range view.Resources {
			if resource.OwnerNodeID != view.DeviceID {
				continue
			}
			acl, err := InboundACLDigest(view, resource.ID)
			if err != nil {
				t.Fatal(err)
			}
			readback := ResourceReadback{ResourceID: resource.ID, ListenerID: resource.ListenerID, Listen: net.JoinHostPort(resource.DialHost, strconv.Itoa(resource.DialPort)), ACLDigest: acl, CertificateDigest: "sha256:" + strings.Repeat("0", 64)}
			if resource.Kind == "wireguard" {
				readback.CertificateDigest, readback.PublicKey = "", *resource.Authentication.PublicKey
			}
			resources = append(resources, readback)
		}
		sort.Slice(resources, func(i, j int) bool { return resources[i].ResourceID < resources[j].ResourceID })
		for index := 0; index < 3; index++ {
			at := now.Add(time.Duration(index-2) * time.Minute)
			observations := []Observation{}
			for _, link := range links {
				if link.FromNodeID != device.ID || device.ID == "demo-echo" {
					continue
				}
				spec, err := LinkSpecDigest(view, link.ID)
				if err != nil {
					t.Fatal(err)
				}
				rtt := int64(25 + index*2)
				if link.ID == forward.ID {
					rtt = int64(13 + index*2)
				}
				if link.ID == reverse.ID {
					rtt = int64(57 + index*2)
				}
				observations = append(observations, Observation{Level: "link", LinkID: link.ID, ResourceID: link.ResourceID, SpecDigest: spec, Target: net.JoinHostPort(link.ProbeTarget.Host, "53"), Action: "wireguard_echo", NetworkGeneration: "demo-underlay", Result: "available", ObservedAt: at.UnixMilli(), ValidUntil: at.Add(30 * time.Second).UnixMilli(), DurationMS: new(int64(100)), RoundTripMS: &rtt})
			}
			sort.Slice(observations, func(i, j int) bool { return compareObservationOrder(observations[i], observations[j]) < 0 })
			values := append([]WireGuardPeerCounter{}, peers...)
			for i := range values {
				values[i].TXBytes = U64(index) * 1048576
			}
			report, err := SignDeviceReport(DeviceReport{Schema: 3, NetworkID: p.NetworkID, DeviceID: view.DeviceID, ViewDigest: digest, ReportSequence: U64(index + 1), ReportedAt: at.UnixMilli(), NetworkGeneration: "demo-underlay", Selections: []ReportSelection{}, Observations: observations, Components: []ComponentReadback{}, Runtime: RuntimeReadback{State: "running", AppliedViewDigest: digest, Resources: &resources}, WireGuardCounters: &WireGuardCounters{Interface: tag, Epoch: strings.Repeat("a", 32), ObservedAt: counterEnd.Add(time.Duration(index-2) * time.Minute).UnixMilli(), Peers: values}}, keys[device.ID])
			if err != nil {
				t.Fatal(err)
			}
			if err := verifyCurrentReport(report, p); err != nil {
				t.Fatalf("signed layout fixture must obey the current view: %s: %v", device.ID, err)
			}
			reports = append(reports, report)
		}
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	testSetObservationReports(t, root, reports, publicKeys...)
	store, err := testOpenObservationStore(t, root)
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{Runtime: &Runtime{Authority: &Authority{root: root, projection: p}, Reports: store}, Now: func() time.Time { return now }}
	historyRequested, resumeHistory := make(chan struct{}), make(chan struct{})
	var requestedOnce, resumeOnce sync.Once
	releaseHistory := func() { resumeOnce.Do(func() { close(resumeHistory) }) }
	handler := server.AdminHandler()
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/control/ui/link-history" || r.URL.Path == "/api/control/ui/traffic-history" {
			requestedOnce.Do(func() { close(historyRequested) })
			select {
			case <-resumeHistory:
			case <-r.Context().Done():
				return
			}
		}
		handler.ServeHTTP(w, r)
	}))
	defer httpServer.Close()
	defer releaseHistory()
	debug := openCommandChrome(t, httpServer.URL+"/topology")
	setViewport := func(width int) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := debug.call(ctx, "Emulation.setDeviceMetricsOverride", map[string]any{"width": width, "height": 1000, "deviceScaleFactor": 1, "mobile": width == 390}, nil); err != nil {
			t.Fatal(err)
		}
		chromeDo(t, debug, `(async()=>{scrollTo(0,0);await document.fonts.ready;await new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve)));return true})()`)
	}
	waitChromeEvaluation(t, debug, `document.querySelectorAll('#topology [data-node]').length===6&&document.querySelector('.topology-edge-card tbody tr')`)
	setViewport(1600)
	select {
	case <-historyRequested:
	case <-time.After(5 * time.Second):
		t.Fatal("the production topology did not request its history")
	}
	chromeDo(t, debug, `window.demoLayoutGeometry=()=>({svg:document.querySelector('#topology svg').getBoundingClientRect().toJSON(),nodes:[...document.querySelectorAll('#topology [data-node] .node')].map(node=>[node.closest('[data-node]').dataset.node,node.getBoundingClientRect().toJSON()]),listTop:document.querySelector('.topology-edge-card').getBoundingClientRect().top});window.demoBeforeDetails=demoLayoutGeometry();true`)
	point := chromeDo(t, debug, `(()=>{const edge=[...document.querySelectorAll('#topology [data-topology-links]')].find(edge=>JSON.parse(edge.dataset.topologyLinks).includes('`+forward.ID+`')),path=edge.querySelector('.edge-hit');for(const fraction of [.5,.4,.6,.3,.7,.2,.8]){const p=path.getPointAtLength(path.getTotalLength()*fraction).matrixTransform(path.getScreenCTM());if(document.elementFromPoint(p.x,p.y)?.closest('.topology-edge')===edge)return {x:p.x,y:p.y}}return {error:'The connection has no visible pointer hit'}})()`).(map[string]any)
	if point["error"] != nil {
		t.Fatal(point)
	}
	topologyMouseChrome(t, debug, "mouseMoved", point, 0)
	waitChromeEvaluation(t, debug, `document.querySelectorAll('.topology-direction').length===2`)
	checkStable := func(stage string) {
		t.Helper()
		result := chromeDo(t, debug, `(async()=>{await new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve)));return {stable:JSON.stringify(demoLayoutGeometry())===JSON.stringify(demoBeforeDetails),before:demoBeforeDetails,after:demoLayoutGeometry()}})()`).(map[string]any)
		if result["stable"] != true {
			topologyViewportScreenshotChrome(t, debug, "demo-layout-failure-1600x1000.png")
			t.Fatalf("%s moved the diagram or the connection list: %#v", stage, result)
		}
	}
	checkStable("hovering before history completes")
	releaseHistory()
	waitChromeEvaluation(t, debug, `document.querySelectorAll('.topology-direction .link-hour').length===48&&document.querySelectorAll('.topology-traffic-card [data-traffic-endpoint]').length===48`)
	checkStable("asynchronous history completion")
	topologyMouseChrome(t, debug, "mousePressed", point, 0)
	topologyMouseChrome(t, debug, "mouseReleased", point, 0)
	waitChromeEvaluation(t, debug, `new URLSearchParams(location.search).has('link')`)
	checkStable("pinning a connection")
	button := chromeDo(t, debug, `(()=>{const r=document.querySelector('button[data-topology-direction="`+reverse.ID+`"]').getBoundingClientRect();return {x:r.x+r.width/2,y:r.y+r.height/2}})()`).(map[string]any)
	topologyMouseChrome(t, debug, "mouseMoved", button, 0)
	topologyMouseChrome(t, debug, "mousePressed", button, 0)
	topologyMouseChrome(t, debug, "mouseReleased", button, 0)
	waitChromeEvaluation(t, debug, `new URLSearchParams(location.search).get('link')==='`+reverse.ID+`'`)
	checkStable("switching the inspected direction")
	result := chromeDo(t, debug, `(()=>{
	 const errors=[],stage=document.querySelector('.topology-stage'),side=document.querySelector('.topology-side'),layout=document.querySelector('.topology-layout'),toolbar=document.querySelector('.topology-toolbar'),list=document.querySelector('.topology-edge-card'),a=stage.getBoundingClientRect(),b=side.getBoundingClientRect(),l=list.getBoundingClientRect(),ratio=a.width/(a.width+b.width),directions=[...side.querySelectorAll('.topology-direction')];
	 if(toolbar.getBoundingClientRect().bottom>a.top+1||toolbar.getBoundingClientRect().width<layout.getBoundingClientRect().width-2)errors.push('filters do not span both columns');
	 if(ratio<.45||ratio>.56||a.height<590||Math.abs(a.bottom-b.bottom)>2)errors.push('diagram and complete details do not share balanced width and height');
	 if(b.bottom>innerHeight||l.top<a.bottom||l.top-a.bottom>32||list.querySelector('tbody tr').getBoundingClientRect().top>=innerHeight)errors.push('complete details and the start of the list do not fit the desktop viewport');
	 if(directions.length!==2||Math.abs(directions[0].getBoundingClientRect().top-directions[1].getBoundingClientRect().top)>2||directions[0].getBoundingClientRect().right>directions[1].getBoundingClientRect().left+1)errors.push('directions are not side by side');
	 for(const direction of directions){if(direction.querySelectorAll('.link-hour').length!==24||!direction.querySelector('[data-link-rtt]')?.textContent.includes('ms')||!direction.querySelector('[data-link-spread]')?.textContent.includes('ms')||!direction.querySelector('[data-link-sample-time]')?.textContent.toLowerCase().includes('sampled')||!direction.textContent.includes('not uptime'))errors.push('a direction lost its original metrics or history');}
	 if(side.querySelectorAll('.wg-traffic-group').length!==24||side.querySelectorAll('[data-traffic-rate]').length!==2||!side.textContent.includes('count this peer pair once')||!side.textContent.includes('Sent bytes do not confirm delivery'))errors.push('shared counters or their scope are incomplete');
	 for(const element of [side,...side.querySelectorAll('section,.wg-traffic,.link-hours,.wg-traffic-hours,.wg-packet-scope')]){const r=element.getBoundingClientRect(),style=getComputedStyle(element);if(r.top<b.top-1||r.bottom>b.bottom+1||r.left<b.left-1||r.right>b.right+1)errors.push('detail content escapes its panel: '+element.className);if(element.clientHeight>0&&element.scrollHeight>element.clientHeight+2&&['auto','scroll','hidden','clip'].includes(style.overflowY))errors.push('detail is internally scrolled or clipped: '+element.className);}
	 const svg=document.querySelector('#topology svg'),s=svg.getBoundingClientRect();for(const text of svg.querySelectorAll('[data-node] text')){const r=text.getBoundingClientRect();if(r.left<s.left-1||r.right>s.right+1||r.top<s.top-1||r.bottom>s.bottom+1)errors.push('node label escapes the reshaped diagram: '+text.textContent);}
	 if(side.querySelector('.topology-observation-summary')||!document.querySelector('.topology-heading .topology-observation-summary')?.textContent.includes('unknown'))errors.push('network summary is still in connection detail');
	 return {errors,stage:a.toJSON(),details:b.toJSON(),list:l.toJSON(),ratio};
	})()`).(map[string]any)
	if len(result["errors"].([]any)) != 0 {
		t.Fatalf("desktop topology does not show the approved full-detail layout: %#v", result)
	}
	topologyViewportScreenshotChrome(t, debug, "demo-six-nodes-1600x1000.png")
	// A real authorized direction with no signed observation keeps Unknown;
	// compact presentation cannot borrow the opposite sender's successful RTT.
	chromeDo(t, debug, `history.pushState({},'','/topology?link=`+unknown.ID+`');dispatchEvent(new PopStateEvent('popstate'));true`)
	waitChromeEvaluation(t, debug, `document.querySelector('[data-link-direction="`+unknown.ID+`"] [data-link-rtt]')?.textContent==='Unknown'&&document.querySelectorAll('.topology-direction .link-hour').length===48`)
	checkStable("inspecting a connection with one unknown direction")
	setViewport(390)
	result = chromeDo(t, debug, `(()=>{
	 const errors=[],stage=document.querySelector('.topology-stage').getBoundingClientRect(),side=document.querySelector('.topology-side'),r=side.getBoundingClientRect();
	 if(r.top<stage.bottom||r.width>innerWidth||r.left<0||r.right>innerWidth)errors.push('narrow screen did not become a readable single column');
	 for(const element of [side,...side.querySelectorAll('.topology-direction,.topology-traffic-card,.wg-traffic,.wg-traffic-hours')]){const b=element.getBoundingClientRect();if(b.left<r.left-1||b.right>r.right+1||element.scrollWidth>element.clientWidth+2&&element.clientWidth>0)errors.push('detail requires horizontal scrolling: '+element.className);if(element.clientHeight>0&&element.scrollHeight>element.clientHeight+2&&['auto','scroll','hidden','clip'].includes(getComputedStyle(element).overflowY))errors.push('narrow detail is internally scrolled or clipped: '+element.className);}
	 if(side.querySelectorAll('.topology-direction').length!==2||side.querySelectorAll('.link-hour').length!==48||side.querySelectorAll('[data-traffic-endpoint]').length!==48)errors.push('narrow detail omitted data');
	 return {errors,diagram:stage.toJSON(),details:r.toJSON()};
	})()`).(map[string]any)
	if len(result["errors"].([]any)) != 0 {
		t.Fatalf("narrow topology cannot be read through normal page scrolling: %#v", result)
	}
}

func topologyViewportScreenshotChrome(t *testing.T, debug *chromeDevTools, name string) {
	t.Helper()
	debug.connection.SetReadLimit(8 << 20)
	defer debug.connection.SetReadLimit(32768)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var screenshot struct {
		Data string `json:"data"`
	}
	if err := debug.call(ctx, "Page.captureScreenshot", map[string]any{"format": "png", "captureBeyondViewport": false}, &screenshot); err != nil {
		t.Fatal(err)
	}
	content, err := base64.StdEncoding.DecodeString(screenshot.Data)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("..", "..", "out", "ui-review", "topology-layout-implemented", name)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
}
