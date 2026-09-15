package webui

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

func browserRequest(d Deps, method, path, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	Handler(d).ServeHTTP(w, r)
	return w
}
func TestBrowserShellDoesNotRenderPrivateData(t *testing.T) {
	d := clientUIDeps()
	d.Admin = true
	calls := 0
	d.Snapshot = func() View { calls++; return View{Self: "demo-private-node"} }
	for _, path := range []string{"/", "/devices", "/devices?new=1", "/topology", "/services", "/routing", "/releases", "/events", "/ssot"} {
		w := browserRequest(d, "GET", path, "")
		if w.Code != 200 || strings.Contains(w.Body.String(), "demo-private-node") || !strings.Contains(w.Body.String(), `type="module"`) {
			t.Fatalf("static shell failed for %s", path)
		}
		if strings.Contains(w.Header().Get("Content-Security-Policy"), "unsafe-inline") {
			t.Fatal("inline execution enabled")
		}
	}
	if calls != 0 {
		t.Fatal("static navigation collected runtime evidence")
	}
	for _, path := range []string{"/devices/create", "/devices/delete", "/devices/pause", "/devices/replace", "/nodes/add", "/login", "/logout"} {
		if w := browserRequest(d, "POST", path, ""); w.Code != 404 {
			t.Fatalf("removed route %s remains: %d", path, w.Code)
		}
	}
}
func TestBrowserJSONPreservesAdminAndRevisionBoundaries(t *testing.T) {
	calls := 0
	d := clientUIDeps()
	d.Control.Services = &ServiceControlDeps{Upsert: func(s ServiceInput, rev string) error {
		calls++
		if rev != "demo-base" || s.ID != "demo-service" || len(s.Addresses) != 1 {
			t.Fatal("service input was lost")
		}
		return errors.New("SSOT conflict")
	}}
	d.Control.Read = func() (string, error) { calls++; return "demo-private-ssot", nil }
	paths := []string{"/api/control/ui/device-action", "/api/control/ui/services", "/api/control/ui/ssot", "/api/control/ui/enrollment-options", "/api/control/ui/invites/demo-invite", "/api/control/ui/releases"}
	for _, path := range paths {
		method := "POST"
		if strings.Contains(path, "options") || strings.Contains(path, "invites/") || strings.HasSuffix(path, "releases") {
			method = "GET"
		}
		if w := browserRequest(d, method, path, `{}`); w.Code != 403 {
			t.Fatalf("anonymous %s: %d", path, w.Code)
		}
	}
	if calls != 0 {
		t.Fatal("anonymous request reached private state")
	}
	d.Admin = true
	w := browserRequest(d, "POST", "/api/control/ui/services", `{"service":{"ID":"demo-service","Addresses":["api.example.net"]},"revision":"demo-base"}`)
	if w.Code != 409 || calls != 1 {
		t.Fatalf("conflict was hidden: %d %d", w.Code, calls)
	}
	d.Snapshot = func() View {
		return View{Nodes: []NodeView{{ID: "demo-node", Name: "Demo", PublicEndpoint: "private.example.net", SSHPort: 12345, Version: &VersionView{Binary: "demo-private-binary"}}}, Warnings: []string{"demo-private-path"}}
	}
	d.Admin = false
	w = browserRequest(d, "GET", "/api/control/ui", "")
	for _, secret := range []string{"private.example.net", "demo-private-binary", "demo-private-path", "demo-private-ssot"} {
		if strings.Contains(w.Body.String(), secret) {
			t.Fatal("read-only API exposed private details")
		}
	}
}
func TestBrowserDeviceActionsAreAuthenticatedAndConfirmed(t *testing.T) {
	d := clientUIDeps()
	calls := 0
	d.Control.Clients.DeleteDevice = func(id string) error {
		if id != "demo-device" {
			t.Fatal(id)
		}
		calls++
		return nil
	}
	d.Control.Clients.SetDevicePaused = func(id string, paused bool) error {
		calls++
		if !paused {
			t.Fatal("pause lost")
		}
		return nil
	}
	body := `{"id":"demo-device","action":"delete","confirm":true}`
	if browserRequest(d, "POST", "/api/control/ui/device-action", body).Code != 403 {
		t.Fatal("anonymous deletion accepted")
	}
	d.Admin = true
	if browserRequest(d, "GET", "/api/control/ui/device-action", "").Code != 405 {
		t.Fatal("GET caused a write")
	}
	if browserRequest(d, "POST", "/api/control/ui/device-action", `{"id":"demo-device","action":"delete"}`).Code != 400 {
		t.Fatal("unconfirmed deletion accepted")
	}
	if calls != 0 {
		t.Fatal("rejected request invoked action")
	}
	if browserRequest(d, "POST", "/api/control/ui/device-action", body).Code != 200 || calls != 1 {
		t.Fatal("confirmed removal not connected")
	}
	if browserRequest(d, "POST", "/api/control/ui/device-action", `{"id":"demo-device","action":"pause"}`).Code != 200 || calls != 2 {
		t.Fatal("pause not connected")
	}
}
func TestBrowserRuntimeProjectionDoesNotPromoteUntrustedReports(t *testing.T) {
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	base := ClientInventory{Clients: []ClientView{{ID: "demo-client", Platform: "android", Status: "ready", Membership: "active"}}}
	v := View{Nodes: []NodeView{{ID: "demo-client", Declared: true, Health: "healthy", Source: "unsigned", ObservedAt: now.Format(time.RFC3339), PresenceAt: now.Format(time.RFC3339)}}}
	got := mergeClientRuntime(base, v, now)
	if got.Clients[0].DataPlaneStatus == "online" {
		t.Fatal("unsigned report became online")
	}
	v.Nodes[0].Source = "签名健康转述"
	got = mergeClientRuntime(base, v, now)
	if got.Clients[0].DataPlaneStatus != "online" {
		t.Fatalf("valid report lost: %+v", got)
	}
	v.Nodes[0].PresenceAt = now.Add(-clientPresenceStaleAfter - time.Second).Format(time.RFC3339)
	got = mergeClientRuntime(base, v, now)
	if got.Clients[0].DataPlaneStatus != "stale" {
		t.Fatal("observation extended presence lease")
	}
}
func TestBrowserNormalNavigationFilteringAndDeviceCreation(t *testing.T) {
	browser := os.Getenv("LOOM_BROWSER_TEST_BINARY")
	if browser == "" {
		t.Skip("设置 LOOM_BROWSER_TEST_BINARY 运行真实浏览器")
	}
	var mu sync.Mutex
	changes := make(chan struct{})
	generation := 0
	d := clientUIDeps()
	d.Admin = true
	d.Now = time.Now
	d.DeviceChanges = func() <-chan struct{} { mu.Lock(); defer mu.Unlock(); return changes }
	d.Snapshot = func() View {
		mu.Lock()
		defer mu.Unlock()
		at := time.Now().UTC().Format(time.RFC3339)
		return View{Nodes: []NodeView{{ID: "demo-device", Declared: true, Health: []string{"healthy", "problem"}[generation], Source: "签名健康转述", ObservedAt: at, PresenceAt: at}}}
	}
	d.Control.Clients.List = func() (ClientInventory, error) {
		return ClientInventory{Clients: []ClientView{{ID: "demo-device", Name: "Demo device", Platform: "linux-server", Responsibilities: []string{"use_loom", "forward"}, DestinationGrants: []string{"demo-grant"}, Membership: "active", Status: "ready"}, {ID: "demo-phone", Name: "<img src=x onerror=alert(1)>", Platform: "android", Responsibilities: []string{"use_loom"}, Membership: "active", Status: "ready"}}}, nil
	}
	created := make(chan ClientInviteInput, 1)
	d.Control.Clients.CreateInvite = func(input ClientInviteInput) (ClientInviteView, error) {
		created <- input
		return ClientInviteView{InviteID: "demo-invite"}, nil
	}
	d.Control.Clients.InviteArtifact = func(id string) (ClientInviteArtifact, error) {
		return ClientInviteArtifact{ClientID: "demo-created", Platform: "windows-desktop", InviteURI: "loom://demo-invite", ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339)}, nil
	}
	result := make(chan string, 1)
	handler := Handler(d)
	script := `
import {matchesDevice,trafficSample,trafficRate,bytes,topologyPositions,historyPoints} from '/assets/model.js';
const assert=(value,message)=>{if(!value)throw Error(message)};
const wait=async(fn)=>{for(let i=0;i<300;i++){if(fn())return;await new Promise(r=>setTimeout(r,20));}throw Error('Timed out: '+fn)};
try{
 await wait(()=>document.documentElement.dataset.ready==='true');
 const marker={};window.demoMarker=marker;
 document.querySelector('a[href="/devices"]').click();await wait(()=>document.querySelector('#devices-body'));
 assert(document.querySelectorAll('#devices-body tr').length===2,'initial device count');
 assert(!document.querySelector('#devices-body img'),'untrusted device name became markup');
 const role=document.querySelector('[name=role][value=forward]');role.checked=true;role.dispatchEvent(new Event('input',{bubbles:true}));
 assert(document.querySelectorAll('#devices-body tr').length===1,'responsibility filtering');assert(location.search.includes('role=forward'),'filter URL');
 const row=document.querySelector('#devices-body tr'),grant=row.querySelector('details');grant.open=true;
 const search=document.querySelector('[name=q]');search.focus();
 await fetch('/__change',{method:'POST'});await wait(()=>row.textContent.includes('problem'));
 assert(row===document.querySelector('#devices-body tr'),'live update replaced device row');assert(grant.open,'live update lost expansion');assert(document.activeElement===search,'live update stole focus');
 for(const [path,selector] of [['/','#overview-nodes'],['/topology','#links-body'],['/routing','#routes-body'],['/services','#services-body'],['/releases','#release-content'],['/events','#events-body'],['/ssot','#ssot-form']]){document.querySelector('nav a[href="'+path+'"]').click();await wait(()=>document.querySelector(selector));assert(!document.querySelector('#retry-page'),'page failed: '+path);}
 document.querySelector('nav a[href="/devices"]').click();await wait(()=>document.querySelector('#devices-body'));
 document.querySelector('a[href="/devices?new=1"]').click();await wait(()=>document.querySelector('#enrollment-form'));
 const form=document.querySelector('#enrollment-form'),direction=document.querySelector('#direction-choice');
 assert(getComputedStyle(direction).display==='none','Windows direction visible');assert(document.querySelector('#role-choices').hidden,'Windows unsupported roles visible');
 form.elements.platform.value='linux-server';form.dispatchEvent(new Event('change',{bubbles:true}));const forward=form.querySelector('[value=forward]');forward.checked=true;forward.dispatchEvent(new Event('change',{bubbles:true}));
 assert(getComputedStyle(direction).display!=='none','forward direction unavailable');assert(!document.querySelector('#egress-choice').hidden,'forward egress option hidden');
 forward.checked=false;forward.dispatchEvent(new Event('change',{bubbles:true}));assert(direction.hidden&&form.elements.direction.disabled,'use-only direction submitted');
 form.elements.platform.value='windows-desktop';form.dispatchEvent(new Event('change',{bubbles:true}));form.elements.name.value='Demo created';form.requestSubmit();
 await wait(()=>location.pathname==='/devices/invites/demo-invite');await wait(()=>document.querySelector('#invite-uri'));
 assert(window.demoMarker===marker,'navigation reloaded the document');assert(!document.querySelector('#install-commands pre'),'Windows got Linux install commands');
 const counter=(rx,at,epoch='demo-epoch')=>({interface:'demo-wg',peer_node:'demo-peer',counter_epoch:epoch,rx_bytes:rx,tx_bytes:'0',observed_at:new Date(at).toISOString(),trusted:true});const now=Date.now();
 const a=trafficSample([counter('0',now-1000)],now),b=trafficSample([counter('1024',now)],now);
 assert(trafficRate(a,b).rx===1024n,'adjacent counter rate');assert(bytes(0n)==='0 B','sampled idle zero missing');assert(trafficRate(b,trafficSample([counter('0',now+1000,'demo-reset')],now))===null,'counter reset became traffic');
 assert(trafficSample([{...counter('1',now),trusted:false}],now)===null,'untrusted counters displayed');
 const history=historyPoints({buckets:[{start:'demo',nodes:[{node:'demo',samples:0,rx_bytes:'0',tx_bytes:'0',resets:1,gaps:0}]}]},'demo');assert(!history[0].present,'reset-only bucket became idle zero');
 const nodes=[{ID:'demo-a',Roles:['access']},{ID:'demo-b',Roles:['server']}];assert(JSON.stringify([...topologyPositions(nodes)])===JSON.stringify([...topologyPositions([...nodes].reverse())]),'topology order depends on input');
 await fetch('/__result',{method:'POST',body:'ok'});
}catch(e){await fetch('/__result',{method:'POST',body:e.stack||String(e)});}
`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/__test.js":
			w.Header().Set("Content-Type", "text/javascript")
			fmt.Fprint(w, script)
			return
		case "/__change":
			mu.Lock()
			generation = 1
			close(changes)
			changes = make(chan struct{})
			mu.Unlock()
			w.WriteHeader(204)
			return
		case "/__result":
			b, _ := io.ReadAll(r.Body)
			result <- string(b)
			w.WriteHeader(204)
			return
		}
		if r.URL.Path == "/" {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, r)
			for k, v := range rec.Header() {
				w.Header()[k] = v
			}
			fmt.Fprint(w, strings.Replace(rec.Body.String(), "</body>", `<script type="module" src="/__test.js"></script></body>`, 1))
			return
		}
		handler.ServeHTTP(w, r)
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 25*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, browser, "--headless", "--no-sandbox", "--disable-gpu", "--no-proxy-server", "--no-first-run", "--disable-background-networking", "--user-data-dir="+t.TempDir(), "--dump-dom", "--virtual-time-budget=8000", server.URL)
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = command.Wait(); cancel() }()
	select {
	case output := <-result:
		if output != "ok" {
			t.Fatal(output)
		}
	case <-ctx.Done():
		t.Fatal("浏览器测试未返回结果")
	}
	select {
	case input := <-created:
		if input.Platform != "windows-desktop" || input.Direction != "" || len(input.Responsibilities) != 1 || input.Responsibilities[0] != "use_loom" {
			t.Fatalf("normal create input: %+v", input)
		}
	case <-time.After(time.Second):
		t.Fatal("normal create did not reach business dependency")
	}
}

func TestBrowserSnapshotMergesIndependentPresenceWithoutCollecting(t *testing.T) {
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	old := now.Add(-time.Minute).Format(time.RFC3339)
	cached := View{Nodes: []NodeView{{ID: "demo-device", Declared: true, Health: "healthy", Source: "签名健康转述", ObservedAt: now.Add(-time.Second).Format(time.RFC3339), PresenceAt: old}}}
	presence := map[string]string{"demo-device": now.Format(time.RFC3339)}
	d := Deps{Admin: true, Now: func() time.Time { return now }, Snapshot: func() View { t.Fatal("browser triggered collection"); return View{} }, TrafficSnapshot: func() View { return cached }, PresenceSnapshot: func() map[string]string { return presence }, Control: &ControlDeps{Devices: &ClientControlDeps{List: func() (ClientInventory, error) {
		return ClientInventory{Clients: []ClientView{{ID: "demo-device", Platform: "linux-server", Status: "ready", Membership: "active"}}}, nil
	}}}}
	view := loadBrowserSnapshot(d)
	if view.Inventory.Devices[0].PresenceStatus != "live" || view.Inventory.Devices[0].DataPlaneStatus != "online" {
		t.Fatal("fresh independent presence was frozen in cached observation")
	}
	if cached.Nodes[0].PresenceAt != old {
		t.Fatal("browser mutated shared cache")
	}
	presence["demo-device"] = old
	if loadBrowserSnapshot(d).Inventory.Devices[0].DataPlaneStatus != "stale" {
		t.Fatal("expired presence inherited observation freshness")
	}
}
