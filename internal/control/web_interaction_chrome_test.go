package control

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
)

type chromeDebugTarget struct {
	Type                 string `json:"type"`
	URL                  string `json:"url"`
	WebSocketDebuggerURL string `json:"webSocketDebuggerUrl"`
}

type chromeDevTools struct {
	connection *websocket.Conn
	nextID     int
}

func (client *chromeDevTools) call(ctx context.Context, method string, params any, result any) error {
	client.nextID++
	id := client.nextID
	if err := wsjson.Write(ctx, client.connection, map[string]any{"id": id, "method": method, "params": params}); err != nil {
		return err
	}
	for {
		var response struct {
			ID     int             `json:"id"`
			Result json.RawMessage `json:"result"`
			Error  *struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := wsjson.Read(ctx, client.connection, &response); err != nil {
			return err
		}
		if response.ID != id {
			continue
		}
		if response.Error != nil {
			return errors.New(response.Error.Message)
		}
		if result == nil {
			return nil
		}
		return json.Unmarshal(response.Result, result)
	}
}

func (client *chromeDevTools) evaluate(ctx context.Context, expression string) (any, error) {
	var response struct {
		Result struct {
			Value any `json:"value"`
		} `json:"result"`
		Exception json.RawMessage `json:"exceptionDetails"`
	}
	err := client.call(ctx, "Runtime.evaluate", map[string]any{"expression": expression, "returnByValue": true, "awaitPromise": true}, &response)
	if err != nil {
		return nil, err
	}
	if len(response.Exception) != 0 {
		return nil, fmt.Errorf("Chrome evaluation failed: %s", response.Exception)
	}
	return response.Result.Value, nil
}

func waitChromeEvaluation(t *testing.T, client *chromeDevTools, expression string) any {
	t.Helper()
	deadline := time.Now().Add(12 * time.Second)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		value, err := client.evaluate(ctx, expression)
		cancel()
		if err == nil && value != nil && value != false && value != "" {
			return value
		}
		time.Sleep(100 * time.Millisecond)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	diagnostic, _ := client.evaluate(ctx, `document.body.innerText`)
	cancel()
	t.Fatalf("Chrome condition did not become true: %s; page: %v", expression, diagnostic)
	return nil
}

func openCommandChrome(t *testing.T, target string) *chromeDevTools {
	t.Helper()
	chrome, err := exec.LookPath("google-chrome")
	if err != nil {
		t.Skip("Chrome is not installed")
	}
	profile := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	command := exec.CommandContext(ctx, chrome, "--headless=new", "--no-sandbox", "--disable-gpu", "--no-first-run", "--disable-background-networking", "--no-proxy-server", "--remote-debugging-port=0", "--remote-allow-origins=*", "--user-data-dir="+profile, target)
	if err := command.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	processDone := make(chan struct{})
	go func() { _ = command.Wait(); close(processDone) }()
	t.Cleanup(func() { cancel(); <-processDone })
	port := 0
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		body, err := os.ReadFile(filepath.Join(profile, "DevToolsActivePort"))
		if err == nil {
			port, _ = strconv.Atoi(strings.Split(string(body), "\n")[0])
			if port > 0 {
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if port == 0 {
		t.Fatal("Chrome did not publish its loopback debugging port")
	}
	client := &http.Client{Timeout: time.Second}
	var socket string
	for time.Now().Before(deadline) {
		response, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/json/list", port))
		if err == nil {
			var targets []chromeDebugTarget
			_ = json.NewDecoder(response.Body).Decode(&targets)
			response.Body.Close()
			for _, item := range targets {
				if item.Type == "page" && strings.HasPrefix(item.URL, target) {
					socket = item.WebSocketDebuggerURL
				}
			}
		}
		if socket != "" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if socket == "" {
		t.Fatal("Chrome page debugger unavailable")
	}
	connection, _, err := websocket.Dial(ctx, socket, nil)
	if err != nil {
		t.Fatal(err)
	}
	debug := &chromeDevTools{connection: connection}
	t.Cleanup(func() {
		shutdown, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		_ = debug.call(shutdown, "Browser.close", map[string]any{}, nil)
		connection.CloseNow()
		select {
		case <-processDone:
		case <-shutdown.Done():
			cancel()
			<-processDone
		}
	})
	return debug
}
func chromeDo(t *testing.T, client *chromeDevTools, expression string) any {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result, err := client.evaluate(ctx, expression)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

// This exercises the unmodified SPA and actual administrator command handler
// against durable signed facts. Browser certificate import is a separate check.
func TestWebChromeServicePolicyAndStaleDraft(t *testing.T) {
	if os.Getenv("LOOM_WEB_CHROME_TEST") != "1" {
		t.Skip("set LOOM_WEB_CHROME_TEST=1 for browser command acceptance")
	}
	root, config, genesis := authorityFixture(t)
	if _, err := InitializeAuthority(root, config, genesis); err != nil {
		t.Fatal(err)
	}
	runtime, err := OpenRuntime(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	server := &Server{Runtime: runtime, Config: config}
	httpServer := httptest.NewServer(server.AdminHandler())
	defer httpServer.Close()
	debug := openCommandChrome(t, httpServer.URL+"/services?new=1")
	waitChromeEvaluation(t, debug, `document.querySelector('#service-form')&&document.querySelector('#connection').textContent.includes('local writes available')`)
	chromeDo(t, debug, `(()=>{const f=document.querySelector('#service-form');f.elements.id.value='demo-web-service';f.elements.name.value='Demo Web';f.elements.matchers.value='dns_exact demo.example';f.requestSubmit();return true})()`)
	waitChromeEvaluation(t, debug, `document.querySelector('#notice').textContent.includes('Accepted locally')`)
	projection := runtime.Authority.Snapshot()
	if len(projection.NetworkIntent.Services) != 1 {
		t.Fatal("browser command did not persist Service")
	}
	// Navigate using the existing SPA, then create a Policy referencing its fact.
	chromeDo(t, debug, `(()=>{history.pushState({},'','/policies?new=1');dispatchEvent(new PopStateEvent('popstate'));const f=document.querySelector('#policy-form');f.elements.id.value='demo-web-policy';f.elements.name.value='Demo Policy';f.requestSubmit();return true})()`)
	waitChromeEvaluation(t, debug, `document.querySelectorAll('.service-item').length===1&&document.querySelector('.service-item').textContent.includes('Demo Policy')`)
	projection = runtime.Authority.Snapshot()
	if len(projection.NetworkIntent.Policies) != 1 || projection.NetworkIntent.Policies[0].ServiceID != "demo-web-service" {
		t.Fatal("browser Policy did not resolve Service")
	}
	chromeDo(t, debug, `(()=>{history.pushState({},'','/services?service=demo-web-service');dispatchEvent(new PopStateEvent('popstate'));window.demoDraft=document.querySelector('#service-form');window.demoName=demoDraft.elements.name;demoName.value='Unsaved demo';demoName.focus();demoName.setSelectionRange(2,5);return true})()`)
	current, _ := projection.CurrentTarget("service", "demo-web-service")
	edit := authorityService("demo-web-service", "demo-concurrent-edit")
	edit.Dependencies = current.MaterialIDs
	value := edit.Payload.(Service)
	value.Name = "Demo concurrent"
	edit.Payload = value
	submitAuthority(t, runtime, edit)
	time.Sleep(2200 * time.Millisecond)
	if chromeDo(t, debug, `demoDraft===document.querySelector('#service-form')&&demoName===document.activeElement&&demoName.value==='Unsaved demo'&&demoName.selectionStart===2`) != true {
		t.Fatal("live snapshot replaced focused draft")
	}
	chromeDo(t, debug, `(()=>{demoDraft.requestSubmit();return true})()`)
	waitChromeEvaluation(t, debug, `document.querySelector('#operation-status').textContent.includes('stale')`)
	if chromeDo(t, debug, `demoName.value==='Unsaved demo'`) != true {
		t.Fatal("stale command destroyed draft")
	}
	chromeDo(t, debug, `(()=>{window.demoRejectedRequest=JSON.parse(demoDraft.submission.body);window.demoFetch=fetch;window.demoEditedRequest=null;fetch=(url,options)=>{if(url==='/api/control/operations')demoEditedRequest=JSON.parse(options.body);return demoFetch(url,options)};demoName.value='Edited unsaved demo';demoDraft.requestSubmit();return true})()`)
	waitChromeEvaluation(t, debug, `document.querySelector('#operation-status').textContent.includes('stale')&&demoEditedRequest`)
	if chromeDo(t, debug, `demoEditedRequest.request_id!==demoRejectedRequest.request_id&&demoEditedRequest.target_id===demoRejectedRequest.target_id&&JSON.stringify(demoEditedRequest.dependencies)===JSON.stringify(demoRejectedRequest.dependencies)&&demoEditedRequest.payload.name==='Edited unsaved demo'&&demoName.value==='Edited unsaved demo'`) != true {
		t.Fatal("editing a rejected draft reused its request ID, changed the reviewed baseline, or lost the edit")
	}
	reopened, err := OpenAuthority(root)
	if err != nil {
		t.Fatal(err)
	}
	if reopened.Snapshot().NetworkIntent.Services[0].Name != "Demo concurrent" || len(reopened.Snapshot().NetworkIntent.Policies) != 1 {
		t.Fatal("browser or stale retry changed durable results")
	}
}

func TestWebChromeDevicePolicyRevocationPreservesIdentity(t *testing.T) {
	if os.Getenv("LOOM_WEB_CHROME_TEST") != "1" {
		t.Skip("set LOOM_WEB_CHROME_TEST=1 for browser command acceptance")
	}
	server, invite, _, claim, _, _ := enrollmentAuthorityFixture(t, func(invite *Invite) { invite.DNSServers = []string{"192.0.2.53"} })
	response := enrollmentHTTP(t, server, "/enrollment/claim", claim, enrollmentTunnel(invite))
	if response.Code != http.StatusOK {
		t.Fatal(response.Body.String())
	}
	original := server.Runtime.Authority.Snapshot().DeviceAuthorizations[0]
	httpServer := httptest.NewServer(server.AdminHandler())
	defer httpServer.Close()
	debug := openCommandChrome(t, httpServer.URL+"/devices/"+invite.DeviceID)
	waitChromeEvaluation(t, debug, `document.querySelector('#device-policy-form')`)
	chromeDo(t, debug, `(()=>{window.demoDeviceDraft=document.querySelector('#device-policy-form');demoDeviceDraft.elements.name.value='Unsaved device draft';document.querySelector('[data-invite-refresh]').click();return true})()`)
	waitChromeEvaluation(t, debug, `document.querySelector('#device-enrollment [data-enrollment-state]')?.textContent==='completed'`)
	if chromeDo(t, debug, `document.querySelector('#device-policy-form')===demoDeviceDraft&&demoDeviceDraft.elements.name.value==='Unsaved device draft'`) != true {
		t.Fatal("transaction refresh replaced the device authorization draft")
	}
	chromeDo(t, debug, `(()=>{const f=document.querySelector('#device-policy-form');for(const input of f.querySelectorAll('[name=policy_id]'))input.checked=false;f.requestSubmit();return true})()`)
	waitChromeEvaluation(t, debug, `document.querySelector('#notice').textContent.includes('Accepted locally')`)
	projection := server.Runtime.Authority.Snapshot()
	if len(projection.DeviceAuthorizations) != 1 || len(projection.DeviceAuthorizations[0].PolicyIDs) != 0 || projection.DeviceAuthorizations[0].RuntimeKey != original.RuntimeKey || projection.DeviceAuthorizations[0].DevicePublicKey != original.DevicePublicKey {
		t.Fatal("browser public operation did not revoke policy while preserving identity")
	}
	view, err := server.deviceEnvelope(invite.DeviceID)
	if err != nil || len(view.View.Routes) != 0 || view.View.RuntimeProfile == nil {
		t.Fatal("browser revoke did not produce deny-only runtime", err)
	}
	if len(view.View.DNSServers) != 1 || view.View.DNSServers[0] != "192.0.2.53" {
		t.Fatal("editing business authorization discarded the existing DNS configuration")
	}
	reopened, err := OpenAuthority(server.Runtime.Authority.root)
	if err != nil || len(reopened.Snapshot().DeviceAuthorizations[0].PolicyIDs) != 0 {
		t.Fatal("browser revoked policy returned after reopen", err)
	}
	waitChromeEvaluation(t, debug, `document.querySelector('#device-enrollment [data-enrollment-state]')?.textContent==='completed'`)
	if chromeDo(t, debug, `document.body.innerText.includes('runtime_key')||!!document.querySelector('#invite-uri')`) == true {
		t.Fatal("completed Invite leaked keys or issued a new capability")
	}
}

func TestWebChromeLocalEgressAuthorizationAndRevocation(t *testing.T) {
	if os.Getenv("LOOM_WEB_CHROME_TEST") != "1" {
		t.Skip("set LOOM_WEB_CHROME_TEST=1 for browser command acceptance")
	}
	server, invite, _, claim, _, _ := enrollmentAuthorityFixture(t)
	if response := enrollmentHTTP(t, server, "/enrollment/claim", claim, enrollmentTunnel(invite)); response.Code != http.StatusOK {
		t.Fatal(response.Body.String())
	}
	original := server.Runtime.Authority.Snapshot().DeviceAuthorizations[0]
	httpServer := httptest.NewServer(server.AdminHandler())
	defer httpServer.Close()
	debug := openCommandChrome(t, httpServer.URL+"/devices/"+invite.DeviceID)
	waitChromeEvaluation(t, debug, `document.querySelector('#device-policy-form')`)
	chromeDo(t, debug, `(()=>{window.demoHybridForm=document.querySelector('#device-policy-form');demoHybridForm.querySelector('[name=responsibility][value=internet_egress]').checked=true;demoHybridForm.requestSubmit();return true})()`)
	waitChromeEvaluation(t, debug, `document.querySelector('#device-policy-form')!==demoHybridForm&&document.querySelector('#device-policy-form [name=responsibility][value=internet_egress]')?.checked`)
	policyPath, _ := json.Marshal("/policies?policy=" + original.PolicyIDs[0])
	deviceID, _ := json.Marshal(invite.DeviceID)
	chromeDo(t, debug, `(()=>{history.pushState({},'',`+string(policyPath)+`);dispatchEvent(new PopStateEvent('popstate'));window.demoLocalForm=document.querySelector('#policy-form');demoLocalForm.elements.allow_direct.checked=false;demoLocalForm.elements.entry_scope_mode.value='none';demoLocalForm.elements.exit_scope_mode.value='only';demoLocalForm.elements.exit_scope_ids.value=`+string(deviceID)+`;demoLocalForm.elements.local_egress_devices.value=`+string(deviceID)+`;demoLocalForm.requestSubmit();return true})()`)
	waitChromeEvaluation(t, debug, `document.querySelector('#policy-form')!==demoLocalForm&&!document.querySelector('#policy-form').elements.allow_direct.checked`)
	view, err := server.deviceEnvelope(invite.DeviceID)
	if err != nil || len(view.View.Routes) != 1 || view.View.Routes[0].FinalExit != invite.DeviceID || len(view.View.Routes[0].NodeChain) != 0 {
		t.Fatal("formal local-only policy did not produce the local exit", err)
	}
	devicePath, _ := json.Marshal("/devices/" + invite.DeviceID)
	chromeDo(t, debug, `(()=>{history.pushState({},'',`+string(devicePath)+`);dispatchEvent(new PopStateEvent('popstate'));return true})()`)
	waitChromeEvaluation(t, debug, `document.querySelector('#app').innerText.includes('local egress: '+`+string(deviceID)+`)`)
	if chromeDo(t, debug, `document.querySelector('#app').innerText.includes('target (Direct)')`) == true {
		t.Fatal("browser mislabelled local egress as ordinary Direct")
	}
	chromeDo(t, debug, `(()=>{window.demoRevokeForm=document.querySelector('#device-policy-form');demoRevokeForm.querySelector('[name=responsibility][value=internet_egress]').checked=false;demoRevokeForm.requestSubmit();return true})()`)
	waitChromeEvaluation(t, debug, `document.querySelector('#device-policy-form')!==demoRevokeForm&&!document.querySelector('#device-policy-form [name=responsibility][value=internet_egress]')?.checked&&!document.querySelector('#app').innerText.includes('local egress:')`)
	reopened, err := OpenAuthority(server.Runtime.Authority.root)
	if err != nil {
		t.Fatal(err)
	}
	denied, err := ProjectDeviceView(reopened.Snapshot(), invite.DeviceID)
	if err != nil || len(denied.Routes) != 0 || len(denied.PolicyIDs) != 1 || denied.DevicePublicKey != original.DevicePublicKey {
		t.Fatal("removing the exit role failed to persist revocation or damaged identity/assignment", err)
	}
}

func TestWebChromeInvitationDeviceDetailAndSignedReports(t *testing.T) {
	if os.Getenv("LOOM_WEB_CHROME_TEST") != "1" {
		t.Skip("set LOOM_WEB_CHROME_TEST=1 for browser command acceptance")
	}
	fixture := newEndpointFixture(t)
	server := fixture.server
	releaseSource, _ := expectedReleaseFixture()
	releaseSource.original.Packages[0].Components[0].Version = "demo-agent"
	releaseSource.original.Packages[0].Components[0].ArtifactDigest = "sha256:" + strings.Repeat("a", 64)
	server.Releases = releaseSource
	var err error
	server.Runtime.Reports, err = OpenObservationStore(server.Runtime.Authority.root)
	if err != nil {
		t.Fatal(err)
	}
	service := submitAuthority(t, server.Runtime, authorityService("demo-service", "demo-browser-service"))
	anyScope := PolicyScope{Mode: "any", NodeIDs: []string{}}
	submitAuthority(t, server.Runtime, Operation{Schema: 3, RequestID: "demo-browser-policy", Operation: "policy.put", TargetKind: "policy", TargetID: "demo-policy", Dependencies: []string{service.MaterialID}, Payload: NetworkPolicy{ID: "demo-policy", Name: "Demo browser policy", ServiceID: "demo-service", Action: "allow", EntryScope: anyScope, RelayScope: anyScope, ExitScope: new(anyScope), AllowDirect: new(true), LocalEgressDevices: new([]string{})}})
	for _, target := range []BusinessProbeTarget{{ID: "demo-no-duration", URL: "https://demo-service.example/no-duration"}, {ID: "demo-zero-duration", URL: "https://demo-service.example/zero-duration"}} {
		submitAuthority(t, server.Runtime, Operation{Schema: 3, RequestID: "demo-create-" + target.ID, Operation: "probe_target.put", TargetKind: "probe_target", TargetID: target.ID, Dependencies: []string{}, Payload: target})
	}
	// Let authenticated enrollment options arrive first. The normal form must
	// wait for its snapshot rather than preserve a draft missing those Policies.
	allowSnapshot := make(chan struct{})
	var releaseOnce sync.Once
	releaseSnapshot := func() { releaseOnce.Do(func() { close(allowSnapshot) }) }
	var delayNextSnapshot atomic.Bool
	snapshotCaptured, delayedSnapshot := make(chan struct{}), make(chan struct{})
	var releaseDelayedOnce sync.Once
	releaseDelayed := func() { releaseDelayedOnce.Do(func() { close(delayedSnapshot) }) }
	adminHandler := server.AdminHandler()
	var inviteRequestsMu sync.Mutex
	var inviteRequests [][]byte
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/control/operations" && r.Method == http.MethodPost {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "demo read failed", http.StatusBadRequest)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
			inviteRequestsMu.Lock()
			inviteRequests = append(inviteRequests, append([]byte(nil), body...))
			first := len(inviteRequests) == 1
			inviteRequestsMu.Unlock()
			if first {
				response := httptest.NewRecorder()
				adminHandler.ServeHTTP(response, r)
				if response.Code != http.StatusOK {
					t.Errorf("first invitation was not accepted: %d", response.Code)
				}
				// The authority has durably accepted the operation; its response
				// is lost before the browser can learn the result.
				http.Error(w, "Demo response interrupted", http.StatusBadGateway)
				return
			}
		}
		if r.URL.Path == "/api/control/ui/snapshot" {
			<-allowSnapshot
			if delayNextSnapshot.CompareAndSwap(true, false) {
				response := httptest.NewRecorder()
				adminHandler.ServeHTTP(response, r)
				close(snapshotCaptured)
				<-delayedSnapshot
				for key, values := range response.Header() {
					w.Header()[key] = values
				}
				w.WriteHeader(response.Code)
				_, _ = w.Write(response.Body.Bytes())
				return
			}
		}
		adminHandler.ServeHTTP(w, r)
	}))
	defer httpServer.Close()
	defer releaseSnapshot()
	defer releaseDelayed()
	debug := openCommandChrome(t, httpServer.URL+"/devices?new=1")
	waitChromeEvaluation(t, debug, `document.querySelector('#app').textContent.includes('Authenticated enrollment options are not ready.')`)
	if chromeDo(t, debug, `document.querySelector('#enrollment-form')===null`) != true {
		t.Fatal("form was created before its authenticated policy snapshot arrived")
	}
	releaseSnapshot()
	waitChromeEvaluation(t, debug, `document.querySelector('#enrollment-form [name=endpoint]')?.options.length>0&&document.querySelector('#connection').textContent.includes('local writes available')`)
	transactionID, ok := chromeDo(t, debug, `document.querySelector('#enrollment-form').dataset.transactionId`).(string)
	if !ok {
		t.Fatal("browser form has no stable transaction ID")
	}
	chromeDo(t, debug, `(()=>{const f=document.querySelector('#enrollment-form');f.elements.device_id.value='demo-browser-device';f.elements.name.value='Demo browser device';f.elements.dns_servers.value='192.0.2.53';f.querySelector('[name=policy_id][value=demo-policy]').checked=true;f.requestSubmit();return true})()`)
	waitChromeEvaluation(t, debug, `document.querySelector('#enrollment-status').textContent==='Demo response interrupted'`)
	beforeRetry := server.Runtime.Authority.Frontier()
	chromeDo(t, debug, `(()=>{window.demoOriginalNow=Date.now;Date.now=()=>demoOriginalNow()+5000;document.querySelector('#enrollment-form').requestSubmit();return true})()`)
	waitChromeEvaluation(t, debug, `location.pathname.startsWith('/devices/invites/')&&document.querySelector('#device-enrollment [data-enrollment-state]')?.textContent==='open'&&document.querySelector('#device-enrollment img.qr')?.naturalWidth>0`)
	chromeDo(t, debug, `(()=>{Date.now=demoOriginalNow;return true})()`)
	inviteRequestsMu.Lock()
	sameRequest := len(inviteRequests) == 2 && bytes.Equal(inviteRequests[0], inviteRequests[1])
	inviteRequestsMu.Unlock()
	if !sameRequest || !slices.Equal(beforeRetry, server.Runtime.Authority.Frontier()) {
		t.Fatal("unchanged invitation retry altered the request or signed another fact")
	}
	if chromeDo(t, debug, `location.pathname`) != "/devices/invites/"+transactionID {
		t.Fatal("initial delivery did not retain the issued transaction route")
	}
	encoded, ok := chromeDo(t, debug, `document.querySelector('#invite-uri').value`).(string)
	if !ok {
		t.Fatal("delivery view did not show its signed invitation")
	}
	bootstrap, err := DecodeInvite(encoded)
	if err != nil || bootstrap.Material.TargetID != transactionID || bootstrap.Material.Payload.(Invite).DeviceID != "demo-browser-device" {
		t.Fatal("device detail invitation does not match its persisted transaction", err)
	}
	if dns := bootstrap.Material.Payload.(Invite).DNSServers; len(dns) != 1 || dns[0] != "192.0.2.53" {
		t.Fatal("normal invitation form lost the initial DNS configuration")
	}
	if chromeDo(t, debug, `(async()=>{const a=document.querySelector('#device-enrollment a[download]');return (await (await fetch(a.href)).text()).trim()===document.querySelector('#invite-uri').value})()`) != true {
		t.Fatal("download and device detail produced different invitations")
	}
	chromeDo(t, debug, `(()=>{document.querySelector('a[data-nav][href="/devices/demo-browser-device"]').click();return true})()`)
	waitChromeEvaluation(t, debug, `location.pathname==='/devices/demo-browser-device'&&document.querySelector('#invite-uri')&&document.querySelector('#device-enrollment img.qr')?.naturalWidth>0`)
	if chromeDo(t, debug, `document.querySelector('#invite-uri').value`) != encoded {
		t.Fatal("continuing into device detail changed the delivered transaction")
	}
	before := server.Runtime.Authority.Frontier()
	chromeDo(t, debug, `(()=>{document.querySelector('[data-invite-refresh]').click();return true})()`)
	waitChromeEvaluation(t, debug, `document.querySelector('#invite-uri')&&document.querySelector('#device-enrollment img.qr')?.naturalWidth>0`)
	if chromeDo(t, debug, `document.querySelector('#invite-uri').value`) != encoded {
		t.Fatal("transaction refresh generated another invitation")
	}
	previousDocument, _ := json.Marshal(chromeDo(t, debug, `String(performance.timeOrigin)`))
	chromeDo(t, debug, `(()=>{location.reload();return true})()`)
	// The old document can satisfy a DOM-only wait before reload begins.
	// Wait for the new document, and read its invitation in the same evaluation.
	reloadedInvite := waitChromeEvaluation(t, debug, `(()=>{const uri=document.querySelector('#invite-uri');return String(performance.timeOrigin)!==`+string(previousDocument)+`&&document.readyState==='complete'&&uri&&document.querySelector('#device-enrollment img.qr')?.naturalWidth>0?uri.value:false})()`)
	if reloadedInvite != encoded {
		t.Fatal("reopening device detail changed the pending transaction")
	}
	reopened, err := OpenAuthority(server.Runtime.Authority.root)
	if err != nil || len(reopened.Snapshot().DeviceAuthorizations) != 0 || fmt.Sprint(reopened.Frontier()) != fmt.Sprint(before) {
		t.Fatal("delivery readback changed authority or manufactured a joined device", err)
	}
	for _, device := range projectWebDevices(reopened.Snapshot()) {
		if device.ID == "demo-browser-device" && (device.Authorized || len(device.Roles) != 1 || device.Roles[0] != "access") {
			t.Fatal("pending device lost its requested responsibility or gained authorization")
		}
	}
	// Hold the post-command HTTP snapshot while the live stream accepts the
	// actual claim below. Its old open transaction must not overwrite completed.
	delayNextSnapshot.Store(true)
	chromeDo(t, debug, `(()=>{history.pushState({},'','/services?new=1');dispatchEvent(new PopStateEvent('popstate'));const f=document.querySelector('#service-form');f.elements.id.value='demo-unrelated-service';f.elements.name.value='Demo unrelated';f.elements.matchers.value='dns_exact unrelated.example';f.requestSubmit();return true})()`)
	select {
	case <-snapshotCaptured:
	case <-time.After(3 * time.Second):
		t.Fatal("browser command did not request its post-command snapshot")
	}
	key := testKey(t)
	inviteID, _ := MaterialID(bootstrap.Material)
	claim, err := SignEnrollmentClaim(EnrollmentClaimRequest{Schema: 3, NetworkID: server.Config.NetworkID, GenesisDigest: server.Config.GenesisID, TransactionID: transactionID, InviteMaterialID: inviteID, RequestID: "demo-browser-claim", DevicePublicKey: base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey)), Platform: "linux"}, key)
	if err != nil {
		t.Fatal(err)
	}
	status, body := endpointPost(t, fixture.dialBootstrap(t, bootstrap), "/enrollment/claim", claim)
	if status != http.StatusOK {
		t.Fatalf("private claim failed: %s", body)
	}
	chromeDo(t, debug, `(()=>{history.pushState({},'','/devices/demo-browser-device');dispatchEvent(new PopStateEvent('popstate'));return true})()`)
	waitChromeEvaluation(t, debug, `location.pathname==='/devices/demo-browser-device'&&document.querySelector('#device-enrollment [data-enrollment-state]')?.textContent==='completed'&&!document.querySelector('#invite-uri')&&!document.querySelector('#device-enrollment img.qr')`)
	chromeDo(t, debug, `(()=>{window.demoSnapshotRegressed=false;window.demoSnapshotStart={path:location.pathname,policyForm:!!document.querySelector('#device-policy-form')};window.demoSnapshotObserver=new MutationObserver(()=>{if(!document.querySelector('#device-policy-form')||document.querySelector('#invite-uri'))demoSnapshotRegressed=true});demoSnapshotObserver.observe(document.querySelector('#app'),{childList:true,subtree:true});return true})()`)
	releaseDelayed()
	waitChromeEvaluation(t, debug, `!document.querySelector('#notice').hidden&&document.querySelector('#notice').textContent.includes('Accepted locally')`)
	if chromeDo(t, debug, `(()=>{demoSnapshotObserver.disconnect();return !demoSnapshotRegressed&&!!document.querySelector('#device-policy-form')&&!document.querySelector('#invite-uri')})()`) != true {
		t.Fatal("late HTTP snapshot overwrote the accepted live completion or revived delivery", chromeDo(t, debug, `({start:demoSnapshotStart,path:location.pathname,policyForm:!!document.querySelector('#device-policy-form'),invite:!!document.querySelector('#invite-uri'),regressed:demoSnapshotRegressed})`))
	}
	if chromeDo(t, debug, `!!document.querySelector('#device-enrollment a[download]')||document.body.innerText.includes('runtime_key')`) == true {
		t.Fatal("completed device detail still delivered a capability or exposed private material")
	}
	invitePath, _ := json.Marshal("/devices/invites/" + transactionID)
	chromeDo(t, debug, `(()=>{history.pushState({},'',`+string(invitePath)+`);dispatchEvent(new PopStateEvent('popstate'));return true})()`)
	waitChromeEvaluation(t, debug, `document.querySelector('#device-enrollment [data-enrollment-state]')?.textContent==='completed'&&!document.querySelector('#invite-uri')&&!document.querySelector('#device-enrollment img.qr')`)
	if chromeDo(t, debug, `!!document.querySelector('a[data-nav][href="/devices/demo-browser-device"]')&&!document.querySelector('#device-enrollment a[download]')`) != true {
		t.Fatal("completed delivery view did not lead to the same device without a capability")
	}
	chromeDo(t, debug, `(()=>{document.querySelector('a[data-nav][href="/devices/demo-browser-device"]').click();return true})()`)
	view, err := server.deviceEnvelope("demo-browser-device")
	if err != nil || len(view.View.Routes) != 1 {
		t.Fatal("joined device has no expected service route", err)
	}
	route := view.View.Routes[0]
	zero := int64(0)
	report := DeviceReport{Schema: 3, NetworkID: server.Config.NetworkID, DeviceID: "demo-browser-device", ReportSequence: 1, ViewDigest: view.ViewDigest, NetworkGeneration: "demo-network-generation", ReportedAt: server.now().UnixMilli(), Selections: []ReportSelection{{ServiceID: route.ServiceID, CandidateID: route.ID}}, Observations: []Observation{}, Runtime: RuntimeReadback{State: "running", AppliedViewDigest: view.ViewDigest}, Components: []ComponentReadback{}}
	report.Components = []ComponentReadback{{ComponentID: "agent", Platform: "linux-amd64", Version: "demo-agent", ArtifactDigest: "sha256:" + strings.Repeat("a", 64)}, {ComponentID: "sing-box", Platform: "linux-amd64", Version: "demo-dataplane", ArtifactDigest: "sha256:" + strings.Repeat("b", 64)}}
	// These signed samples test the UI mapping, not a live request to the example targets.
	for index, target := range []string{"https://demo-service.example/no-duration", "https://demo-service.example/zero-duration"} {
		observation := Observation{Level: "service", ServiceID: route.ServiceID, CandidateID: route.ID, Target: target, Action: "https_request", SpecDigest: route.SpecDigest, NetworkGeneration: report.NetworkGeneration, Result: "unknown", ObservedAt: report.ReportedAt, ValidUntil: report.ReportedAt + 60000}
		if index == 1 {
			observation.Result, observation.DurationMS = "available", &zero
		}
		report.Observations = append(report.Observations, observation)
	}
	sendReport := func(value DeviceReport) {
		t.Helper()
		value, err := SignDeviceReport(value, key)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		connection, err := DialEndpoint(ctx, fixture.endpoint, TunnelHello{Schema: 3, Mode: "device", EndpointID: fixture.endpoint.ID, Generation: fixture.endpoint.Generation, DeviceID: value.DeviceID}, key)
		if err != nil {
			t.Fatal(err)
		}
		defer connection.Close()
		status, body := endpointPost(t, connection, "/device/report", value)
		if status != http.StatusOK {
			t.Fatalf("private signed report failed: %s", body)
		}
	}
	sendReport(report)
	waitChromeEvaluation(t, debug, `document.querySelector('#device-runtime [data-runtime-state]')?.textContent==='running'&&document.querySelector('#device-measurements')?.innerText.includes('https://demo-service.example/zero-duration')`)
	if chromeDo(t, debug, `(()=>{const rows=[...document.querySelectorAll('#device-measurements tbody tr')];return rows[0].cells[1].textContent==='https://demo-service.example/no-duration'&&rows[0].cells[3].firstChild.textContent==='—'&&rows[0].cells[3].querySelector('small').textContent==='Complete HTTPS request'&&rows[1].cells[1].textContent==='https://demo-service.example/zero-duration'&&rows[1].cells[3].firstChild.textContent==='0 ms'&&rows[1].cells[3].querySelector('small').textContent==='Complete HTTPS request'})()`) != true {
		t.Fatal("measurements confused target/candidate or zero/missing duration")
	}
	if chromeDo(t, debug, `(()=>{const fields=[...document.querySelectorAll('#device-runtime dt')].map(v=>v.textContent);return fields.join('|')==='State|Applied view|Error code'&&!document.querySelector('.device-status').textContent.includes('overlay')})()`) != true {
		t.Fatal("current runtime report was interpreted with legacy execution fields")
	}
	if chromeDo(t, debug, `(()=>{const rows=[...document.querySelectorAll('#device-runtime tr[data-component]')];return rows.length===2&&rows[0].dataset.component==='agent'&&rows[0].dataset.platform==='linux-amd64'&&rows[0].innerText.includes('demo-agent')&&rows[0].innerText.includes('sha256:'+'a'.repeat(64))&&rows.every(v=>v.innerText.includes('No expectation set'))})()`) != true {
		t.Fatal("component coordinates without expectations were hidden or treated as applied")
	}
	if chromeDo(t, debug, `(async()=>{const {componentComparisons}=await import('/assets/model.js');const value={component_id:'sing-box',platform:'linux-amd64',version:'demo-version',artifact_digest:'sha256:'+'c'.repeat(64)},device={expected_components:[value]};const mismatch=componentComparisons(device,{components:[{...value,platform:'linux-arm64'}]});const missing=componentComparisons(device,{components:[{...value,artifact_digest:''}]});return mismatch.length===2&&mismatch[0].result==='missing'&&mismatch[1].result==='unconfigured'&&missing[0].result==='unknown'})()`) != true {
		t.Fatal("component comparison ignored platform or accepted a missing digest")
	}
	chromeDo(t, debug, `(()=>{history.pushState({},'','/deployments');dispatchEvent(new PopStateEvent('popstate'));document.querySelector('[data-version-device="demo-browser-device"] details').open=true;return true})()`)
	if chromeDo(t, debug, `document.querySelector('h1').textContent==='Device versions'&&document.querySelector('[data-version-device="demo-browser-device"]').innerText.includes('demo-dataplane')&&!document.querySelector('.release-workflow')&&!document.querySelector('.publisher-card')`) != true {
		t.Fatal("device versions lost signed components or restored publisher progress")
	}
	// Reopen the ordinary report history rather than storing component state.
	reopenedReports, err := OpenObservationStore(server.Runtime.Authority.root)
	if err != nil || len(reopenedReports.Verified(server.Runtime.Authority.Snapshot())) != 1 || len(reopenedReports.Verified(server.Runtime.Authority.Snapshot())[0].Components) != 2 {
		t.Fatal("signed component reports did not survive observation store reopen", err)
	}
	assertChromeLivePaths(t, debug)
	report = assertChromeEvidenceExpiry(t, debug, report, sendReport)
	for _, sample := range []struct {
		value *ReportPreference
		label string
	}{{&ReportPreference{Mode: "auto"}, "Mode: Auto"}, {&ReportPreference{Mode: "direct"}, "Mode: Direct"}, {&ReportPreference{Mode: "fixed_exit", Exit: "demo-unavailable-exit"}, "Mode: Fixed exit · demo-unavailable-exit"}, {nil, "Mode: not reported"}} {
		report.ReportSequence++
		report.Preference = sample.value
		sendReport(report)
		chromeDo(t, debug, `(()=>{history.pushState({},'','/routing?service=demo-service&device=demo-browser-device');dispatchEvent(new PopStateEvent('popstate'));return true})()`)
		label, _ := json.Marshal(sample.label)
		waitChromeEvaluation(t, debug, `document.querySelector('[data-routing-preference]')?.textContent.includes(`+string(label)+`)`)
		if chromeDo(t, debug, `document.querySelector('.paths-current').textContent.includes('Current selection confirmed')&&[...document.querySelectorAll('tr[data-candidate]')].some(row=>row.cells[0].textContent.includes('Direct')&&row.cells[2].textContent.includes('Current selection'))`) != true {
			t.Fatal("reported preference rewrote the actual path or created health")
		}
	}
	chromeDo(t, debug, `(()=>{history.pushState({},'','/devices/demo-browser-device');dispatchEvent(new PopStateEvent('popstate'));return true})()`)
	chromeDo(t, debug, `(()=>{const f=document.querySelector('#expected-component-form');f.requestSubmit();return true})()`)
	waitChromeEvaluation(t, debug, `document.querySelector('#notice').textContent.includes('Accepted locally')&&document.querySelector('#expected-component-form [data-delete-kind="expected_component"]')`)
	if len(server.Runtime.Authority.Snapshot().NetworkIntent.ExpectedComponents) != 1 {
		t.Fatal("browser expected-component operation did not persist")
	}
	view, err = server.deviceEnvelope("demo-browser-device")
	if err != nil || len(view.View.ExpectedComponents) != 1 {
		t.Fatal("browser expectation did not enter the signed device view", err)
	}
	assertChromeWaitingForView(t, debug)
	report.ReportSequence++
	report.ViewDigest, report.Runtime.AppliedViewDigest = view.ViewDigest, view.ViewDigest
	sendReport(report)
	waitChromeEvaluation(t, debug, `document.querySelector('#device-runtime [data-component="agent"]')?.innerText.includes('Reported coordinates match')`)
	if chromeDo(t, debug, `document.querySelector('#device-runtime [data-component="sing-box"]').innerText.includes('No expectation set')`) != true {
		t.Fatal("one expected component manufactured another expectation")
	}
	chromeDo(t, debug, `(()=>{window.confirm=()=>true;document.querySelector('#expected-component-form [data-delete-kind="expected_component"]').click();return true})()`)
	waitChromeEvaluation(t, debug, `!document.querySelector('#expected-component-form [data-delete-kind="expected_component"]')&&document.querySelector('#notice').textContent.includes('Deletion accepted locally')`)
	if len(server.Runtime.Authority.Snapshot().NetworkIntent.ExpectedComponents) != 0 {
		t.Fatal("browser clear did not withdraw the exact expectation")
	}
	view, err = server.deviceEnvelope("demo-browser-device")
	if err != nil {
		t.Fatal(err)
	}
	report.ViewDigest = view.ViewDigest
	report.Components = report.Components[:1]
	report.ReportSequence++
	report.Runtime = RuntimeReadback{State: "error", ErrorCode: "demo-execution-failed"}
	report.Selections, report.Observations = []ReportSelection{}, []Observation{}
	sendReport(report)
	waitChromeEvaluation(t, debug, `document.querySelector('#device-runtime [data-runtime-state]')?.textContent==='error'&&document.querySelector('#device-runtime').textContent.includes('demo-execution-failed')`)
	if chromeDo(t, debug, `document.querySelector('#device-runtime dd.mono').textContent==='—'&&!document.querySelector('.device-status').textContent.includes('overlay')`) != true {
		t.Fatal("failed execution manufactured an applied view or legacy overlay")
	}
	chromeDo(t, debug, `(()=>{history.pushState({},'','/devices');dispatchEvent(new PopStateEvent('popstate'));return true})()`)
	if chromeDo(t, debug, `[...document.querySelector('select[name=role]').options].map(v=>v.value).join('|')`) != "|access|control|forward|internet_egress" {
		t.Fatal("node filter lost one of the four model responsibilities")
	}
	assertChromeRuntimeHistory(t, debug)
}
