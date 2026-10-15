package control

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"sync"
	"testing"
	"time"
)

func TestWebChromeProbeTargetsCRUDReadbackRestartAndAuthorization(t *testing.T) {
	if os.Getenv("LOOM_WEB_CHROME_TEST") != "1" {
		t.Skip("set LOOM_WEB_CHROME_TEST=1 for browser command acceptance")
	}
	server, invite, _, claim, _, _ := enrollmentAuthorityFixture(t)
	if response := enrollmentHTTP(t, server, "/enrollment/claim", claim, enrollmentTunnel(invite)); response.Code != http.StatusOK {
		t.Fatal("first join failed")
	}
	original, err := ProjectDeviceView(server.Runtime.Authority.Snapshot(), invite.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	host := httptest.NewServer(server.AdminHandler())
	defer host.Close()
	debug := openCommandChrome(t, host.URL+"/services")
	waitChromeEvaluation(t, debug, `document.querySelector('nav[aria-label="Access configuration"] a[href="/services?tab=probes"]')&&document.querySelector('#connection').title.includes('local writes available')`)
	if chromeDo(t, debug, `document.querySelectorAll('nav[aria-label="Access configuration"] a').length===4`) != true {
		t.Fatal("shared access navigation lost one of the four views")
	}
	chromeDo(t, debug, `document.querySelector('nav[aria-label="Access configuration"] a[href="/services?tab=probes"]').click();true`)
	waitChromeEvaluation(t, debug, `document.querySelector('.probe-pool')&&new URLSearchParams(location.search).get('tab')==='probes'`)
	chromeDo(t, debug, `document.querySelector('a[href="/services?tab=probes&new=1"]').click();true`)
	waitChromeEvaluation(t, debug, `document.querySelector('#probe-target-form')?.dataset.creating==='true'`)
	chromeDo(t, debug, `(()=>{const f=document.querySelector('#probe-target-form');f.elements.id.value='demo-web-probe';f.elements.url.value='https://demo-unused.example/health';f.requestSubmit();return true})()`)
	waitChromeEvaluation(t, debug, `document.querySelector('#notice').textContent.includes('Accepted locally')&&new URLSearchParams(location.search).get('target')==='demo-web-probe'&&document.querySelector('[data-probe-target="demo-web-probe"]')?.textContent.includes('No matching service')`)
	if got := server.Runtime.Authority.Snapshot().NetworkIntent.BusinessProbeTargets; !reflect.DeepEqual(got, []BusinessProbeTarget{{ID: "demo-web-probe", URL: "https://demo-unused.example/health"}}) {
		t.Fatal("browser did not persist the unused target in the shared pool")
	}
	view, err := ProjectDeviceView(server.Runtime.Authority.Snapshot(), invite.DeviceID)
	if err != nil || !reflect.DeepEqual(view.BusinessProbeTargets, original.BusinessProbeTargets) || !reflect.DeepEqual(view.PolicyIDs, original.PolicyIDs) || len(view.Routes) != len(original.Routes) {
		t.Fatal("unmatched shared target changed device permission", err)
	}
	root := server.Runtime.Authority.root
	server.Runtime.Close()
	server.Runtime, err = OpenRuntime(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { server.Runtime.Close() }()
	chromeDo(t, debug, `location.reload();true`)
	waitChromeEvaluation(t, debug, `document.querySelector('#probe-target-form')?.elements.url.value==='https://demo-unused.example/health'`)
	if chromeDo(t, debug, `(async()=>{const {probeTargetsHTML}=await import('/assets/probe-targets.js'),snapshot=await(await fetch('/api/control/ui/snapshot')).json(),doc=new DOMParser().parseFromString(probeTargetsHTML(snapshot,new URLSearchParams({target:'demo-web-probe'})),'text/html');return !doc.querySelector('#probe-target-form,[data-delete-kind="probe_target"]')&&doc.body.textContent.includes('Read only')&&doc.querySelector('[data-probe-target="demo-web-probe"]')?.textContent.includes('Inspect')})()`) != true {
		t.Fatal("read-only probe projection exposed a write action or hid the saved target")
	}
	chromeDo(t, debug, `(()=>{document.querySelector('#notice').textContent='';const f=document.querySelector('#probe-target-form');f.elements.url.value='https://demo-service.example/health';f.requestSubmit();return true})()`)
	waitChromeEvaluation(t, debug, `document.querySelector('#notice').textContent.includes('Accepted locally')&&document.querySelector('#probe-target-form')?.elements.url.value==='https://demo-service.example/health'&&document.querySelector('[data-probe-target="demo-web-probe"] a[href="/services?service=demo-service"]')`)
	view, err = ProjectDeviceView(server.Runtime.Authority.Snapshot(), invite.DeviceID)
	if err != nil || !reflect.DeepEqual(view.BusinessProbeTargets, []ServiceProbeTargets{{ServiceID: "demo-service", Targets: []string{"https://demo-service.example/health"}}}) || !reflect.DeepEqual(view.PolicyIDs, original.PolicyIDs) || !reflect.DeepEqual(view.Services, original.Services) || len(view.Routes) != len(original.Routes) {
		t.Fatal("matching target failed to reach its existing device scope or widened authorization", err)
	}
	frontier := server.Runtime.Authority.Frontier()
	chromeDo(t, debug, `window.confirm=()=>false;document.querySelector('[data-delete-kind="probe_target"][data-delete-id="demo-web-probe"]').click();true`)
	if !reflect.DeepEqual(frontier, server.Runtime.Authority.Frontier()) || len(server.Runtime.Authority.Snapshot().NetworkIntent.BusinessProbeTargets) != 1 {
		t.Fatal("cancelling deletion changed the accepted target")
	}
	chromeDo(t, debug, `window.confirm=()=>true;document.querySelector('[data-delete-kind="probe_target"][data-delete-id="demo-web-probe"]').click();true`)
	waitChromeEvaluation(t, debug, `document.querySelector('#notice').textContent.includes('Deletion accepted locally')&&!document.querySelector('[data-probe-target="demo-web-probe"]')`)
	view, err = ProjectDeviceView(server.Runtime.Authority.Snapshot(), invite.DeviceID)
	if err != nil || len(server.Runtime.Authority.Snapshot().NetworkIntent.BusinessProbeTargets) != 0 || !reflect.DeepEqual(view.BusinessProbeTargets, original.BusinessProbeTargets) || !reflect.DeepEqual(view.PolicyIDs, original.PolicyIDs) {
		t.Fatal("deletion did not withdraw the target while retaining existing device authorization", err)
	}
}

func TestWebChromeProbeTargetsRetryAndNavigationAfterDelayedAcceptance(t *testing.T) {
	if os.Getenv("LOOM_WEB_CHROME_TEST") != "1" {
		t.Skip("set LOOM_WEB_CHROME_TEST=1 for browser command acceptance")
	}
	server, _, _, _, _, _ := enrollmentAuthorityFixture(t)
	admin := server.AdminHandler()
	var mu sync.Mutex
	var requests [][]byte
	editAccepted, releaseEdit := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseEdit) }) }
	host := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/api/control/operations" {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "Demo request interrupted", http.StatusBadRequest)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
			op, err := DecodeOperation(body)
			if err == nil && op.Operation == "probe_target.put" && op.TargetID == "demo-retry-probe" {
				mu.Lock()
				requests = append(requests, append([]byte{}, body...))
				index := len(requests)
				mu.Unlock()
				if index == 1 || index == 3 {
					response := httptest.NewRecorder()
					admin.ServeHTTP(response, r)
					if response.Code != http.StatusOK {
						t.Errorf("probe write was not accepted: %d %s", response.Code, response.Body.String())
					}
					if index == 1 {
						http.Error(w, "Demo response lost after saving probe target", http.StatusBadGateway)
						return
					}
					close(editAccepted)
					select {
					case <-releaseEdit:
					case <-r.Context().Done():
						return
					}
					for key, values := range response.Header() {
						w.Header()[key] = values
					}
					w.WriteHeader(response.Code)
					_, _ = w.Write(response.Body.Bytes())
					return
				}
			}
		}
		admin.ServeHTTP(w, r)
	}))
	defer host.Close()
	defer release()
	debug := openCommandChrome(t, host.URL+"/services?tab=probes&new=1")
	waitChromeEvaluation(t, debug, `document.querySelector('#probe-target-form')&&document.querySelector('#connection').title.includes('local writes available')`)
	chromeDo(t, debug, `(()=>{const f=document.querySelector('#probe-target-form');f.elements.id.value='demo-retry-probe';f.elements.url.value='https://demo-unused.example/health';f.requestSubmit();return true})()`)
	waitChromeEvaluation(t, debug, `document.querySelector('#probe-target-form [role=alert]')?.textContent==='Demo response lost after saving probe target'`)
	frontier := server.Runtime.Authority.Frontier()
	chromeDo(t, debug, `document.querySelector('#probe-target-form').requestSubmit();true`)
	waitChromeEvaluation(t, debug, `document.querySelector('#notice').textContent.includes('Accepted locally')&&new URLSearchParams(location.search).get('target')==='demo-retry-probe'`)
	mu.Lock()
	same := len(requests) == 2 && bytes.Equal(requests[0], requests[1])
	mu.Unlock()
	if !same || !reflect.DeepEqual(frontier, server.Runtime.Authority.Frontier()) {
		t.Fatal("unchanged probe retry changed canonical bytes or signed a second fact")
	}
	chromeDo(t, debug, `(()=>{document.querySelector('#notice').textContent='';const f=document.querySelector('#probe-target-form');f.elements.url.value='https://demo-service.example/health';f.requestSubmit();return true})()`)
	select {
	case <-editAccepted:
	case <-time.After(5 * time.Second):
		t.Fatal("edited probe was not durably accepted")
	}
	chromeDo(t, debug, `document.querySelector('nav[aria-label="Access configuration"] a[href="/services?tab=dns"]').click();true`)
	waitChromeEvaluation(t, debug, `document.querySelector('nav[aria-label="Access configuration"] a[aria-current="page"][href="/services?tab=dns"]')&&!document.querySelector('#probe-target-form')`)
	release()
	waitChromeEvaluation(t, debug, `document.querySelector('#notice').textContent.includes('Accepted locally')`)
	if chromeDo(t, debug, `new URLSearchParams(location.search).get('tab')==='dns'&&!new URLSearchParams(location.search).has('target')&&!document.querySelector('#probe-target-form')`) != true {
		t.Fatal("delayed probe acceptance reclaimed the page after navigation")
	}
	if got := server.Runtime.Authority.Snapshot().NetworkIntent.BusinessProbeTargets; !reflect.DeepEqual(got, []BusinessProbeTarget{{ID: "demo-retry-probe", URL: "https://demo-service.example/health"}}) {
		t.Fatal("delayed response lost the accepted target update")
	}
}

func TestWebChromeNewIntentDraftSurvivesLiveReadbackBeforeAcceptance(t *testing.T) {
	if os.Getenv("LOOM_WEB_CHROME_TEST") != "1" {
		t.Skip("set LOOM_WEB_CHROME_TEST=1 for browser command acceptance")
	}
	for _, tc := range []struct {
		name, tab, form, operation, target, selected, row, fill, retained string
	}{
		{
			name: "DNS", tab: "dns", form: "dns-record-form", operation: "dns_record.put", target: "demo-live-dns", selected: "record",
			row:      `[data-dns-record="demo-live-dns"]`,
			fill:     `f.elements.name.value='demo-live.loom';f.elements.addresses.value='192.0.2.10\n2001:db8::10'`,
			retained: `f.elements.name.value==='demo-live.loom'&&f.elements.addresses.value==='192.0.2.10\n2001:db8::10'`,
		},
		{
			name: "Probe", tab: "probes", form: "probe-target-form", operation: "probe_target.put", target: "demo-live-probe", selected: "target",
			row:      `[data-probe-target="demo-live-probe"]`,
			fill:     `f.elements.url.value='https://demo-unused.example/health'`,
			retained: `f.elements.url.value==='https://demo-unused.example/health'`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, _, _, _, _, _ := enrollmentAuthorityFixture(t)
			admin := server.AdminHandler()
			accepted, releaseResponse := make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			release := func() { releaseOnce.Do(func() { close(releaseResponse) }) }
			host := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost && r.URL.Path == "/api/control/operations" {
					body, err := io.ReadAll(r.Body)
					if err != nil {
						http.Error(w, "Demo request interrupted", http.StatusBadRequest)
						return
					}
					r.Body = io.NopCloser(bytes.NewReader(body))
					if op, err := DecodeOperation(body); err == nil && op.Operation == tc.operation && op.TargetID == tc.target {
						response := httptest.NewRecorder()
						admin.ServeHTTP(response, r)
						if response.Code != http.StatusOK {
							t.Errorf("new object was not accepted: %d %s", response.Code, response.Body.String())
						}
						close(accepted)
						select {
						case <-releaseResponse:
						case <-r.Context().Done():
							return
						}
						for key, values := range response.Header() {
							w.Header()[key] = values
						}
						w.WriteHeader(response.Code)
						_, _ = w.Write(response.Body.Bytes())
						return
					}
				}
				admin.ServeHTTP(w, r)
			}))
			defer host.Close()
			defer release()
			debug := openCommandChrome(t, host.URL+"/services?tab="+tc.tab+"&new=1")
			waitChromeEvaluation(t, debug, fmt.Sprintf(`document.querySelector('#%s')&&document.querySelector('#connection').title.includes('local writes available')`, tc.form))
			chromeDo(t, debug, fmt.Sprintf(`(()=>{const f=document.querySelector('#%s');window.demoLiveDraft=f;window.demoLiveRequestID=f.dataset.requestId;f.elements.id.value='%s';%s;f.requestSubmit();return true})()`, tc.form, tc.target, tc.fill))
			select {
			case <-accepted:
			case <-time.After(5 * time.Second):
				t.Fatal("new object was not durably accepted")
			}
			// The original POST response remains withheld. Only the normal live
			// snapshot can insert this persisted record into the current table.
			waitChromeEvaluation(t, debug, fmt.Sprintf(`document.querySelector('%s')`, tc.row))
			if chromeDo(t, debug, fmt.Sprintf(`(()=>{const f=demoLiveDraft;return new URLSearchParams(location.search).get('new')==='1'&&f===document.querySelector('#%s')&&f.isConnected&&f.submitting&&f.dataset.requestId===demoLiveRequestID&&f.elements.id.value==='%s'&&%s})()`, tc.form, tc.target, tc.retained)) != true {
				t.Fatal("live insertion detached the submitted draft or replaced its identity and fields")
			}
			release()
			waitChromeEvaluation(t, debug, fmt.Sprintf(`document.querySelector('#notice').textContent.includes('Accepted locally')&&new URLSearchParams(location.search).get('%s')==='%s'&&!new URLSearchParams(location.search).has('new')`, tc.selected, tc.target))
			if chromeDo(t, debug, fmt.Sprintf(`(()=>{const f=document.querySelector('#%s');return f?.elements.id.value==='%s'&&%s})()`, tc.form, tc.target, tc.retained)) != true {
				t.Fatal("accepted draft did not navigate to and read back its saved object")
			}
		})
	}
}
