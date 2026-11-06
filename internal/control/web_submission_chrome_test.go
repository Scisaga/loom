package control

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestWebChromeIntentSubmissionWaitRetryAndNavigation(t *testing.T) {
	if os.Getenv("LOOM_WEB_CHROME_TEST") != "1" {
		t.Skip("requires browser command acceptance")
	}
	for _, kind := range []string{"service", "policy"} {
		t.Run(kind, func(t *testing.T) {
			server, key := localNetworkWriteFixture(t)
			reportLocalNetworks(t, server, key, 1, []string{"192.0.2.0/24"})
			op := previewLocalNetwork(t, server, "demo-wait-lan", "demo-wait-create-lan")
			if response := localNetworkAdminHTTP(t, server, "/api/control/operations", op); response.Code != http.StatusOK {
				t.Fatal("LAN fixture was not accepted", response.Body.String())
			}
			id, route := "demo-wait-lan", "/services?service=demo-wait-lan"
			if kind == "policy" {
				id, route = "demo-wait-policy", "/policies?new=1&service=demo-wait-lan"
			}
			name := "Demo pending " + kind
			waitingLabel := "Saving service…"
			if kind == "policy" {
				waitingLabel = "Adding policy…"
			}
			admin := server.AdminHandler()
			var mu sync.Mutex
			var requests [][]byte
			releases := []chan struct{}{make(chan struct{}), make(chan struct{})}
			var once [2]sync.Once
			release := func(i int) { once[i].Do(func() { close(releases[i]) }) }
			host := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost && r.URL.Path == "/api/control/operations" {
					body, err := io.ReadAll(r.Body)
					if err != nil {
						http.Error(w, "Demo request interrupted", http.StatusBadRequest)
						return
					}
					r.Body = io.NopCloser(bytes.NewReader(body))
					operation, err := DecodeOperation(body)
					if err == nil && operation.Operation == kind+".put" && operation.TargetID == id {
						mu.Lock()
						requests = append(requests, append([]byte{}, body...))
						index := len(requests) - 1
						mu.Unlock()
						if index >= len(releases) {
							http.Error(w, "Demo duplicate submission", http.StatusConflict)
							return
						}
						response := httptest.NewRecorder()
						admin.ServeHTTP(response, r)
						if response.Code != http.StatusOK {
							t.Errorf("normal operation rejected: %d %s", response.Code, response.Body.String())
						}
						select {
						case <-releases[index]:
						case <-r.Context().Done():
							return
						}
						if index == 0 {
							http.Error(w, "Demo response lost after saving", http.StatusBadGateway)
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
			defer func() { release(0); release(1); host.Close() }()
			debug := openCommandChrome(t, host.URL+route)
			selector := "#" + kind + "-form"
			waitChromeEvaluation(t, debug, fmt.Sprintf(`document.querySelector(%q)&&document.querySelector('#connection').title.includes('local writes available')`, selector))
			chromeDo(t, debug, fmt.Sprintf(`(()=>{const f=document.querySelector(%q);window.demoWaitingForm=f;window.demoInitialControls=[...f.closest('.intent-editor').querySelectorAll('input,select,textarea,button')].map(node=>({node,disabled:node.disabled}));f.elements.name.value=%q;if(f.dataset.creating==='true')f.elements.id.value=%q;f.querySelector('[type=submit]').focus();f.requestSubmit();return true})()`, selector, name, id))
			waitChromeEvaluation(t, debug, `demoWaitingForm.submitting&&demoWaitingForm.getAttribute('aria-busy')==='true'&&document.querySelector('.submission-overlay [class=request-spinner]')`)
			if chromeDo(t, debug, fmt.Sprintf(`document.querySelector('.submission-message').textContent===%q&&demoWaitingForm.querySelector('[type=submit]').textContent===%q`, waitingLabel, waitingLabel)) != true {
				t.Fatal("waiting feedback did not identify the submitted operation")
			}
			// The actual accepted fact reaches the live catalog while its HTTP response is held.
			waitChromeEvaluation(t, debug, fmt.Sprintf(`[...document.querySelectorAll('.intent-catalog .service-item')].some(node=>node.textContent.includes(%q))`, name))
			if chromeDo(t, debug, `(()=>{const f=demoWaitingForm,p=f.closest('.intent-editor');f.dispatchEvent(new Event('submit',{bubbles:true,cancelable:true}));f.elements.name.focus();return f.isConnected&&f.submitting&&p.classList.contains('is-submitting')&&[...p.children].filter(n=>!n.classList.contains('submission-overlay')).every(n=>n.inert)&&demoInitialControls.every(v=>v.node.disabled)&&document.activeElement!==f.elements.name&&p.querySelector('.submission-overlay').getAttribute('role')==='status'&&getComputedStyle(p.querySelector('.submission-overlay .request-spinner')).animationName==='request-spin'})()`) != true {
				t.Fatal("live readback removed waiting feedback or panel remained interactive")
			}
			for _, width := range []int{1440, 390} {
				accessConfigurationChromeViewport(t, debug, width)
				if chromeDo(t, debug, `document.documentElement.scrollWidth<=innerWidth+1&&document.querySelector('.submission-message').getBoundingClientRect().width<=document.querySelector('.intent-editor').getBoundingClientRect().width`) != true {
					t.Fatalf("pending panel overflowed at %d px", width)
				}
				accessConfigurationChromeScreenshot(t, debug, fmt.Sprintf("demo-%s-waiting-%d", kind, width))
			}
			release(0)
			waitChromeEvaluation(t, debug, `!demoWaitingForm.submitting&&demoWaitingForm.querySelector('[role=alert]').textContent==='Demo response lost after saving'`)
			if chromeDo(t, debug, fmt.Sprintf(`demoWaitingForm.isConnected&&demoWaitingForm.elements.name.value===%q&&!demoWaitingForm.hasAttribute('aria-busy')&&!document.querySelector('.submission-overlay')&&demoInitialControls.every(v=>v.node.disabled===v.disabled)&&[...demoWaitingForm.closest('.intent-editor').children].every(n=>!n.inert)`, name)) != true {
				t.Fatal("failed request did not restore draft and original disabled fields")
			}
			frontier := server.Runtime.Authority.Frontier()
			chromeDo(t, debug, `demoWaitingForm.requestSubmit();true`)
			waitChromeEvaluation(t, debug, `demoWaitingForm.submitting&&!!document.querySelector('.submission-overlay')`)
			chromeDo(t, debug, `document.querySelector('nav[aria-label="Access configuration"] a[href="/services?tab=dns"]').click();true`)
			waitChromeEvaluation(t, debug, `new URLSearchParams(location.search).get('tab')==='dns'&&!document.querySelector('.submission-overlay')`)
			release(1)
			waitChromeEvaluation(t, debug, `document.querySelector('#notice').textContent.includes('Accepted locally')`)
			mu.Lock()
			identical := len(requests) == 2 && bytes.Equal(requests[0], requests[1])
			mu.Unlock()
			if !identical || !reflect.DeepEqual(frontier, server.Runtime.Authority.Frontier()) {
				t.Fatal("retry changed canonical bytes, duplicated a fact or submitted more than once")
			}
			if chromeDo(t, debug, `new URLSearchParams(location.search).get('tab')==='dns'&&!document.querySelector('.submission-overlay')`) != true {
				t.Fatal("late acceptance reclaimed navigation or left a busy overlay")
			}
			plural := kind + "s"
			if kind == "policy" {
				plural = "policies"
			}
			route = "/" + plural + "?" + kind + "=" + id
			chromeDo(t, debug, fmt.Sprintf(`location.href=%q;true`, host.URL+route))
			waitChromeEvaluation(t, debug, fmt.Sprintf(`document.querySelector(%q)?.elements.name.value===%q&&!document.querySelector('.submission-overlay')`, selector, name))
		})
	}
}

func TestWebChromePolicyIdentitySuggestionsPreserveEdits(t *testing.T) {
	if os.Getenv("LOOM_WEB_CHROME_TEST") != "1" {
		t.Skip("requires browser command acceptance")
	}
	server, key := localNetworkWriteFixture(t)
	reportLocalNetworks(t, server, key, 1, []string{"192.0.2.0/24"})
	op := previewLocalNetwork(t, server, "demo-prefill-lan", "demo-prefill-service")
	service := submitAuthority(t, server.Runtime, op)
	anyScope := PolicyScope{Mode: "any", NodeIDs: []string{}}
	submitAuthority(t, server.Runtime, Operation{Schema: 3, RequestID: "demo-prefill-occupied", Operation: "policy.put", TargetKind: "policy", TargetID: "demo-prefill-lan-default", Dependencies: []string{service.MaterialID}, Payload: NetworkPolicy{ID: "demo-prefill-lan-default", Name: "Demo existing policy", ServiceID: "demo-prefill-lan", Action: "allow", EntryScope: anyScope, RelayScope: anyScope}})
	longID, longName := "demo-"+strings.Repeat("界", 40), "Demo "+strings.Repeat("名", 83)
	submitAuthority(t, server.Runtime, Operation{Schema: 3, RequestID: "demo-prefill-long", Operation: "service.put", TargetKind: "service", TargetID: longID, Dependencies: []string{}, Payload: Service{ID: longID, Name: longName, Kind: "internet", RestrictToProbeTargets: new(false)}})
	host := httptest.NewServer(server.AdminHandler())
	defer host.Close()
	debug := openCommandChrome(t, host.URL+"/policies?new=1&service=demo-prefill-lan")
	waitChromeEvaluation(t, debug, `document.querySelector('#policy-form')?.elements.id.value==='demo-prefill-lan-default-2'`)
	if chromeDo(t, debug, `(()=>{const f=document.querySelector('#policy-form');return f.elements.name.value.endsWith('-Default 2')&&!f.elements.id.disabled&&!f.elements.id.readOnly&&!f.elements.name.disabled&&!f.elements.name.readOnly&&f.elements.id.type==='text'})()`) != true {
		t.Fatal("new policy identity did not inherit the service or avoid an occupied ID")
	}
	chromeDo(t, debug, fmt.Sprintf(`(()=>{const f=document.querySelector('#policy-form');f.elements.service_id.value=%q;f.elements.service_id.dispatchEvent(new Event('change',{bubbles:true}));return true})()`, longID))
	if chromeDo(t, debug, `(()=>{const f=document.querySelector('#policy-form'),bytes=new TextEncoder();return f.elements.id.value.startsWith('demo-')&&f.elements.id.value.endsWith('-default')&&bytes.encode(f.elements.id.value).length<=128&&f.elements.name.value.startsWith('Demo ')&&f.elements.name.value.endsWith('-Default')&&bytes.encode(f.elements.name.value).length<=256})()`) != true {
		t.Fatalf("inherited Unicode prefix exceeded the existing contract text limits: %v", chromeDo(t, debug, `(()=>{const f=document.querySelector('#policy-form'),bytes=new TextEncoder();return {service:f.elements.service_id.value,id:f.elements.id.value,name:f.elements.name.value,id_bytes:bytes.encode(f.elements.id.value).length,name_bytes:bytes.encode(f.elements.name.value).length,suggestion:JSON.parse(f.dataset.policyIdentitySuggestion||'null')}})()`))
	}
	chromeDo(t, debug, `(()=>{const f=document.querySelector('#policy-form');f.elements.id.value='demo-custom-policy';f.elements.service_id.value='demo-prefill-lan';f.elements.service_id.dispatchEvent(new Event('change',{bubbles:true}));return true})()`)
	if chromeDo(t, debug, `document.querySelector('#policy-form').elements.id.value==='demo-custom-policy'&&document.querySelector('#policy-form').elements.name.value.endsWith('-Default 2')`) != true {
		t.Fatal("switching service overwrote a manual ID or retained an untouched old name")
	}
	chromeDo(t, debug, `(()=>{const f=document.querySelector('#policy-form');f.elements.name.value='Demo custom access';f.elements.service_id.value='demo-service';f.elements.service_id.dispatchEvent(new Event('change',{bubbles:true}));return true})()`)
	if chromeDo(t, debug, `document.querySelector('#policy-form').elements.id.value==='demo-custom-policy'&&document.querySelector('#policy-form').elements.name.value==='Demo custom access'`) != true {
		t.Fatal("service switch overwrote a manually edited identity")
	}
	chromeDo(t, debug, `document.querySelector('#policy-form').requestSubmit();true`)
	waitChromeEvaluation(t, debug, `location.search==='?policy=demo-custom-policy'&&document.querySelector('#notice').textContent.includes('Accepted locally')`)
	chromeDo(t, debug, `location.reload();true`)
	waitChromeEvaluation(t, debug, `document.querySelector('#policy-form')?.elements.name.value==='Demo custom access'&&document.querySelector('#policy-form').elements.service_id.value==='demo-service'`)
}

func TestWebChromeServiceDefaultPolicyPartialRetry(t *testing.T) {
	if os.Getenv("LOOM_WEB_CHROME_TEST") != "1" {
		t.Skip("requires browser command acceptance")
	}
	server, _, _, _, _, _ := enrollmentAuthorityFixture(t)
	before := server.Runtime.Authority.Snapshot()
	service, _ := before.CurrentTarget("service", "demo-service")
	anyScope := PolicyScope{Mode: "any", NodeIDs: []string{}}
	occupied := NetworkPolicy{ID: "demo-auto-service-default", Name: "Demo occupied policy", ServiceID: "demo-service", Action: "allow", EntryScope: anyScope, RelayScope: anyScope, ExitScope: &anyScope, AllowDirect: new(true), LocalEgressDevices: new([]string{})}
	submitAuthority(t, server.Runtime, Operation{Schema: 3, RequestID: "demo-auto-occupied", Operation: "policy.put", TargetKind: "policy", TargetID: occupied.ID, Dependencies: service.MaterialIDs, Payload: occupied})
	admin := server.AdminHandler()
	var mu sync.Mutex
	requests := map[string][][]byte{}
	seen, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	finish := func() { once.Do(func() { close(release) }) }
	host := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/api/control/operations" {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "Demo request interrupted", http.StatusBadRequest)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
			op, err := DecodeOperation(body)
			if err == nil {
				mu.Lock()
				requests[op.Operation] = append(requests[op.Operation], append([]byte{}, body...))
				attempt := len(requests[op.Operation])
				mu.Unlock()
				if op.Operation == "policy.put" && attempt == 1 {
					response := httptest.NewRecorder()
					admin.ServeHTTP(response, r)
					if response.Code != http.StatusOK {
						t.Errorf("default policy rejected: %d %s", response.Code, response.Body.String())
					}
					close(seen)
					select {
					case <-release:
					case <-r.Context().Done():
						return
					}
					http.Error(w, "Demo policy response interrupted", http.StatusBadGateway)
					return
				}
			}
		}
		admin.ServeHTTP(w, r)
	}))
	defer func() { finish(); host.Close() }()
	debug := openCommandChrome(t, host.URL+"/services?new=1&kind=internet")
	waitChromeEvaluation(t, debug, `document.querySelector('#service-form')?.elements.kind.value==='internet'`)
	chromeDo(t, debug, `(()=>{const f=document.querySelector('#service-form');window.demoAutoForm=f;f.elements.id.value='demo-auto-service';f.elements.name.value='Demo automatic access';const matcher=f.querySelector('[data-matcher-value]');matcher.value='demo-auto.example';matcher.dispatchEvent(new Event('input',{bubbles:true}));f.requestSubmit();return true})()`)
	waitChromeEvaluation(t, debug, `demoAutoForm.submitting&&document.querySelector('.submission-message').textContent==='Adding default policy…'`)
	select {
	case <-seen:
	case <-time.After(5 * time.Second):
		t.Fatal("service creation did not submit its default policy")
	}
	if chromeDo(t, debug, `demoAutoForm.getAttribute('aria-busy')==='true'&&[...demoAutoForm.querySelectorAll('input,select,textarea,button')].every(n=>n.disabled)&&!document.querySelector('#notice').textContent.includes('Accepted locally')`) != true {
		t.Fatal("service creation unlocked or reported success before default policy confirmation")
	}
	finish()
	waitChromeEvaluation(t, debug, `!demoAutoForm.submitting&&demoAutoForm.querySelector('[role=alert]').textContent.includes('Service saved; default policy is not confirmed.')&&demoAutoForm.querySelector('[role=alert] a')`)
	frontier := server.Runtime.Authority.Frontier()
	chromeDo(t, debug, `demoAutoForm.elements.name.value='Demo edited pending draft';demoAutoForm.requestSubmit();true`)
	waitChromeEvaluation(t, debug, `demoAutoForm.querySelector('[role=alert]').textContent.includes('Retry the unchanged draft')`)
	chromeDo(t, debug, `(()=>{demoAutoForm.elements.name.value='Demo automatic access';demoAutoForm.requestSubmit();document.querySelector('nav[aria-label="Access configuration"] a[href="/services?tab=dns"]').click();return true})()`)
	waitChromeEvaluation(t, debug, `document.querySelector('#notice').textContent.includes('Service and default access policy saved.')`)
	mu.Lock()
	identical := len(requests["service.put"]) == 2 && len(requests["policy.put"]) == 2 && bytes.Equal(requests["service.put"][0], requests["service.put"][1]) && bytes.Equal(requests["policy.put"][0], requests["policy.put"][1])
	mu.Unlock()
	if !identical || !reflect.DeepEqual(frontier, server.Runtime.Authority.Frontier()) {
		t.Fatal("partial default creation retry replaced the reviewed intent or duplicated facts")
	}
	if chromeDo(t, debug, `new URLSearchParams(location.search).get('tab')==='dns'&&!document.querySelector('.submission-overlay')`) != true {
		t.Fatal("default policy follow-up reclaimed a page the operator left")
	}
	reopened, err := OpenAuthority(server.Runtime.Authority.root)
	if err != nil {
		t.Fatal(err)
	}
	actual := reopened.Snapshot()
	var found bool
	for _, policy := range actual.NetworkIntent.Policies {
		if policy.ID == "demo-auto-service-default-2" {
			found = policy.Name == "Demo automatic access-Default 2" && policy.ServiceID == "demo-auto-service" && policy.EntryScope.Mode == "any" && policy.RelayScope.Mode == "any" && policy.AllowDirect != nil && *policy.AllowDirect
		}
		if policy.ID == occupied.ID && !reflect.DeepEqual(policy, occupied) {
			t.Fatal("automatic naming overwrote an existing policy")
		}
	}
	if !found || !reflect.DeepEqual(before.DeviceAuthorizations, actual.DeviceAuthorizations) {
		t.Fatal("default policy was not durable or changed device assignments")
	}
}
