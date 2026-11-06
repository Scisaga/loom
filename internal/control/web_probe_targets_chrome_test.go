package control

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"
)

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

func TestWebChromeServiceEditsProbeURLsAndRestrictionTogether(t *testing.T) {
	if os.Getenv("LOOM_WEB_CHROME_TEST") != "1" {
		t.Skip("set LOOM_WEB_CHROME_TEST=1 for browser command acceptance")
	}
	server, _, _, _, _, _ := enrollmentAuthorityFixture(t)
	host := httptest.NewServer(server.AdminHandler())
	defer host.Close()
	debug := openCommandChrome(t, host.URL+"/services?new=1&kind=internet")
	waitChromeEvaluation(t, debug, `document.querySelector('#service-form')&&document.querySelector('#connection').title.includes('local writes available')`)
	if chromeDo(t, debug, `(()=>{const f=document.querySelector('#service-form');return !f.elements.restrict_to_probe_targets.checked&&!f.elements.probe_urls.required&&!f.querySelector('[name=access_scope]')&&!f.querySelector('[name=matchers]')&&!document.querySelector('a[href="/services?tab=probes"]')})()`) != true {
		t.Fatal("new Internet service did not expose only probe URLs and its restriction flag")
	}
	chromeDo(t, debug, `(()=>{const f=document.querySelector('#service-form');f.elements.id.value='demo-ordinary';f.elements.name.value='Demo ordinary internet';f.elements.probe_urls.value='https://demo-one.example/health\nhttps://demo-two.example/health';f.requestSubmit();return true})()`)
	waitChromeEvaluation(t, debug, `document.querySelector('#service-form')?.elements.id.value==='demo-ordinary'&&document.querySelector('#notice').textContent.includes('Accepted locally')&&!new URLSearchParams(location.search).has('new')`)
	p := server.Runtime.Authority.Snapshot()
	found := false
	for _, service := range p.NetworkIntent.Services {
		if service.ID != "demo-ordinary" {
			continue
		}
		found = service.IsPublicInternet() && service.RestrictToProbeTargets != nil && !*service.RestrictToProbeTargets && service.Matchers == nil && len(service.ProbeURLs) == 2
	}
	if !found {
		t.Fatal("normal Service entry did not persist the restriction flag and probe configuration")
	}
	chromeDo(t, debug, `(()=>{const f=document.querySelector('#service-form');f.elements.probe_urls.value='https://127.0.0.1/health';f.requestSubmit();return true})()`)
	waitChromeEvaluation(t, debug, `(()=>{const message=document.querySelector('#operation-status').textContent;return message.length>0&&message!=='Submitting…'&&!document.querySelector('#service-form').submitting})()`)
	for _, service := range server.Runtime.Authority.Snapshot().NetworkIntent.Services {
		if service.ID == "demo-ordinary" && len(service.ProbeURLs) != 2 {
			t.Fatal("invalid probe URL replaced accepted Service permission")
		}
	}
}
