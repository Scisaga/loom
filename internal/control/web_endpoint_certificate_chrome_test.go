package control

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

func TestWebChromeEndpointCertificatesAndOfflineExpiry(t *testing.T) {
	if os.Getenv("LOOM_WEB_CHROME_TEST") != "1" {
		t.Skip("set LOOM_WEB_CHROME_TEST=1 for endpoint certificate browser acceptance")
	}
	f := newEndpointFixture(t)
	var offline atomic.Bool
	normal := f.server.AdminHandler()
	host := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if offline.Load() && r.URL.Path == "/api/control/ui/live" {
			http.Error(w, "demo readback stream unavailable", http.StatusServiceUnavailable)
			return
		}
		normal.ServeHTTP(w, r)
	}))
	defer host.Close()
	debug := openCommandChrome(t, host.URL+"/ssot?section=certificates")
	waitChromeEvaluation(t, debug, `document.querySelector('[data-certificate-endpoint="demo-lifecycle-entry"][data-certificate-status="renewal_due"]')?.textContent.includes('bootstrap · device')`)
	if chromeDo(t, debug, `document.querySelector('[data-certificate-endpoint] .badge.warn')?.textContent==='Renew soon'&&document.querySelector('.administration-section-head h2').textContent==='Endpoint certificates'&&document.querySelector('#public-trust-form')&&document.documentElement.scrollWidth<=innerWidth`) != true {
		t.Fatal("device certificate reminder lost the existing administration layout or website controls")
	}
	if chromeDo(t, debug, `(async()=>{
	 const {expireEvidence,nextEvidenceExpiry}=await import('/assets/model.js'),now=Date.now(),day=86400000;
	 const value={status:'valid',leaf_not_before:new Date(now-day).toISOString(),leaf_not_after:new Date(now+31*day).toISOString(),root_not_before:new Date(now-day).toISOString(),root_not_after:new Date(now+30*day+2000).toISOString()},remote={status:'unknown',reason:'inspect_owning_control'},source={endpoint_certificates:[value,remote]},before=JSON.stringify(source);
	 const current=expireEvidence(source,now),due=expireEvidence(source,now+2000),expired=expireEvidence(source,now+30*day+2000);
	 return JSON.stringify(source)===before&&current.endpoint_certificates[0].status==='valid'&&nextEvidenceExpiry(current,now)===now+2000&&due.endpoint_certificates[0].status==='renewal_due'&&expired.endpoint_certificates[0].status==='expired'&&expired.endpoint_certificates[1]===remote&&nextEvidenceExpiry(expired,now+30*day+2000)===0;
	})()`) != true {
		t.Fatal("certificate display timing ignored the root validity or invented a remote certificate result")
	}
	projection := f.server.Runtime.Authority.Snapshot()
	before, _ := CanonicalEncode(projection)
	rows := EndpointCertificateReadbacks(f.server.Runtime.Authority.root, f.server.Config.ControlID, projection, f.server.now())
	end, err := time.Parse(time.RFC3339, rows[0].LeafNotAfter)
	if err != nil {
		t.Fatal(err)
	}
	// Move only the browser clock close to the real leaf's expiry, then remove
	// live readbacks. The existing display timer must expire the diagnosis.
	offline.Store(true)
	offset, _ := json.Marshal(end.Add(-5 * time.Second).Sub(time.Now()).Milliseconds())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	err = debug.call(ctx, "Page.enable", map[string]any{}, nil)
	if err == nil {
		err = debug.call(ctx, "Page.addScriptToEvaluateOnNewDocument", map[string]any{"source": `const demoRealNow=Date.now.bind(Date);Date.now=()=>demoRealNow()+` + string(offset) + `;`}, nil)
	}
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	chromeDo(t, debug, `location.reload();true`)
	waitChromeEvaluation(t, debug, `Date.now.toString().includes('demoRealNow')&&document.querySelector('[data-certificate-endpoint="demo-lifecycle-entry"]')`)
	waitChromeEvaluation(t, debug, `document.querySelector('[data-certificate-endpoint="demo-lifecycle-entry"][data-certificate-status="renewal_due"]')`)
	waitChromeEvaluation(t, debug, `document.querySelector('[data-certificate-endpoint="demo-lifecycle-entry"][data-certificate-status="expired"] .badge.bad')?.textContent==='Expired'`)
	after, _ := CanonicalEncode(f.server.Runtime.Authority.Snapshot())
	if string(before) != string(after) || !f.runtime.Ready(f.endpoint) {
		t.Fatal("browser certificate diagnosis rewrote authority or stopped the actually valid listener")
	}
}
