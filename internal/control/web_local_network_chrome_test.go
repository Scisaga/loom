package control

import (
	"net/http/httptest"
	"os"
	"testing"
)

func TestWebChromeLocalNetworkWriteReadRestart(t *testing.T) {
	if os.Getenv("LOOM_WEB_CHROME_TEST") != "1" {
		t.Skip("requires browser command acceptance")
	}
	server, key := localNetworkWriteFixture(t)
	reportLocalNetworks(t, server, key, 1, []string{"192.0.2.0/24"})
	httpServer := httptest.NewServer(server.AdminHandler())
	defer httpServer.Close()
	browser := openCommandChrome(t, httpServer.URL+"/services?new=1&kind=local_network&gateway=demo-gateway")
	waitChromeEvaluation(t, browser, `document.querySelector('#service-form')?.elements.local_prefix.options.length>1`)
	chromeDo(t, browser, `(()=>{const f=document.querySelector('#service-form');f.elements.id.value='demo-browser-lan';f.elements.name.value='Demo office';f.elements.local_prefix.value='192.0.2.0/24';f.querySelector('[data-lan-allocate]').click();return true})()`)
	waitChromeEvaluation(t, browser, `document.querySelector('[data-lan-mapping]').textContent.includes(' → 192.0.2.0/24')`)
	chromeDo(t, browser, `document.querySelector('#service-form').requestSubmit();true`)
	waitChromeEvaluation(t, browser, `location.search==='?service=demo-browser-lan'&&document.querySelector('#notice').textContent.includes('Accepted locally')`)
	want := currentLocalNetwork(t, server, "demo-browser-lan")
	if !want.LocalNetwork.Enabled {
		t.Fatal("browser failed to persist enabled LAN")
	}
	chromeDo(t, browser, `document.querySelector('a[href="/policies?new=1&service=demo-browser-lan"]').click();true`)
	waitChromeEvaluation(t, browser, `document.querySelector('#policy-form')&&document.querySelector('[data-policy-internet]').hidden`)
	chromeDo(t, browser, `(()=>{const f=document.querySelector('#policy-form');f.elements.id.value='demo-browser-lan-policy';f.elements.name.value='Demo office access';f.requestSubmit();return true})()`)
	waitChromeEvaluation(t, browser, `location.search==='?policy=demo-browser-lan-policy'&&document.querySelector('#notice').textContent.includes('Accepted locally')`)
	found := false
	for _, policy := range server.Runtime.Authority.Snapshot().NetworkIntent.Policies {
		if policy.ID == "demo-browser-lan-policy" {
			found = true
			if policy.ValidateForService(want) != nil || policy.ExitScope != nil || policy.AllowDirect != nil || policy.LocalEgressDevices != nil {
				t.Fatal("browser manufactured Internet permissions for LAN")
			}
		}
	}
	if !found {
		t.Fatal("browser did not persist LAN Policy")
	}
	root := server.Runtime.Authority.root
	server.Runtime.Close()
	var err error
	server.Runtime, err = OpenRuntime(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Runtime.Close()
	chromeDo(t, browser, `location.href='/services?service=demo-browser-lan';true`)
	waitChromeEvaluation(t, browser, `document.querySelector('#service-form')?.elements.kind.value==='local_network'&&document.querySelector('[data-lan-mapping]').textContent.includes('192.0.2.0/24')`)
	chromeDo(t, browser, `(()=>{const f=document.querySelector('#service-form');f.elements.lan_enabled.checked=false;f.requestSubmit();return true})()`)
	waitChromeEvaluation(t, browser, `document.querySelector('[data-lan-state]').textContent==='Disabled'`)
	if currentLocalNetwork(t, server, want.ID).LocalNetwork.Enabled {
		t.Fatal("browser disabled display without persisting withdrawal")
	}
}
