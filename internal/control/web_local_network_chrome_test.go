package control

import (
	"fmt"
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
	browser := openCommandChrome(t, httpServer.URL+"/services?new=1&gateway=demo-gateway")
	waitChromeEvaluation(t, browser, `document.querySelector('#service-form')?.elements.kind.value===''&&document.querySelector('#service-form').elements.id.disabled&&document.querySelector('#service-form').elements.name.disabled`)
	chromeDo(t, browser, `(()=>{const f=document.querySelector('#service-form');f.elements.kind.value='local_network';f.elements.kind.dispatchEvent(new Event('change',{bubbles:true}));return true})()`)
	waitChromeEvaluation(t, browser, `document.querySelector('#service-form')?.elements.local_prefix.options.length>1`)
	chromeDo(t, browser, `(()=>{const f=document.querySelector('#service-form');f.elements.id.value='demo-browser-lan';f.elements.name.value='Demo office';f.elements.local_prefix.value='192.0.2.0/24';f.elements.local_prefix.dispatchEvent(new Event('change',{bubbles:true}));return true})()`)
	waitChromeEvaluation(t, browser, `document.querySelector('[data-lan-virtual]').textContent==='10.0.2.0/24'&&!document.querySelector('#service-form [type=submit]').disabled`)
	chromeDo(t, browser, `document.querySelector('#service-form').requestSubmit();true`)
	waitChromeEvaluation(t, browser, `location.search==='?service=local-demo-browser-lan'&&document.querySelector('#notice').textContent.includes('Accepted locally')`)
	want := currentLocalNetwork(t, server, "local-demo-browser-lan")
	if !want.LocalNetwork.Enabled || want.Name != "Local-Demo office" {
		t.Fatal("browser failed to persist the complete LAN identity and mapping")
	}
	chromeDo(t, browser, `document.querySelector('a[href="/policies?new=1&service=local-demo-browser-lan"]').click();true`)
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
	chromeDo(t, browser, `location.href='/services?service=local-demo-browser-lan';true`)
	waitChromeEvaluation(t, browser, `document.querySelector('#service-form')?.elements.kind.value==='local_network'&&document.querySelector('#service-form').elements.name.value==='Demo office'&&document.querySelector('[data-lan-mapping]').textContent.includes('192.0.2.0/24')`)
	chromeDo(t, browser, `(()=>{const f=document.querySelector('#service-form');f.elements.lan_enabled.checked=false;f.requestSubmit();return true})()`)
	waitChromeEvaluation(t, browser, `document.querySelector('[data-lan-state]').textContent==='Disabled'`)
	if currentLocalNetwork(t, server, want.ID).LocalNetwork.Enabled {
		t.Fatal("browser disabled display without persisting withdrawal")
	}
}

func TestWebChromeLocalNetworkAutomaticPreviewRaceRetryAndLayout(t *testing.T) {
	if os.Getenv("LOOM_WEB_CHROME_TEST") != "1" {
		t.Skip("requires browser command acceptance")
	}
	server, key := localNetworkWriteFixture(t)
	reportLocalNetworkValues(t, server, key, 1, []LocalNetworkPrefix{{Prefix: "10.64.8.0/24", LAN: true}, {Prefix: "192.0.2.0/24", LAN: true}})
	httpServer := httptest.NewServer(server.AdminHandler())
	defer httpServer.Close()
	browser := openCommandChrome(t, httpServer.URL+"/services?new=1&kind=local_network&gateway=demo-gateway")
	waitChromeEvaluation(t, browser, `document.querySelector('#service-form')?.elements.local_prefix.options.length===3`)
	chromeDo(t, browser, `(()=>{window.demoFetch=window.fetch;window.demoPending=[];window.fetch=async(url,options={})=>{if(!String(url).endsWith('/local-network-allocation'))return demoFetch(url,options);const copy={...options};delete copy.signal;const response=await demoFetch(url,copy);return new Promise(resolve=>demoPending.push(()=>resolve(response)))};const f=document.querySelector('#service-form');f.elements.id.value='demo-auto-lan';f.elements.name.value='Demo office';f.elements.local_prefix.value='10.64.8.0/24';f.elements.local_prefix.dispatchEvent(new Event('change',{bubbles:true}));return true})()`)
	waitChromeEvaluation(t, browser, `demoPending.length===1&&document.querySelector('#service-form [type=submit]').disabled`)
	chromeDo(t, browser, `(()=>{const f=document.querySelector('#service-form');f.elements.local_prefix.value='192.0.2.0/24';f.elements.local_prefix.dispatchEvent(new Event('change',{bubbles:true}));return true})()`)
	waitChromeEvaluation(t, browser, `demoPending.length===2`)
	chromeDo(t, browser, `demoPending[1]();true`)
	waitChromeEvaluation(t, browser, `document.querySelector('[data-lan-virtual]').textContent==='10.0.2.0/24'&&!document.querySelector('#service-form [type=submit]').disabled`)
	chromeDo(t, browser, `demoPending[0]();true`)
	waitChromeEvaluation(t, browser, `!document.querySelector('#service-form').lanRequest`)
	if chromeDo(t, browser, `document.querySelector('[data-lan-virtual]').textContent==='10.0.2.0/24'&&document.querySelector('[data-lan-local]').textContent==='192.0.2.0/24'&&document.querySelector('#operation-status').textContent===''&&document.querySelector('[data-lan-allocate]').hidden`) != true {
		t.Fatal("late allocation replaced the selected network or normal preview required a manual action")
	}
	chromeDo(t, browser, `(()=>{window.fetch=(url,options)=>{if(String(url).endsWith('/local-network-allocation')){window.fetch=demoFetch;return Promise.resolve(new Response('Demo allocation unavailable',{status:503}))}return demoFetch(url,options)};const f=document.querySelector('#service-form');f.elements.local_prefix.value='10.64.8.0/24';f.elements.local_prefix.dispatchEvent(new Event('change',{bubbles:true}));return true})()`)
	waitChromeEvaluation(t, browser, `document.querySelector('[data-lan-state]').textContent==='Demo allocation unavailable'&&!document.querySelector('[data-lan-allocate]').hidden&&document.querySelector('#service-form [type=submit]').disabled`)
	chromeDo(t, browser, `document.querySelector('[data-lan-allocate]').click();true`)
	waitChromeEvaluation(t, browser, `document.querySelector('[data-lan-virtual]').textContent==='10.64.8.0/24'&&!document.querySelector('#service-form [type=submit]').disabled&&document.querySelector('[data-lan-allocate]').hidden`)
	chromeDo(t, browser, `(()=>{const f=document.querySelector('#service-form');f.elements.name.value='Demo renamed office';f.elements.name.dispatchEvent(new Event('input',{bubbles:true}));return true})()`)
	if chromeDo(t, browser, `!!document.querySelector('#service-form').lanAllocation&&!document.querySelector('#service-form').lanRequest&&document.querySelector('[data-lan-summary]').textContent==='Addresses stay the same.'`) != true {
		t.Fatal("display name change invalidated the address mapping")
	}
	for _, width := range []int{1440, 390} {
		accessConfigurationChromeViewport(t, browser, width)
		if chromeDo(t, browser, `(()=>{const box=document.querySelector('.lan-mapping-card'),gateway=document.querySelector('#lan-gateway').getBoundingClientRect(),prefix=document.querySelector('#lan-prefix').getBoundingClientRect();return box.scrollWidth<=box.clientWidth+1&&document.documentElement.scrollWidth<=innerWidth+1&&(innerWidth>760?Math.abs(gateway.top-prefix.top)<1:prefix.top>=gateway.bottom)})()`) != true {
			t.Fatalf("LAN selectors or address mapping overflowed at %d px", width)
		}
		accessConfigurationChromeScreenshot(t, browser, fmt.Sprintf("demo-lan-automatic-preview-%d", width))
	}
	chromeDo(t, browser, `document.querySelector('#service-form').requestSubmit();true`)
	waitChromeEvaluation(t, browser, `location.search==='?service=local-demo-auto-lan'&&document.querySelector('#notice').textContent.includes('Accepted locally')`)
	actual := currentLocalNetwork(t, server, "local-demo-auto-lan")
	if actual.Name != "Local-Demo renamed office" || actual.LocalNetwork.VirtualPrefix != "10.64.8.0/24" || actual.LocalNetwork.LocalPrefix != "10.64.8.0/24" {
		t.Fatal("automatic preview did not persist the selected mapping and final display name")
	}
}
