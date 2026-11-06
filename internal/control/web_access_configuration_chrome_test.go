package control

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func accessConfigurationChromeViewport(t *testing.T, debug *chromeDevTools, width int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := debug.call(ctx, "Emulation.setDeviceMetricsOverride", map[string]any{"width": width, "height": 1000, "deviceScaleFactor": 1, "mobile": false}, nil); err != nil {
		t.Fatal(err)
	}
	chromeDo(t, debug, `(async()=>{scrollTo(0,0);await document.fonts.ready;await new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve)));return true})()`)
}

func accessConfigurationChromeScreenshot(t *testing.T, debug *chromeDevTools, name string) {
	t.Helper()
	directory := os.Getenv("LOOM_WEB_CHROME_SCREENSHOT_DIR")
	if directory == "" {
		return
	}
	debug.connection.SetReadLimit(8 << 20)
	defer debug.connection.SetReadLimit(32768)
	clip := chromeDo(t, debug, `(async()=>{scrollTo(0,0);await document.fonts.ready;await new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve)));return {x:0,y:0,width:innerWidth,height:document.documentElement.scrollHeight,scale:1}})()`)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var screenshot struct {
		Data string `json:"data"`
	}
	if err := debug.call(ctx, "Page.captureScreenshot", map[string]any{"format": "png", "captureBeyondViewport": true, "clip": clip}, &screenshot); err != nil {
		t.Fatal(err)
	}
	content, err := base64.StdEncoding.DecodeString(screenshot.Data)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, name+".png")
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	t.Log("Page screenshot:", path)
}

func TestWebChromeAccessConfigurationNavigationFiltersAndResponsiveEditors(t *testing.T) {
	if os.Getenv("LOOM_WEB_CHROME_TEST") != "1" {
		t.Skip("set LOOM_WEB_CHROME_TEST=1 for access configuration browser acceptance")
	}
	server, key := localNetworkWriteFixture(t)
	reportLocalNetworks(t, server, key, 1, []string{"192.0.2.0/24"})
	lan := submitAuthority(t, server.Runtime, previewLocalNetwork(t, server, "demo-office", "demo-access-ui-lan"))
	anyScope := PolicyScope{Mode: "any", NodeIDs: []string{}}
	submitAuthority(t, server.Runtime, Operation{Schema: 3, RequestID: "demo-access-ui-lan-policy", Operation: "policy.put", TargetKind: "policy", TargetID: "demo-office-policy", Dependencies: []string{lan.MaterialID}, Payload: NetworkPolicy{ID: "demo-office-policy", Name: "Demo office access", ServiceID: "demo-office", Action: "allow", EntryScope: anyScope, RelayScope: anyScope}})
	second := authorityService("demo-api", "demo-access-ui-api")
	second.Payload = Service{ID: "demo-api", Name: "Demo API", Kind: "internet", RestrictToProbeTargets: new(false)}
	api := submitAuthority(t, server.Runtime, second)
	submitAuthority(t, server.Runtime, Operation{Schema: 3, RequestID: "demo-access-ui-api-policy", Operation: "policy.put", TargetKind: "policy", TargetID: "demo-api-policy", Dependencies: []string{api.MaterialID}, Payload: NetworkPolicy{ID: "demo-api-policy", Name: "Demo API access", ServiceID: "demo-api", Action: "allow", EntryScope: anyScope, RelayScope: anyScope, ExitScope: &anyScope, AllowDirect: new(true), LocalEgressDevices: new([]string{})}})
	submitAuthority(t, server.Runtime, Operation{Schema: 3, RequestID: "demo-access-ui-dns", Operation: "dns_record.put", TargetKind: "dns_record", TargetID: "demo-console-record", Dependencies: []string{}, Payload: DNSRecord{ID: "demo-console-record", Name: "demo-console.loom", Addresses: []string{"192.0.2.42", "2001:db8::42"}}})
	setServiceProbeURLs(t, server.Runtime, "demo-service", "demo-access-ui-probe", "https://demo-service.example/health/"+strings.Repeat("demo", 32))
	host := httptest.NewServer(server.AdminHandler())
	defer host.Close()
	debug := openCommandChrome(t, host.URL+"/services?service=demo-service")
	waitChromeEvaluation(t, debug, `document.querySelector('#service-form')&&document.querySelector('#connection').title.includes('local writes available')`)
	accessConfigurationChromeViewport(t, debug, 1440)

	assertNavigation := func(href string) {
		t.Helper()
		waitChromeEvaluation(t, debug, fmt.Sprintf(`(()=>{const tabs=[...document.querySelectorAll('.intent-tabs a')],active=tabs.filter(a=>a.getAttribute('aria-current')==='page'),main=[...document.querySelectorAll('header nav a[aria-current="page"]')];return tabs.length===3&&active.length===1&&active[0].getAttribute('href')===%q&&main.length===1&&main[0].getAttribute('href')==='/services'&&!document.querySelector('header nav a[href="/policies"]')})()`, href))
	}
	clickTab := func(href string) {
		t.Helper()
		chromeDo(t, debug, fmt.Sprintf(`document.querySelector('.intent-tabs a[href=%q]').click();true`, href))
		assertNavigation(href)
	}
	assertNavigation("/services")
	for _, href := range []string{"/policies", "/services?tab=dns"} {
		clickTab(href)
	}
	for _, href := range []string{"/policies", "/services"} {
		chromeDo(t, debug, `history.back();true`)
		assertNavigation(href)
	}
	chromeDo(t, debug, `history.forward();true`)
	assertNavigation("/policies")
	clickTab("/services")
	chromeDo(t, debug, `document.querySelector('.service-item[href="/services?service=demo-service"]').click();true`)
	waitChromeEvaluation(t, debug, `document.querySelector('#service-form')?.elements.id.value==='demo-service'`)
	if chromeDo(t, debug, `(()=>{window.demoServiceDraft=document.querySelector('#service-form');demoServiceDraft.elements.name.value='Unsaved service name';const matcher=demoServiceDraft.querySelector('[data-matcher-value]');matcher.value='draft-only.example';matcher.dispatchEvent(new Event('input',{bubbles:true}));const search=document.querySelector('input[data-catalog-search]');for(const [query,id] of [['demo-api.example','demo-api'],['198.51.100.0/24','demo-api'],['demo-service.example','demo-service']]){search.value=query;search.dispatchEvent(new Event('input',{bubbles:true}));const visible=[...document.querySelectorAll('.service-item')].filter(row=>!row.hidden);if(visible.length!==1||!visible[0].dataset.catalogSearch.includes(id)||document.querySelector('#service-form')!==demoServiceDraft||demoServiceDraft.elements.name.value!=='Unsaved service name'||matcher.value!=='draft-only.example')return false}return true})()`) != true {
		t.Fatal("destination search ignored signed domain/IP matchers or replaced the current unsaved service editor")
	}
	clickTab("/policies")
	chromeDo(t, debug, `document.querySelector('.service-item[href="/policies?policy=demo-policy"]').click();true`)
	waitChromeEvaluation(t, debug, `document.querySelector('#policy-form')?.elements.id.value==='demo-policy'`)
	if chromeDo(t, debug, `(()=>{window.demoPolicyDraft=document.querySelector('#policy-form');demoPolicyDraft.elements.name.value='Unsaved policy name';const filter=document.querySelector('[data-policy-service-filter]');filter.value='demo-api';filter.dispatchEvent(new Event('change',{bubbles:true}));const visible=[...document.querySelectorAll('.service-item')].filter(row=>!row.hidden),order=[...demoPolicyDraft.querySelectorAll('[data-policy-scope]')].map(row=>row.dataset.policyScope);return visible.length===1&&visible[0].dataset.catalogService==='demo-api'&&document.querySelector('#policy-form')===demoPolicyDraft&&demoPolicyDraft.elements.name.value==='Unsaved policy name'&&JSON.stringify(order)===JSON.stringify(['entry_scope','relay_scope','exit_scope'])})()`) != true {
		t.Fatal("service policy filter replaced the draft, leaked another service or changed the managed path order")
	}
	chromeDo(t, debug, `(()=>{const filter=document.querySelector('[data-policy-service-filter]');filter.value='';filter.dispatchEvent(new Event('change',{bubbles:true}));document.querySelector('.service-item[data-catalog-service="demo-office"]').click();return true})()`)
	waitChromeEvaluation(t, debug, `document.querySelector('#policy-form')?.elements.id.value==='demo-office-policy'`)
	if chromeDo(t, debug, `(()=>{const form=document.querySelector('#policy-form'),hidden=[...form.querySelectorAll('[data-policy-internet]')].every(section=>section.hidden&&[...section.querySelectorAll('input,select')].every(field=>field.disabled));return hidden&&form.querySelector('[data-policy-lan]').textContent.includes('demo-gateway')&&form.elements.service_id.disabled&&form.elements.service_id.value==='demo-office'&&[...form.querySelectorAll('[data-policy-scope]:not([hidden])')].map(row=>row.dataset.policyScope).join(',')==='entry_scope,relay_scope,exit_scope'})()`) != true {
		t.Fatal("LAN policy lost its fixed service/gateway or exposed internet permissions")
	}
	clickTab("/services?tab=dns")
	chromeDo(t, debug, `(()=>{const search=document.querySelector('.dns-filters');search.elements.q.value='control.loom';search.requestSubmit();return true})()`)
	waitChromeEvaluation(t, debug, `document.querySelector('[data-dns-system="control.loom"]')&&!document.querySelector('[data-dns-record]')`)
	if chromeDo(t, debug, `(()=>{const row=document.querySelector('[data-dns-system="control.loom"]');return row.cells[2].textContent.includes('System generated')&&row.cells[2].textContent.includes('read only')&&!row.querySelector('[data-delete-kind]')})()`) != true {
		t.Fatal("system name search lost its read-only source")
	}
	chromeDo(t, debug, `(()=>{const search=document.querySelector('.dns-filters');search.elements.q.value='2001:db8::42';search.requestSubmit();return true})()`)
	waitChromeEvaluation(t, debug, `document.querySelector('[data-dns-record="demo-console-record"]')&&!document.querySelector('[data-dns-system]')`)
	chromeDo(t, debug, `document.querySelector('[data-dns-record="demo-console-record"] td:last-child a').click();true`)
	waitChromeEvaluation(t, debug, `document.querySelector('#dns-record-form')?.elements.id.value==='demo-console-record'`)
	if chromeDo(t, debug, `(()=>{const row=document.querySelector('[data-dns-record="demo-console-record"]'),form=document.querySelector('#dns-record-form');return row.cells[1].textContent.includes('192.0.2.42')&&row.cells[1].textContent.includes('2001:db8::42')&&row.cells[2].textContent.includes('Custom record')&&row.getAttribute('aria-selected')==='true'&&form.elements.addresses.value==='192.0.2.42\n2001:db8::42'&&new URLSearchParams(location.search).get('q')==='2001:db8::42'})()`) != true {
		t.Fatal("DNS search/edit lost multiple current answers, custom source or selection")
	}

	views := []struct{ name, href, selector string }{
		{"services", "/services?service=demo-api", "#service-form"},
		{"policies", "/policies?policy=demo-policy", "#policy-form"},
		{"dns", "/services?tab=dns&record=demo-console-record", "#dns-record-form"},
		{"live-paths", "/routing?service=demo-service", ".paths-devices"},
		{"administration-controls", "/ssot?section=controls", ".administration-content"},
		{"administration-administrators", "/ssot?section=administrators&add=1", ".administration-content"},
		{"administration-certificates", "/ssot?section=certificates", ".administration-content"},
		{"administration-configuration", "/ssot?section=configuration", ".administration-content"},
	}
	for _, width := range []int{1440, 390} {
		accessConfigurationChromeViewport(t, debug, width)
		for _, view := range views {
			chromeDo(t, debug, fmt.Sprintf(`history.pushState({},'',%q);dispatchEvent(new PopStateEvent('popstate'));true`, view.href))
			waitChromeEvaluation(t, debug, fmt.Sprintf(`document.querySelector(%q)`, view.selector))
			accessConfigurationChromeScreenshot(t, debug, fmt.Sprintf("%s-%d", view.name, width))
			geometry := chromeDo(t, debug, fmt.Sprintf(`(async()=>{await new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve)));const form=document.querySelector(%q),fields=[...form.querySelectorAll('input:not([type=hidden]),select,textarea,button[type=submit]')].filter(field=>field.getClientRects().length&&getComputedStyle(field).visibility!=='hidden'),outside=fields.filter(field=>{const r=field.getBoundingClientRect();return r.left<0||r.right>innerWidth+1}).map(field=>({name:field.name||field.type,left:field.getBoundingClientRect().left,right:field.getBoundingClientRect().right})),tables=[...document.querySelectorAll('.table-wrap')].map(wrap=>({width:wrap.clientWidth,scroll:wrap.scrollWidth,overflow:getComputedStyle(wrap).overflowX}));const sidebar=document.querySelector('.administration-sidebar'),menuOutside=sidebar?[...sidebar.querySelectorAll('nav a')].filter(link=>{const r=link.getBoundingClientRect(),b=sidebar.getBoundingClientRect();return r.top<b.top||r.bottom>b.bottom||r.left<b.left||r.right>b.right}).map(link=>link.textContent):[];return {passed:document.documentElement.scrollWidth<=innerWidth+1&&outside.length===0&&menuOutside.length===0&&tables.every(wrap=>wrap.scroll<=wrap.width+1||['auto','scroll'].includes(wrap.overflow)),viewport:innerWidth,document:document.documentElement.scrollWidth,outside,menuOutside,tables}})()`, view.selector))
			result, ok := geometry.(map[string]any)
			if !ok || result["passed"] != true {
				t.Fatalf("page content overflows at %s/%d: %#v", view.name, width, geometry)
			}
		}
	}
}
