package control

import (
	"net/http/httptest"
	"os"
	"testing"
)

func TestWebChromeDNSWriteReadRestart(t *testing.T) {
	if os.Getenv("LOOM_WEB_CHROME_TEST") != "1" {
		t.Skip("requires browser command acceptance")
	}
	root, config, genesis := authorityFixture(t)
	if _, err := InitializeAuthority(root, config, genesis); err != nil {
		t.Fatal(err)
	}
	runtime, err := OpenRuntime(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	server := &Server{Runtime: runtime, Config: config}
	defer func() { server.Runtime.Close() }()
	httpServer := httptest.NewServer(server.AdminHandler())
	defer httpServer.Close()
	browser := openCommandChrome(t, httpServer.URL+"/services?tab=dns&new=1")
	waitChromeEvaluation(t, browser, `document.querySelector('#dns-record-form')&&document.querySelector('#connection').textContent.includes('local writes available')`)
	chromeDo(t, browser, `(()=>{const f=document.querySelector('#dns-record-form');f.elements.id.value='demo-web-dns';f.elements.name.value='demo-business.loom';f.elements.addresses.value='192.0.2.10\n2001:db8::10';f.requestSubmit();return true})()`)
	waitChromeEvaluation(t, browser, `document.querySelector('#notice').textContent.includes('Accepted locally')&&location.search.includes('record=demo-web-dns')`)
	records := runtime.Authority.Snapshot().NetworkIntent.DNSRecords
	if len(records) != 1 || records[0].Name != "demo-business.loom" || len(records[0].Addresses) != 2 {
		t.Fatal("browser did not persist exact record")
	}
	runtime.Close()
	server.Runtime, err = OpenRuntime(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	chromeDo(t, browser, `location.reload();true`)
	waitChromeEvaluation(t, browser, `document.querySelector('#dns-record-form')?.elements.name.value==='demo-business.loom'`)
	// Browser keeps the actual saved value visible when a reserved name fails.
	chromeDo(t, browser, `(()=>{const f=document.querySelector('#dns-record-form');f.elements.name.value='control.loom';f.requestSubmit();return true})()`)
	waitChromeEvaluation(t, browser, `document.querySelector('#dns-record-form [role=alert]').textContent&&!document.querySelector('#dns-record-form [role=alert]').textContent.includes('Submitting')`)
	if got := server.Runtime.Authority.Snapshot().NetworkIntent.DNSRecords; len(got) != 1 || got[0].Name != "demo-business.loom" {
		t.Fatal("reserved name changed current fact")
	}
	chromeDo(t, browser, `window.confirm=()=>true;document.querySelector('[data-delete-kind=dns_record]').click();true`)
	waitChromeEvaluation(t, browser, `document.querySelector('#notice').textContent.includes('Deletion accepted locally')`)
	if len(server.Runtime.Authority.Snapshot().NetworkIntent.DNSRecords) != 0 {
		t.Fatal("browser deletion did not persist")
	}
}
