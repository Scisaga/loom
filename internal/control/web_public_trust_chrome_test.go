package control

import (
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestWebChromeWebsiteRootWriteExportRestartDelete(t *testing.T) {
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
	browser := openCommandChrome(t, httpServer.URL+"/settings")
	waitChromeEvaluation(t, browser, `document.querySelector('#public-trust-form')&&document.querySelector('#connection').textContent.includes('local writes available')`)
	value := testWebsiteTrust(t, time.Now())
	der, _ := base64.RawURLEncoding.DecodeString(value.CertificateDER)
	certificate, _ := json.Marshal(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})))
	id, _ := json.Marshal(value.ID)
	chromeDo(t, browser, `(()=>{const f=document.querySelector('#public-trust-form'),transfer=new DataTransfer();transfer.items.add(new File([`+string(certificate)+`],'demo-website-root.pem',{type:'application/x-pem-file'}));f.elements.certificate.files=transfer.files;f.requestSubmit();return true})()`)
	waitChromeEvaluation(t, browser, `document.querySelector('[data-website-root]')?.dataset.websiteRoot===`+string(id))
	if got := runtime.Authority.Snapshot().NetworkIntent.PublicTrust; len(got) != 1 || got[0] != value {
		t.Fatal("browser did not persist the exact constrained root")
	}
	waitChromeEvaluation(t, browser, `(async()=>{const r=await fetch(document.querySelector('[data-website-root] a[download]').href);return r.ok&&await r.text()===`+string(certificate)+`})()`)
	runtime.Close()
	server.Runtime, err = OpenRuntime(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	chromeDo(t, browser, `location.reload();true`)
	waitChromeEvaluation(t, browser, `document.querySelector('[data-website-root]')?.dataset.websiteRoot===`+string(id))
	chromeDo(t, browser, `window.confirm=()=>true;document.querySelector('[data-delete-kind=public_trust]').click();true`)
	waitChromeEvaluation(t, browser, `document.querySelector('#notice').textContent.includes('Deletion accepted locally')&&!document.querySelector('[data-website-root]')`)
	if len(server.Runtime.Authority.Snapshot().NetworkIntent.PublicTrust) != 0 {
		t.Fatal("browser root withdrawal did not persist")
	}
}
