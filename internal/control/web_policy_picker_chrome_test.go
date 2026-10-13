package control

import (
	"net/http/httptest"
	"os"
	"testing"
)

func TestWebChromePolicyNodeTagsStayDraftAndKeepOnlyMode(t *testing.T) {
	if os.Getenv("LOOM_WEB_CHROME_TEST") != "1" {
		t.Skip("set LOOM_WEB_CHROME_TEST=1 for prototype node selection acceptance")
	}
	server, _, _, _, _, _ := enrollmentAuthorityFixture(t)
	host := httptest.NewServer(server.AdminHandler())
	defer host.Close()
	debug := openCommandChrome(t, host.URL+"/policies?new=1")
	waitChromeEvaluation(t, debug, `document.querySelector('#policy-form')`)
	if chromeDo(t, debug, `(async()=>{const {nodePickerHTML}=await import('/assets/selection.js');const f=document.querySelector('#policy-form');f.insertAdjacentHTML('beforeend',nodePickerHTML('demo_ids',[],[{id:'demo-a',name:'Alpha'},{id:'demo-b',name:'Beta'}]));const picker=f.querySelector('[data-node-picker=demo_ids]');picker.querySelector('summary').click();picker.querySelector('[data-node-choice=demo-a]').click();picker.querySelector('[data-node-choice=demo-b]').click();const selected=picker.querySelector('input[name=demo_ids]').value;picker.querySelector('[data-node-search]').value='Alpha';picker.querySelector('[data-node-search]').dispatchEvent(new Event('input',{bubbles:true}));return selected==='demo-a, demo-b'&&picker.querySelector('details').open&&picker.querySelectorAll('.selected-node-tag').length===2&&!picker.querySelector('[data-node-choice=demo-a]').closest('label').hidden&&picker.querySelector('[data-node-choice=demo-b]').closest('label').hidden})()`) != true {
		t.Fatal("tag multi-selection closed the list, lost IDs or failed search")
	}
	if chromeDo(t, debug, `(()=>{const picker=document.querySelector('[data-node-picker=demo_ids]');picker.querySelector('[data-node-remove=demo-a]').click();picker.querySelector('[data-node-remove=demo-b]').click();const f=document.querySelector('#policy-form');f.elements.entry_scope_mode.value='only';f.elements.entry_scope_mode[1].dispatchEvent(new Event('change',{bubbles:true}));return picker.querySelector('[name=demo_ids]').value===''&&f.elements.entry_scope_mode.value==='only'&&f.elements.entry_scope_ids.value===''&&document.querySelector('.services-layout .card')===null})()`) != true {
		t.Fatal("empty tag draft became unrestricted or the old directory frame survived")
	}
}
