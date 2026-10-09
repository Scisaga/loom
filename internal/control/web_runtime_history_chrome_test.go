package control

import "testing"

// The enclosing test joins through the private endpoint and submits signed
// running/error reports. This tests their ordinary browser history readback.
func assertChromeRuntimeHistory(t *testing.T, debug *chromeDevTools) {
	t.Helper()
	waitChromeEvaluation(t, debug, `document.querySelectorAll('[data-runtime-history="demo-browser-device"] .runtime-hour').length===24&&document.querySelector('[data-runtime-history="demo-browser-device"] .runtime-hour.error')`)
	if chromeDo(t, debug, `(()=>{const history=document.querySelector('[data-runtime-history="demo-browser-device"]');return history.closest('tr').textContent.includes('Runtime: error')&&history.querySelectorAll('.runtime-hour.missing').length===23&&history.querySelector('.runtime-hour.error').title.includes('demo-execution-failed')&&history.textContent.includes('not uptime')})()`) != true {
		t.Fatal("runtime history inferred uptime, filled missing hours, or lost the actual error")
	}
	if chromeDo(t, debug, `(async()=>{const response=await fetch('/api/control/ui/runtime-history?device=demo-browser-device'),value=await response.json(),sample=value.buckets.find(v=>v.sample)?.sample;const repeated=await fetch('/api/control/ui/runtime-history?device=demo-browser-device&device=demo-browser-device'),outside=await fetch('/api/control/ui/runtime-history?device=demo-unassigned-device'),extra=await fetch('/api/control/ui/runtime-history?device=demo-browser-device&window=all');return response.ok&&value.schema===3&&sample.state==='error'&&sample.error_code==='demo-execution-failed'&&sample.report_id.startsWith('sha256:')&&sample.applied_view_digest===''&&repeated.status===400&&extra.status===400&&outside.status===404})()`) != true {
		t.Fatal("history admitted ambiguous/unauthorized queries or lost the original runtime fields")
	}
	chromeDo(t, debug, `(()=>{const input=document.querySelector('[name=q]');window.demoHistorySearch=input;input.value='Unsaved filter';input.focus();input.setSelectionRange(1,4);document.querySelector('[data-runtime-history-retry="demo-browser-device"]').click();return true})()`)
	waitChromeEvaluation(t, debug, `document.querySelector('[data-runtime-history="demo-browser-device"] .runtime-hour.error')`)
	if chromeDo(t, debug, `document.querySelector('[name=q]')===demoHistorySearch&&demoHistorySearch.value==='Unsaved filter'&&demoHistorySearch.selectionStart===1&&demoHistorySearch.selectionEnd===4`) != true {
		t.Fatal("history refresh lost the unsubmitted device filter")
	}
	chromeDo(t, debug, `(()=>{document.querySelector('a[href="/devices/demo-browser-device"]').click();return true})()`)
	waitChromeEvaluation(t, debug, `location.pathname==='/devices/demo-browser-device'&&document.querySelector('[data-runtime-history="demo-browser-device"] .runtime-hour.error')`)
	chromeDo(t, debug, `(()=>{window.confirm=()=>true;document.querySelector('#device-policy-form [data-revoke-device]').click();return true})()`)
	waitChromeEvaluation(t, debug, `(async()=>{const response=await fetch('/api/control/ui/runtime-history?device=demo-browser-device');return response.status===404&&!document.querySelector('[data-runtime-history="demo-browser-device"]')})()`)
}
