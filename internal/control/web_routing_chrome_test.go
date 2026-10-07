package control

import "testing"

// Called after the ordinary browser invitation, private claim and signed report.
func assertChromeLivePaths(t *testing.T, debug *chromeDevTools) {
	t.Helper()
	chromeDo(t, debug, `(()=>{history.pushState({},'','/routing?service=demo-service');dispatchEvent(new PopStateEvent('popstate'));return true})()`)
	waitChromeEvaluation(t, debug, `document.querySelector('[data-paths-device="demo-browser-device"]')&&document.querySelector('[data-service="demo-unrelated-service"]')`)
	if chromeDo(t, debug, `(()=>{const row=document.querySelector('[data-paths-device="demo-browser-device"]');return row.textContent.includes('Demo browser policy')&&row.textContent.includes('Reported: Direct')&&row.textContent.includes('Current result unknown')&&!document.body.innerText.includes('Fresh')})()`) != true {
		t.Fatal("Live paths lost the assigned Policy, manufactured current health or still uses legacy scopes")
	}
	chromeDo(t, debug, `(()=>{const form=document.querySelector('[name=q]').form;form.elements.q.value='demo-browser-device';form.requestSubmit();[...document.querySelectorAll('.paths-filters a')].find(a=>a.textContent==='Unconfirmed route / target').click();document.querySelector('[data-paths-device="demo-browser-device"] a').click();return true})()`)
	waitChromeEvaluation(t, debug, `document.querySelector('.paths-detail')&&document.querySelector('.paths-current')?.textContent.includes('Current route unknown')`)
	if chromeDo(t, debug, `document.querySelector('[data-routing-preference]')?.textContent==='Mode: not reported'`) != true {
		t.Fatal("a Direct selection was used to infer a routing preference")
	}
	if chromeDo(t, debug, `(()=>{const back=new URL(document.querySelector('[data-paths-back]').href);return back.searchParams.get('service')==='demo-service'&&back.searchParams.get('q')==='demo-browser-device'&&back.searchParams.get('filter')==='unconfirmed'&&!back.searchParams.has('device')&&document.querySelectorAll('.paths-detail select').length===0&&document.querySelector('.paths-policy').textContent.includes('Any eligible node')})()`) != true {
		t.Fatal("detail lost the Service/filter return context or reintroduced device/Service choosers")
	}
	chromeDo(t, debug, `(()=>{[...document.querySelectorAll('[role=tab]')].find(a=>a.textContent==='Historical samples').click();[...document.querySelectorAll('.paths-history-select a')].find(a=>a.textContent==='https://demo-service.example/zero-duration').click();return true})()`)
	waitChromeEvaluation(t, debug, `document.querySelectorAll('.paths-hour').length===24&&[...document.querySelectorAll('.paths-hour')].some(v=>v.title.includes('0 ms'))`)
	if chromeDo(t, debug, `(async()=>{const q=new URLSearchParams(location.search);q.delete('q');q.delete('filter');q.delete('tab');const candidate=document.querySelector('.paths-history-select a').href;const id=new URL(candidate).searchParams.get('candidate');q.set('candidate',id);q.set('device','demo-browser-device');const response=await fetch('/api/control/ui/path-history?'+q);const body=await response.json();const sample=body.buckets.find(v=>v.observation)?.observation;const malformed=await fetch('/api/control/ui/path-history?'+q+'&service=demo-service');const outside=new URLSearchParams(q);outside.set('target','https://other.example/');const rejected=await fetch('/api/control/ui/path-history?'+outside);return response.ok&&sample?.result==='available'&&sample.duration_ms===0&&malformed.status===400&&rejected.status===404})()`) != true {
		t.Fatal("history lost original zero duration or admitted an ambiguous/unauthorized scope")
	}
	chromeDo(t, debug, `(()=>{document.querySelector('[data-paths-back]').click();return true})()`)
	waitChromeEvaluation(t, debug, `!document.querySelector('.paths-detail')&&document.querySelector('[name=q]')?.value==='demo-browser-device'&&document.querySelector('.paths-filters [aria-current=true]')?.textContent==='Unconfirmed route / target'`)
	chromeDo(t, debug, `(()=>{history.back();return true})()`)
	waitChromeEvaluation(t, debug, `document.querySelector('.paths-detail')&&new URLSearchParams(location.search).get('tab')==='history'`)
	chromeDo(t, debug, `(()=>{history.forward();return true})()`)
	waitChromeEvaluation(t, debug, `document.querySelector('[data-paths-device="demo-browser-device"]')`)
	chromeDo(t, debug, `(()=>{document.querySelector('[data-service="demo-unrelated-service"]').click();return true})()`)
	if chromeDo(t, debug, `(()=>{const q=new URLSearchParams(location.search);return document.querySelectorAll('[data-paths-device]').length===0&&document.querySelector('[data-service="demo-unrelated-service"]').textContent.includes('0 assigned')&&!q.has('q')&&!q.has('filter')})()`) != true {
		t.Fatal("zero-assignment Service disappeared or kept another Service's filter")
	}
	chromeDo(t, debug, `(()=>{history.pushState({},'','/routing?service=demo-unrelated-service&device=demo-browser-device');dispatchEvent(new PopStateEvent('popstate'));return true})()`)
	if chromeDo(t, debug, `document.querySelector('.paths-detail').textContent.includes('No available Policy assigned')&&document.querySelectorAll('[data-candidate]').length===0&&!document.querySelector('.paths-route')`) != true {
		t.Fatal("unassigned deep link retained another Service's routes")
	}
	// Extra devices exercise only the bounded list renderer, not enrollment authority.
	if chromeDo(t, debug, `(async()=>{const {routingHTML,routingContext}=await import('/assets/routing.js');const snapshot=await(await fetch('/api/control/ui/snapshot')).json(),source=snapshot.devices.find(d=>d.id==='demo-browser-device');snapshot.devices=Array.from({length:25},(_,i)=>({...source,id:'demo-list-'+String(i).padStart(2,'0'),name:'Demo '+String(i).padStart(2,'0')})).reverse();const read=page=>{const doc=new DOMParser().parseFromString(routingHTML(snapshot,new URLSearchParams({service:'demo-service',page:String(page)}),Date.now()),'text/html');return [...doc.querySelectorAll('[data-paths-device]')].map(v=>v.dataset.pathsDevice)};const first=read(1),second=read(2);snapshot.policies=snapshot.policies.map(p=>p.id==='demo-policy'?{...p,action:'deny'}:p);const denied=routingContext(snapshot,new URLSearchParams({service:'demo-service'}));return first.length<25&&second.length>0&&[...first,...second].join('|')===snapshot.devices.map(d=>d.id).sort().join('|')&&denied.records.length===25&&denied.records.every(r=>!r.allowed&&!r.paths.length&&r.reason==='Access denied by Policy')})()`) != true {
		t.Fatal("bounded stable pagination or deny assignment semantics failed")
	}
	chromeDo(t, debug, `(()=>{history.pushState({},'','/devices/demo-browser-device');dispatchEvent(new PopStateEvent('popstate'));return true})()`)
}

func assertChromeWaitingForView(t *testing.T, debug *chromeDevTools) {
	t.Helper()
	chromeDo(t, debug, `(()=>{history.pushState({},'','/routing?service=demo-service&device=demo-browser-device');dispatchEvent(new PopStateEvent('popstate'));return true})()`)
	waitChromeEvaluation(t, debug, `document.querySelector('.paths-detail')?.textContent.includes('Waiting for device confirmation')`)
	if chromeDo(t, debug, `document.querySelector('.paths-detail').textContent.includes('Current route unknown')&&!document.querySelector('.paths-detail').textContent.includes('Last reported selection')`) != true {
		t.Fatal("old View report remained a current selection after the control accepted a new View")
	}
	chromeDo(t, debug, `(()=>{history.pushState({},'','/devices/demo-browser-device');dispatchEvent(new PopStateEvent('popstate'));return true})()`)
}
