package control

import (
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
)

// These display inputs isolate grouping and mode boundaries. The next test
// exercises authenticated reports, persistence and the ordinary device editor.
func TestWebChromePolicyPathOptionsStayDeviceScoped(t *testing.T) {
	if os.Getenv("LOOM_WEB_CHROME_TEST") != "1" {
		t.Skip("set LOOM_WEB_CHROME_TEST=1 for policy path presentation acceptance")
	}
	server, _, _, _, _, _ := enrollmentAuthorityFixture(t)
	host := httptest.NewServer(server.AdminHandler())
	defer host.Close()
	debug := openCommandChrome(t, host.URL+"/devices")
	waitChromeEvaluation(t, debug, `document.querySelector('.node-inventory')`)
	result := chromeDo(t, debug, `(async()=>{
 const {policyPathOptions,policyRuntimeHTML}=await import('/assets/policy-selection.js');
 const now=Date.UTC(2030,0,2,12),policy={id:'demo-policy',name:'Demo policy',service_id:'demo-service',action:'allow'},service={id:'demo-service',kind:'internet'};
 const evidence={freshness:'current',current_until:now+60000,reported_at:new Date(now).toISOString(),view_digest:'demo-view',runtime:{state:'running',applied_view_digest:'demo-view'},preference:{mode:'auto'}};
 const device=id=>({id,authorized:true,policy_ids:[policy.id],evidence:structuredClone(evidence)});
 const path=(id,owner,exit,state)=>({candidate_id:id,device:owner,service_id:service.id,final_exit:exit,availability:state,current_until:now+30000,targets:['https://demo.example/health']});
 const original={policies:[policy],services:[service],devices:[device('demo-a'),device('demo-b')],paths:[path('demo-a-one','demo-a','demo-exit-a','unavailable'),path('demo-a-two','demo-a','demo-exit-b','unavailable'),path('demo-b-one','demo-b','demo-exit-a','available')],targets:[]};
 const encoded=JSON.stringify(original),read=(p,id='demo-a',reviewed=policy)=>policyPathOptions(p,id,reviewed,now),check=(p,state,reason)=>{const result=read(p);if(result.state!==state||reason&&!result.reason.includes(reason))throw Error(JSON.stringify(result))};
 check(original,'unavailable');if(read(original,'demo-b').state!=='available'||JSON.stringify(original)!==encoded)throw Error('cross-device health or mutated projection');
 let p=structuredClone(original);p.paths[1].availability='available';check(p,'available');
 p.devices[0].evidence.preference={mode:'fixed_exit',exit:'demo-exit-a'};check(p,'unavailable','Fixed exit demo-exit-a');
 p.devices[0].evidence.preference={mode:'direct'};check(p,'unknown','no candidate');
 p.paths.push(path('demo-a-direct','demo-a','direct','available'));check(p,'available','Direct');
 p=structuredClone(original);p.paths[1].availability='unknown';check(p,'unknown','1 unknown');
 for(const change of [v=>v.devices[0].evidence.current_until=now,v=>v.devices[0].evidence.freshness='stale',v=>v.devices[0].evidence.reported_at=new Date(now+5001).toISOString(),v=>v.devices[0].evidence.runtime.applied_view_digest='demo-other-view',v=>delete v.devices[0].evidence,v=>delete v.devices[0].evidence.preference,v=>v.paths.forEach(path=>path.current_until=now),v=>v.paths.forEach(path=>path.targets=[]),v=>v.paths=v.paths.filter(path=>path.device!=='demo-a'),v=>v.devices[0].authorized=false,v=>v.devices[0].policy_ids=[],v=>v.targets=[{target_kind:'service',target_id:service.id,conflicted:true}]]){p=structuredClone(original);change(p);check(p,'unknown')}
 p=structuredClone(original);p.policies[0].name='Demo changed';check(p,'unknown','changed since this draft');
 p=structuredClone(original);p.targets=[{target_kind:'policy',target_id:policy.id,material_ids:['demo-policy-original']},{target_kind:'service',target_id:service.id,material_ids:['demo-service-original']}];const reviewed=structuredClone(p.targets);p.targets[1].material_ids=['demo-service-changed'];if(policyPathOptions(p,'demo-a',policy,now,reviewed).state!=='unknown')throw Error('new Service facts authenticated an older draft');
 p=structuredClone(original);p.policies[0].action='deny';if(read(p,'demo-a',p.policies[0]).state!=='unknown'||!read(p,'demo-a',p.policies[0]).reason.includes('denied'))throw Error('deny became a network failure');
 p=structuredClone(original);p.services[0].kind='local_network';p.devices[0].evidence.preference={mode:'fixed_exit',exit:'demo-unrelated-exit'};check(p,'unavailable','Fixed LAN gateway');
 const html=policyRuntimeHTML(policy,{projection:original,deviceID:'demo-a',now},true,true),doc=new DOMParser().parseFromString(html,'text/html'),link=doc.querySelector('a');
 if(new URL(link.href).searchParams.get('device')!=='demo-a'||new URL(link.href).searchParams.get('service')!==service.id||link.target!=='_blank'||link.hasAttribute('data-nav'))throw Error('details lost context or navigated away from a draft');
 return true;
})()`)
	if result != true {
		t.Fatalf("policy path projection escaped its device, mode or time: %#v", result)
	}
}

func TestWebChromePolicyPathsFollowReportsWithoutReplacingDraft(t *testing.T) {
	if os.Getenv("LOOM_WEB_CHROME_TEST") != "1" {
		t.Skip("set LOOM_WEB_CHROME_TEST=1 for policy runtime readback acceptance")
	}
	server, invite, _, claim, key, _ := enrollmentAuthorityFixture(t)
	var clock atomic.Int64
	clock.Store(time.Now().UTC().UnixMilli())
	server.Now = func() time.Time { return time.UnixMilli(clock.Load()).UTC() }
	if response := enrollmentHTTP(t, server, "/enrollment/claim", claim, enrollmentTunnel(invite)); response.Code != http.StatusOK {
		t.Fatal("normal enrollment failed", response.Body.String())
	}
	submitAuthority(t, server.Runtime, Operation{Schema: 3, RequestID: "demo-policy-runtime-probe", Operation: "probe_target.put", TargetKind: "probe_target", TargetID: "demo-policy-probe", Dependencies: []string{}, Payload: BusinessProbeTarget{ID: "demo-policy-probe", URL: "https://demo-service.example/health"}})
	p := server.Runtime.Authority.Snapshot()
	copy := p.NetworkIntent.Policies[0]
	copy.ID, copy.Name = "demo-draft-policy", "Demo unapplied policy"
	service, _ := p.CurrentTarget("service", copy.ServiceID)
	submitAuthority(t, server.Runtime, Operation{Schema: 3, RequestID: "demo-policy-runtime-copy", Operation: "policy.put", TargetKind: "policy", TargetID: copy.ID, Dependencies: service.MaterialIDs, Payload: copy})
	before := server.Runtime.Authority.Frontier()
	view, err := server.deviceEnvelope(invite.DeviceID)
	if err != nil || len(view.View.Routes) != 1 || len(view.View.BusinessProbeTargets) != 1 {
		t.Fatal("fixture needs one fully scoped business candidate", err)
	}
	sequence := U64(0)
	publish := func(result string, lifetime time.Duration) {
		t.Helper()
		sequence++
		at := time.Now().UTC().Truncate(time.Millisecond)
		clock.Store(at.UnixMilli())
		route := view.View.Routes[0]
		report, err := SignDeviceReport(DeviceReport{Schema: 3, NetworkID: view.View.NetworkID, DeviceID: invite.DeviceID,
			ReportSequence: sequence, ViewDigest: view.ViewDigest, ReportedAt: at.UnixMilli(), NetworkGeneration: "demo-network",
			Preference: &ReportPreference{Mode: "auto"}, Selections: []ReportSelection{},
			Observations: []Observation{{Level: "service", ServiceID: route.ServiceID, CandidateID: route.ID, SpecDigest: route.SpecDigest, NetworkGeneration: "demo-network", Target: "https://demo-service.example/health", Action: "https_request", Result: result, ObservedAt: at.UnixMilli(), ValidUntil: at.Add(lifetime).UnixMilli()}},
			Runtime:      RuntimeReadback{State: "running", AppliedViewDigest: view.ViewDigest}, Components: []ComponentReadback{}}, key)
		if err != nil {
			t.Fatal(err)
		}
		response := enrollmentHTTP(t, server, "/device/report", report, tunnelIdentity{Mode: "device", DeviceID: invite.DeviceID})
		if response.Code != http.StatusOK {
			t.Fatal("authenticated report failed", response.Body.String())
		}
	}
	publish("unavailable", 30*time.Second)
	host := httptest.NewServer(server.AdminHandler())
	defer host.Close()
	debug := openCommandChrome(t, host.URL+"/devices/"+invite.DeviceID+"?section=access")
	waitChromeEvaluation(t, debug, `document.querySelector('[data-policy-access-row="demo-policy"] [data-policy-state="unavailable"]')`)
	if chromeDo(t, debug, `document.querySelector('[data-policy-access-row="demo-policy"] td:nth-child(3) .badge').textContent==='unknown'`) != true {
		t.Fatal("candidate results fabricated a current selected Service")
	}
	for _, width := range []int{390, 1440} {
		accessConfigurationChromeViewport(t, debug, width)
		if chromeDo(t, debug, `document.documentElement.scrollWidth<=innerWidth+1&&[...document.querySelectorAll('[data-device-panel=access] .table-wrap')].every(wrap=>wrap.scrollWidth<=wrap.clientWidth+1||['auto','scroll'].includes(getComputedStyle(wrap).overflowX))`) != true {
			t.Fatalf("policy path details overflowed the device page at %d px", width)
		}
	}
	chromeDo(t, debug, `document.querySelector('[data-policy-access-row="demo-policy"] [data-policy-runtime] a').click();true`)
	waitChromeEvaluation(t, debug, `location.pathname==='/routing'&&new URLSearchParams(location.search).get('device')==='`+invite.DeviceID+`'&&new URLSearchParams(location.search).get('service')==='demo-service'&&document.querySelector('.paths-detail')`)
	chromeDo(t, debug, `history.back();true`)
	waitChromeEvaluation(t, debug, `document.querySelector('[data-device-panel=access]:not([hidden])')`)
	chromeDo(t, debug, `document.querySelector('[href="/devices/`+invite.DeviceID+`?edit=access"]').click();true`)
	waitChromeEvaluation(t, debug, `document.querySelector('[data-selected-policy-summary] [data-policy-state="unavailable"]')`)
	if chromeDo(t, debug, `(()=>{const form=document.querySelector('#device-policy-form'),link=form.querySelector('[data-selected-policy-summary] [data-policy-runtime] a');return !form.querySelector('[value=demo-policy]').disabled&&link.target==='_blank'&&!link.hasAttribute('data-nav')})()`) != true {
		t.Fatal("runtime failure disabled valid authorization or details discarded the draft")
	}
	chromeDo(t, debug, `(()=>{window.confirm=()=>true;window.demoPolicyForm=document.querySelector('#device-policy-form');window.demoPolicyRequest=demoPolicyForm.dataset.requestId;window.demoPolicyTargets=demoPolicyForm.dataset.targets;demoPolicyForm.querySelector('.policy-picker details').open=true;demoPolicyForm.querySelector('[value=demo-draft-policy]').click();demoPolicyForm.querySelector('.invitation-settings').open=true;const name=demoPolicyForm.elements.name;name.value='Demo retained draft';name.focus();name.setSelectionRange(2,5);return true})()`)
	waitChromeEvaluation(t, debug, `document.querySelector('[data-selected-policy-summary] [data-policy-runtime="demo-draft-policy"]')?.textContent.includes('not applied')`)
	publish("available", 8*time.Second)
	waitChromeEvaluation(t, debug, `document.querySelector('.policy-picker [data-policy-runtime="demo-policy"]')?.dataset.policyState==='available'`)
	if chromeDo(t, debug, `(()=>{const form=document.querySelector('#device-policy-form');return form===demoPolicyForm&&form.dataset.requestId===demoPolicyRequest&&form.dataset.targets===demoPolicyTargets&&form.elements.name.value==='Demo retained draft'&&document.activeElement===form.elements.name&&form.elements.name.selectionStart===2&&form.elements.name.selectionEnd===5&&form.querySelector('[value=demo-draft-policy]').checked&&!form.querySelector('[value=demo-policy]').checked&&form.querySelector('[data-selected-policy-summary] [data-policy-state="unknown"]')!==null})()`) != true {
		t.Fatal("live recovery replaced the form, changed the draft or borrowed another Policy's outcome", chromeDo(t, debug, `(()=>{const form=document.querySelector('#device-policy-form');return {same:form===demoPolicyForm,request:form.dataset.requestId===demoPolicyRequest,targets:form.dataset.targets===demoPolicyTargets,name:form.elements.name.value,active:document.activeElement?.name,start:form.elements.name.selectionStart,end:form.elements.name.selectionEnd,draft:form.querySelector('[value=demo-draft-policy]').checked,original:form.querySelector('[value=demo-policy]').checked,summary:form.querySelector('[data-selected-policy-summary]').textContent}})()`))
	}
	chromeDo(t, debug, `demoPolicyForm.querySelector('[value=demo-policy]').click();true`)
	waitChromeEvaluation(t, debug, `document.querySelector('[data-selected-policy-summary] [data-policy-state="available"]')`)
	accessConfigurationChromeScreenshot(t, debug, "demo-policy-path-options")
	chromeDo(t, debug, `demoPolicyForm.querySelector('.policy-picker details').open=false;true`)
	accessConfigurationChromeScreenshot(t, debug, "demo-policy-runtime-summary")
	// Server time and its live projection remain fixed. The original sample's
	// local deadline must still update the hint inside the retained form.
	waitChromeEvaluation(t, debug, `document.querySelector('[data-selected-policy-summary] [data-policy-state="unknown"]')`)
	if !reflect.DeepEqual(before, server.Runtime.Authority.Frontier()) {
		t.Fatal("runtime display or draft editing wrote authorization facts")
	}
}
