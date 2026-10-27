package control

import (
	"fmt"
	"net/http/httptest"
	"os"
	"reflect"
	"slices"
	"testing"
)

func assertPolicyPickerPresentationChrome(t *testing.T, debug *chromeDevTools, selector string) {
	t.Helper()
	chromeDo(t, debug, fmt.Sprintf(`(()=>{const f=document.querySelector(%q);window.demoPickerForm=f;window.demoPickerIDs=[...new FormData(f).getAll('policy_id')].sort();window.demoPickerRequest=f.dataset.requestId;window.demoPickerTargets=f.dataset.targets;return true})()`, selector))
	for _, width := range []int{1440, 390} {
		accessConfigurationChromeViewport(t, debug, width)
		chromeDo(t, debug, `(()=>{const p=demoPickerForm.querySelector('.policy-picker');p.querySelector('details').open=true;const input=p.querySelector('[data-policy-search]');input.value='Demo';input.dispatchEvent(new Event('input',{bubbles:true}));p.scrollIntoView({block:'center'});return true})()`)
		if chromeDo(t, debug, `(()=>{const p=demoPickerForm.querySelector('.policy-picker'),menu=p.querySelector('.node-picker-popup'),a=p.getBoundingClientRect(),b=menu.getBoundingClientRect(),list=demoPickerForm.querySelector('[data-policy-summary-list]');return getComputedStyle(p).borderBottomLeftRadius==='0px'&&getComputedStyle(p).borderBottomRightRadius==='0px'&&getComputedStyle(menu).borderTopLeftRadius==='0px'&&getComputedStyle(menu).borderTopRightRadius==='0px'&&Math.abs(a.left-b.left)<1&&Math.abs(a.right-b.right)<1&&Math.abs(a.bottom-b.top)<=1&&list.clientHeight<=Math.min(480,innerHeight*.55)+1&&getComputedStyle(list).overflowY==='auto'&&document.documentElement.scrollWidth<=innerWidth+1})()`) != true {
			t.Fatalf("open picker seam or bounded summaries failed at %d px", width)
		}
		accessConfigurationChromeScreenshot(t, debug, fmt.Sprintf("demo-policy-picker-open-%s-%d", selector[1:], width))
		point := chromeDo(t, debug, `(()=>{const heading=demoPickerForm.querySelector('[data-device-access] h2');heading.scrollIntoView({block:'center'});const r=heading.getBoundingClientRect();return{x:r.left+r.width/2,y:r.top+r.height/2}})()`).(map[string]any)
		topologyMouseChrome(t, debug, "mousePressed", point, 0)
		topologyMouseChrome(t, debug, "mouseReleased", point, 0)
		waitChromeEvaluation(t, debug, `!demoPickerForm.querySelector('.policy-picker details').open`)
		if chromeDo(t, debug, `(()=>{const p=demoPickerForm.querySelector('.policy-picker');return p.querySelector('[data-policy-search]').value==='Demo'&&JSON.stringify([...new FormData(demoPickerForm).getAll('policy_id')].sort())===JSON.stringify(demoPickerIDs)&&getComputedStyle(p).borderBottomLeftRadius!=='0px'&&demoPickerForm.dataset.requestId===demoPickerRequest&&demoPickerForm.dataset.targets===demoPickerTargets})()`) != true {
			t.Fatal("outside click lost selection, search, reviewed dependencies or closed corners")
		}
	}
	if chromeDo(t, debug, `(()=>{const f=demoPickerForm,summary=f.querySelector('[data-selected-policy-summary]'),next=summary.querySelectorAll('[data-policy-summary-page]')[1],ids=[];do{const rows=[...summary.querySelectorAll('.selected-policy-summary:not([hidden])')];if(rows.length>3||!rows.length)return false;ids.push(...rows.map(row=>new URL(row.querySelector('.sectionhead a').href).searchParams.get('policy')));if(next.disabled)break;next.click()}while(true);return JSON.stringify(ids.sort())===JSON.stringify(demoPickerIDs)&&JSON.stringify([...new FormData(f).getAll('policy_id')].sort())===JSON.stringify(demoPickerIDs)&&summary.querySelector('[data-policy-summary-page-status]').textContent.includes('of 3')})()`) != true {
		t.Fatal("paging lost, duplicated or silently deselected a policy")
	}
	accessConfigurationChromeScreenshot(t, debug, "demo-policy-details-last-page-"+selector[1:])
	if chromeDo(t, debug, `(()=>{const f=demoPickerForm,inputs=[...f.querySelectorAll('[name=policy_id]:checked')];inputs.slice(2).forEach(input=>input.checked=false);inputs[0].dispatchEvent(new Event('change',{bubbles:true}));const summary=f.querySelector('[data-selected-policy-summary]');if(summary.dataset.page!=='0'||summary.querySelectorAll('.selected-policy-summary:not([hidden])').length!==2||!summary.querySelector('.policy-summary-pagination').hidden)return false;f.querySelector('.policy-picker details').open=true;f.querySelector('[data-policy-select-all]').click();f.querySelector('.policy-picker details').open=false;return JSON.stringify([...new FormData(f).getAll('policy_id')].sort())===JSON.stringify(demoPickerIDs)&&f.dataset.requestId===demoPickerRequest&&f.dataset.targets===demoPickerTargets})()`) != true {
		t.Fatal("selection reduction left an empty page or restore changed the draft")
	}
}

func TestWebChromeInvitationPolicyPickerDismissPagesAndPersist(t *testing.T) {
	if os.Getenv("LOOM_WEB_CHROME_TEST") != "1" {
		t.Skip("requires browser command acceptance")
	}
	fixture := newEndpointFixture(t)
	server := fixture.server
	service := submitAuthority(t, server.Runtime, authorityService("demo-service", "demo-picker-service"))
	anyScope := PolicyScope{Mode: "any", NodeIDs: []string{}}
	policy := NetworkPolicy{ID: "demo-policy", Name: "Demo policy", ServiceID: "demo-service", Action: "allow", EntryScope: anyScope, RelayScope: anyScope, ExitScope: &anyScope, AllowDirect: new(true), LocalEgressDevices: new([]string{})}
	submitAuthority(t, server.Runtime, Operation{Schema: 3, RequestID: "demo-picker-policy", Operation: "policy.put", TargetKind: "policy", TargetID: policy.ID, Dependencies: []string{service.MaterialID}, Payload: policy})
	for i := 1; i <= 8; i++ {
		extra := policy
		extra.ID, extra.Name = fmt.Sprintf("demo-paged-policy-%d", i), fmt.Sprintf("Demo paged policy %d", i)
		submitAuthority(t, server.Runtime, Operation{Schema: 3, RequestID: "demo-create-" + extra.ID, Operation: "policy.put", TargetKind: "policy", TargetID: extra.ID, Dependencies: []string{service.MaterialID}, Payload: extra})
	}
	before := server.Runtime.Authority.Frontier()
	want := []string{}
	for _, value := range server.Runtime.Authority.Snapshot().NetworkIntent.Policies {
		want = append(want, value.ID)
	}
	slices.Sort(want)
	host := httptest.NewServer(server.AdminHandler())
	defer host.Close()
	debug := openCommandChrome(t, host.URL+"/devices?new=1")
	waitChromeEvaluation(t, debug, `document.querySelector('#enrollment-form [name=endpoint]')?.options.length>0`)
	chromeDo(t, debug, `(()=>{const f=document.querySelector('#enrollment-form');f.elements.device_id.value='demo-paged-device';f.elements.name.value='Demo paged invitation';f.querySelector('.policy-picker details').open=true;f.querySelector('[data-policy-select-all]').click();return true})()`)
	assertPolicyPickerPresentationChrome(t, debug, "#enrollment-form")
	if !reflect.DeepEqual(before, server.Runtime.Authority.Frontier()) {
		t.Fatal("closing or paging the picker wrote an authorization")
	}
	chromeDo(t, debug, `document.querySelector('#enrollment-form').requestSubmit();true`)
	waitChromeEvaluation(t, debug, `location.pathname.startsWith('/devices/invites/')&&document.querySelector('#notice').textContent.includes('Accepted locally')`)
	reopened, err := OpenAuthority(server.Runtime.Authority.root)
	if err != nil {
		t.Fatal(err)
	}
	for _, invite := range reopened.Snapshot().Invites {
		if invite.DeviceID == "demo-paged-device" {
			if !reflect.DeepEqual(invite.PolicyIDs, want) {
				t.Fatal("invite dropped policies from another summary page")
			}
			return
		}
	}
	t.Fatal("paged invitation did not persist through the formal entry")
}
