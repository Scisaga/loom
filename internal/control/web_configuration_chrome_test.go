package control

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"
	"time"
)

func configurationTestServer(t *testing.T) (*Server, materialFixture, []Material) {
	t.Helper()
	f, facts, _ := conflictTestFacts(t)
	authorities, configs := materialAuthorities(t, f)
	for _, fact := range facts {
		raw, _, _ := EncodeMaterial(fact)
		if _, err := authorities[0].PutMaterial(raw); err != nil {
			t.Fatal(err)
		}
	}
	runtime, err := OpenRuntime(authorities[0].root, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { runtime.Close() })
	return &Server{Runtime: runtime, Config: configs[0]}, f, facts
}

func TestWebChromeConfigurationConflictEditStaleRefreshAndReadback(t *testing.T) {
	if os.Getenv("LOOM_WEB_CHROME_TEST") != "1" {
		t.Skip("set LOOM_WEB_CHROME_TEST=1 for configuration browser acceptance")
	}
	server, f, facts := configurationTestServer(t)
	web := httptest.NewServer(server.AdminHandler())
	defer web.Close()
	debug := openCommandChrome(t, web.URL+"/ssot#configuration-state")
	waitChromeEvaluation(t, debug, `document.querySelector('[data-configuration-target="service:demo-service"] [data-configuration-choice]')`)
	chromeDo(t, debug, `(()=>{document.querySelector('[data-configuration-target="service:demo-service"] summary').click();document.querySelector('[data-configuration-choice]').click();const form=document.querySelector('[data-configuration-form]');form.querySelector('[data-value-field=name]').value='Demo browser final';form.elements.reviewed.checked=true;return true})()`)
	// A newer remote edit supersedes a reviewed source before submission. The
	// real authority must reject it, and the browser must retain the draft.
	value := materialTestService("demo-service")
	value.Name = "Demo new source"
	third := f.sign(t, 1, 2, &facts[2], "demo-third", "service.put", "service", value.ID, value, materialTestID(t, facts[2]))
	raw, _, _ := EncodeMaterial(third)
	if _, err := server.Runtime.Authority.PutMaterial(raw); err != nil {
		t.Fatal(err)
	}
	chromeDo(t, debug, `(()=>{document.querySelector('[data-configuration-form]').requestSubmit();return true})()`)
	waitChromeEvaluation(t, debug, `document.querySelector('[data-configuration-form] [role=alert]').textContent.includes('stale')`)
	if chromeDo(t, debug, `document.querySelector('[data-value-field=name]').value==='Demo browser final'`) != true {
		t.Fatal("stale submission discarded reviewed draft")
	}
	chromeDo(t, debug, `(()=>{document.querySelector('[data-configuration-refresh]').click();return true})()`)
	waitChromeEvaluation(t, debug, `document.querySelector('[data-configuration-form]')&&JSON.parse(document.querySelector('[data-configuration-form]').dataset.review).conflicts.includes('`+materialTestID(t, third)+`')`)
	if chromeDo(t, debug, `document.querySelector('[data-value-field=name]').value==='Demo browser final'&&!document.querySelector('[data-configuration-form]').elements.reviewed.checked`) != true {
		t.Fatal("refresh lost the final draft or silently approved new sources")
	}
	chromeDo(t, debug, `(()=>{const form=document.querySelector('[data-configuration-form]');form.elements.reviewed.checked=true;form.requestSubmit();return true})()`)
	waitChromeEvaluation(t, debug, `!document.querySelector('[data-configuration-form]')&&document.querySelector('[data-configuration-target="service:demo-service"]').textContent.includes('Effective here')`)
	reopened, err := OpenAuthority(server.Runtime.Authority.root)
	if err != nil || len(reopened.Snapshot().NetworkIntent.Services) != 1 || reopened.Snapshot().NetworkIntent.Services[0].Name != "Demo browser final" {
		t.Fatal("normal browser resolution did not persist", err)
	}
	target, _ := reopened.Snapshot().CurrentTarget("service", value.ID)
	original, err := reopened.Material(target.MaterialIDs[0])
	if err != nil {
		t.Fatal(err)
	}
	signed, err := DecodeMaterial(original)
	if err != nil || signed.Operation != "conflict.resolve" || !bytes.Equal(original, mustMaterialBytes(t, signed)) {
		t.Fatal("UI replaced original signed facts or used ordinary put", err)
	}
	resolution := signed.Payload.(ConflictResolution)
	want := []string{materialTestID(t, facts[1]), materialTestID(t, third)}
	if !reflect.DeepEqual(resolution.Conflicts, sortedUniqueStrings(want)) {
		t.Fatal("resolution did not reference exactly the current sources")
	}
	chromeDo(t, debug, `(()=>{history.pushState({},'','/services?service=demo-service');dispatchEvent(new PopStateEvent('popstate'));return true})()`)
	waitChromeEvaluation(t, debug, `document.querySelector('#service-form [name=name]')?.value==='Demo browser final'`)
	leftDeleteValue, rightDeleteValue := materialTestService("demo-delete-service"), materialTestService("demo-delete-service")
	leftDeleteValue.Name, rightDeleteValue.Name = "Demo delete left", "Demo delete right"
	leftDelete := f.sign(t, 0, 4, &signed, "demo-delete-left", "service.put", "service", leftDeleteValue.ID, leftDeleteValue)
	rightDelete := f.sign(t, 1, 3, &third, "demo-delete-right", "service.put", "service", rightDeleteValue.ID, rightDeleteValue)
	for _, value := range []Material{leftDelete, rightDelete} {
		if _, err := server.Runtime.Authority.PutMaterial(mustMaterialBytes(t, value)); err != nil {
			t.Fatal(err)
		}
	}
	chromeDo(t, debug, `(()=>{history.pushState({},'','/ssot#configuration-state');dispatchEvent(new PopStateEvent('popstate'));document.querySelector('[data-configuration-refresh]').click();return true})()`)
	waitChromeEvaluation(t, debug, `document.querySelector('[data-configuration-delete="service:demo-delete-service"]')`)
	chromeDo(t, debug, `(()=>{document.querySelector('[data-configuration-delete="service:demo-delete-service"]').click();document.querySelector('[data-configuration-refresh]').click();return true})()`)
	waitChromeEvaluation(t, debug, `document.querySelector('[data-configuration-form] h4')?.textContent==='Review deletion'`)
	chromeDo(t, debug, `(()=>{const form=document.querySelector('[data-configuration-form]');form.elements.reviewed.checked=true;form.requestSubmit();return true})()`)
	waitChromeEvaluation(t, debug, `!document.querySelector('[data-configuration-form]')&&document.querySelector('[data-configuration-target="service:demo-delete-service"]').textContent.includes('Deleted')`)
	deletion, _ := server.Runtime.Authority.Snapshot().CurrentTarget("service", leftDeleteValue.ID)
	deleteOriginal, err := DecodeMaterial(mustAuthorityOriginal(t, server.Runtime.Authority, deletion.MaterialIDs[0]))
	if err != nil {
		t.Fatal(err)
	}
	deletePayload := deleteOriginal.Payload.(ConflictResolution)
	if deleteOriginal.Operation != "conflict.resolve" || deletePayload.Action != "delete" || deletePayload.Value != nil {
		t.Fatal("browser deletion used an ambiguous value or bypassed resolution")
	}
}

func mustAuthorityOriginal(t *testing.T, a *Authority, id string) []byte {
	t.Helper()
	raw, err := a.Material(id)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func mustMaterialBytes(t *testing.T, value Material) []byte {
	t.Helper()
	raw, _, err := EncodeMaterial(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestConfigurationImpactUsesPausedOriginalsAndPendingInvitations(t *testing.T) {
	f, history, device := conflictTestJoinedDevice(t)
	service := f.sign(t, 0, 6, &history[4], "demo-service", "service.put", "service", "demo-service", materialTestService("demo-service"))
	policy := f.sign(t, 0, 7, &service, "demo-policy", "policy.put", "policy", "demo-policy", materialTestPolicy("demo-policy", "demo-service"), materialTestID(t, service))
	device.PolicyIDs = []string{"demo-policy"}
	assigned := f.sign(t, 0, 8, &policy, "demo-assign", "device.put", "device", device.ID, device, materialTestID(t, history[4]), materialTestID(t, policy), materialTestID(t, service))
	invite := history[2].Payload.(Invite)
	invite.ID, invite.DeviceID, invite.PolicyIDs = "demo-pending", "demo-next-device", device.PolicyIDs
	pending := f.sign(t, 0, 9, &assigned, "demo-pending", "invite.issue", "invite", invite.ID, invite, materialTestID(t, history[1]), materialTestID(t, policy), materialTestID(t, service))
	leftValue, rightValue := materialTestService("demo-service"), materialTestService("demo-service")
	leftValue.Name, rightValue.Name = "Demo left", "Demo right"
	left := f.sign(t, 0, 10, &pending, "demo-left", "service.put", "service", "demo-service", leftValue, materialTestID(t, service))
	right := f.sign(t, 1, 1, nil, "demo-right", "service.put", "service", "demo-service", rightValue, materialTestID(t, service))
	authorities, configs := materialAuthorities(t, f)
	for _, fact := range append(history, service, policy, assigned, pending, left, right) {
		raw, _, _ := EncodeMaterial(fact)
		if _, err := authorities[0].PutMaterial(raw); err != nil {
			t.Fatal(err)
		}
	}
	review, err := authorities[0].configurationReview(configs[0].ControlID, time.UnixMilli(0))
	if err != nil {
		t.Fatal(err)
	}
	var row WebConfigurationRow
	for _, value := range review.Rows {
		if value.Target.TargetKind == "service" && value.Target.TargetID == "demo-service" {
			row = value
		}
	}
	if !row.Resolvable || len(row.References) != 3 {
		t.Fatal("paused projection hid Policy, device or pending Invite references", len(row.References))
	}
	for _, ref := range row.References {
		if ref.Effect == "" || ref.Kind == "invite" && (ref.ExpiresAt != 1000 || len(ref.Responsibilities) == 0 || ref.State != "open") {
			t.Fatal("impact omitted paused access or pending Invite details")
		}
	}
	raw, _ := json.Marshal(review)
	for _, secret := range []string{device.RuntimeKey, "runtime_key", "device_public_key", "binding_material_id"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatal("public conflict impact leaked private material")
		}
	}
}
