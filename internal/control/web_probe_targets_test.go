package control

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

// Uses the normal authority entry with the exact reviewed Service frontier.
func setServiceProbeURLs(t *testing.T, runtime *Runtime, id, request string, urls ...string) {
	t.Helper()
	p := runtime.Authority.Snapshot()
	for _, service := range p.NetworkIntent.Services {
		if service.ID != id {
			continue
		}
		service.ProbeURLs = append([]string(nil), urls...)
		state, _ := p.CurrentTarget("service", id)
		submitAuthority(t, runtime, Operation{Schema: 3, RequestID: request, Operation: "service.put", TargetKind: "service", TargetID: id, Dependencies: state.MaterialIDs, Payload: service})
		return
	}
	t.Fatal("test Service not found")
}

func TestServiceProbeFormalWriteReadbackRestartAndNoPermissionExpansion(t *testing.T) {
	server, invite, _, claim, _, _ := enrollmentAuthorityFixture(t)
	if response := enrollmentHTTP(t, server, "/enrollment/claim", claim, enrollmentTunnel(invite)); response.Code != http.StatusOK {
		t.Fatal("join", response.Code)
	}
	before, err := ProjectDeviceView(server.Runtime.Authority.Snapshot(), invite.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	setServiceProbeURLs(t, server.Runtime, "demo-service", "demo-add-service-url", "https://demo-service.example/health")
	read := func() WebSnapshot {
		t.Helper()
		response := httptest.NewRecorder()
		server.AdminHandler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/control/ui/snapshot", nil))
		var snapshot WebSnapshot
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &snapshot) != nil {
			t.Fatal("Service readback failed", response.Code)
		}
		return snapshot
	}
	check := func() {
		t.Helper()
		snapshot := read()
		if len(snapshot.Services) != 1 || !reflect.DeepEqual(snapshot.Services[0].ProbeURLs, []string{"https://demo-service.example/health"}) {
			t.Fatal("Service lost saved URLs")
		}
		for _, op := range snapshot.Capabilities.Operations {
			if op == "probe_target.put" || op == "probe_target.delete" {
				t.Fatal("retired object has a management operation")
			}
		}
		after, err := ProjectDeviceView(server.Runtime.Authority.Snapshot(), invite.DeviceID)
		if err != nil || !reflect.DeepEqual(testDeviceExecution(before).Routes, testDeviceExecution(after).Routes) || !reflect.DeepEqual(testDeviceExecution(before).RuntimeProfile, testDeviceExecution(after).RuntimeProfile) || !reflect.DeepEqual(before.TransportCredentials, after.TransportCredentials) {
			t.Fatal("measurement configuration changed execution permission", err)
		}
		previousExecution, beforeErr := RuntimeExecutionDigest(before)
		nextExecution, afterErr := RuntimeExecutionDigest(after)
		if beforeErr != nil || afterErr != nil || previousExecution != nextExecution {
			t.Fatal("probe URL changed execution comparison", beforeErr, afterErr)
		}
		if len(testDeviceExecution(after).BusinessProbeTargets) != 1 || len(testDeviceExecution(after).BusinessProbeTargets[0].Targets) != 1 {
			t.Fatal("Service URL not delivered")
		}
	}
	check()
	state, _ := server.Runtime.Authority.Snapshot().CurrentTarget("service", "demo-service")
	original, err := server.Runtime.Authority.Material(state.MaterialIDs[0])
	if err != nil {
		t.Fatal(err)
	}
	root := server.Runtime.Authority.root
	server.Runtime.Close()
	server.Runtime, err = OpenRuntime(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { server.Runtime.Close() }()
	check()
	again, err := server.Runtime.Authority.Material(state.MaterialIDs[0])
	if err != nil || !bytes.Equal(original, again) {
		t.Fatal("restart changed signed bytes", err)
	}
	op := Operation{Schema: 3, RequestID: "demo-retired-probe", Operation: "probe_target.put", TargetKind: "probe_target", TargetID: "demo-old", Dependencies: []string{}, Payload: BusinessProbeTarget{ID: "demo-old", URL: "https://demo-service.example/health"}}
	if _, err := EncodeOperation(op); err == nil {
		t.Fatal("accepted retired Probe object")
	}
}

func TestWebProbeTargetConflictsRemainVisibleWithoutRestoringPoolValue(t *testing.T) {
	f := newMaterialFixture(t)
	// Construct historical signed bytes explicitly. Current production signing
	// must reject this retired payload; historical validation keeps its meaning.
	historical := func(index int, sequence U64, previous *Material, request string, target BusinessProbeTarget, deps ...string) Material {
		value := f.sign(t, index, sequence, previous, request, "service.put", "service", target.ID, materialTestService(target.ID), deps...)
		value.Operation, value.TargetKind, value.Payload = "probe_target.put", "probe_target", target
		unsigned, err := CanonicalEncode(value.contractObject(false))
		if err != nil {
			t.Fatal(err)
		}
		value.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(f.keys[index], append([]byte(materialDomain), unsigned...)))
		if err := VerifyMaterial(value, f.keys[index].Public().(ed25519.PublicKey)); err != nil {
			t.Fatal(err)
		}
		if _, err := SignMaterial(value, f.keys[index]); err == nil {
			t.Fatal("current signer created retired probe authority")
		}
		return value
	}
	target := BusinessProbeTarget{ID: "demo-probe", URL: "https://demo-original.example/health"}
	original := historical(0, 1, nil, "demo-original-probe", target)
	id := materialTestID(t, original)
	target.URL = "https://demo-left.example/health"
	left := historical(0, 2, &original, "demo-left-probe", target, id)
	target.URL = "https://demo-right.example/health"
	right := historical(1, 1, nil, "demo-right-probe", target, id)
	for _, facts := range [][]Material{{original, left, right}, {right, left, original}} {
		p, err := Project(f.genesis, nil, facts)
		if err != nil {
			t.Fatal(err)
		}
		snapshot := testWebSnapshotWithIntent(p, true, true, true)
		state, ok := p.CurrentTarget("probe_target", target.ID)
		if !ok || !state.Conflicted || len(snapshot.UIState.Warnings) != 1 || snapshot.UIState.Warnings[0].Code != "conflicting_facts" {
			t.Fatal("probe conflict restored an ancestor or hid the conflicted target")
		}
	}
}
