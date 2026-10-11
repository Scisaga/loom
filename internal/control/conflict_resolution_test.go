package control

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

func conflictTestFacts(t *testing.T) (materialFixture, []Material, []string) {
	t.Helper()
	f := newMaterialFixture(t)
	first := f.sign(t, 0, 1, nil, "demo-original", "service.put", "service", "demo-service", materialTestService("demo-service"))
	leftValue, rightValue := materialTestService("demo-service"), materialTestService("demo-service")
	leftValue.Name, rightValue.Name = "Demo left", "Demo right"
	left := f.sign(t, 0, 2, &first, "demo-left", "service.put", "service", "demo-service", leftValue, materialTestID(t, first))
	right := f.sign(t, 1, 1, nil, "demo-right", "service.put", "service", "demo-service", rightValue, materialTestID(t, first))
	refs := []string{materialTestID(t, left), materialTestID(t, right)}
	sort.Strings(refs)
	return f, []Material{first, left, right}, refs
}

func TestConflictResolutionCanonicalPublicCommandAndSignedOriginal(t *testing.T) {
	f, facts, refs := conflictTestFacts(t)
	value := materialTestService("demo-service")
	value.Name = "Demo reviewed final value"
	payload := ConflictResolution{Conflicts: refs, Action: "put", Value: value}
	op := Operation{Schema: 3, RequestID: "demo-resolution", Operation: "conflict.resolve", TargetKind: "service", TargetID: value.ID, Dependencies: refs, Payload: payload}
	body, err := EncodeOperation(op)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeOperation(body)
	if err != nil || !reflect.DeepEqual(op, decoded) {
		t.Fatal("public resolution did not round trip", err)
	}
	for _, bad := range []string{
		strings.Replace(string(body), `"action":"put"`, `"action":"guess"`, 1),
		strings.Replace(string(body), `"action":"put"`, `"action":"delete"`, 1),
		strings.Replace(string(body), `"payload":{`, `"payload":{"winner":"demo-left",`, 1),
		strings.Replace(string(body), `"target_kind":"service"`, `"target_kind":"invite"`, 1),
	} {
		if _, err := DecodeOperation([]byte(bad)); err == nil {
			t.Fatal("accepted ambiguous or unsupported resolution")
		}
	}
	material := f.sign(t, 0, 3, &facts[1], "demo-resolution", "conflict.resolve", "service", value.ID, payload, refs...)
	raw, id, err := EncodeMaterial(material)
	if err != nil {
		t.Fatal(err)
	}
	again, err := DecodeMaterial(raw)
	if err != nil || !reflect.DeepEqual(material, again) {
		t.Fatal("signed resolution did not round trip", err)
	}
	raw2, id2, err := EncodeMaterial(again)
	if err != nil || id != id2 || !bytes.Equal(raw, raw2) {
		t.Fatal("signed original changed", err)
	}
	request, err := material.OperationRequest()
	if err != nil || !reflect.DeepEqual(op, request) {
		t.Fatal("resolution retry cannot reconstruct public command", err)
	}
}

func TestConflictResolutionCausalCoverageAndLaterConcurrentFact(t *testing.T) {
	f, facts, refs := conflictTestFacts(t)
	value := materialTestService("demo-service")
	value.Name = "Demo resolved"
	resolve := f.sign(t, 0, 3, &facts[1], "demo-resolution", "conflict.resolve", "service", value.ID, ConflictResolution{Conflicts: refs, Action: "put", Value: value}, refs...)
	if err := ValidateAdmission(resolve, f.genesis, nil, facts); err != nil {
		t.Fatal(err)
	}
	for _, originals := range [][]Material{{facts[2], resolve, facts[1], facts[0]}, append(append([]Material{}, facts...), resolve, resolve)} {
		projection, err := Project(f.genesis, nil, originals)
		state, _ := projection.CurrentTarget("service", value.ID)
		if err != nil || state.Conflicted || len(projection.NetworkIntent.Services) != 1 || !reflect.DeepEqual(projection.NetworkIntent.Services[0], value) || !reflect.DeepEqual(state.MaterialIDs, []string{materialTestID(t, resolve)}) {
			t.Fatal("resolution did not consume all concurrent values deterministically", err)
		}
	}
	ordinary := f.sign(t, 0, 3, &facts[1], "demo-bypass", "service.put", "service", value.ID, value, refs...)
	if err := ValidateAdmission(ordinary, f.genesis, nil, facts); err == nil {
		t.Fatal("ordinary save bypassed conflict review")
	}
	// The predecessor makes the left edit part of history even when omitted
	// from the explicit conflict set; implicit ancestry does not count as review.
	missing := []string{refs[0], materialTestID(t, facts[0])}
	sort.Strings(missing)
	incomplete := f.sign(t, 0, 3, &facts[1], "demo-incomplete", "conflict.resolve", "service", value.ID, ConflictResolution{Conflicts: missing, Action: "put", Value: value}, append(append([]string{}, refs...), materialTestID(t, facts[0]))...)
	if err := ValidateAdmission(incomplete, f.genesis, nil, facts); err == nil {
		t.Fatal("accepted an incomplete current conflict set")
	}
	laterValue := value
	laterValue.Name = "Demo late edit"
	later := f.sign(t, 1, 2, &facts[2], "demo-later", "service.put", "service", value.ID, laterValue, materialTestID(t, facts[2]))
	projection, err := Project(f.genesis, nil, append(append([]Material{}, facts...), resolve, later))
	state, _ := projection.CurrentTarget("service", value.ID)
	if err != nil || !state.Conflicted || len(projection.NetworkIntent.Services) != 0 {
		t.Fatal("resolution incorrectly won against a later unreviewed concurrent edit", err)
	}
	deleteFact := f.sign(t, 0, 3, &facts[1], "demo-resolve-delete", "conflict.resolve", "service", value.ID, ConflictResolution{Conflicts: refs, Action: "delete"}, refs...)
	projection, err = Project(f.genesis, nil, append(append([]Material{}, facts...), deleteFact, later))
	state, _ = projection.CurrentTarget("service", value.ID)
	if err != nil || !state.Deleted || len(projection.NetworkIntent.Services) != 0 {
		t.Fatal("reviewed deletion lost withdrawal priority", err)
	}
}

func conflictTestJoinedDevice(t *testing.T) (materialFixture, []Material, DeviceAuthorization) {
	t.Helper()
	f := newMaterialFixture(t)
	digest := materialTestID(t, f.genesis)
	endpoint := EndpointGeneration{ID: "demo-endpoint", Generation: 1, OwnerControlID: f.members[0].ControlID, Host: "demo.example", Port: 443, ServerName: "demo.example", SPKISHA256: digest, CertificateDigest: digest, Modes: []string{"bootstrap", "device"}, State: "prepared"}
	prepared := f.sign(t, 0, 1, nil, "demo-prepare", "endpoint.put", "endpoint", endpoint.ID, endpoint)
	endpoint.State = "serving"
	serving := f.sign(t, 0, 2, &prepared, "demo-serving", "endpoint.put", "endpoint", endpoint.ID, endpoint, materialTestID(t, prepared))
	invite := Invite{ID: "demo-invite", GenesisDigest: digest, IssuerControlID: f.members[0].ControlID, DeviceID: "demo-device", Name: "Demo device", Responsibilities: []string{"access"}, PolicyIDs: []string{}, Medium: "qr", Endpoint: endpoint, ExpiresAt: 1000}
	issued := f.sign(t, 0, 3, &serving, "demo-issue", "invite.issue", "invite", invite.ID, invite, materialTestID(t, serving))
	seed := sha256.Sum256([]byte("demo-resolution-device"))
	public := base64.RawURLEncoding.EncodeToString(ed25519.NewKeyFromSeed(seed[:]).Public().(ed25519.PublicKey))
	binding := EnrollmentBind{TransactionID: invite.ID, InviteMaterialID: materialTestID(t, issued), ClaimRequestID: "demo-claim", DevicePublicKey: public, Platform: "linux"}
	bound := f.sign(t, 0, 4, &issued, "demo-bind", "invite.bind", "invite", invite.ID, binding, binding.InviteMaterialID)
	device := DeviceAuthorization{ID: invite.DeviceID, Name: invite.Name, Platform: "linux", DevicePublicKey: public, Responsibilities: []string{"access"}, PolicyIDs: []string{}, DistributionURLs: []string{}, RuntimeKey: base64.RawURLEncoding.EncodeToString(seed[:]), TransactionID: invite.ID, InviteMaterialID: binding.InviteMaterialID, BindingMaterialID: materialTestID(t, bound)}
	joined := f.sign(t, 0, 5, &bound, "demo-join", "device.join", "device", device.ID, device, device.BindingMaterialID)
	return f, []Material{prepared, serving, issued, bound, joined}, device
}

func TestConflictResolutionDeviceProtectsIdentityRetryRestartAndDeletion(t *testing.T) {
	f, history, original := conflictTestJoinedDevice(t)
	leftValue, rightValue := original, original
	leftValue.Name, rightValue.Name = "Demo left", "Demo right"
	left := f.sign(t, 0, 6, &history[4], "demo-left", "device.put", "device", original.ID, leftValue, materialTestID(t, history[4]))
	right := f.sign(t, 1, 1, nil, "demo-right", "device.put", "device", original.ID, rightValue, materialTestID(t, history[4]))
	history = append(history, left, right)
	authorities, configs := materialAuthorities(t, f)
	a := authorities[0]
	for _, fact := range history {
		raw, _, _ := EncodeMaterial(fact)
		if _, err := a.PutMaterial(raw); err != nil {
			t.Fatal(err)
		}
	}
	target, _ := a.Snapshot().CurrentTarget("device", original.ID)
	public := publicDeviceValue(original)
	public.Name, public.DNSServers = "Demo reviewed", []string{"192.0.2.53"}
	op := Operation{Schema: 3, RequestID: "demo-resolve-device", Operation: "conflict.resolve", TargetKind: "device", TargetID: original.ID, Dependencies: target.MaterialIDs, Payload: ConflictResolution{Conflicts: target.MaterialIDs, Action: "put", Value: public}}
	body, err := EncodeOperation(op)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"runtime_key", "device_public_key", "transaction_id", "binding_material_id", "platform"} {
		if bytes.Contains(body, []byte(secret)) {
			t.Fatal("public resolution leaked protected device fields")
		}
	}
	for _, extra := range []string{"runtime_key", "device_public_key", "binding_material_id"} {
		bad := bytes.Replace(body, []byte(`"value":{`), []byte(`"value":{"`+extra+`":"demo-forbidden",`), 1)
		if _, err := DecodeOperation(bad); err == nil {
			t.Fatal("public resolver accepted protected fields")
		}
	}
	result, err := a.Submit(context.Background(), op, configs[0])
	if err != nil {
		t.Fatal(err)
	}
	again, err := a.Submit(context.Background(), op, configs[0])
	if err != nil || result.MaterialID != again.MaterialID {
		t.Fatal("retry signed a second resolution", err)
	}
	reopened, err := OpenAuthority(a.root)
	if err != nil {
		t.Fatal(err)
	}
	values := reopened.Snapshot().DeviceAuthorizations
	want := original
	want.Name, want.DNSServers = public.Name, public.DNSServers
	if len(values) != 1 || !reflect.DeepEqual(values[0], want) {
		t.Fatal("device resolution lost protected identity or reviewed configuration on restart")
	}
	view, err := ProjectDeviceView(reopened.Snapshot(), original.ID)
	if err != nil || view.DNSServers[0] != "192.0.2.53" {
		t.Fatal("runtime View did not consume the resolved device", err)
	}
	review, err := reopened.configurationReview(configs[0].ControlID, time.UnixMilli(0))
	raw, marshalErr := json.Marshal(review)
	if err != nil || marshalErr != nil || bytes.Contains(raw, []byte(original.RuntimeKey)) || bytes.Contains(raw, []byte("runtime_key")) || bytes.Contains(raw, []byte("device_public_key")) {
		t.Fatal("configuration review leaked private credentials", err, marshalErr)
	}
	// Recreate a concurrent public edit from the right branch, then delete the
	// resolved conflict and prove no ordinary grant resurrects its identity.
	third := f.sign(t, 1, 2, &right, "demo-third", "device.put", "device", original.ID, rightValue, materialTestID(t, right))
	thirdRaw, _, _ := EncodeMaterial(third)
	if _, err := reopened.PutMaterial(thirdRaw); err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.Submit(context.Background(), op, configs[0]); err != nil {
		t.Fatal("exact retry stopped returning its original result", err)
	}
	stale := op
	stale.RequestID = "demo-stale"
	if _, err := reopened.Submit(context.Background(), stale, configs[0]); err == nil {
		t.Fatal("stale reviewed sources overwrote a new conflict")
	}
	current, _ := reopened.Snapshot().CurrentTarget("device", original.ID)
	deletion := op
	deletion.RequestID, deletion.Dependencies, deletion.Payload = "demo-delete-resolution", current.MaterialIDs, ConflictResolution{Conflicts: current.MaterialIDs, Action: "delete"}
	deleted, err := reopened.Submit(context.Background(), deletion, configs[0])
	if err != nil {
		t.Fatal(err)
	}
	grant := Operation{Schema: 3, RequestID: "demo-resurrect", Operation: "device.put", TargetKind: "device", TargetID: original.ID, Dependencies: []string{deleted.MaterialID}, Payload: public}
	if _, err := reopened.Submit(context.Background(), grant, configs[0]); err == nil {
		t.Fatal("resolution deletion did not preserve the permanent device tombstone")
	}
}
