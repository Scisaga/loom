package control

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"reflect"
	"sort"
	"strings"
	"testing"
)

type materialFixture struct {
	genesis  Material
	keys     []ed25519.PrivateKey
	members  []Member
	configID string
}

func newMaterialFixture(t *testing.T) materialFixture {
	t.Helper()
	fixture := materialFixture{}
	for _, suffix := range []string{"a", "b"} {
		seed := sha256.Sum256([]byte("demo-material-control-" + suffix))
		key := ed25519.NewKeyFromSeed(seed[:])
		fixture.keys = append(fixture.keys, key)
		fixture.members = append(fixture.members, Member{ControlID: "demo-control-" + suffix, NodeID: "demo-node-" + suffix, PublicKey: base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))})
	}
	config := ControlConfig{Schema: 3, NetworkID: "demo-network", Operation: "genesis", Members: fixture.members, SealedKeys: []ControlSealedKey{}}
	fixture.configID, _ = ConfigID(config)
	keyID, _ := KeyID(fixture.members[0].PublicKey)
	var err error
	fixture.genesis, err = SignMaterial(Material{Schema: 3, NetworkID: "demo-network", IssuerControlID: fixture.members[0].ControlID, IssuerKeyID: keyID, Operation: "genesis", Payload: Genesis{ControlConfig: config, NetworkIntent: EmptyNetworkIntent(), AdminCertificates: []AdminCertificate{}}}, fixture.keys[0])
	if err != nil {
		t.Fatal(err)
	}
	return fixture
}
func (fixture materialFixture) sign(t *testing.T, index int, sequence U64, previous *Material, request, operation, kind, id string, payload MaterialPayload, dependencies ...string) Material {
	t.Helper()
	keyID, _ := KeyID(fixture.members[index].PublicKey)
	prior := EmptyMaterialChainID()
	if previous != nil {
		prior, _ = MaterialID(*previous)
	}
	deps := append([]string{}, dependencies...)
	sort.Strings(deps)
	value, err := SignMaterial(Material{Schema: 3, NetworkID: "demo-network", IssuerControlID: fixture.members[index].ControlID, IssuerKeyID: keyID, ControlConfigID: fixture.configID, Sequence: sequence, PreviousMaterialID: prior, Dependencies: deps, RequestID: request, TargetKind: kind, TargetID: id, Operation: operation, Payload: payload}, fixture.keys[index])
	if err != nil {
		t.Fatal(err)
	}
	return value
}
func materialTestID(t *testing.T, value Material) string {
	t.Helper()
	id, err := MaterialID(value)
	if err != nil {
		t.Fatal(err)
	}
	return id
}
func materialTestService(id string) Service {
	return Service{ID: id, Name: "Demo service", Kind: "internet", Matchers: []ServiceMatcher{{Kind: "dns_exact", Value: id + ".example"}}}
}
func materialTestPolicy(id, service string) NetworkPolicy {
	scope := PolicyScope{Mode: "any", NodeIDs: []string{}}
	return NetworkPolicy{ID: id, Name: "Demo policy", ServiceID: service, Action: "allow", EntryScope: scope, RelayScope: scope, ExitScope: scope, AllowDirect: true, LocalEgressDevices: []string{}}
}

func TestMaterialUniqueCodecAndSignedGenesis(t *testing.T) {
	fixture := newMaterialFixture(t)
	service := fixture.sign(t, 1, 1, nil, "demo-create", "service.put", "service", "demo-service", materialTestService("demo-service"))
	for _, value := range []Material{fixture.genesis, service} {
		body, id, err := EncodeMaterial(value)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := DecodeMaterial(body)
		if err != nil || !reflect.DeepEqual(value, decoded) {
			t.Fatalf("round trip failed: %v", err)
		}
		again, id2, err := EncodeMaterial(decoded)
		if err != nil || id != id2 || !bytes.Equal(body, again) {
			t.Fatal("canonical bytes changed")
		}
	}
	body, _, _ := EncodeMaterial(fixture.genesis)
	for _, bad := range [][]byte{bytes.Replace(body, []byte(`"schema":3`), []byte(`"schema":2`), 1), bytes.Replace(body, []byte(`"schema":3`), []byte(`"Schema":3`), 1), bytes.Replace(body, []byte(`"schema":3`), []byte(`"schema":3,"sequence":"0"`), 1), bytes.Replace(body, []byte(`"services":[]`), []byte(`"services":null`), 1), bytes.Replace(body, []byte(`"dns_records":[]`), []byte(`"dns_records":[{}]`), 1)} {
		if _, err := DecodeMaterial(bad); err == nil {
			t.Fatal("non-current or ambiguous genesis accepted")
		}
	}
	changed := fixture.genesis
	value := changed.Payload.(Genesis)
	value.ControlConfig.NetworkID = "demo-other"
	changed.Payload = value
	if VerifyMaterial(changed, fixture.keys[0].Public().(ed25519.PublicKey)) == nil {
		t.Fatal("signed nested genesis alteration accepted")
	}
	unknown := fixture.genesis
	value = unknown.Payload.(Genesis)
	value.ControlConfig.Members = append([]Member{}, value.ControlConfig.Members...)
	value.ControlConfig.Members[1].NodeID = value.ControlConfig.Members[0].NodeID
	unknown.Payload = value
	if _, _, err := EncodeMaterial(unknown); err == nil {
		t.Fatal("duplicate member identity accepted")
	}
}

func TestMaterialCausalReplayAndPolicyIdentityAfterDeletion(t *testing.T) {
	fixture := newMaterialFixture(t)
	a := fixture.sign(t, 0, 1, nil, "demo-service-a", "service.put", "service", "demo-service-a", materialTestService("demo-service-a"))
	aid := materialTestID(t, a)
	b := fixture.sign(t, 1, 1, nil, "demo-service-b", "service.put", "service", "demo-service-b", materialTestService("demo-service-b"))
	bid := materialTestID(t, b)
	policy := fixture.sign(t, 0, 2, &a, "demo-policy-create", "policy.put", "policy", "demo-policy", materialTestPolicy("demo-policy", "demo-service-a"), aid)
	pid := materialTestID(t, policy)
	deletion := fixture.sign(t, 0, 3, &policy, "demo-policy-delete", "policy.delete", "policy", "demo-policy", DeleteTarget{ID: "demo-policy"}, pid)
	did := materialTestID(t, deletion)
	changed := fixture.sign(t, 0, 4, &deletion, "demo-policy-recreate", "policy.put", "policy", "demo-policy", materialTestPolicy("demo-policy", "demo-service-b"), did, bid)
	if err := ValidateAdmission(changed, fixture.genesis, nil, []Material{deletion, b, policy, a}); err == nil {
		t.Fatal("deleted Policy changed Service ownership")
	}
	if err := ValidateAdmission(policy, fixture.genesis, nil, nil); !errors.Is(err, ErrMissingDependencies) {
		t.Fatalf("missing dependency not distinguished: %v", err)
	}
	pending, err := Project(fixture.genesis, nil, []Material{policy})
	if err != nil || len(pending.PendingMaterialIDs) != 1 || len(pending.NetworkIntent.Policies) != 0 {
		t.Fatalf("pending projection: %v", err)
	}
	all := []Material{a, b, policy, deletion}
	expected, err := Project(fixture.genesis, nil, all)
	if err != nil {
		t.Fatal(err)
	}
	reverse := []Material{deletion, policy, b, a, policy}
	actual, err := Project(fixture.genesis, nil, reverse)
	if err != nil || !reflect.DeepEqual(expected, actual) {
		t.Fatalf("order/duplicate changed projection: %v", err)
	}
	if len(actual.NetworkIntent.Policies) != 0 || len(actual.NetworkIntent.Services) != 2 {
		t.Fatal("deletion resurrected policy or removed unrelated services")
	}
}

func TestMaterialConflictWithdrawalAndKeyForkDoNotRestoreAncestor(t *testing.T) {
	fixture := newMaterialFixture(t)
	original := fixture.sign(t, 0, 1, nil, "demo-original", "service.put", "service", "demo-service", materialTestService("demo-service"))
	originalID := materialTestID(t, original)
	leftValue := materialTestService("demo-service")
	leftValue.Name = "Demo left"
	left := fixture.sign(t, 0, 2, &original, "demo-left", "service.put", "service", "demo-service", leftValue, originalID)
	rightValue := materialTestService("demo-service")
	rightValue.Name = "Demo right"
	right := fixture.sign(t, 1, 1, nil, "demo-right", "service.put", "service", "demo-service", rightValue, originalID)
	projection, err := Project(fixture.genesis, nil, []Material{original, left, right})
	if err != nil {
		t.Fatal(err)
	}
	state, _ := projection.CurrentTarget("service", "demo-service")
	if !state.Conflicted || len(projection.NetworkIntent.Services) != 0 {
		t.Fatal("concurrent edits restored ancestor or selected a winner")
	}
	revoke := fixture.sign(t, 1, 1, nil, "demo-delete", "service.delete", "service", "demo-service", DeleteTarget{ID: "demo-service"}, originalID)
	projection, err = Project(fixture.genesis, nil, []Material{original, left, revoke})
	if err != nil {
		t.Fatal(err)
	}
	state, _ = projection.CurrentTarget("service", "demo-service")
	if !state.Deleted || len(projection.NetworkIntent.Services) != 0 {
		t.Fatal("concurrent grant bypassed withdrawal")
	}
	fork := fixture.sign(t, 0, 2, &original, "demo-fork-delete", "service.delete", "service", "demo-service", DeleteTarget{ID: "demo-service"}, originalID)
	if err := ValidateAdmission(fork, fixture.genesis, nil, []Material{original, left}); !errors.Is(err, ErrMaterialEquivocation) {
		t.Fatalf("fork not reported after signature verification: %v", err)
	}
	unrelated := fixture.sign(t, 1, 1, nil, "demo-unrelated", "service.put", "service", "demo-other", materialTestService("demo-other"))
	projection, err = Project(fixture.genesis, nil, []Material{original, left, fork, unrelated})
	if err != nil {
		t.Fatal(err)
	}
	state, _ = projection.CurrentTarget("service", "demo-service")
	if !state.Conflicted || len(projection.NetworkIntent.Services) != 1 || projection.NetworkIntent.Services[0].ID != "demo-other" || len(projection.InvalidMaterials) != 2 {
		t.Fatal("fork restored ancestor or stopped unrelated target")
	}
	for _, prefix := range projection.Frontier {
		if prefix.KeyID == original.IssuerKeyID && prefix.Sequence != 1 {
			t.Fatal("fork advanced effective frontier")
		}
	}
}

func TestMaterialLateDependencyInvalidValuePreservedOutsideFrontier(t *testing.T) {
	fixture := newMaterialFixture(t)
	service := fixture.sign(t, 0, 1, nil, "demo-service-create", "service.put", "service", "demo-service", materialTestService("demo-service"))
	// The issuer signs a Policy without explicitly reviewing the Service fact.
	policy := fixture.sign(t, 0, 2, &service, "demo-policy-invalid", "policy.put", "policy", "demo-policy", materialTestPolicy("demo-policy", "demo-service"))
	projection, err := Project(fixture.genesis, nil, []Material{policy})
	if err != nil || len(projection.PendingMaterialIDs) != 1 {
		t.Fatal("missing predecessor was not pending")
	}
	projection, err = Project(fixture.genesis, nil, []Material{policy, service})
	if err != nil {
		t.Fatal("invalid old fact prevented valid dependency arrival", err)
	}
	if len(projection.PendingMaterialIDs) != 0 || len(projection.InvalidMaterials) != 1 || len(projection.NetworkIntent.Policies) != 0 || len(projection.NetworkIntent.Services) != 1 {
		t.Fatal("late semantic invalidity was not isolated")
	}
	for _, prefix := range projection.Frontier {
		if prefix.KeyID == service.IssuerKeyID && prefix.Sequence != 1 {
			t.Fatal("invalid fact advanced frontier")
		}
	}
}

func TestMaterialDevicePublicOperationDoesNotEncodeSecrets(t *testing.T) {
	fixture := newMaterialFixture(t)
	digest := materialTestID(t, fixture.genesis)
	key := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	value := DeviceAuthorization{ID: "demo-device", Name: "Demo device", Platform: "linux", DevicePublicKey: key, Responsibilities: []string{"access"}, PolicyIDs: []string{}, DistributionURLs: []string{}, RuntimeKey: key, TransactionID: "demo-invite", InviteMaterialID: digest, BindingMaterialID: digest}
	material := fixture.sign(t, 0, 1, nil, "demo-device-put", "device.put", "device", value.ID, value)
	operation, err := material.OperationRequest()
	if err != nil {
		t.Fatal(err)
	}
	body, err := EncodeOperation(operation)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"runtime_key", "device_public_key", "transaction_id", "platform", "binding_material_id"} {
		if strings.Contains(string(body), field) {
			t.Fatalf("public operation leaked %s", field)
		}
	}
	decoded, err := DecodeOperation(body)
	if err != nil || !reflect.DeepEqual(operation, decoded) {
		t.Fatal("public operation did not round trip", err)
	}
	operation.Payload = value
	if _, err := EncodeOperation(operation); err == nil {
		t.Fatal("management command accepted full device secrets")
	}
}

func TestMaterialEnrollmentDeviceRevocationAndImmutableBinding(t *testing.T) {
	fixture := newMaterialFixture(t)
	genesisID := materialTestID(t, fixture.genesis)
	digest := genesisID
	endpoint := EndpointGeneration{ID: "demo-endpoint", Generation: 1, OwnerControlID: "demo-control-a", Host: "demo.example", Port: 443, ServerName: "demo.example", SPKISHA256: digest, CertificateDigest: digest, Modes: []string{"bootstrap", "device"}, State: "prepared"}
	endpointFact := fixture.sign(t, 0, 1, nil, "demo-endpoint-create", "endpoint.put", "endpoint", endpoint.ID, endpoint)
	endpointPrepared := endpointFact
	endpoint.State = "serving"
	endpointFact = fixture.sign(t, 0, 2, &endpointPrepared, "demo-endpoint-serving", "endpoint.put", "endpoint", endpoint.ID, endpoint, materialTestID(t, endpointPrepared))
	invite := Invite{ID: "demo-invite", GenesisDigest: genesisID, IssuerControlID: "demo-control-a", DeviceID: "demo-device", Name: "Demo device", Responsibilities: []string{"access"}, PolicyIDs: []string{}, Medium: "qr", Endpoint: endpoint, ExpiresAt: 1000}
	inviteFact := fixture.sign(t, 0, 3, &endpointFact, "demo-invite-issue", "invite.issue", "invite", invite.ID, invite, materialTestID(t, endpointFact))
	seed := sha256.Sum256([]byte("demo-device-identity"))
	key := ed25519.NewKeyFromSeed(seed[:])
	public := base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
	binding := EnrollmentBind{TransactionID: invite.ID, InviteMaterialID: materialTestID(t, inviteFact), ClaimRequestID: "demo-claim", DevicePublicKey: public, Platform: "linux"}
	bindFact := fixture.sign(t, 0, 4, &inviteFact, "demo-bind", "invite.bind", "invite", invite.ID, binding, binding.InviteMaterialID)
	device := DeviceAuthorization{ID: invite.DeviceID, Name: invite.Name, Platform: "linux", DevicePublicKey: public, Responsibilities: []string{"access"}, PolicyIDs: []string{}, DistributionURLs: []string{}, RuntimeKey: base64.RawURLEncoding.EncodeToString(seed[:]), TransactionID: invite.ID, InviteMaterialID: binding.InviteMaterialID, BindingMaterialID: materialTestID(t, bindFact)}
	join := fixture.sign(t, 0, 5, &bindFact, "demo-device-join", "device.join", "device", device.ID, device, device.BindingMaterialID)
	history := []Material{endpointPrepared, endpointFact, inviteFact, bindFact, join}
	projection, err := Project(fixture.genesis, nil, history)
	if err != nil {
		t.Fatal(err)
	}
	if len(projection.DeviceAuthorizations) != 1 || len(projection.InvalidMaterials) != 0 || len(projection.Invites) != 1 || len(projection.Bindings) != 1 {
		t.Fatalf("legitimate enrollment did not project: %#v", projection.InvalidMaterials)
	}
	cancel := fixture.sign(t, 0, 6, &join, "demo-cancel-completed", "invite.cancel", "invite", invite.ID, EnrollmentTermination{TransactionID: invite.ID, InviteMaterialID: binding.InviteMaterialID}, binding.InviteMaterialID, device.BindingMaterialID)
	if err := ValidateAdmission(cancel, fixture.genesis, nil, history); err == nil {
		t.Fatal("completed enrollment was cancelled")
	}
	revoke := fixture.sign(t, 0, 6, &join, "demo-device-revoke", "device.revoke", "device", device.ID, DeleteTarget{ID: device.ID}, materialTestID(t, join))
	history = append(history, revoke)
	projection, err = Project(fixture.genesis, nil, history)
	if err != nil || len(projection.DeviceAuthorizations) != 0 {
		t.Fatal("revoked device stayed authorized", err)
	}
	device.Name = "Demo restored"
	restore := fixture.sign(t, 0, 7, &revoke, "demo-device-restore", "device.put", "device", device.ID, device, materialTestID(t, revoke))
	if err := ValidateAdmission(restore, fixture.genesis, nil, history); err != nil {
		t.Fatal("explicit causally later regrant failed", err)
	}
	changed := device
	changed.RuntimeKey = public
	tampered := fixture.sign(t, 0, 7, &revoke, "demo-device-change-key", "device.put", "device", device.ID, changed, materialTestID(t, revoke))
	if err := ValidateAdmission(tampered, fixture.genesis, nil, history); err == nil {
		t.Fatal("ordinary update changed original RuntimeKey")
	}
	deletion := fixture.sign(t, 0, 7, &revoke, "demo-device-delete", "device.delete", "device", device.ID, DeleteTarget{ID: device.ID}, materialTestID(t, revoke))
	history = append(history, deletion)
	resurrection := fixture.sign(t, 0, 8, &deletion, "demo-device-resurrect", "device.put", "device", device.ID, device, materialTestID(t, deletion))
	if err := ValidateAdmission(resurrection, fixture.genesis, nil, history); err == nil {
		t.Fatal("permanent device tombstone was resurrected")
	}
}
