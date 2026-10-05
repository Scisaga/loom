package control

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func enrollmentAuthorityFixture(t *testing.T, changes ...func(*Invite)) (*Server, Invite, string, EnrollmentClaimRequest, ed25519.PrivateKey, []string) {
	t.Helper()
	root, config, genesis := authorityFixture(t)
	if _, err := InitializeAuthority(root, config, genesis); err != nil {
		t.Fatal(err)
	}
	runtime, err := OpenRuntime(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { runtime.Close() })
	now := time.Unix(2000000000, 0).UTC()
	server := &Server{Runtime: runtime, Config: config, Now: func() time.Time { return now }}
	service := submitAuthority(t, runtime, authorityService("demo-service", "demo-create-service"))
	scope := PolicyScope{Mode: "any", NodeIDs: []string{}}
	policy := submitAuthority(t, runtime, Operation{Schema: 3, RequestID: "demo-create-policy", Operation: "policy.put", TargetKind: "policy", TargetID: "demo-policy", Dependencies: []string{service.MaterialID}, Payload: NetworkPolicy{ID: "demo-policy", Name: "Demo policy", ServiceID: "demo-service", Action: "allow", EntryScope: scope, RelayScope: scope, ExitScope: scope, AllowDirect: true, LocalEgressDevices: []string{}}})
	endpoint := EndpointGeneration{ID: "demo-entry", Generation: 1, OwnerControlID: config.ControlID, Host: "192.0.2.1", Port: 443, ServerName: "demo.example", SPKISHA256: "sha256:" + strings.Repeat("a", 64), CertificateDigest: "sha256:" + strings.Repeat("b", 64), Modes: []string{"bootstrap", "device"}, State: "prepared"}
	prepared := submitAuthority(t, runtime, Operation{Schema: 3, RequestID: "demo-prepare-endpoint", Operation: "endpoint.put", TargetKind: "endpoint", TargetID: endpoint.ID, Dependencies: []string{}, Payload: endpoint})
	endpoint.State = "serving"
	serving := submitAuthority(t, runtime, Operation{Schema: 3, RequestID: "demo-serve-endpoint", Operation: "endpoint.put", TargetKind: "endpoint", TargetID: endpoint.ID, Dependencies: []string{prepared.MaterialID}, Payload: endpoint})
	invite := Invite{ID: "demo-enrollment", GenesisDigest: config.GenesisID, IssuerControlID: config.ControlID, DeviceID: "demo-access", Name: "Demo access", Responsibilities: []string{"access"}, PolicyIDs: []string{"demo-policy"}, Medium: "qr", Endpoint: endpoint, ExpiresAt: now.Add(time.Hour).UnixMilli()}
	for _, change := range changes {
		change(&invite)
	}
	dependencies := sortedUniqueDependencies([]string{service.MaterialID, policy.MaterialID, serving.MaterialID})
	issued := submitAuthority(t, runtime, Operation{Schema: 3, RequestID: "demo-issue-invite", Operation: "invite.issue", TargetKind: "invite", TargetID: invite.ID, Dependencies: dependencies, Payload: invite})
	seed := sha256.Sum256([]byte("demo-joining-device"))
	key := ed25519.NewKeyFromSeed(seed[:])
	claim, err := SignEnrollmentClaim(EnrollmentClaimRequest{Schema: 3, NetworkID: config.NetworkID, GenesisDigest: config.GenesisID, TransactionID: invite.ID, InviteMaterialID: issued.MaterialID, RequestID: "demo-first-claim", DevicePublicKey: base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey)), Platform: "linux"}, key)
	if err != nil {
		t.Fatal(err)
	}
	return server, invite, issued.MaterialID, claim, key, []string{service.MaterialID, policy.MaterialID}
}
func enrollmentTunnel(invite Invite) tunnelIdentity {
	return tunnelIdentity{Mode: "bootstrap", TransactionID: invite.ID, EndpointID: invite.Endpoint.ID, Generation: invite.Endpoint.Generation}
}
func enrollmentHTTP(t *testing.T, server *Server, path string, value any, identity tunnelIdentity) *httptest.ResponseRecorder {
	t.Helper()
	body, err := CanonicalEncode(value)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	request = request.WithContext(context.WithValue(request.Context(), tunnelIdentityKey{}, identity))
	response := httptest.NewRecorder()
	server.DeviceHandler().ServeHTTP(response, request)
	return response
}

func TestEnrollmentClaimResumeAndPublicPolicyChange(t *testing.T) {
	server, invite, _, claim, key, policyDependencies := enrollmentAuthorityFixture(t)
	response := enrollmentHTTP(t, server, "/enrollment/claim", claim, enrollmentTunnel(invite))
	if response.Code != http.StatusOK {
		t.Fatalf("claim failed: %d %s", response.Code, response.Body.String())
	}
	var enrollment EnrollmentResponse
	if err := DecodeCanonical(response.Body.Bytes(), &enrollment, ContractDecodeLimits{MaxBytes: 8 << 20, MaxDepth: 128, MaxItems: 1 << 20}); err != nil {
		t.Fatal(err)
	}
	if enrollment.State != "completed" || enrollment.DeviceView == nil || len(enrollment.DeviceView.View.Routes) != 1 {
		t.Fatal("claim did not produce the actual authorized Direct view")
	}
	authorization := server.Runtime.Authority.Snapshot().DeviceAuthorizations[0]
	originalKey := authorization.RuntimeKey
	frontier := server.Runtime.Authority.Frontier()[0]
	root := server.Runtime.Authority.root
	server.Runtime.Close()
	runtime, err := OpenRuntime(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	server.Runtime = runtime
	resume := EnrollmentResumeRequest(claim)
	resume.Signature = ""
	resume, err = SignEnrollmentResume(resume, key)
	if err != nil {
		t.Fatal(err)
	}
	server.Now = func() time.Time { return time.UnixMilli(invite.ExpiresAt).Add(time.Hour) }
	response = enrollmentHTTP(t, server, "/enrollment/resume", resume, enrollmentTunnel(invite))
	if response.Code != http.StatusOK {
		t.Fatalf("resume failed: %s", response.Body.String())
	}
	if runtime.Authority.Frontier()[0] != frontier || runtime.Authority.Snapshot().DeviceAuthorizations[0].RuntimeKey != originalKey {
		t.Fatal("resume signed another authorization or changed the RuntimeKey")
	}
	wrong := resume
	wrong.RequestID = "demo-other-claim"
	wrong.Signature = ""
	wrong, _ = SignEnrollmentResume(wrong, key)
	response = enrollmentHTTP(t, server, "/enrollment/resume", wrong, enrollmentTunnel(invite))
	if response.Code == http.StatusOK {
		t.Fatal("resume accepted another claim request binding")
	}
	current, _ := runtime.Authority.Snapshot().CurrentTarget("device", invite.DeviceID)
	put := Operation{Schema: 3, RequestID: "demo-remove-policy", Operation: "device.put", TargetKind: "device", TargetID: invite.DeviceID, Dependencies: current.MaterialIDs, Payload: DevicePut{ID: invite.DeviceID, Name: "Demo access renamed", Responsibilities: []string{"access"}, PolicyIDs: []string{}, DistributionURLs: []string{"https://downloads.example/"}}}
	updated := submitAuthority(t, runtime, put)
	next := updated.Projection.DeviceAuthorizations[0]
	if next.RuntimeKey != originalKey || next.DevicePublicKey != authorization.DevicePublicKey || next.BindingMaterialID != authorization.BindingMaterialID || len(next.PolicyIDs) != 0 {
		t.Fatal("public update changed the private identity or retained revoked policy")
	}
	view, err := server.deviceEnvelope(invite.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	if len(view.View.Routes) != 0 || view.View.RuntimeProfile == nil {
		t.Fatal("removal did not produce a valid deny-only runtime")
	}
	put.RequestID = "demo-regrant-policy"
	put.Dependencies = sortedUniqueDependencies(append(policyDependencies, updated.MaterialID))
	public := put.Payload.(DevicePut)
	public.PolicyIDs = []string{"demo-policy"}
	put.Payload = public
	regranted := submitAuthority(t, runtime, put)
	if regranted.Projection.DeviceAuthorizations[0].RuntimeKey != originalKey {
		t.Fatal("policy regrant regenerated device key")
	}
	wire, _ := EncodeOperation(put)
	if bytes.Contains(wire, []byte(originalKey)) || bytes.Contains(wire, []byte("runtime_key")) {
		t.Fatal("public device command leaked RuntimeKey")
	}
}

func TestEnrollmentDurableBindRecoversAndExpiredClaimCannotBind(t *testing.T) {
	server, invite, inviteID, claim, key, deps := enrollmentAuthorityFixture(t)
	binding := EnrollmentBind{TransactionID: invite.ID, InviteMaterialID: inviteID, ClaimRequestID: claim.RequestID, DevicePublicKey: claim.DevicePublicKey, Platform: claim.Platform}
	bound := submitAuthority(t, server.Runtime, Operation{Schema: 3, RequestID: enrollmentRequestID("bind", invite.ID), Operation: "invite.bind", TargetKind: "invite", TargetID: invite.ID, Dependencies: sortedUniqueDependencies(append(deps, inviteID)), Payload: binding})
	if len(bound.Projection.DeviceAuthorizations) != 0 {
		t.Fatal("binding itself granted authorization")
	}
	root := server.Runtime.Authority.root
	server.Runtime.Close()
	runtime, err := OpenRuntime(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	server.Runtime = runtime
	resume := EnrollmentResumeRequest(claim)
	resume.Signature = ""
	resume, err = SignEnrollmentResume(resume, key)
	if err != nil {
		t.Fatal(err)
	}
	response := enrollmentHTTP(t, server, "/enrollment/resume", resume, enrollmentTunnel(invite))
	if response.Code != http.StatusOK || len(runtime.Authority.Snapshot().DeviceAuthorizations) != 1 {
		t.Fatalf("durable bind did not recover: %s", response.Body.String())
	}

	other, expired, _, expiredClaim, _, _ := enrollmentAuthorityFixture(t)
	other.Now = func() time.Time { return time.UnixMilli(expired.ExpiresAt) }
	response = enrollmentHTTP(t, other, "/enrollment/claim", expiredClaim, enrollmentTunnel(expired))
	if response.Code == http.StatusOK {
		t.Fatal("expired unbound invite claimed")
	}
	state, err := other.Runtime.Authority.EnrollmentState(expired.ID)
	if err != nil || state != "expired" || len(other.Runtime.Authority.Snapshot().Bindings) != 0 {
		t.Fatal("expiration did not persist without binding")
	}
}

func TestAuthorityForkEvidenceIsDurableAndStopsSigning(t *testing.T) {
	root, config, genesis := authorityFixture(t)
	if _, err := InitializeAuthority(root, config, genesis); err != nil {
		t.Fatal(err)
	}
	runtime, err := OpenRuntime(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	accepted := submitAuthority(t, runtime, authorityService("demo-one", "demo-one-request"))
	body, err := runtime.Authority.Material(accepted.MaterialID)
	if err != nil {
		t.Fatal(err)
	}
	fact, err := DecodeMaterial(body)
	if err != nil {
		t.Fatal(err)
	}
	fact.RequestID = "demo-fork-request"
	fact.TargetID = "demo-two"
	fact.Payload = authorityService("demo-two", "demo-fork-request").Payload
	fact.Signature = ""
	key, err := config.PrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	fact, err = SignMaterial(fact, key)
	if err != nil {
		t.Fatal(err)
	}
	fork, id, err := EncodeMaterial(fact)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.Authority.PutMaterial(fork); !errors.Is(err, ErrMaterialEquivocation) {
		t.Fatalf("fork was not rejected: %v", err)
	}
	stored, err := runtime.Authority.Material(id)
	if err != nil || !bytes.Equal(stored, fork) {
		t.Fatal("fork evidence was not preserved")
	}
	if runtime.Writable() || len(runtime.Authority.Snapshot().NetworkIntent.Services) != 0 {
		t.Fatal("fork retained authority or restored an ancestor")
	}
	reopened, err := OpenRuntime(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if reopened.Writable() || reopened.Authority.Frontier()[0].Sequence != 0 {
		t.Fatal("restart forgot signing fork")
	}
	bodies, err := reopened.Authority.MaterialsAfter(fact.IssuerKeyID, 0)
	if err != nil || len(bodies) != 0 {
		t.Fatal("diff RPC exposes non-contiguous fork as ordinary prefix")
	}
}

func TestObservationMonotonicPersistenceAndForkEvidence(t *testing.T) {
	server, invite, _, claim, key, _ := enrollmentAuthorityFixture(t)
	if _, err := server.Runtime.Authority.CompleteEnrollment(context.Background(), claim, false, enrollmentTunnel(invite), server.now(), server.Runtime.Config); err != nil {
		t.Fatal(err)
	}
	view, err := server.deviceEnvelope(invite.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := OpenObservationStore(root)
	if err != nil {
		t.Fatal(err)
	}
	report := DeviceReport{Schema: 3, NetworkID: server.Runtime.Config.NetworkID, DeviceID: invite.DeviceID, ReportSequence: 1, ViewDigest: view.ViewDigest, NetworkGeneration: "demo-underlay", ReportedAt: server.now().UnixMilli(), Selections: []ReportSelection{{ServiceID: "demo-service", CandidateID: view.View.Routes[0].ID}}, Observations: []Observation{}, Runtime: RuntimeReadback{State: "running", AppliedViewDigest: view.ViewDigest, ErrorCode: ""}, Components: []ComponentReadback{}}
	report, err = SignDeviceReport(report, key)
	if err != nil {
		t.Fatal(err)
	}
	public := claim.DevicePublicKey
	if err := store.Put(report, public); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(root, "observations.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put(report, public); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(filepath.Join(root, "observations.json"))
	if !bytes.Equal(before, after) {
		t.Fatal("report retry changed original signed values")
	}
	otherWriter, err := OpenObservationStore(root)
	if err != nil {
		t.Fatal(err)
	}
	fork := report
	fork.Signature = ""
	fork.Runtime.State = "stopped"
	fork, err = SignDeviceReport(fork, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put(fork, public); !errors.Is(err, ErrReportEquivocation) {
		t.Fatalf("report fork not rejected: %v", err)
	}
	store, err = OpenObservationStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(store.History()) != 2 || len(store.All()) != 0 {
		t.Fatal("report fork evidence lost or one fork was chosen")
	}
	forkBytes, _ := os.ReadFile(filepath.Join(root, "observations.json"))
	reverseRoot := t.TempDir()
	if err := os.Chmod(reverseRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	reverse, err := OpenObservationStore(reverseRoot)
	if err != nil {
		t.Fatal(err)
	}
	if err := reverse.Put(fork, public); err != nil {
		t.Fatal(err)
	}
	if err := reverse.Put(report, public); !errors.Is(err, ErrReportEquivocation) {
		t.Fatal("reverse arrival order lost the signed fork", err)
	}
	reversedBytes, _ := os.ReadFile(filepath.Join(reverseRoot, "observations.json"))
	if !bytes.Equal(forkBytes, reversedBytes) {
		t.Fatal("arrival order changed canonical signed history")
	}
	next := report
	next.ReportSequence = 3
	next.Signature = ""
	next, err = SignDeviceReport(next, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put(next, public); err != nil {
		t.Fatal(err)
	}
	stale := report
	stale.ReportSequence = 2
	stale.Signature = ""
	stale, err = SignDeviceReport(stale, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put(stale, public); !errors.Is(err, ErrReportReplay) {
		t.Fatal("older sequence overrode report high-water")
	}
	if err := otherWriter.Put(stale, public); !errors.Is(err, ErrReportReplay) {
		t.Fatal("another writer's accepted sequence was hidden by the decode cache", err)
	}
	if len(store.Verified(server.Runtime.Authority.Snapshot())) != 1 {
		t.Fatal("latest signed current-view report unavailable")
	}
	path := filepath.Join(root, "observations.json")
	valid, _ := os.ReadFile(path)
	invalid := append(append([]byte{}, valid...), '\n')
	if err := os.WriteFile(path, invalid, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.Put(next, public); err == nil {
		t.Fatal("cached report history bypassed strict file decoding")
	}
	if got, _ := os.ReadFile(path); !bytes.Equal(got, invalid) {
		t.Fatal("rejected history was overwritten from the cache")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := store.Put(next, public); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("missing history was restored from the decode cache", err)
	}
}

func TestInitialControlBindsItsOwnDeviceIdentityWithoutChangingMembership(t *testing.T) {
	server, previous, _, _, deviceKey, policyDeps := enrollmentAuthorityFixture(t)
	projection := server.Runtime.Authority.Snapshot()
	endpoint, _ := projection.CurrentTarget("endpoint", previous.Endpoint.ID)
	invite := previous
	invite.ID = "demo-control-enrollment"
	invite.DeviceID = server.Runtime.Config.NodeID
	invite.Name = "Demo combined node"
	invite.Responsibilities = []string{"access", "control"}
	invite.Medium = "ssh"
	issued := submitAuthority(t, server.Runtime, Operation{Schema: 3, RequestID: "demo-control-first-bind", Operation: "invite.issue", TargetKind: "invite", TargetID: invite.ID, Dependencies: sortedUniqueDependencies(append(policyDeps, endpoint.MaterialIDs...)), Payload: invite})
	controlKey, err := server.Runtime.Config.PrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	claim := EnrollmentClaimRequest{Schema: 3, NetworkID: server.Runtime.Config.NetworkID, GenesisDigest: server.Runtime.Config.GenesisID, TransactionID: invite.ID, InviteMaterialID: issued.MaterialID, RequestID: "demo-control-device-claim", DevicePublicKey: base64.RawURLEncoding.EncodeToString(controlKey.Public().(ed25519.PublicKey)), Platform: "linux"}
	copied, err := SignEnrollmentClaim(claim, controlKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.Runtime.Authority.CompleteEnrollment(context.Background(), copied, false, enrollmentTunnel(invite), server.now(), server.Runtime.Config); err == nil {
		t.Fatal("first binding copied the control identity key into a device")
	}
	claim.DevicePublicKey = base64.RawURLEncoding.EncodeToString(deviceKey.Public().(ed25519.PublicKey))
	signed, err := SignEnrollmentClaim(claim, deviceKey)
	if err != nil {
		t.Fatal(err)
	}
	result, err := server.Runtime.Authority.CompleteEnrollment(context.Background(), signed, false, enrollmentTunnel(invite), server.now(), server.Runtime.Config)
	if err != nil {
		t.Fatal(err)
	}
	if result.Projection.ControlConfigID != projection.ControlConfigID || len(result.Projection.Config.Members) != len(projection.Config.Members) {
		t.Fatal("ordinary first binding changed membership")
	}
	view, err := server.deviceEnvelope(invite.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	if !containsString(view.View.Responsibilities, "control") || !containsString(view.View.Responsibilities, "access") || view.View.DevicePublicKey == base64.RawURLEncoding.EncodeToString(controlKey.Public().(ed25519.PublicKey)) {
		t.Fatal("combined responsibilities lost their independent identities")
	}
}

func TestObservationEvidenceCannotBeReinitializedOrMigrated(t *testing.T) {
	root, config, genesis := authorityFixture(t)
	if _, err := InitializeAuthority(root, config, genesis); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenObservationStore(root); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "observations.json")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenObservationStore(root); err == nil {
		t.Fatal("missing report high-water history was silently reset")
	}
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenObservationStore(root); err == nil {
		t.Fatal("empty report history was accepted as an empty decode cache")
	}
	old := []byte("{\"schema\":2,\"records\":[],\"latest\":[]}")
	if err := os.WriteFile(path, old, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenObservationStore(root); err == nil {
		t.Fatal("old report evidence entered current decoder")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(after, old) {
		t.Fatal("rejected report evidence was changed")
	}
}
