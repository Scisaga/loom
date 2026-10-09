package loomcore

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"loom/internal/control"
	"loom/internal/deviceclient"
)

func androidFixture(t *testing.T, sequence uint64, deny bool, changes ...func(*control.Projection)) (deviceclient.State, []byte) {
	t.Helper()
	members := []control.Member{}
	keys := []ed25519.PrivateKey{}
	for _, suffix := range []string{"a", "b"} {
		seed := sha256.Sum256([]byte("demo-mobile-control-" + suffix))
		key := ed25519.NewKeyFromSeed(seed[:])
		keys = append(keys, key)
		members = append(members, control.Member{ControlID: "demo-control-" + suffix, NodeID: "demo-node-" + suffix, PublicKey: base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))})
	}
	keyID, _ := control.KeyID(members[1].PublicKey)
	config := control.ControlConfig{Schema: 3, NetworkID: "demo-network", Operation: "genesis", Members: members, SealedKeys: []control.ControlSealedKey{}}
	genesis, err := control.SignMaterial(control.Material{Schema: 3, NetworkID: "demo-network", IssuerControlID: members[1].ControlID, IssuerKeyID: keyID, Operation: "genesis", Payload: control.Genesis{ControlConfig: config, NetworkIntent: control.EmptyNetworkIntent(), AdminCertificates: []control.AdminCertificate{}}}, keys[1])
	if err != nil {
		t.Fatal(err)
	}
	anchor, _ := control.MaterialID(genesis)
	configID, _ := control.ConfigID(config)
	endpoint := control.EndpointGeneration{ID: "demo-entry", Generation: 1, OwnerControlID: members[1].ControlID, Host: "192.0.2.1", Port: 443, ServerName: "demo.example", SPKISHA256: "sha256:" + strings.Repeat("1", 64), CertificateDigest: "sha256:" + strings.Repeat("2", 64), Modes: []string{"bootstrap", "device"}, State: "serving"}
	invitation := control.Invite{ID: "demo-transaction", GenesisDigest: anchor, IssuerControlID: members[1].ControlID, DeviceID: "demo-access", Name: "Demo Android", Responsibilities: []string{"access"}, PolicyIDs: []string{"demo-policy"}, Medium: "qr", Endpoint: endpoint, ExpiresAt: 1893456000000}
	material, err := control.SignMaterial(control.Material{Schema: 3, NetworkID: "demo-network", IssuerControlID: members[1].ControlID, IssuerKeyID: keyID, ControlConfigID: configID, Sequence: 1, PreviousMaterialID: control.EmptyMaterialChainID(), Dependencies: []string{}, RequestID: "demo-issue", TargetKind: "invite", TargetID: invitation.ID, Operation: "invite.issue", Payload: invitation}, keys[1])
	if err != nil {
		t.Fatal(err)
	}
	invite := control.BootstrapInvite{Schema: 3, NetworkID: "demo-network", GenesisDigest: anchor, ControlProof: control.ControlProof{Genesis: genesis, Successors: []control.ControlCertificate{}}, Material: material}
	seed := sha256.Sum256([]byte("demo-mobile-device"))
	private := ed25519.NewKeyFromSeed(seed[:])
	state, err := deviceclient.NewIdentityState(invite, "android", private, "demo-claim")
	if err != nil {
		t.Fatal(err)
	}
	p, err := control.Project(genesis, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	scope := control.PolicyScope{Mode: "any", NodeIDs: []string{}}
	p.NetworkIntent.Services = []control.Service{{ID: "demo-service", Name: "Demo service", Kind: "internet", Matchers: []control.ServiceMatcher{{Kind: "dns_exact", Value: "demo.example"}}}}
	action := "allow"
	if deny {
		action = "deny"
	}
	p.NetworkIntent.Policies = []control.NetworkPolicy{{ID: "demo-policy", Name: "Demo policy", ServiceID: "demo-service", Action: action, EntryScope: scope, RelayScope: scope, ExitScope: new(scope), AllowDirect: new(true), LocalEgressDevices: new([]string{})}}
	inviteID, _ := control.MaterialID(material)
	p.DeviceAuthorizations = []control.DeviceAuthorization{{ID: invitation.DeviceID, Name: invitation.Name, Platform: "android", DevicePublicKey: state.PublicKey, Responsibilities: []string{"access"}, PolicyIDs: []string{"demo-policy"}, DistributionURLs: []string{}, RuntimeKey: members[0].PublicKey, TransactionID: invitation.ID, InviteMaterialID: inviteID, BindingMaterialID: anchor}}
	p.EndpointGenerations = []control.EndpointGeneration{endpoint}
	p.NetworkIntent.BusinessProbeTargets = []control.BusinessProbeTarget{{ID: "demo-probe", URL: "https://demo.example:8443/health"}}
	for _, change := range changes {
		change(&p)
	}
	view, err := control.ProjectDeviceView(p, invitation.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(fmt.Sprintf("demo-prefix-%d", sequence)))
	envelope, err := control.SignDeviceViewEnvelope(control.DeviceViewEnvelope{Schema: 3, NetworkID: "demo-network", GenesisDigest: anchor, IssuerControlID: members[1].ControlID, IssuerKeyID: keyID, ControlProof: invite.ControlProof, FactFrontier: []control.FactFrontier{{KeyID: keyID, Sequence: control.U64(sequence), TipMaterialID: "sha256:" + hex.EncodeToString(sum[:])}}, View: view}, keys[1])
	if err != nil {
		t.Fatal(err)
	}
	state, err = deviceclient.AcceptLKG(state, envelope)
	if err != nil {
		t.Fatal(err)
	}
	body, err := deviceclient.EncodeIdentityState(state)
	if err != nil {
		t.Fatal(err)
	}
	return state, body
}
func TestAndroidSharesAuthorityAndDerivesOnlyHostRuntime(t *testing.T) {
	state, body := androidFixture(t, 7, false)
	profileBody, err := AndroidDeviceProfile(body)
	if err != nil {
		t.Fatal(err)
	}
	var profile androidProfile
	if err := json.Unmarshal(profileBody, &profile); err != nil {
		t.Fatal(err)
	}
	if profile.Schema != 3 || profile.Name != "Demo Android" || profile.RecordID != state.LKG.ViewDigest || len(profile.Routes) != 1 || len(profile.DNS) != 0 || len(profile.BusinessProbeTargets) != 1 || profile.BusinessProbeTargets[0].Targets[0] != "https://demo.example:8443/health" {
		t.Fatal("Android authority projection changed or invented inputs")
	}
	if bytes.Contains(profileBody, []byte(`"head"`)) || bytes.Contains(profileBody, []byte(`"generation"`)) {
		t.Fatal("Android manufactured global head/floor")
	}
	var original, derived map[string]json.RawMessage
	_ = json.Unmarshal([]byte(state.LKG.View.RuntimeProfile.Config), &original)
	_ = json.Unmarshal([]byte(profile.Config), &derived)
	if !bytes.Equal(original["outbounds"], derived["outbounds"]) || len(derived["inbounds"]) == 0 || len(derived["experimental"]) == 0 || derived["dns"] != nil {
		t.Fatal("Android host adapter changed authorization or invented DNS")
	}
	var capture struct {
		Inbounds []struct {
			Exclusions []string `json:"route_exclude_address"`
		} `json:"inbounds"`
		Route struct {
			Protect bool `json:"auto_detect_interface"`
		} `json:"route"`
	}
	if json.Unmarshal([]byte(profile.Config), &capture) != nil || !capture.Route.Protect || len(capture.Inbounds) != 1 ||
		len(capture.Inbounds[0].Exclusions) != 1 || capture.Inbounds[0].Exclusions[0] != state.LKG.View.Endpoints[0].Host+"/32" {
		t.Fatal("Android captured its libbox or private management underlay")
	}
	after, err := deviceclient.EncodeIdentityState(state)
	if err != nil || !bytes.Equal(body, after) {
		t.Fatal("host projection changed authoritative state")
	}
	state.LKG.View.Endpoints[0].Host = "demo-entry.example"
	if _, err := androidRuntimeConfig(state.LKG.View, "demo-selector"); err == nil || !strings.Contains(err.Error(), "authenticated endpoint address resolution") {
		t.Fatal("Android used unresolved management names or an implicit host resolver")
	}
	state.LKG.View.DNSServers = []string{"192.0.2.53"}
	configured, err := androidRuntimeConfig(state.LKG.View, "demo-selector")
	if err != nil {
		t.Fatal("authenticated resolver did not enable the named endpoint", err)
	}
	if !strings.Contains(configured, `udp://192.0.2.53:53`) || !strings.Contains(configured, `"detour":"loom-underlay-dns"`) {
		t.Fatal("Android did not keep resolver sockets on its protected underlay")
	}
}
func TestAndroidReportReservationDoesNotChangeActiveProfileOrPermitStaleWrites(t *testing.T) {
	_, body := androidFixture(t, 7, false)
	reserved, err := ReserveAndroidReportSequence(body)
	if err != nil {
		t.Fatal(err)
	}
	first, _ := AndroidDeviceProfile(body)
	second, _ := AndroidDeviceProfile(reserved)
	if !bytes.Equal(first, second) {
		t.Fatal("reserving report restarted Android runtime")
	}
	if err := CheckAndroidDeviceStateAdvance(reserved, body); err != nil {
		t.Fatal(err)
	}
	if err := CheckAndroidDeviceStateAdvance(body, reserved); err == nil {
		t.Fatal("stale enrollment write reused report sequence")
	}
	state, err := decodeState(reserved)
	if err != nil || state.ReportSequence != 1 {
		t.Fatal("report reservation not represented in shared State")
	}
	before := append([]byte{}, reserved...)
	if _, err := (&androidIdentity{state: state}).ReserveReportSequence(); err == nil {
		t.Fatal("temporary Android adapter reserved without protected persistence")
	}
	if !bytes.Equal(before, reserved) {
		t.Fatal("reservation mutated caller bytes")
	}
}
func TestAndroidAcceptsRevokedViewAndRejectsSameFrontierChange(t *testing.T) {
	before, body := androidFixture(t, 7, false)
	revoked, next := androidFixture(t, 8, true)
	if err := CheckAndroidDeviceStateAdvance(next, body); err != nil {
		t.Fatal(err)
	}
	if _, err := AndroidDeviceProfile(next); err != nil {
		t.Fatal("empty routes were rejected by host projection")
	}
	if err := CheckAndroidDeviceStateAdvance(body, next); err == nil {
		t.Fatal("revocation rolled back")
	}
	fork, _ := androidFixture(t, 8, false)
	if _, err := deviceclient.AcceptLKG(revoked, *fork.LKG); err == nil {
		t.Fatal("same facts restored withdrawn permission")
	}
	if _, err := deviceclient.AcceptLKG(before, *revoked.LKG); err != nil {
		t.Fatal(err)
	}
}
func TestAndroidReportsActualRuntimeAndActualScopedProbe(t *testing.T) {
	_, body := androidFixture(t, 7, false)
	reserved, err := ReserveAndroidReportSequence(body)
	if err != nil {
		t.Fatal(err)
	}
	state, _ := decodeState(reserved)
	route := state.LKG.View.Routes[0]
	observations, _ := json.Marshal([]androidObservation{{CandidateID: route.ID, NetworkGeneration: "demo-network-generation", Scope: route.Scope, Result: "available", Action: "https_request", Target: "https://demo.example:8443/health", ObservedAt: "2030-01-01T00:00:00Z", ValidUntil: "2030-01-01T00:10:00Z"}})
	selections, _ := json.Marshal([]androidSelection{{Scope: route.Scope, CandidateID: route.ID}})
	runtime, _ := json.Marshal(control.RuntimeReadback{State: "running", AppliedViewDigest: state.LKG.ViewDigest})
	components, _ := json.Marshal([]control.ComponentReadback{{ComponentID: "agent", Platform: androidComponentPlatform(), Version: "demo-agent", ArtifactDigest: "sha256:" + strings.Repeat("a", 64)}, {ComponentID: "sing-box", Platform: androidComponentPlatform(), Version: "demo-native", ArtifactDigest: "sha256:" + strings.Repeat("b", 64)}})
	report, err := androidReport(state, nil, nil, observations, selections, runtime, components, "demo-network-generation", "2030-01-01T00:01:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if report.ReportSequence != 1 || report.Observations[0].SpecDigest != route.SpecDigest || report.Observations[0].Target != "https://demo.example:8443/health" || len(report.Components) != 2 || report.Components[0].Version != "demo-agent" || report.Components[1].Version != "demo-native" {
		t.Fatal("report replaced actual inputs with declarations")
	}
	if err := report.Verify(state.PublicKey); err != nil {
		t.Fatal(err)
	}
	runtime, _ = json.Marshal(control.RuntimeReadback{State: "error", ErrorCode: "demo-start-failed"})
	report, err = androidReport(state, nil, nil, []byte("[]"), []byte("[]"), runtime, components, "demo-network-generation", "2030-01-01T00:01:00Z")
	if err != nil || report.Runtime.AppliedViewDigest != "" {
		t.Fatal("failed runtime manufactured applied digest")
	}
	for _, badComponents := range [][]byte{
		[]byte("null"),
		bytes.ReplaceAll(components, []byte(androidComponentPlatform()), []byte("windows-amd64")),
		bytes.ReplaceAll(components, []byte("sing-box"), []byte("agent")),
		bytes.ReplaceAll(components, []byte("sing-box"), []byte("wintun")),
		bytes.ReplaceAll(components, []byte("sha256:"), []byte("unknown:")),
		append([]byte(`[{"unknown":true},`), components[1:]...),
	} {
		if _, err := androidReport(state, nil, nil, []byte("[]"), []byte("[]"), runtime, badComponents, "demo-network-generation", "2030-01-01T00:01:00Z"); err == nil {
			t.Fatal("invalid Android runtime components were signed")
		}
	}
	if empty, err := androidReport(state, nil, nil, []byte("[]"), []byte("[]"), runtime, []byte("[]"), "demo-network-generation", "2030-01-01T00:01:00Z"); err != nil || len(empty.Components) != 0 {
		t.Fatal("measurement failure blocked otherwise valid report")
	}
	bad := bytes.ReplaceAll(observations, []byte("demo.example:8443"), []byte("other.example:8443"))
	if _, err := androidReport(state, nil, nil, bad, selections, runtime, components, "demo-network-generation", "2030-01-01T00:01:00Z"); err == nil {
		t.Fatal("report accepted undeclared probe target")
	}
}
func TestAndroidRejectsHistoricalStateAndUsesSingleCompressedInviteCodec(t *testing.T) {
	if ValidateAndroidDeviceState([]byte(`{"schema":1,"floor":1}`)) == nil {
		t.Fatal("historical state accepted")
	}
	state, _ := androidFixture(t, 7, false)
	uri, err := control.EncodeInvite(state.Invite)
	if err != nil {
		t.Fatal(err)
	}
	body, err := NewAndroidDeviceState(uri)
	if err != nil {
		t.Fatal(err)
	}
	newState, err := deviceclient.DecodeIdentityState(body)
	if err != nil || newState.LKG != nil || newState.Platform != "android" {
		t.Fatalf("Android created another authority shape: %v", err)
	}
	if strings.Contains(string(body), `"capability"`) {
		t.Fatal("old capability persisted")
	}
}
