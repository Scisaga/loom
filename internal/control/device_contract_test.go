package control

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"reflect"
	"strings"
	"testing"
)

func deviceContractFixture(t *testing.T) (materialFixture, ControlProof, Projection) {
	t.Helper()
	f := newMaterialFixture(t)
	// Use the second member as genesis signer: member count/order is not a mode.
	f.genesis.IssuerControlID = f.members[1].ControlID
	f.genesis.IssuerKeyID, _ = KeyID(f.members[1].PublicKey)
	var err error
	f.genesis, err = SignMaterial(f.genesis, f.keys[1])
	if err != nil {
		t.Fatal(err)
	}
	p, err := Project(f.genesis, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	public := base64.RawURLEncoding.EncodeToString(f.keys[0].Public().(ed25519.PublicKey))
	p.DeviceAuthorizations = []DeviceAuthorization{{ID: "demo-access", Name: "Demo access", Platform: "linux", DevicePublicKey: public, Responsibilities: []string{"access"}, PolicyIDs: []string{"demo-policy"}, DistributionURLs: []string{}, RuntimeKey: public, TransactionID: "demo-join", InviteMaterialID: materialTestID(t, f.genesis), BindingMaterialID: materialTestID(t, f.genesis)}}
	p.NetworkIntent.Services = []Service{materialTestService("demo-service")}
	p.NetworkIntent.Policies = []NetworkPolicy{materialTestPolicy("demo-policy", "demo-service")}
	return f, ControlProof{Genesis: f.genesis, Successors: []ControlCertificate{}}, p
}

func TestControlProofAuthenticatesAnyInitialMemberAndRefusesIncompleteSuccessors(t *testing.T) {
	f, proof, _ := deviceContractFixture(t)
	anchor := materialTestID(t, f.genesis)
	config, err := VerifyControlProof(proof, "demo-network", anchor)
	if err != nil || len(config.Members) != 2 {
		t.Fatalf("proof: %v", err)
	}
	body, err := CanonicalEncode(proof)
	if err != nil {
		t.Fatal(err)
	}
	var decoded ControlProof
	if err := DecodeCanonical(body, &decoded, ContractDecodeLimits{MaxBytes: 8 << 20, MaxDepth: 128, MaxItems: 1 << 20}); err != nil || !reflect.DeepEqual(proof, decoded) {
		t.Fatalf("proof round trip: %v", err)
	}
	for _, bad := range []ControlProof{{Genesis: f.genesis}, {Genesis: f.genesis, Successors: []ControlCertificate{{}}}} {
		if _, err := VerifyControlProof(bad, "demo-network", anchor); err == nil {
			t.Fatal("incomplete proof accepted")
		}
	}
	if _, err := VerifyControlProof(proof, "demo-other", anchor); err == nil {
		t.Fatal("different anchor network accepted")
	}
	if _, err := VerifyControlProofExtension(proof, ControlProof{Genesis: f.genesis, Successors: []ControlCertificate{{}}}, "demo-network", anchor); err == nil {
		t.Fatal("accepted successor history rolled back")
	}
	corrupted := proof
	corrupted.Genesis.Signature = strings.Repeat("A", 86)
	if _, err := VerifyControlProof(corrupted, "demo-network", materialTestID(t, corrupted.Genesis)); err == nil {
		t.Fatal("self-consistent digest replaced signature verification")
	}
	if _, err := VerifyControlProof(ControlProof{Genesis: f.genesis, Successors: []ControlCertificate{{}}}, "demo-network", anchor); err == nil {
		t.Fatal("successor rejection was not explicit")
	}
}

func TestDirectViewUsesOnlySelectedEffectiveServicePermissions(t *testing.T) {
	_, _, projection := deviceContractFixture(t)
	view, err := ProjectDeviceView(projection, "demo-access")
	if err != nil {
		t.Fatal(err)
	}
	if len(view.Routes) != 1 || view.Routes[0].FinalExit != "direct" || !strings.Contains(view.RuntimeProfile.Config, `"final":"reject"`) || !strings.Contains(view.RuntimeProfile.Config, `"outbound":"service:demo-service"`) {
		t.Fatal("Direct route does not bind service selector and default deny")
	}
	for _, change := range []func(*Projection){
		func(p *Projection) { p.DeviceAuthorizations[0].PolicyIDs = []string{} },
		func(p *Projection) { p.NetworkIntent.Policies[0].Action = "deny" },
		func(p *Projection) { p.NetworkIntent.Services = []Service{} },
		func(p *Projection) { p.NetworkIntent.Policies = []NetworkPolicy{} },
	} {
		_, _, p := deviceContractFixture(t)
		change(&p)
		denied, err := ProjectDeviceView(p, "demo-access")
		if err != nil || len(denied.Routes) != 0 || denied.RuntimeProfile == nil {
			t.Fatalf("permission withdrawal must remain acceptable: %v", err)
		}
		if strings.Contains(denied.RuntimeProfile.Config, `"type":"direct"`) {
			t.Fatal("withdrawal retained Direct execution")
		}
	}
	injected := view
	injected.RuntimeProfile = &RuntimeProfile{Kind: "sing_box", Config: `{"outbounds":[{"tag":"direct","type":"direct"}],"route":{"final":"direct","rules":[]}}`}
	if injected.Validate() == nil {
		t.Fatal("signed profile escaped authorization projection")
	}
	injected = view
	injected.Routes = append([]RouteCandidate{}, view.Routes...)
	injected.Routes[0].SpecDigest = "sha256:" + strings.Repeat("f", 64)
	if injected.Validate() == nil {
		t.Fatal("candidate changed without its permission spec")
	}
}

func TestLocalEgressRetainsNodeIdentityAndEveryPermissionCondition(t *testing.T) {
	fixture := func() Projection {
		_, _, projection := deviceContractFixture(t)
		projection.DeviceAuthorizations[0].Responsibilities = []string{"access", "internet_egress"}
		policy := &projection.NetworkIntent.Policies[0]
		policy.AllowDirect = false
		policy.EntryScope = PolicyScope{Mode: "none", NodeIDs: []string{}}
		policy.RelayScope = PolicyScope{Mode: "none", NodeIDs: []string{}}
		policy.ExitScope = PolicyScope{Mode: "only", NodeIDs: []string{"demo-access"}}
		policy.LocalEgressDevices = []string{"demo-access"}
		return projection
	}
	projection := fixture()
	view, err := ProjectDeviceView(projection, "demo-access")
	if err != nil || len(view.Routes) != 1 {
		t.Fatalf("local exit without an entry resource: %v", err)
	}
	local := view.Routes[0]
	if local.FinalExit != view.DeviceID || local.FirstResourceID != "" || len(local.NodeChain) != 0 || len(local.LinkIDs) != 0 {
		t.Fatal("local execution lost its logical final exit or dialed back into itself")
	}
	body, err := CanonicalEncode(view)
	var decoded DeviceView
	if err != nil || DecodeCanonical(body, &decoded, ContractDecodeLimits{MaxBytes: 8 << 20, MaxDepth: 128, MaxItems: 100000}) != nil || !reflect.DeepEqual(view, decoded) {
		t.Fatalf("local exit View did not round trip: %v", err)
	}
	projection.NetworkIntent.Policies[0].AllowDirect = true
	both, err := ProjectDeviceView(projection, "demo-access")
	if err != nil || len(both.Routes) != 2 || both.Routes[0].ID == both.Routes[1].ID {
		t.Fatalf("Direct and local exit did not coexist: %v", err)
	}
	for _, candidate := range both.Routes {
		if candidate.FinalExit == view.DeviceID && (candidate.ID != local.ID || candidate.SpecDigest == local.SpecDigest) {
			t.Fatal("Policy change must retain path identity and invalidate its previous observation digest")
		}
	}
	for name, change := range map[string]func(*Projection){
		"assignment removed":  func(p *Projection) { p.DeviceAuthorizations[0].PolicyIDs = []string{} },
		"egress role removed": func(p *Projection) { p.DeviceAuthorizations[0].Responsibilities = []string{"access"} },
		"access role removed": func(p *Projection) {
			p.DeviceAuthorizations[0].Responsibilities = []string{"internet_egress"}
			p.DeviceAuthorizations[0].PolicyIDs = []string{}
		},
		"device not listed": func(p *Projection) { p.NetworkIntent.Policies[0].LocalEgressDevices = []string{"demo-other"} },
		"exit excluded": func(p *Projection) {
			p.NetworkIntent.Policies[0].ExitScope = PolicyScope{Mode: "only", NodeIDs: []string{"demo-other"}}
		},
		"exit none": func(p *Projection) {
			p.NetworkIntent.Policies[0].ExitScope = PolicyScope{Mode: "none", NodeIDs: []string{}}
		},
		"deny":            func(p *Projection) { p.NetworkIntent.Policies[0].Action = "deny" },
		"policy removed":  func(p *Projection) { p.NetworkIntent.Policies = []NetworkPolicy{} },
		"service removed": func(p *Projection) { p.NetworkIntent.Services = []Service{} },
	} {
		t.Run(name, func(t *testing.T) {
			p := fixture()
			change(&p)
			denied, err := ProjectDeviceView(p, "demo-access")
			if err != nil || len(denied.Routes) != 0 {
				t.Fatalf("revoked local exit retained a path: %v", err)
			}
			if denied.RuntimeProfile != nil && strings.Contains(denied.RuntimeProfile.Config, `"type":"direct"`) {
				t.Fatal("revocation retained executable outbound")
			}
		})
	}
}

func TestViewEnvelopeBindsMemberRoleAndMonotonicFactPrefixes(t *testing.T) {
	f, proof, p := deviceContractFixture(t)
	view, err := ProjectDeviceView(p, "demo-access")
	if err != nil {
		t.Fatal(err)
	}
	keyID, _ := KeyID(f.members[1].PublicKey)
	envelope := DeviceViewEnvelope{Schema: 3, NetworkID: "demo-network", GenesisDigest: materialTestID(t, f.genesis), IssuerControlID: f.members[1].ControlID, IssuerKeyID: keyID, ControlProof: proof, FactFrontier: []FactFrontier{{KeyID: keyID, Sequence: 3, TipMaterialID: "sha256:" + strings.Repeat("a", 64)}}, View: view}
	envelope, err = SignDeviceViewEnvelope(envelope, f.keys[1])
	if err != nil {
		t.Fatal(err)
	}
	body, err := CanonicalEncode(envelope)
	if err != nil {
		t.Fatal(err)
	}
	var decoded DeviceViewEnvelope
	if err := DecodeCanonical(body, &decoded, ContractDecodeLimits{MaxBytes: 8 << 20, MaxDepth: 128, MaxItems: 1 << 20}); err != nil {
		t.Fatal(err)
	}
	again, _ := CanonicalEncode(decoded)
	if !bytes.Equal(body, again) {
		t.Fatal("envelope bytes changed")
	}
	for _, frontier := range [][]FactFrontier{{}, {{KeyID: keyID, Sequence: 2, TipMaterialID: "sha256:" + strings.Repeat("b", 64)}}, {{KeyID: keyID, Sequence: 3, TipMaterialID: "sha256:" + strings.Repeat("b", 64)}}} {
		next := envelope
		next.FactFrontier = frontier
		next, err = SignDeviceViewEnvelope(next, f.keys[1])
		if err != nil {
			t.Fatal(err)
		}
		if CheckDeviceViewAdvance(next, envelope, envelope.FactFrontier) == nil {
			t.Fatal("old fact prefix omitted, rolled back, or forked")
		}
	}
	bad := envelope
	bad.View.Responsibilities = []string{"access", "control"}
	if _, err := SignDeviceViewEnvelope(bad, f.keys[1]); err == nil {
		t.Fatal("ordinary device gained control role")
	}
	bad = envelope
	bad.FactFrontier = []FactFrontier{{KeyID: "sha256:" + strings.Repeat("f", 64), Sequence: 1, TipMaterialID: envelope.GenesisDigest}}
	if _, err := SignDeviceViewEnvelope(bad, f.keys[1]); err == nil {
		t.Fatal("unproven verification key accepted")
	}
}

func TestEndpointDrainingDeadlineIsExplicitWithoutReadingClock(t *testing.T) {
	endpoint := EndpointGeneration{ID: "demo-endpoint", Generation: 1, OwnerControlID: "demo-control", Host: "192.0.2.1", Port: 443, ServerName: "demo.example", SPKISHA256: "sha256:" + strings.Repeat("a", 64), CertificateDigest: "sha256:" + strings.Repeat("b", 64), Modes: []string{"bootstrap", "device"}, State: "serving"}
	if endpoint.Validate() != nil {
		t.Fatal("valid serving endpoint rejected")
	}
	endpoint.State = "draining"
	if endpoint.Validate() == nil {
		t.Fatal("draining without deadline accepted")
	}
	endpoint.DrainUntil = 1
	if endpoint.Validate() != nil {
		t.Fatal("pure validation read current clock")
	}
	endpoint.State = "retired"
	if endpoint.Validate() == nil {
		t.Fatal("non-draining endpoint retained deadline")
	}
}

func TestBootstrapControlResponsibilityTargetsOnlyIssuersOwnMemberNode(t *testing.T) {
	f, proof, _ := deviceContractFixture(t)
	anchor := materialTestID(t, f.genesis)
	endpoint := EndpointGeneration{ID: "demo-endpoint", Generation: 1, OwnerControlID: f.members[1].ControlID, Host: "192.0.2.1", Port: 443, ServerName: "demo.example", SPKISHA256: "sha256:" + strings.Repeat("a", 64), CertificateDigest: "sha256:" + strings.Repeat("b", 64), Modes: []string{"bootstrap", "device"}, State: "serving"}
	invite := Invite{ID: "demo-control-bind", GenesisDigest: anchor, IssuerControlID: f.members[1].ControlID, DeviceID: f.members[1].NodeID, Name: "Demo initial control", Responsibilities: []string{"control"}, PolicyIDs: []string{}, Medium: "sh", Endpoint: endpoint, ExpiresAt: 1893456000000}
	for _, own := range []bool{true, false} {
		if !own {
			invite.DeviceID = f.members[0].NodeID
		}
		material := f.sign(t, 1, 1, nil, "demo-control-invite", "invite.issue", "invite", invite.ID, invite)
		value := BootstrapInvite{Schema: 3, NetworkID: "demo-network", GenesisDigest: anchor, ControlProof: proof, Material: material}
		if err := value.Validate(); (err == nil) != own {
			t.Fatalf("control binding own=%t: %v", own, err)
		}
	}
}
