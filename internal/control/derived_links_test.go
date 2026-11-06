package control

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestRetiredManualLinkOriginalRemainsSignedCausalEvidence(t *testing.T) {
	f := newMaterialFixture(t)
	history := []Material{}
	appendFact := func(operation, kind, id string, payload MaterialPayload, dependencies ...string) Material {
		t.Helper()
		var previous *Material
		if len(history) > 0 {
			previous = &history[len(history)-1]
		}
		value := f.sign(t, 0, U64(len(history)+1), previous, fmt.Sprintf("demo-history-%d", len(history)+1), operation, kind, id, payload, dependencies...)
		history = append(history, value)
		return value
	}
	anchor := materialTestID(t, f.genesis)
	endpoint := EndpointGeneration{ID: "demo-endpoint", Generation: 1, OwnerControlID: f.members[0].ControlID, Host: "demo.example", Port: 443, ServerName: "demo.example", SPKISHA256: anchor, CertificateDigest: anchor, Modes: []string{"bootstrap", "device"}, State: "prepared"}
	prepared := appendFact("endpoint.put", "endpoint", endpoint.ID, endpoint)
	endpoint.State = "serving"
	serving := appendFact("endpoint.put", "endpoint", endpoint.ID, endpoint, materialTestID(t, prepared))
	joinIDs, resourceIDs := []string{}, []string{}
	fixture := relayProjectionFixture(t)
	for _, id := range []string{"demo-entry", "demo-exit"} {
		invite := Invite{ID: id + "-invite", GenesisDigest: anchor, IssuerControlID: f.members[0].ControlID, DeviceID: id, Name: id, Responsibilities: []string{"forward"}, PolicyIDs: []string{}, Medium: "ssh", Endpoint: endpoint, ExpiresAt: 1000}
		issued := appendFact("invite.issue", "invite", invite.ID, invite, materialTestID(t, serving))
		seed := sha256.Sum256([]byte(id))
		public := base64.RawURLEncoding.EncodeToString(ed25519.NewKeyFromSeed(seed[:]).Public().(ed25519.PublicKey))
		binding := EnrollmentBind{TransactionID: invite.ID, InviteMaterialID: materialTestID(t, issued), ClaimRequestID: id + "-claim", DevicePublicKey: public, Platform: "linux"}
		bound := appendFact("invite.bind", "invite", invite.ID, binding, binding.InviteMaterialID)
		device := DeviceAuthorization{ID: id, Name: id, Platform: "linux", DevicePublicKey: public, Responsibilities: []string{"forward"}, PolicyIDs: []string{}, DistributionURLs: []string{}, RuntimeKey: base64.RawURLEncoding.EncodeToString(seed[:]), TransactionID: invite.ID, InviteMaterialID: binding.InviteMaterialID, BindingMaterialID: materialTestID(t, bound)}
		joined := appendFact("device.join", "device", id, device, device.BindingMaterialID)
		joinIDs = append(joinIDs, materialTestID(t, joined))
		for _, resource := range fixture.NetworkIntent.Resources {
			if resource.OwnerNodeID == id && resource.Kind == "wireguard" {
				fact := appendFact("resource.put", "resource", resource.ID, resource, materialTestID(t, joined))
				resourceIDs = append(resourceIDs, materialTestID(t, fact))
			}
		}
	}
	p, err := Project(f.genesis, nil, history)
	if err != nil || len(p.InvalidMaterials) != 0 {
		t.Fatal("resource history is not admissible", err, p.InvalidMaterials)
	}
	// Historical owners have no registered node key. Verify their originals,
	// then register existing keys with new facts before using the current graph.
	if _, err := DerivedNetworkLinks(p); err == nil {
		t.Fatal("historical resources silently registered their owners")
	}
	link, err := derivedNetworkLink(p.NetworkID, p.NetworkIntent.Resources[0], p.NetworkIntent.Resources[1])
	if err != nil {
		t.Fatal(err)
	}
	link.ID = "demo-original-manual-link"
	link.ProbeTarget.Action = "wireguard_dns"
	previous := history[len(history)-1]
	keyID, _ := KeyID(f.members[0].PublicKey)
	dependencies := append(append([]string{}, joinIDs...), resourceIDs...)
	sort.Strings(dependencies)
	original := Material{Schema: 3, NetworkID: p.NetworkID, IssuerControlID: f.members[0].ControlID, IssuerKeyID: keyID, ControlConfigID: f.configID, Sequence: U64(len(history) + 1), PreviousMaterialID: materialTestID(t, previous), Dependencies: dependencies, RequestID: "demo-original-write", TargetKind: "link", TargetID: link.ID, Operation: "link.put", Payload: link}
	// Construct an original as the retired writer once did; production SignMaterial
	// deliberately cannot create this fact. Its verifier retains the old meaning.
	unsigned, err := CanonicalEncode(original.contractObject(false))
	if err != nil {
		t.Fatal(err)
	}
	original.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(f.keys[0], append([]byte(materialDomain), unsigned...)))
	before, _, err := EncodeMaterial(original)
	decoded, decodeErr := DecodeMaterial(before)
	if err != nil || decodeErr != nil || VerifyMaterial(decoded, f.keys[0].Public().(ed25519.PublicKey)) != nil || ValidateAdmission(decoded, f.genesis, nil, history) != nil {
		t.Fatal("retired original lost its signature or causal verification", err, decodeErr)
	}
	after, _, err := EncodeMaterial(decoded)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("retired original bytes were reinterpreted", err)
	}
	next := f.sign(t, 0, original.Sequence+1, &original, "demo-after-original", "service.put", "service", "demo-after-original", materialTestService("demo-after-original"), materialTestID(t, original))
	p, err = Project(f.genesis, nil, append(append(history, original), next))
	if err != nil || len(p.InvalidMaterials) != 0 || len(p.PendingMaterialIDs) != 0 || len(p.NetworkIntent.Services) != 1 {
		t.Fatal("retired original interrupted a valid dependent signing chain", err, p.InvalidMaterials)
	}
	if _, err := DerivedNetworkLinks(p); err == nil {
		t.Fatal("historical Link supplied a missing current identity")
	}
	all := append(append(history, original), next)
	for _, device := range p.DeviceAuthorizations {
		for _, resource := range p.NetworkIntent.Resources {
			if resource.OwnerNodeID == device.ID {
				device.WireGuardPublicKey = *resource.Authentication.PublicKey
			}
		}
		target, _ := p.CurrentTarget("device", device.ID)
		previous := all[len(all)-1]
		registered := f.sign(t, 0, previous.Sequence+1, &previous, "demo-register-"+device.ID, "device.put", "device", device.ID, device, target.MaterialIDs...)
		all = append(all, registered)
	}
	p, err = Project(f.genesis, nil, all)
	if err != nil || len(p.InvalidMaterials) != 0 {
		t.Fatal("explicit forward identity registration failed", err, p.InvalidMaterials)
	}
	current, err := DerivedNetworkLinks(p)
	if err != nil || len(current) != 2 {
		t.Fatal("registered resource graph did not recover", err)
	}
	for _, value := range current {
		if value.ID == link.ID {
			t.Fatal("retired original became current relay authority")
		}
	}
	preserved, _, err := EncodeMaterial(decoded)
	if err != nil || !bytes.Equal(before, preserved) {
		t.Fatal("forward registration changed historical signed bytes", err)
	}
}

func TestAutomaticRelayGraphPreservesResourcesAndRejectsManualWrites(t *testing.T) {
	p := relayProjectionFixture(t)
	if len(p.NetworkIntent.Links) != 0 {
		t.Fatal("fixture must not configure relay pairs")
	}
	before, _ := CanonicalEncode(p)
	links, err := DerivedNetworkLinks(p)
	if err != nil || len(links) != 4 {
		t.Fatal("two forwarding nodes require two automatic business directions", err)
	}
	if links[0].ID == links[1].ID {
		t.Fatal("automatic business directions do not share one deterministic peer")
	}
	after, _ := CanonicalEncode(p)
	if string(before) != string(after) {
		t.Fatal("derived graph modified authority")
	}
	for _, node := range []string{"demo-entry", "demo-exit"} {
		view, err := ProjectDeviceView(p, node)
		if err != nil || len(testDeviceExecution(view).Links) != 4 || len(testDeviceExecution(view).WireGuardPeers) != 1 {
			t.Fatal("automatic graph did not reach the shared runtime", node, err)
		}
		var config struct {
			Endpoints []struct {
				Peers []map[string]any `json:"peers"`
			} `json:"endpoints"`
		}
		if json.Unmarshal([]byte(testDeviceExecution(view).RuntimeProfile.Config), &config) != nil || len(config.Endpoints) != 1 || len(config.Endpoints[0].Peers) != 1 {
			t.Fatal("automatic directions duplicated WG sessions")
		}
		peer := config.Endpoints[0].Peers[0]
		if peer["address"] == nil || peer["port"] == nil || peer["persistent_keepalive_interval"] != float64(25) {
			t.Fatal("a native peer lost its certified dialing endpoint")
		}
	}
	operation := Operation{Schema: 3, RequestID: "demo-write", Dependencies: []string{}, Operation: "link.put", TargetKind: "link", TargetID: links[0].ID, Payload: links[0]}
	if operation.Validate() == nil {
		t.Fatal("manual Link writes are still accepted")
	}
	if _, err := SignMaterial(Material{Payload: links[0]}, nil); err == nil || !strings.Contains(err.Error(), "manual Link writes") {
		t.Fatal("signer did not reject a retired Link write", err)
	}
	operation.Operation, operation.Payload = "link.delete", DeleteTarget{ID: links[0].ID}
	if operation.Validate() != nil {
		t.Fatal("forward withdrawal of historical Link facts was blocked")
	}
	p.NetworkIntent.Links = []NetworkLink{{ID: "demo-retired-link"}}
	withoutHistory, err := DerivedNetworkLinks(p)
	if err != nil || !reflect.DeepEqual(links, withoutHistory) {
		t.Fatal("historical manual Link changed the current graph", err)
	}
	for i, j := 0, len(p.NetworkIntent.Resources)-1; i < j; i, j = i+1, j-1 {
		p.NetworkIntent.Resources[i], p.NetworkIntent.Resources[j] = p.NetworkIntent.Resources[j], p.NetworkIntent.Resources[i]
	}
	reordered, err := DerivedNetworkLinks(p)
	if err != nil || !reflect.DeepEqual(links, reordered) {
		t.Fatal("resource traversal order changed automatic identities", err)
	}
}

func TestAutomaticRelayGraphUsesOnlyCurrentUnambiguousIdentities(t *testing.T) {
	for _, change := range []func(*Projection){
		func(p *Projection) {
			p.NetworkIntent.Resources[1].Authentication.PublicKey = p.NetworkIntent.Resources[3].Authentication.PublicKey
		},
		func(p *Projection) {
			p.NetworkIntent.Resources[1].Authentication.LocalAddresses = p.NetworkIntent.Resources[3].Authentication.LocalAddresses
		},
		func(p *Projection) { p.NetworkIntent.Resources[1].AccessHY2ResourceID = "demo-entry-hy2" },
		func(p *Projection) {
			p.NetworkIntent.Resources = append(p.NetworkIntent.Resources, p.NetworkIntent.Resources[1])
		},
	} {
		p := relayProjectionFixture(t)
		change(&p)
		if _, err := DerivedNetworkLinks(p); err == nil {
			t.Fatal("ambiguous or retired resource became an automatic peer")
		}
	}
	p := relayProjectionFixture(t)
	p.DeviceAuthorizations[2].Responsibilities = []string{"internet_egress"}
	links, err := DerivedNetworkLinks(p)
	if err != nil || len(links) != 2 || links[0].FromNodeID != "demo-exit" || links[0].ToNodeID != "demo-entry" {
		t.Fatal("pure egress acquired forwarding rights", err)
	}
}

func TestCurrentViewDerivesLinksWithoutSigningAnExpandedGraph(t *testing.T) {
	p := relayProjectionFixture(t)
	view, err := ProjectDeviceView(p, "demo-entry")
	if err != nil {
		t.Fatal(err)
	}
	first, err := DerivedViewLinks(view)
	if err != nil || len(first) == 0 {
		t.Fatal("missing directed graph", err)
	}
	body, err := CanonicalEncode(view)
	var decoded DeviceView
	if err != nil || DecodeCanonical(body, &decoded, ContractDecodeLimits{MaxBytes: 8 << 20, MaxDepth: 128, MaxItems: 100000}) != nil || !reflect.DeepEqual(view, decoded) {
		t.Fatal("stable View roundtrip", err)
	}
	next, err := DerivedViewLinks(decoded)
	if err != nil || !reflect.DeepEqual(first, next) {
		t.Fatal("derived graph changed on recovery", err)
	}
	parsed, err := parseContractJSON(body, ContractDecodeLimits{MaxBytes: 8 << 20, MaxDepth: 128, MaxItems: 100000})
	if err != nil {
		t.Fatal(err)
	}
	object := parsed.(map[string]any)
	object["links"] = []any{}
	raw := appendContractJSON(nil, object)
	if err != nil {
		t.Fatal(err)
	}
	if DecodeCanonical(raw, &decoded, ContractDecodeLimits{MaxBytes: 8 << 20, MaxDepth: 128, MaxItems: 100000}) == nil {
		t.Fatal("manual graph became signed current authority")
	}
}
