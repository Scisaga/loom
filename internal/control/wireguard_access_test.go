package control

import (
	"bytes"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"sort"
	"testing"
)

func wireGuardAccessFixture(t *testing.T) Projection {
	t.Helper()
	p := relayProjectionFixture(t)
	for index := range p.NetworkIntent.Resources {
		resource := &p.NetworkIntent.Resources[index]
		if resource.ID == "demo-exit-wg" {
			resource.AccessEnabled = true
		}
	}
	return p
}

func accessWireGuardOutbounds(t *testing.T, view DeviceView) []map[string]any {
	t.Helper()
	var document struct {
		Endpoints []map[string]any `json:"endpoints"`
	}
	if err := json.Unmarshal([]byte(testDeviceExecution(view).RuntimeProfile.Config), &document); err != nil {
		t.Fatal(err)
	}
	var result []map[string]any
	for _, outbound := range document.Endpoints {
		if outbound["type"] == "wireguard" {
			result = append(result, outbound)
		}
	}
	return result
}

func TestWireGuardAdmissionUsesExistingSourceAndExactExecutionBinding(t *testing.T) {
	p := wireGuardAccessFixture(t)
	view, err := ProjectDeviceView(p, "demo-access")
	if err != nil {
		t.Fatal(err)
	}
	execution := testDeviceExecution(view)
	probes, err := FirstHopProbes(execution)
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Outbounds []map[string]any `json:"outbounds"`
		Endpoints []map[string]any `json:"endpoints"`
	}
	if err := json.Unmarshal([]byte(execution.RuntimeProfile.Config), &document); err != nil {
		t.Fatal(err)
	}
	byTag := map[string]map[string]any{}
	for _, outbound := range document.Outbounds {
		byTag[outbound["tag"].(string)] = outbound
	}
	checked := 0
	for _, probe := range probes {
		if probe.Resource.Kind != "wireguard" {
			continue
		}
		checked++
		address, _ := WireGuardAccessAddress(probe.Resource, "")
		source, _ := WireGuardPacketSource(probe.Resource, probe.Credential)
		pool, _ := WireGuardTargetPrefix(view.NetworkID, probe.Resource)
		found := false
		for _, endpoint := range document.Endpoints {
			for _, raw := range endpoint["source_routes"].([]any) {
				binding := raw.(map[string]any)
				if binding["source"] == source.String() && binding["execution"] == address.String() && binding["destination"] == pool.String() {
					found = true
				}
			}
		}
		transport := byTag[mustTransportTag(probe.Resource.ID)]
		if !found || transport["execution"] == nil || transport["detour"] != WireGuardEndpointTag || transport["inet6_bind_address"] != source.String() {
			t.Fatal("diagnostic changed transport identity or bypassed the business context contract")
		}
	}
	if checked == 0 {
		t.Fatal("fixture did not exercise ordinary WG admission")
	}
}

func TestWireGuardAccessSharesResourceAndMatchesPrivatePublicProjection(t *testing.T) {
	p := wireGuardAccessFixture(t)
	first, err := ProjectDeviceView(p, "demo-access")
	if err != nil {
		t.Fatal(err)
	}
	if len(testDeviceExecution(first).Routes) != 3 || len(testDeviceExecution(first).WireGuardPeers) != 0 {
		t.Fatal("WG, public Hy2 and same-exit relay did not coexist privately")
	}
	wg := accessWireGuardOutbounds(t, first)
	if len(wg) != 1 || wg[0]["system"] != false {
		t.Fatal("ordinary access did not use one user-space WG session")
	}
	receiver, err := ProjectDeviceView(p, "demo-exit")
	if err != nil || len(testDeviceExecution(receiver).WireGuardPeers) != 2 {
		t.Fatal("receiver did not obtain its one permitted peer", err)
	}
	private, err := wireGuardAccessPrivate(wg[0]["private_key"].(string))
	if err != nil || base64.RawURLEncoding.EncodeToString(private.PublicKey().Bytes()) != testDeviceExecution(receiver).WireGuardPeers[0].PublicKey {
		t.Fatal("client and receiver keys differ", err)
	}
	for _, route := range testDeviceExecution(first).Routes {
		if route.FirstResourceID == "demo-exit-wg" && route.EntryNodeID != "demo-exit" {
			t.Fatal("ordinary access invented a Link or extra node")
		}
	}
	second := p.DeviceAuthorizations[0]
	second.ID = "demo-other"
	root := sha256.Sum256([]byte("demo-other-runtime-root"))
	second.RuntimeKey = base64.RawURLEncoding.EncodeToString(root[:])
	second.WireGuardPublicKey, err = DerivedWireGuardPublicKey(p.NetworkID, second)
	if err != nil {
		t.Fatal(err)
	}
	p.DeviceAuthorizations = append(p.DeviceAuthorizations, second)
	sort.Slice(p.DeviceAuthorizations, func(i, j int) bool { return p.DeviceAuthorizations[i].ID < p.DeviceAuthorizations[j].ID })
	after, err := ProjectDeviceView(p, "demo-access")
	if err != nil || !reflect.DeepEqual(first, after) {
		t.Fatal("another device changed existing access identity or runtime", err)
	}
	receiver, err = ProjectDeviceView(p, "demo-exit")
	if err != nil || len(testDeviceExecution(receiver).WireGuardPeers) != 3 || testDeviceExecution(receiver).WireGuardPeers[0].PublicKey == testDeviceExecution(receiver).WireGuardPeers[1].PublicKey {
		t.Fatal("shared resource did not separate devices", err)
	}
	for _, view := range []DeviceView{first, receiver} {
		body, err := CanonicalEncode(view)
		var decoded DeviceView
		if err != nil || DecodeCanonical(body, &decoded, ContractDecodeLimits{MaxBytes: 8 << 20, MaxDepth: 128, MaxItems: 100000}) != nil || !reflect.DeepEqual(view, decoded) {
			t.Fatal("WG View did not round trip", err)
		}
		for _, source := range p.DeviceAuthorizations {
			if bytes.Contains(body, []byte(source.RuntimeKey)) {
				t.Fatal("runtime root leaked in View")
			}
		}
		if view.DeviceID == "demo-exit" && bytes.Contains(body, []byte(wg[0]["private_key"].(string))) {
			t.Fatal("receiver obtained client WG private key")
		}
	}
}

func TestWireGuardAccessServiceWithdrawalPreservesOtherServiceAndPeer(t *testing.T) {
	p := wireGuardAccessFixture(t)
	service := Service{ID: "demo-other-service", Name: "Demo other service", Kind: "internet", RestrictToProbeTargets: new(false)}
	policy := p.NetworkIntent.Policies[0]
	policy.ID, policy.ServiceID = "demo-other-policy", service.ID
	p.NetworkIntent.Services = append(p.NetworkIntent.Services, service)
	p.NetworkIntent.Policies = append(p.NetworkIntent.Policies, policy)
	p.DeviceAuthorizations[0].PolicyIDs = append(p.DeviceAuthorizations[0].PolicyIDs, policy.ID)
	sort.Slice(p.NetworkIntent.Services, func(i, j int) bool { return p.NetworkIntent.Services[i].ID < p.NetworkIntent.Services[j].ID })
	sort.Slice(p.NetworkIntent.Policies, func(i, j int) bool { return p.NetworkIntent.Policies[i].ID < p.NetworkIntent.Policies[j].ID })
	sort.Strings(p.DeviceAuthorizations[0].PolicyIDs)
	first, err := ProjectDeviceView(p, "demo-access")
	if err != nil {
		t.Fatal(err)
	}
	var sharedSpec string
	for _, policyID := range first.PolicyIDs {
		execution, err := ProjectDeviceCandidates(first, []string{policyID})
		if err != nil {
			t.Fatal(err)
		}
		bindings, err := CandidateFirstHopProbes(execution)
		if err != nil {
			t.Fatal(err)
		}
		count := 0
		for _, route := range execution.Routes {
			if route.FirstResourceID != "demo-exit-wg" {
				continue
			}
			probe, found := bindings[route.ID]
			if !found || sharedSpec != "" && sharedSpec == probe.SpecDigest {
				t.Fatal("independent Policy admission was conflated")
			}
			sharedSpec = probe.SpecDigest
			count++
		}
		if count != 1 {
			t.Fatal("missing selected Policy admission")
		}
	}
	if len(accessWireGuardOutbounds(t, first)) != 1 {
		t.Fatal("multiple services created competing WG sessions")
	}
	receiver, err := ProjectDeviceView(p, "demo-exit")
	if err != nil || len(testDeviceExecution(receiver).WireGuardPeers) != 2 {
		t.Fatal("multiple services created duplicate peers", err)
	}
	for i := range p.NetworkIntent.Policies {
		if p.NetworkIntent.Policies[i].ID != policy.ID {
			p.NetworkIntent.Policies[i].Action = "deny"
		}
	}
	after, err := ProjectDeviceView(p, "demo-access")
	if err != nil {
		t.Fatal(err)
	}
	if accessWireGuardOutbounds(t, first)[0]["private_key"] != accessWireGuardOutbounds(t, after)[0]["private_key"] {
		t.Fatal("one Service withdrawal rotated shared transport")
	}
	restricted, err := ProjectDeviceView(p, "demo-exit")
	if err != nil || !reflect.DeepEqual(testDeviceExecution(receiver).WireGuardPeers, testDeviceExecution(restricted).WireGuardPeers) || len(restricted.TransportCredentials) != len(receiver.TransportCredentials) {
		t.Fatal("Service withdrawal lost other service or retained old ACL", err)
	}
	p.DeviceAuthorizations[0].PolicyIDs = []string{}
	withdrawn, err := ProjectDeviceView(p, "demo-exit")
	if err != nil || len(testDeviceExecution(withdrawn).WireGuardPeers) != 1 || testDeviceExecution(withdrawn).WireGuardPeers[0].DeviceID != "demo-entry" || len(testDeviceExecution(withdrawn).AccessGrants) != 0 {
		t.Fatal("withdrawn access retained a transport peer or origin grant", err)
	}
	for _, permission := range withdrawn.TransportCredentials {
		if permission.SenderID == "demo-access" {
			t.Fatal("withdrawn origin retained an access credential")
		}
	}
}

func TestWireGuardAccessRejectsAmbiguousNodeIdentitiesAndNestedTargets(t *testing.T) {
	p := wireGuardAccessFixture(t)
	view, err := ProjectDeviceView(p, "demo-exit")
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*DeviceView){
		func(v *DeviceView) { v.Nodes = append(v.Nodes, v.Nodes[0]) },
		func(v *DeviceView) {
			v.Nodes[0].WireGuardPublicKey = base64.RawURLEncoding.EncodeToString(make([]byte, 32))
		},
		func(v *DeviceView) { v.WireGuardPrivateKey = "invalid" },
	} {
		clone := view
		clone.Nodes = append([]ViewNode{}, view.Nodes...)
		change(&clone)
		if clone.Validate() == nil {
			t.Fatal("ambiguous native sender identity admitted")
		}
	}
	for _, resource := range p.NetworkIntent.Resources {
		if resource.Kind != "wireguard" {
			continue
		}
		resource.AccessHY2ResourceID = "demo-entry-hy2"
		if validateCurrentTransportPayload(resource) == nil {
			t.Fatal("restored WG dependency on Hy2")
		}
	}
}

func TestWireGuardAccessDerivationAndAbsentFieldsAreStable(t *testing.T) {
	p := wireGuardAccessFixture(t)
	var resource TransportResource
	for _, value := range p.NetworkIntent.Resources {
		if value.ID == "demo-exit-wg" {
			resource = value
		}
	}
	private, peer, err := deriveWireGuardAccess(p.NetworkID, p.DeviceAuthorizations[0], resource)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := base64.StdEncoding.DecodeString(private)
	x, _ := ecdh.X25519().NewPrivateKey(key)
	if peer.PublicKey != base64.RawURLEncoding.EncodeToString(x.PublicKey().Bytes()) {
		t.Fatal("X25519 public projection differs")
	}
	server, _ := WireGuardAccessAddress(resource, "")
	client, _ := WireGuardAccessAddress(resource, peer.PublicKey)
	if !server.Is6() || !server.IsPrivate() || server == client {
		t.Fatal("access addresses are not separate private IPv6 values")
	}
	source := p.DeviceAuthorizations[0]
	source.Name = "Demo renamed"
	again, same, err := deriveWireGuardAccess(p.NetworkID, source, resource)
	if err != nil || private != again || peer != same {
		t.Fatal("display name rotated WG identity", err)
	}
	other, _, err := deriveWireGuardAccess("demo-other-network", source, resource)
	if err != nil || other == private {
		t.Fatal("network domain was not isolated", err)
	}
	resource.AccessEnabled = false
	body, err := CanonicalEncode(resource)
	if err != nil || bytes.Contains(body, []byte("access_enabled")) {
		t.Fatal("absent access field changed old resource bytes", err)
	}
	view, err := ProjectDeviceView(relayProjectionFixture(t), "demo-exit")
	body, e := CanonicalEncode(view)
	if err != nil || e != nil || len(testDeviceExecution(view).WireGuardPeers) != 1 || testDeviceExecution(view).WireGuardPeers[0].DeviceID != "demo-entry" {
		t.Fatal("old View gained peer authority", err, e)
	}
	if bytes.Contains(body, []byte(private)) {
		t.Fatal("old view gained private material")
	}
}
