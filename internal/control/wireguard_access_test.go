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
			resource.AccessHY2ResourceID = "demo-hy2"
		}
	}
	return p
}

func accessWireGuardOutbounds(t *testing.T, view DeviceView) []map[string]any {
	t.Helper()
	var document struct {
		Outbounds []map[string]any `json:"outbounds"`
	}
	if err := json.Unmarshal([]byte(view.RuntimeProfile.Config), &document); err != nil {
		t.Fatal(err)
	}
	var result []map[string]any
	for _, outbound := range document.Outbounds {
		if outbound["type"] == "wireguard" {
			result = append(result, outbound)
		}
	}
	return result
}

func TestWireGuardAccessSharesResourceAndMatchesPrivatePublicProjection(t *testing.T) {
	p := wireGuardAccessFixture(t)
	first, err := ProjectDeviceView(p, "demo-access")
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Routes) != 3 || len(first.WireGuardPeers) != 0 {
		t.Fatal("WG, public Hy2 and same-exit relay did not coexist privately")
	}
	wg := accessWireGuardOutbounds(t, first)
	if len(wg) != 1 || wg[0]["system_interface"] != false {
		t.Fatal("ordinary access did not use one user-space WG session")
	}
	receiver, err := ProjectDeviceView(p, "demo-exit")
	if err != nil || len(receiver.WireGuardPeers) != 1 {
		t.Fatal("receiver did not obtain its one permitted peer", err)
	}
	private, err := wireGuardAccessPrivate(wg[0]["private_key"].(string))
	if err != nil || base64.RawURLEncoding.EncodeToString(private.PublicKey().Bytes()) != receiver.WireGuardPeers[0].PublicKey {
		t.Fatal("client and receiver keys differ", err)
	}
	for _, route := range first.Routes {
		if route.FirstResourceID == "demo-exit-wg" && (len(route.LinkIDs) != 0 || !reflect.DeepEqual(route.NodeChain, []string{"demo-exit"})) {
			t.Fatal("ordinary access invented a Link or extra node")
		}
	}
	second := p.DeviceAuthorizations[0]
	second.ID = "demo-other"
	root := sha256.Sum256([]byte("demo-other-runtime-root"))
	second.RuntimeKey = base64.RawURLEncoding.EncodeToString(root[:])
	p.DeviceAuthorizations = append(p.DeviceAuthorizations, second)
	sort.Slice(p.DeviceAuthorizations, func(i, j int) bool { return p.DeviceAuthorizations[i].ID < p.DeviceAuthorizations[j].ID })
	after, err := ProjectDeviceView(p, "demo-access")
	if err != nil || !reflect.DeepEqual(first, after) {
		t.Fatal("another device changed existing access identity or runtime", err)
	}
	receiver, err = ProjectDeviceView(p, "demo-exit")
	if err != nil || len(receiver.WireGuardPeers) != 2 || receiver.WireGuardPeers[0].PublicKey == receiver.WireGuardPeers[1].PublicKey {
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
	service := Service{ID: "demo-other-service", Name: "Demo other service", Kind: "internet", Matchers: []ServiceMatcher{{Kind: "dns_exact", Value: "other.example.test"}}}
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
	if len(accessWireGuardOutbounds(t, first)) != 1 {
		t.Fatal("multiple services created competing WG sessions")
	}
	receiver, err := ProjectDeviceView(p, "demo-exit")
	if err != nil || len(receiver.WireGuardPeers) != 1 {
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
	if !reflect.DeepEqual(accessWireGuardOutbounds(t, first), accessWireGuardOutbounds(t, after)) {
		t.Fatal("one Service withdrawal rotated shared transport")
	}
	restricted, err := ProjectDeviceView(p, "demo-exit")
	if err != nil || !reflect.DeepEqual(receiver.WireGuardPeers, restricted.WireGuardPeers) || len(restricted.InboundCredentials) != 1 || restricted.InboundCredentials[0].ServiceID != service.ID {
		t.Fatal("Service withdrawal lost other service or retained old ACL", err)
	}
	p.DeviceAuthorizations[0].PolicyIDs = []string{}
	withdrawn, err := ProjectDeviceView(p, "demo-exit")
	if err != nil || len(withdrawn.WireGuardPeers) != 0 || len(withdrawn.InboundCredentials) != 0 {
		t.Fatal("last permission withdrawal retained peer", err)
	}
}

func TestWireGuardAccessRejectsUnboundPeersAndTargets(t *testing.T) {
	for name, change := range map[string]func(*DeviceView){
		"missing":        func(v *DeviceView) { v.WireGuardPeers = nil },
		"empty":          func(v *DeviceView) { v.WireGuardPeers = []WireGuardAccessPeer{} },
		"extra":          func(v *DeviceView) { v.WireGuardPeers[0].DeviceID = "demo-stranger" },
		"wrong resource": func(v *DeviceView) { v.WireGuardPeers[0].ResourceID = "demo-entry-wg" },
		"duplicate":      func(v *DeviceView) { v.WireGuardPeers = append(v.WireGuardPeers, v.WireGuardPeers[0]) },
		"low order": func(v *DeviceView) {
			v.WireGuardPeers[0].PublicKey = base64.RawURLEncoding.EncodeToString(make([]byte, 32))
		},
	} {
		t.Run(name, func(t *testing.T) {
			v, err := ProjectDeviceView(wireGuardAccessFixture(t), "demo-exit")
			if err != nil {
				t.Fatal(err)
			}
			change(&v)
			if v.Validate() == nil {
				t.Fatal("accepted peer without precise permission")
			}
		})
	}
	for name, change := range map[string]func(*TransportResource){
		"other node":     func(r *TransportResource) { r.AccessHY2ResourceID = "demo-entry-hy2" },
		"missing target": func(r *TransportResource) { r.AccessHY2ResourceID = "demo-missing" },
		"wrong kind":     func(r *TransportResource) { r.AccessHY2ResourceID = "demo-entry-wg" },
	} {
		t.Run(name, func(t *testing.T) {
			p := wireGuardAccessFixture(t)
			for i := range p.NetworkIntent.Resources {
				if p.NetworkIntent.Resources[i].ID == "demo-exit-wg" {
					change(&p.NetworkIntent.Resources[i])
				}
			}
			v, err := ProjectDeviceView(p, "demo-access")
			if err != nil {
				t.Fatal(err)
			}
			if len(v.Routes) != 2 || len(accessWireGuardOutbounds(t, v)) != 0 {
				t.Fatal("invalid target became a first hop or removed old paths")
			}
		})
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
	resource.AccessHY2ResourceID = ""
	body, err := CanonicalEncode(resource)
	if err != nil || bytes.Contains(body, []byte("access_hy2")) {
		t.Fatal("absent access field changed old resource bytes", err)
	}
	view, err := ProjectDeviceView(relayProjectionFixture(t), "demo-exit")
	body, e := CanonicalEncode(view)
	if err != nil || e != nil || bytes.Contains(body, []byte("wireguard_peers")) {
		t.Fatal("old View gained peer authority", err, e)
	}
	if bytes.Contains(body, []byte(private)) {
		t.Fatal("old view gained private material")
	}
}
