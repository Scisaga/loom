package control

import (
	"strings"
	"testing"
)

func TestNetworkIntentFromLegacySSOTPreservesRuntimeMeaning(t *testing.T) {
	ca := []byte(testNetworkIntent(t).PublicDataPlaneCA)
	legacy := []byte(`defaults:
  components: {agent: 0.1.0, sing_box: 1.11.4, wireguard: 1.0.0}
  dns: [1.1.1.1]
  distribution_url: https://dist.example/loom/
nodes:
  - id: demo-access
    name: Demo access
    probe_targets: [https://probe.example/]
    access: {platform: windows-desktop, credentials: [demo-credential], mixed_ports: [{port: 1080, services: true}]}
  - id: demo-exit
    name: Demo exit
    public_endpoint: 192.0.2.10
    server:
      direction: direct_only
      public_data_ingress: true
      inbound_port: 443
      inbound_protocol: hysteria2
      egress_capable: true
      wg_public_key: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
  - id: demo-reverse
    name: Demo reverse
    public_endpoint: reverse.example
    server:
      direction: reverse_only
      inbound_port: 444
      inbound_protocol: trojan
      wg_public_key: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=
tunnels:
  - {from: demo-exit, to: demo-reverse, protocol: wg, listen_port: 61618, from_addr: 10.90.0.1/32, to_addr: 10.90.0.2/32, retired_ports: [61617]}
declarations:
  - id: demo-policy
    name: Demo policy
    address_axis: from_request
    egress_axis: any
    probe_url: https://probe.example/
    objective: latency
    allowed_servers: [demo-exit, demo-reverse]
    max_hops: 2
    tuning_period: 30s
    switch_threshold: 0.1
    fallback: fail_closed
services:
  - {id: demo-service, name: Demo service, addresses: [.example.com, api.example.net], declaration: demo-policy}
credentials:
  - {id: demo-credential, owner: demo-access, declaration: demo-policy, secret_ref: cred/demo-credential}
`)
	intent, err := NetworkIntentFromLegacySSOT(legacy, ca)
	if err != nil {
		t.Fatal(err)
	}
	if len(intent.Nodes) != 3 || len(intent.Links) != 1 || len(intent.Policies) != 1 || len(intent.Services) != 1 {
		t.Fatalf("conversion lost certified objects: %+v", intent)
	}
	if intent.Nodes[0].Platform != "windows" || intent.Links[0].ProbeTargets[0].Target != "10.90.0.2" ||
		!intent.Policies[0].AllowDirect || strings.Join(intent.Services[0].Matchers, ",") != ".example.com,api.example.net" {
		t.Fatalf("conversion changed runtime meaning: %+v", intent)
	}
}

func TestNetworkIntentFromLegacySSOTRejectsUnrepresentableTransport(t *testing.T) {
	ca := []byte(testNetworkIntent(t).PublicDataPlaneCA)
	legacy := []byte(`defaults:
  components: {agent: 0.1.0, sing_box: 1.11.4, wireguard: 1.0.0}
  dns: [1.1.1.1]
nodes:
  - {id: demo-a, public_endpoint: 192.0.2.1, server: {direction: reverse_only, inbound_port: 443, egress_capable: true, wg_public_key: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=}}
  - {id: demo-b, public_endpoint: 192.0.2.2, server: {direction: direct_only, inbound_port: 443, egress_capable: true, wg_public_key: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=}}
tunnels:
  - {from: demo-a, to: demo-b, protocol: awg, listen_port: 61618, from_addr: 10.90.0.1/32, to_addr: 10.90.0.2/32}
declarations:
  - {id: demo-policy, address_axis: from_request, egress_axis: any, probe_url: https://probe.example/, objective: latency, allowed_servers: [demo-a, demo-b], max_hops: 1, tuning_period: 30s, switch_threshold: 0.1, fallback: fail_closed}
services:
  - {id: demo-service, addresses: [example.com], declaration: demo-policy}
`)
	if _, err := NetworkIntentFromLegacySSOT(legacy, ca); err == nil || !strings.Contains(err.Error(), "unsupported transport") {
		t.Fatalf("unrepresentable transport was not rejected: %v", err)
	}
}

func TestNetworkIntentFromLegacySSOTPreservesPerDeviceLocalEgress(t *testing.T) {
	ca := []byte(testNetworkIntent(t).PublicDataPlaneCA)
	legacy := []byte(`defaults:
  components: {agent: 0.1.0, sing_box: 1.11.4, wireguard: 1.0.0}
  dns: [1.1.1.1]
nodes:
  - id: demo-hybrid
    public_endpoint: 192.0.2.1
    access: {platform: linux-server, credentials: [demo-credential], mixed_ports: [{port: 1080, services: true}]}
    server: {direction: bidirectional, inbound_port: 443, egress_capable: true, wg_public_key: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=}
declarations:
  - {id: demo-policy, address_axis: from_request, egress_axis: "pinned:demo-hybrid", probe_url: https://probe.example/, objective: latency, allowed_servers: [demo-hybrid], max_hops: 1, tuning_period: 30s, switch_threshold: 0.1, fallback: fail_closed}
services:
  - {id: demo-service, addresses: [example.com], declaration: demo-policy}
credentials:
  - {id: demo-credential, owner: demo-hybrid, declaration: demo-policy, secret_ref: cred/demo-credential}
`)
	intent, err := NetworkIntentFromLegacySSOT(legacy, ca)
	if err != nil {
		t.Fatal(err)
	}
	policy := intent.Policies[0]
	if policy.AllowDirect || strings.Join(policy.LocalEgressDevices, ",") != "demo-hybrid" ||
		strings.Join(policy.AllowedExits, ",") != "demo-hybrid" {
		t.Fatalf("per-device local egress was not preserved: %+v", policy)
	}
	projection := Projection{Schema: 1, NetworkIntent: &intent,
		DeviceAuthorizations: []DeviceAuthorization{{Schema: 2, DeviceID: "demo-hybrid",
			DestinationGrants: []string{"demo-policy"},
			DevicePublicKey:   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			RuntimeKey:        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", Floor: 1}}}
	routes, _, err := projectAuthorizationRuntime(projection, projection.DeviceAuthorizations[0])
	if err != nil || len(routes) != 1 || len(routes[0].Chain) != 0 || routes[0].FinalExit != "direct" ||
		routes[0].ID != "route:demo-policy:local:demo-hybrid" {
		t.Fatalf("local egress runtime meaning changed: routes=%+v err=%v", routes, err)
	}
}
