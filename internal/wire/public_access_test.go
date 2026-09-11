package wire

import "testing"

func publicAccessFixture(t *testing.T, deployment string) (ServerPublicAccessProfileV1, ForwardServerListenerResourcesV1) {
	t.Helper()
	resources := ForwardServerListenerResourcesV1{
		Schema: 1, ClusterID: "demo-cluster", ServerID: "demo-edge", Generation: 1,
		NginxLocalTCPPort: 8443, HY2LocalUDPPortPool: []int64{24443},
		WireGuardLocalUDPPorts: []int64{51820}, TrojanLocalTCPPortPool: []int64{24444},
		Mappings: []PortMappingIntentV1{},
	}
	publicPort := int64(443)
	if deployment == "direct_alternate" {
		publicPort = 10443
	}
	if deployment == "nat_mapped" {
		publicPort = 10443
		resources.Mappings = []PortMappingIntentV1{
			{Schema: 1, MappingID: "https", Transport: "tcp", PublicAddress: "203.0.113.10", PublicPortStart: 10443, PublicPortEnd: 10443, LocalAddress: "10.0.0.10", LocalPortStart: 8443, LocalPortEnd: 8443, MappingGeneration: 1},
			{Schema: 1, MappingID: "hy2", Transport: "udp", PublicAddress: "203.0.113.10", PublicPortStart: 30443, PublicPortEnd: 30443, LocalAddress: "10.0.0.10", LocalPortStart: 24443, LocalPortEnd: 24443, MappingGeneration: 1},
			{Schema: 1, MappingID: "trojan", Transport: "tcp", PublicAddress: "203.0.113.10", PublicPortStart: 30444, PublicPortEnd: 30444, LocalAddress: "10.0.0.10", LocalPortStart: 24444, LocalPortEnd: 24444, MappingGeneration: 1},
			{Schema: 1, MappingID: "wireguard", Transport: "udp", PublicAddress: "203.0.113.10", PublicPortStart: 51820, PublicPortEnd: 51820, LocalAddress: "10.0.0.10", LocalPortStart: 51820, LocalPortEnd: 51820, MappingGeneration: 1},
		}
	}
	resourcesHash, err := ForwardServerListenerResourcesHash(&resources)
	if err != nil {
		t.Fatal(err)
	}
	profile := ServerPublicAccessProfileV1{
		Schema: 1, ClusterID: resources.ClusterID, ServerID: resources.ServerID, Generation: 1,
		FQDN: "demo-edge.example", DNSZoneRef: "demo-zone", AddressFamilyPolicy: "dual_stack",
		HTTPSPublicPort: publicPort, DeploymentKind: deployment,
		PublicFrontendAddresses: []string{"2001:db8::10", "203.0.113.10"},
		CertificateProfileRef:   "public-webpki", ForwardListenerResourcesHash: resourcesHash,
	}
	return profile, resources
}

func TestPublicAccessProfilesBindAddressFamiliesAndNATMappings(t *testing.T) {
	for _, deployment := range []string{"direct_standard", "direct_alternate", "nat_mapped"} {
		profile, resources := publicAccessFixture(t, deployment)
		if _, err := ServerPublicAccessProfileHash(&profile, &resources); err != nil {
			t.Fatalf("%s profile rejected: %v", deployment, err)
		}
	}
	profile, resources := publicAccessFixture(t, "nat_mapped")
	resources.Mappings = resources.Mappings[:3]
	resourcesHash, _ := ForwardServerListenerResourcesHash(&resources)
	profile.ForwardListenerResourcesHash = resourcesHash
	if err := ValidatePublicAccess(&profile, &resources); err == nil {
		t.Fatal("接受了缺 WireGuard mapping 的 NAT profile")
	}

	profile, resources = publicAccessFixture(t, "direct_standard")
	profile.AddressFamilyPolicy = "ipv4_only"
	if err := ValidatePublicAccess(&profile, &resources); err == nil {
		t.Fatal("接受了 address family policy 与地址集合不一致的 profile")
	}
}

func TestForwardResourcesRejectOverlappingMappingRanges(t *testing.T) {
	_, resources := publicAccessFixture(t, "nat_mapped")
	resources.Mappings[2].PublicPortStart = resources.Mappings[0].PublicPortStart
	resources.Mappings[2].PublicPortEnd = resources.Mappings[0].PublicPortEnd
	if err := ValidateForwardServerListenerResources(&resources); err == nil {
		t.Fatal("接受了重叠 TCP public mapping")
	}
}

func TestActivePublicAccessStateRequiresVerificationEvidence(t *testing.T) {
	state := ServerPublicAccessStateV1{
		Schema: 1, ClusterID: "demo-cluster", ServerID: "demo-edge", Generation: 1,
		PublicAccessProfileHash: HashRaw("test-public-profile-v1", []byte("profile")),
		Status:                  "active", LastChangedHeadHash: HashRaw("test-head-v1", []byte("head")),
	}
	if err := ValidateServerPublicAccessState(&state); err == nil {
		t.Fatal("active state 没有 external verification evidence 却被接受")
	}
	state.LastVerifiedObservationHash = HashRaw("test-observation-v1", []byte("observation"))
	if _, err := ServerPublicAccessStateHash(&state); err != nil {
		t.Fatal(err)
	}
}
