package bootstrapaccess

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/netip"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"loom/internal/rotation"
	"loom/internal/wire"
)

type runtimePlanFixture struct {
	catalog    wire.BootstrapEndpointCatalogV1
	head       wire.HeadEntryV2
	controlSet wire.ControlSetV1
	authorized rotation.AuthorizedRuntimePlanV1
	profile    wire.ServerPublicAccessProfileV1
	resources  wire.ForwardServerListenerResourcesV1
	tlsConfig  *tls.Config
	endpointID string
	generation int64
	now        time.Time
}

func TestBuildBootstrapIngressRuntimePlanBindsCertifiedDirectTuple(t *testing.T) {
	for _, transport := range []string{"hysteria2", "trojan_tls"} {
		t.Run(transport, func(t *testing.T) {
			fixture := newRuntimePlanFixture(t, transport, "direct_standard")
			plan, err := BuildBootstrapIngressRuntimePlan(&fixture.catalog, &fixture.head,
				&fixture.controlSet, nil, fixture.authorized, &fixture.profile, &fixture.resources,
				fixture.endpointID, fixture.generation, fixture.now, 2)
			if err != nil {
				t.Fatal(err)
			}
			bindings := plan.Bindings()
			if len(bindings) != 1 || bindings[0].Transport() != transport ||
				bindings[0].ServerName() != fixture.profile.FQDN ||
				bindings[0].IngressSetHash() != fixture.catalog.BootstrapIngressSetHash ||
				!bindings[0].valid() {
				t.Fatalf("runtime bindings=%#v", bindings)
			}
			manager, err := Open(filepath.Join(t.TempDir(), "usage.json"), func() time.Time { return fixture.now })
			if err != nil {
				t.Fatal(err)
			}
			registry, err := NewCredentialRegistry(fixture.catalog.BootstrapIngressSetHash, nil)
			if err != nil {
				t.Fatal(err)
			}
			dial := func(_ context.Context, _, _ string) (net.Conn, error) { return nil, net.ErrClosed }
			if transport == "hysteria2" {
				_, err = NewHysteria2Server(manager, registry, Hysteria2ServerOptions{
					Listener: bindings[0], TLSConfig: fixture.tlsConfig, HandshakeTimeout: 5 * time.Second,
					IdleTimeout: 30 * time.Second, MaximumConcurrentConnections: 4,
					MaximumStreamsPerConnection: 4, Dial: dial,
				})
			} else {
				_, err = NewTrojanTLSServer(manager, registry, TrojanTLSServerOptions{
					Listener: bindings[0], TLSConfig: fixture.tlsConfig, HandshakeTimeout: 5 * time.Second,
					MaximumConcurrentConnections: 4, Dial: dial,
				})
			}
			if err != nil {
				t.Fatalf("transport server 拒绝 verified runtime binding: %v", err)
			}
		})
	}
}

func TestBuildBootstrapIngressRuntimePlanRequiresExactNATMapping(t *testing.T) {
	fixture := newRuntimePlanFixture(t, "hysteria2", "nat_mapped")
	plan, err := BuildBootstrapIngressRuntimePlan(&fixture.catalog, &fixture.head,
		&fixture.controlSet, nil, fixture.authorized, &fixture.profile, &fixture.resources,
		fixture.endpointID, fixture.generation, fixture.now, 2)
	if err != nil || len(plan.Bindings()) != 1 || plan.Bindings()[0].Tuple().Address != "10.0.0.10" ||
		plan.Bindings()[0].Tuple().Port != 24443 {
		t.Fatalf("NAT runtime plan=%#v err=%v", plan.Bindings(), err)
	}

	fixture = newRuntimePlanFixture(t, "hysteria2", "nat_mapped")
	fixture.resources.Mappings[1].Transport = "tcp"
	resourcesHash, _ := wire.ForwardServerListenerResourcesHash(&fixture.resources)
	fixture.profile.ForwardListenerResourcesHash = resourcesHash
	if _, err := BuildBootstrapIngressRuntimePlan(&fixture.catalog, &fixture.head,
		&fixture.controlSet, nil, fixture.authorized, &fixture.profile, &fixture.resources,
		fixture.endpointID, fixture.generation, fixture.now, 2); err == nil {
		t.Fatal("TCP mapping 被用于 HY2/UDP listener")
	}
}

func TestDeriveRuntimeBindingsRejectsAmbiguousDirectCoverage(t *testing.T) {
	fixture := newRuntimePlanFixture(t, "hysteria2", "direct_standard")
	endpoint, listener, err := findBootstrapListener(&fixture.catalog, fixture.endpointID, fixture.generation)
	if err != nil {
		t.Fatal(err)
	}
	pins, err := bootstrapIdentityPins(listener.TransportIdentityRefs, fixture.profile.CertificateProfileRef)
	if err != nil {
		t.Fatal(err)
	}
	tuples := []rotation.Tuple{
		{Transport: "udp", Address: "0.0.0.0", Port: 24443},
		{Transport: "udp", Address: "203.0.113.10", Port: 24443},
	}
	if _, err := deriveRuntimeBindings(&fixture.catalog, endpoint, listener, "preferred",
		&fixture.profile, &fixture.resources, tuples, pins, ""); err == nil {
		t.Fatal("同一 public tuple 同时命中 wildcard/exact local listener")
	}
}

func TestBuildBootstrapIngressRuntimePlanRejectsSplicedAuthority(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*runtimePlanFixture)
	}{
		{name: "catalog set", mutate: func(fixture *runtimePlanFixture) {
			fixture.catalog.BootstrapIngressSet.Endpoints[0].ListenerGenerations[0].PublicPort++
		}},
		{name: "profile", mutate: func(fixture *runtimePlanFixture) {
			fixture.profile.FQDN = "other.example"
		}},
		{name: "resources", mutate: func(fixture *runtimePlanFixture) {
			fixture.resources.HY2LocalUDPPortPool[0]++
		}},
		{name: "qc", mutate: func(fixture *runtimePlanFixture) {
			fixture.catalog.BootstrapIngressSet.ConfigQC = json.RawMessage(`{"schema":1}`)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newRuntimePlanFixture(t, "hysteria2", "direct_standard")
			test.mutate(&fixture)
			if _, err := BuildBootstrapIngressRuntimePlan(&fixture.catalog, &fixture.head,
				&fixture.controlSet, nil, fixture.authorized, &fixture.profile, &fixture.resources,
				fixture.endpointID, fixture.generation, fixture.now, 2); err == nil {
				t.Fatal("拼接 runtime authority 被接受")
			}
		})
	}
}

func newRuntimePlanFixture(t *testing.T, transport, deployment string) runtimePlanFixture {
	return newRuntimePlanFixtureWithEvidencePolicy(t, transport, deployment, runtimePlanHash("evidence"))
}

func newRuntimePlanFixtureWithEvidencePolicy(t *testing.T, transport, deployment,
	evidencePolicyHash string) runtimePlanFixture {
	t.Helper()
	const clusterID = "demo-cluster"
	now := time.Date(2026, 9, 11, 11, 1, 0, 0, time.UTC)
	member, configKey := runtimeControlMember(t, clusterID)
	controlSet := wire.ControlSetV1{Schema: 1, ClusterID: clusterID,
		Members: []wire.ControlMemberV1{member}}
	controlSetHash, err := wire.ControlSetHash(&controlSet)
	if err != nil {
		t.Fatal(err)
	}
	transitionContext, _ := json.Marshal(wire.BootstrapHeadContextV1{
		Schema: 1, Kind: "bootstrap", InitialV2HeadPayloadHash: runtimePlanHash("initial-payload")})
	head, err := wire.NewHeadEntry(wire.HeadEntryBodyV2{
		Payload: wire.HeadEntryPayloadV2{
			Schema: 2, HeadKind: "bootstrap", ClusterID: clusterID,
			RecoveryEpoch: 0, RecoveryStatementHash: runtimePlanHash("recovery-statement"),
			RecoveryPolicyHash: runtimePlanHash("recovery-policy"), ControlEpoch: 0,
			ControlSetHash: controlSetHash, ControlPeerDirectoryHash: runtimePlanHash("peer-directory"),
			RaftTerm: 1, RaftIndex: 1, PreviousLogEntryHash: wire.EmptyHashV1,
			ControlRevision: 1, ParentHeadHash: wire.EmptyHashV1,
			OperationRoot: runtimePlanHash("operation-root"), SnapshotHash: runtimePlanHash("snapshot"),
			EffectiveSSOTHash: runtimePlanHash("ssot"), DeviceViewsRoot: runtimePlanHash("device-views"),
			AdminACLRoot: runtimePlanHash("admin-acl"), CAProfileRoot: runtimePlanHash("ca-profile"),
			BootstrapIssuerRegistryRoot: runtimePlanHash("issuer-registry"), RenderContractVersion: 2,
			MinReaderVersion: 2, CommittedLogicalTime: "2026-09-11T10:00:00Z",
			MaxClockSkewSeconds: 30, TransitionContext: transitionContext,
		},
		TransitionProofHash: runtimePlanHash("transition"),
	})
	if err != nil {
		t.Fatal(err)
	}
	signature, err := wire.SignHeadAttestation(wire.AttestationForHead(&head), member, configKey)
	if err != nil {
		t.Fatal(err)
	}
	qcRaw, err := json.Marshal(wire.StableQC(&head, []wire.ControlConfigSignatureV1{signature}))
	if err != nil {
		t.Fatal(err)
	}

	resources := wire.ForwardServerListenerResourcesV1{
		Schema: 1, ClusterID: clusterID, ServerID: "demo-edge", Generation: 1,
		NginxLocalTCPPort: 8443, HY2LocalUDPPortPool: []int64{24443},
		WireGuardLocalUDPPorts: []int64{51820}, TrojanLocalTCPPortPool: []int64{24444},
		Mappings: []wire.PortMappingIntentV1{},
	}
	publicPort := int64(24443)
	localAddress := "0.0.0.0"
	if transport == "trojan_tls" {
		publicPort = 24444
	}
	if deployment == "nat_mapped" {
		publicPort = 30443
		localAddress = "10.0.0.10"
		resources.Mappings = []wire.PortMappingIntentV1{
			{Schema: 1, MappingID: "https", Transport: "tcp", PublicAddress: "203.0.113.10",
				PublicPortStart: 10443, PublicPortEnd: 10443, LocalAddress: localAddress,
				LocalPortStart: 8443, LocalPortEnd: 8443, MappingGeneration: 1},
			{Schema: 1, MappingID: "hy2", Transport: "udp", PublicAddress: "203.0.113.10",
				PublicPortStart: 30443, PublicPortEnd: 30443, LocalAddress: localAddress,
				LocalPortStart: 24443, LocalPortEnd: 24443, MappingGeneration: 1},
			{Schema: 1, MappingID: "trojan", Transport: "tcp", PublicAddress: "203.0.113.10",
				PublicPortStart: 30444, PublicPortEnd: 30444, LocalAddress: localAddress,
				LocalPortStart: 24444, LocalPortEnd: 24444, MappingGeneration: 1},
			{Schema: 1, MappingID: "wireguard", Transport: "udp", PublicAddress: "203.0.113.10",
				PublicPortStart: 51820, PublicPortEnd: 51820, LocalAddress: localAddress,
				LocalPortStart: 51820, LocalPortEnd: 51820, MappingGeneration: 1},
		}
		if transport == "trojan_tls" {
			publicPort = 30444
		}
	}
	resourcesHash, err := wire.ForwardServerListenerResourcesHash(&resources)
	if err != nil {
		t.Fatal(err)
	}
	httpsPort := int64(443)
	if deployment == "nat_mapped" {
		httpsPort = 10443
	}
	profile := wire.ServerPublicAccessProfileV1{
		Schema: 1, ClusterID: clusterID, ServerID: resources.ServerID, Generation: 1,
		FQDN: "bootstrap.example", DNSZoneRef: "demo-zone", AddressFamilyPolicy: "ipv4_only",
		HTTPSPublicPort: httpsPort, DeploymentKind: deployment,
		PublicFrontendAddresses: []string{"203.0.113.10"}, CertificateProfileRef: "public-webpki",
		ForwardListenerResourcesHash: resourcesHash,
	}
	profileHash, err := wire.ServerPublicAccessProfileHash(&profile, &resources)
	if err != nil {
		t.Fatal(err)
	}
	localPort := int64(24443)
	if transport == "trojan_tls" {
		localPort = 24444
	}
	_, tlsConfig, certificate := trojanCertificate(t, profile.FQDN)
	certificateDigest := sha256.Sum256(certificate.RawSubjectPublicKeyInfo)
	listener := wire.ListenerGenerationV2{
		Schema: 2, ListenerGeneration: 1, PublishedState: "preferred",
		DialTargetFQDN: profile.FQDN, PublicPort: publicPort, AddressFamilies: []string{"ipv4"},
		TransportIdentityRefs: []string{"profile:" + profile.CertificateProfileRef,
			"sha256:" + hex.EncodeToString(certificateDigest[:])},
		CredentialGeneration: 1, CertificateIdentityProjectionHash: runtimePlanHash("certificate-projection"),
		PublicProfileGeneration: profile.Generation, IntroducedRevision: 2,
		ValidFrom: "2026-09-11T00:00:00Z", ValidUntil: "2026-09-13T00:00:00Z",
		RotationOperationHash: runtimePlanHash("rotation-operation"),
	}
	endpointID := "bootstrap-edge"
	ingressSet := wire.BootstrapIngressEndpointSetV1{
		Schema: 1, ClusterID: clusterID, EndpointSetID: "bootstrap-ingress", Generation: 1,
		ValidFrom: listener.ValidFrom, ValidUntil: listener.ValidUntil,
		Endpoints: []wire.BootstrapIngressEndpointV1{{
			EndpointID: endpointID, LogicalServerID: resources.ServerID, Transport: transport,
			HintRank: 0, ListenerGenerations: []wire.ListenerGenerationV2{listener},
			ListenerTombstones: []wire.ListenerGenerationTombstoneV1{},
		}},
		ParentHeadHash: head.HeadHash, ConfigQC: qcRaw,
	}
	ingressSetHash, err := wire.BootstrapIngressSetHash(&ingressSet)
	if err != nil {
		t.Fatal(err)
	}
	qcHash, err := wire.ConfigQCHash(qcRaw)
	if err != nil {
		t.Fatal(err)
	}
	catalog := wire.BootstrapEndpointCatalogV1{
		Schema: 1, ClusterID: clusterID, CatalogGeneration: 1,
		ValidFrom: ingressSet.ValidFrom, ValidUntil: ingressSet.ValidUntil,
		BootstrapIngressSet: ingressSet, BootstrapIngressSetHash: ingressSetHash,
		RequiredClientProtocol: 2, ParentHeadHash: head.HeadHash, ConfigQCHash: qcHash,
	}
	dependency := rotation.FrozenDependenciesV1{
		Schema: 1, ClusterID: clusterID, EndpointKind: "bootstrap",
		EndpointSetID: ingressSet.EndpointSetID, EndpointID: endpointID,
		LogicalServerID: resources.ServerID, Transport: transport, TargetListenerGeneration: 1,
		LogicalPublicEndpointIntentHash: runtimePlanHash("public-endpoint"),
		PublicAccessProfileHash:         profileHash, DNSAddressBindingHash: runtimePlanHash("dns"),
		CertificateIdentityProjectionHash: runtimePlanHash("certificate-projection"),
		CredentialArtifactRefsRoot:        runtimePlanHash("credentials"), RenderContractHash: runtimePlanHash("render"),
		EvidencePolicyHash: evidencePolicyHash, PortPoolHash: runtimePlanHash("port-pool"),
		FirewallPolicyHash: runtimePlanHash("firewall"), ForwardListenerResourceGenerationHash: resourcesHash,
		LinkIntentHashes: []string{},
	}
	if deployment == "nat_mapped" {
		for _, mapping := range resources.Mappings {
			if mapping.Transport == map[string]string{"hysteria2": "udp", "trojan_tls": "tcp"}[transport] &&
				mapping.PublicPortStart == publicPort {
				dependency.PortMappingIntentHash, _ = wire.PortMappingIntentHash(&mapping)
				break
			}
		}
	}
	dependencyHash, err := wire.HashObject(rotation.DomainFrozenDependencies, dependency)
	if err != nil {
		t.Fatal(err)
	}
	intent := rotation.IntentV1{
		Schema: 1, ClusterID: clusterID, RotationID: "bootstrap-rotation", OperationID: "bootstrap-operation",
		BaseHeadHash: head.HeadHash, ExpectedEndpointSetHash: ingressSetHash,
		FrozenDependencies: dependency, FrozenDependenciesHash: dependencyHash,
		AdvertiseNotBefore: "2026-09-11T10:00:00Z", PreferNotBefore: "2026-09-11T10:10:00Z",
		DrainNotBefore: "2026-09-11T10:20:00Z", DrainNotAfter: "2026-09-11T10:30:00Z",
		RetireNotBefore: "2026-09-11T10:40:00Z", MinimumReaderFloor: 1,
	}
	verify := func(_ *rotation.IntentV1, _ *rotation.StateV1, transition *rotation.Transition) error {
		_, err := wire.ParseHash(transition.CertifiedHeadHash)
		return err
	}
	store, err := rotation.OpenStore(filepath.Join(t.TempDir(), "rotation.json"), verify)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Begin(intent, rotation.Transition{NextPhase: "allocated",
		CertifiedHeadHash: runtimePlanHash("allocated-head"), CertifiedAt: "2026-09-11T10:00:00Z"}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Advance(rotation.Transition{NextPhase: "prepared",
		CertifiedHeadHash: runtimePlanHash("prepared-head"), CertifiedAt: "2026-09-11T10:01:00Z"}); err != nil {
		t.Fatal(err)
	}
	l4 := "udp"
	if transport == "trojan_tls" {
		l4 = "tcp"
	}
	executionPlan := rotation.ExecutionPlanV1{
		Schema: 1, ClusterID: clusterID, RotationID: intent.RotationID,
		FrozenDependenciesHash: dependencyHash, SourceTuples: []rotation.Tuple{},
		TargetTuples: []rotation.Tuple{{Transport: l4, Address: localAddress, Port: localPort}},
	}
	planStore, err := rotation.OpenExecutionPlanStore(filepath.Join(t.TempDir(), "plans.json"))
	if err != nil {
		t.Fatal(err)
	}
	frozen, err := planStore.Freeze(intent, executionPlan)
	if err != nil {
		t.Fatal(err)
	}
	authorized, err := rotation.AuthorizeRuntimePlan(store.Snapshot(), frozen, verify)
	if err != nil {
		t.Fatal(err)
	}
	return runtimePlanFixture{catalog: catalog, head: head, controlSet: controlSet,
		authorized: authorized, profile: profile, resources: resources,
		tlsConfig: tlsConfig, endpointID: endpointID, generation: 1, now: now}
}

func runtimeControlMember(t *testing.T, clusterID string) (wire.ControlMemberV1, ed25519.PrivateKey) {
	t.Helper()
	keys := make([]ed25519.PrivateKey, 3)
	ids := make([]string, 3)
	public := make([]string, 3)
	for index := range keys {
		seed := make([]byte, ed25519.SeedSize)
		seed[len(seed)-1] = byte(index + 1)
		keys[index] = ed25519.NewKeyFromSeed(seed)
		raw := keys[index].Public().(ed25519.PublicKey)
		ids[index], _ = wire.ControlKeyID(raw)
		public[index] = base64.RawURLEncoding.EncodeToString(raw)
	}
	return wire.ControlMemberV1{
		Schema: 1, ClusterID: clusterID, MemberID: "00000000000000000000000001",
		MembershipKeyID: ids[0], MembershipPublicKey: public[0], ConfigKeyID: ids[1],
		ConfigPublicKey: public[1], EnrollmentKeyID: ids[2], EnrollmentPublicKey: public[2],
		MinimumControlProtocol: 2,
	}, keys[1]
}

func runtimePlanHash(value string) string {
	return wire.HashRaw("bootstrap-runtime-plan-test-v1", []byte(value))
}

func testListenerBinding(t *testing.T, transport, ingressSetHash, serverName string,
	address net.Addr, certificate *x509.Certificate) VerifiedBootstrapListenerV1 {
	t.Helper()
	host, rawPort, err := net.SplitHostPort(address.String())
	if err != nil {
		t.Fatal(err)
	}
	parsedAddress, err := netip.ParseAddr(host)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.ParseInt(rawPort, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	l4 := "tcp"
	if transport == "hysteria2" {
		l4 = "udp"
	}
	digest := sha256.Sum256(certificate.RawSubjectPublicKeyInfo)
	projection := bootstrapListenerRuntimeProjectionV1{
		Schema: 1, ClusterID: "demo-cluster", IngressSetHash: ingressSetHash,
		EndpointSetID: "bootstrap-ingress", EndpointID: "bootstrap-edge",
		LogicalServerID: "demo-edge", Transport: transport, ListenerGeneration: 1,
		ListenerState: "preferred", ServerName: serverName, PublicPort: port,
		BindTuple:    rotation.Tuple{Transport: l4, Address: parsedAddress.String(), Port: port},
		PublicTuples: []rotation.Tuple{{Transport: l4, Address: parsedAddress.String(), Port: port}},
		SPKIPins:     []string{"sha256:" + hex.EncodeToString(digest[:])},
		ValidFrom:    "2026-09-11T00:00:00Z", ValidUntil: "2026-09-12T00:00:00Z",
	}
	bindingHash, err := wire.HashObject(domainBootstrapListenerRuntimeBinding, projection)
	if err != nil {
		t.Fatal(err)
	}
	return VerifiedBootstrapListenerV1{projection: projection, bindingHash: bindingHash}
}
