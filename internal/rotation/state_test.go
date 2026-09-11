package rotation

import (
	"strings"
	"testing"

	"loom/internal/wire"
)

const testHash = "sha256:1111111111111111111111111111111111111111111111111111111111111111"

func testIntent(t *testing.T) IntentV1 {
	t.Helper()
	source := int64(1)
	dep := FrozenDependenciesV1{
		Schema: 1, ClusterID: "cluster", EndpointKind: "data", EndpointSetID: "set", EndpointID: "edge", LogicalServerID: "server", Transport: "hysteria2",
		SourceListenerGeneration: &source, SourceListenerGenerationHash: testHash, TargetListenerGeneration: 2,
		LogicalPublicEndpointIntentHash: testHash, PublicAccessProfileHash: testHash, DNSAddressBindingHash: testHash,
		CertificateIdentityProjectionHash: testHash, CredentialArtifactRefsRoot: testHash, RenderContractHash: testHash,
		EvidencePolicyHash: testHash, PortPoolHash: testHash, FirewallPolicyHash: testHash,
		ForwardListenerResourceGenerationHash: testHash, LinkIntentHashes: []string{},
	}
	depHash, err := wire.HashObject(DomainFrozenDependencies, dep)
	if err != nil {
		t.Fatal(err)
	}
	return IntentV1{
		Schema: 1, ClusterID: "cluster", RotationID: "rotation", OperationID: "operation", BaseHeadHash: testHash,
		ExpectedEndpointSetHash: testHash, FrozenDependencies: dep, FrozenDependenciesHash: depHash,
		AdvertiseNotBefore: "2026-01-01T00:00:00Z", PreferNotBefore: "2026-01-01T00:01:00Z",
		DrainNotBefore: "2026-01-01T00:02:00Z", DrainNotAfter: "2026-01-01T00:03:00Z",
		RetireNotBefore: "2026-01-01T00:04:00Z", MinimumReaderFloor: 7,
	}
}

func TestRotationRequiresEvidenceFloorAndGuard(t *testing.T) {
	intent := testIntent(t)
	state, err := Allocate(intent, testHash)
	if err != nil {
		t.Fatal(err)
	}
	state = mustAdvance(t, intent, state, Transition{NextPhase: "preparing", CertifiedHeadHash: testHash, CertifiedAt: "2026-01-01T00:00:00Z"})
	if _, err := Advance(intent, state, Transition{NextPhase: "advertised", CertifiedHeadHash: testHash, CertifiedAt: "2026-01-01T00:00:00Z", EvidenceRefs: []string{testHash}}); err == nil {
		t.Fatal("advertise without local+external evidence accepted")
	}
	state = mustAdvance(t, intent, state, Transition{NextPhase: "advertised", CertifiedHeadHash: testHash, CertifiedAt: "2026-01-01T00:00:00Z", EvidenceRefs: []string{testHash, strings.Replace(testHash, "11", "22", 1)}})
	if _, err := Advance(intent, state, Transition{NextPhase: "preferred", CertifiedHeadHash: testHash, CertifiedAt: "2026-01-01T00:01:00Z", ReaderFloor: 6}); err == nil {
		t.Fatal("prefer below reader floor accepted")
	}
	state = mustAdvance(t, intent, state, Transition{NextPhase: "preferred", CertifiedHeadHash: testHash, CertifiedAt: "2026-01-01T00:01:00Z", ReaderFloor: 7})
	leaf := RetirementDependencyLeafV1{Schema: 1, Kind: "offline_lkg", ObjectHash: testHash, ReferenceNotAfter: "2026-01-01T00:05:00Z"}
	guard, err := BuildGuard(intent, testHash, []RetirementDependencyLeafV1{leaf}, "2026-01-01T00:05:00Z", "2026-01-01T00:05:00Z", "2026-01-01T00:05:00Z")
	if err != nil {
		t.Fatal(err)
	}
	state = mustAdvance(t, intent, state, Transition{NextPhase: "draining", CertifiedHeadHash: testHash, CertifiedAt: "2026-01-01T00:02:00Z", Guard: &guard})
	if _, err := Advance(intent, state, Transition{NextPhase: "retired", CertifiedHeadHash: testHash, CertifiedAt: "2026-01-01T00:04:00Z", ReaderFloor: 7, Guard: &guard}); err == nil {
		t.Fatal("retire before dependency deadline accepted")
	}
	state = mustAdvance(t, intent, state, Transition{NextPhase: "retired", CertifiedHeadHash: testHash, CertifiedAt: "2026-01-01T00:05:00Z", ReaderFloor: 7, Guard: &guard})
	if state.Phase != "retired" {
		t.Fatal(state.Phase)
	}
}

func TestFrozenDependencyMutationRejected(t *testing.T) {
	intent := testIntent(t)
	state, err := Allocate(intent, testHash)
	if err != nil {
		t.Fatal(err)
	}
	intent.FrozenDependencies.PortPoolHash = strings.Replace(testHash, "11", "33", 1)
	if _, err := Advance(intent, state, Transition{NextPhase: "preparing", CertifiedHeadHash: testHash, CertifiedAt: "2026-01-01T00:00:00Z"}); err == nil {
		t.Fatal("mutable latest dependency replaced frozen bytes")
	}
}

func TestNATPoolAndWGOwnership(t *testing.T) {
	pool := MappingPool{Transport: "udp", PublicAddress: "203.0.113.1", PublicPortStart: 41000, PublicPortEnd: 41001, LocalAddress: "10.0.0.2", LocalPortStart: 51000, LocalPortEnd: 51001, Generation: 1}
	public, local, err := pool.Allocate([]Tuple{{Transport: "udp", Address: "203.0.113.1", Port: 41000}})
	if err != nil || public.Port != 41001 || local.Port != 51001 {
		t.Fatalf("allocation failed: %#v %#v %v", public, local, err)
	}
	overlap := WireGuardOverlap{
		Old: WireGuardGeneration{Generation: 1, InterfaceName: "wg-old", ListenTuple: Tuple{Transport: "udp", Address: "0.0.0.0", Port: 42000}, PrivateKeyRef: "key-old", PeerPublicKey: "peer-old", TunnelAddress: "10.1.0.1/32", RouteTable: 100, FwMark: 100, AllowedIPs: []string{"10.2.0.0/16"}, State: "draining"},
		New: WireGuardGeneration{Generation: 2, InterfaceName: "wg-new", ListenTuple: Tuple{Transport: "udp", Address: "0.0.0.0", Port: 42001}, PrivateKeyRef: "key-new", PeerPublicKey: "peer-new", TunnelAddress: "10.1.0.2/32", RouteTable: 101, FwMark: 101, AllowedIPs: []string{"10.2.0.0/16"}, State: "active"},
	}
	if err := overlap.Validate(); err != nil {
		t.Fatal(err)
	}
	overlap.New.InterfaceName = overlap.Old.InterfaceName
	if err := overlap.Validate(); err == nil {
		t.Fatal("WG overlap sharing interface accepted")
	}
}

func TestGatesStayClosedWithoutWindowsEvidence(t *testing.T) {
	gates := GateStatus{Schema: 1, ServerOverlapGuard: true, LinuxV2Reader: true, AndroidV2Reader: true, LinuxAcceptance: true, AndroidAcceptance: true, NoV1CallersEvidence: true, RecoverableBackupProof: true}
	if !gates.ServerLinuxAndroidReady() {
		t.Fatal("Windows 条件错误地阻塞了服务端/Linux/Android 独立完成里程碑")
	}
	if gates.GateA() || gates.GateB() {
		t.Fatal("Gate A/B opened without Windows evidence")
	}
}

func TestRotationRejectsForgedStateAndUnauditedEmergencyRevoke(t *testing.T) {
	intent := testIntent(t)
	state, err := Allocate(intent, testHash)
	if err != nil {
		t.Fatal(err)
	}
	forged := state
	forged.Phase = "draining"
	if _, err := Advance(intent, forged, Transition{NextPhase: "retired", CertifiedHeadHash: testHash, CertifiedAt: "2026-01-01T00:10:00Z"}); err == nil {
		t.Fatal("接受了缺 retirement guard hash 的伪造 draining state")
	}
	if _, err := Advance(intent, state, Transition{NextPhase: "revoked", Emergency: true, CertifiedHeadHash: testHash, CertifiedAt: "2026-01-01T00:00:00Z"}); err == nil {
		t.Fatal("接受了没有中断证据的 emergency revoke")
	}
}

func mustAdvance(t *testing.T, intent IntentV1, state StateV1, transition Transition) StateV1 {
	t.Helper()
	next, err := Advance(intent, state, transition)
	if err != nil {
		t.Fatal(err)
	}
	return next
}
