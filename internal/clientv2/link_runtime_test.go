package clientv2

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"loom/internal/wire"
)

func TestLinuxLinkRuntimePlanIsDrivenByCertifiedViewArtifactAndGenerationFloor(t *testing.T) {
	set, key := clientControlSet(t)
	envelope := clientEnvelope(t, &set, key)
	now := time.Date(2026, 9, 12, 0, 0, 0, 0, time.UTC)
	grant := wire.EnrollmentDestinationGrantsV1{Schema: 1,
		Values: []wire.EnrollmentDestinationGrantV1{{Kind: "service", TargetID: "service-a"}}}
	envelope.Payload.Active.Grants = grant
	envelope.Payload.Active.GrantsHash, _ = wire.HashObject("loom-enrollment-destination-grants-v1", grant)
	generation := func(number int64, state string) wire.ListenerGenerationV2 {
		return wire.ListenerGenerationV2{
			Schema: 2, ListenerGeneration: number, PublishedState: state,
			DialTargetFQDN: "edge.example.test", PublicPort: 443 + number,
			AddressFamilies: []string{"ipv4", "ipv6"}, TransportIdentityRefs: []string{"credential-a"},
			CredentialGeneration: number, CertificateIdentityProjectionHash: runtimePlanHash("certificate"),
			PublicProfileGeneration: 1, IntroducedRevision: number,
			ValidFrom: "2026-01-01T00:00:00Z", ValidUntil: "2027-01-01T00:00:00Z",
			RotationOperationHash: runtimePlanHash(fmt.Sprintf("rotation-%d", number)),
		}
	}
	endpoint := wire.DataIngressEndpointV2{
		EndpointID: "edge-a", LogicalServerID: "server-a", Transport: "hysteria2",
		ListenerGenerations: []wire.ListenerGenerationV2{generation(1, "advertised"), generation(2, "preferred")},
		ListenerTombstones:  []wire.ListenerGenerationTombstoneV1{}, PathCapabilities: []string{"l3"},
	}
	endpointSet := wire.DataIngressEndpointSetV2{
		Schema: 2, ClusterID: set.ClusterID, EndpointSetID: "data-a", Generation: 1,
		ValidFrom: "2026-01-01T00:00:00Z", ValidUntil: "2027-01-01T00:00:00Z",
		Endpoints: []wire.DataIngressEndpointV2{endpoint}, GrantsRoot: envelope.Payload.Active.GrantsHash,
		ParentHeadHash: envelope.SignedCurrent.Head.HeadHash,
		ConfigQC:       append([]byte(nil), envelope.SignedCurrent.QuorumCertificate...),
	}
	endpointSetHash, err := wire.DataIngressSetHash(&endpointSet)
	if err != nil {
		t.Fatal(err)
	}
	bundle := wire.DeviceEndpointBundleV1{
		Schema: 1, ClusterID: set.ClusterID, DeviceID: envelope.Payload.DeviceID,
		DeviceGeneration: envelope.Payload.DeviceGeneration,
		DataIngressSets: []wire.DeviceDataIngressBindingV1{{
			EndpointSetID: endpointSet.EndpointSetID, EndpointSet: endpointSet, EndpointSetHash: endpointSetHash,
		}},
	}
	envelope.Payload.Active.EndpointBundle = bundle
	envelope.Payload.Active.EndpointBundleHash, _ = wire.DeviceEndpointBundleHash(&bundle)
	artifact := LinuxLinkIntentArtifactV1{
		Schema: 1, ClusterID: set.ClusterID, DeviceID: envelope.Payload.DeviceID,
		DeviceGeneration: envelope.Payload.DeviceGeneration, Generation: 1,
		RenderContractID: wire.LinuxLinkIntentRenderContract, AuthorityHeadHash: envelope.SignedCurrent.Head.HeadHash,
		LinkIntents: []wire.LinkIntentV1{{
			Schema: 1, ClusterID: set.ClusterID, LinkID: "link-a", FromDeviceID: envelope.Payload.DeviceID,
			To: wire.LinkIntentDestinationV1{ServiceID: "service-a"}, Purpose: "data_forward",
			AllowedTransports: []string{"hysteria2"}, Initiator: "from",
			ListenerResourceRefs: []string{"edge-a"}, CredentialRefs: []string{"credential-a"},
			RouteScope: "service-a", Generation: 1, ParentHeadHash: envelope.SignedCurrent.Head.HeadHash,
		}},
	}
	raw := bindRuntimeArtifactToEnvelope(t, &envelope, &set, key, artifact)
	plan, err := BuildLinuxLinkRuntimePlan(&envelope, &set, nil, nil, raw,
		[]InstalledSecretV1{{SecretID: "credential-a"}}, now, map[string]int64{"edge-a": 1})
	if err != nil {
		t.Fatal(err)
	}
	if !plan.EnableTUN || !plan.EnableMixed || plan.ServeForward || plan.CertifiedControl ||
		len(plan.Actions) != 1 || plan.Actions[0].Mode != "dial" || plan.Actions[0].ResolveAtFinalEgress ||
		len(plan.Actions[0].DialCandidates) != 2 ||
		plan.Actions[0].DialCandidates[0].ListenerGeneration != 2 ||
		plan.Actions[0].DialCandidates[1].ListenerGeneration != 1 {
		t.Fatalf("unexpected Linux runtime plan: %#v", plan)
	}
	if _, err := BuildLinuxLinkRuntimePlan(&envelope, &set, nil, nil, raw,
		[]InstalledSecretV1{{SecretID: "credential-a"}}, now, map[string]int64{"edge-a": 3}); err == nil {
		t.Fatal("已见 generation floor 之下的 endpoint 被恢复")
	}
	tampered := bytes.Replace(raw, []byte("service-a"), []byte("service-b"), 1)
	if _, err := BuildLinuxLinkRuntimePlan(&envelope, &set, nil, nil, tampered,
		[]InstalledSecretV1{{SecretID: "credential-a"}}, now, nil); err == nil {
		t.Fatal("未被 Device view content hash 承诺的 LinkIntent artifact 被接受")
	}
}

func TestLinuxLinkRuntimeRejectsLocalResponsibilityOrControlEscalation(t *testing.T) {
	set, key := clientControlSet(t)
	envelope := clientEnvelope(t, &set, key)
	artifact := LinuxLinkIntentArtifactV1{
		Schema: 1, ClusterID: set.ClusterID, DeviceID: envelope.Payload.DeviceID,
		DeviceGeneration: 1, Generation: 1, RenderContractID: wire.LinuxLinkIntentRenderContract,
		AuthorityHeadHash: envelope.SignedCurrent.Head.HeadHash,
		LinkIntents: []wire.LinkIntentV1{{
			Schema: 1, ClusterID: set.ClusterID, LinkID: "control-a", FromDeviceID: envelope.Payload.DeviceID,
			To: wire.LinkIntentDestinationV1{DeviceID: "control-peer"}, Purpose: "control_overlay",
			AllowedTransports: []string{"wireguard"}, Initiator: "from",
			ListenerResourceRefs: []string{"wg-control-a"}, CredentialRefs: []string{"credential-a"},
			RouteScope: "control-overlay", Generation: 1, ParentHeadHash: envelope.SignedCurrent.Head.HeadHash,
		}},
	}
	raw := bindRuntimeArtifactToEnvelope(t, &envelope, &set, key, artifact)
	_, err := BuildLinuxLinkRuntimePlan(&envelope, &set, nil, nil, raw,
		[]InstalledSecretV1{{SecretID: "credential-a"}}, time.Date(2026, 9, 12, 0, 0, 0, 0, time.UTC), nil)
	if err == nil || !strings.Contains(err.Error(), "ControlSet") {
		t.Fatalf("本机参数把普通 Device 提升为 control: %v", err)
	}
}

func bindRuntimeArtifactToEnvelope(t *testing.T, envelope *wire.DeviceViewEnvelopeV2,
	set *wire.ControlSetV1, key ed25519.PrivateKey, artifact LinuxLinkIntentArtifactV1) []byte {
	t.Helper()
	artifact.AuthorityHeadHash = envelope.SignedCurrent.Head.Body.Payload.ParentHeadHash
	for index := range artifact.LinkIntents {
		artifact.LinkIntents[index].ParentHeadHash = artifact.AuthorityHeadHash
	}
	raw, err := wire.MarshalCanonical(artifact)
	if err != nil {
		t.Fatal(err)
	}
	contentHash, _ := wire.DeviceConfigArtifactContentHash(raw)
	envelope.Payload.Active.ConfigArtifactRefs = []wire.DeviceConfigArtifactRefV1{{
		ArtifactID: LinuxLinkIntentArtifactID, Generation: artifact.Generation, Platform: "linux-server",
		MediaType: "application/vnd.loom.config+json", RenderContractID: artifact.RenderContractID,
		SizeBytes: int64(len(raw)), ContentHash: contentHash,
	}}
	resignRuntimeEnvelope(t, envelope, set, key)
	return raw
}

func resignRuntimeEnvelope(t *testing.T, envelope *wire.DeviceViewEnvelopeV2,
	set *wire.ControlSetV1, key ed25519.PrivateKey) {
	t.Helper()
	payloadHash, err := wire.DeviceViewHash(&envelope.Payload)
	if err != nil {
		t.Fatal(err)
	}
	envelope.Leaf.PayloadHash = payloadHash
	envelope.Leaf.EndpointSetHash = envelope.Payload.Active.EndpointBundleHash
	leafBytes, _ := wire.MarshalCanonical(envelope.Leaf)
	root := wire.MerkleRoot([][]byte{leafBytes})
	body := envelope.SignedCurrent.Head.Body
	body.Payload.DeviceViewsRoot = "sha256:" + fmt.Sprintf("%x", root)
	head, err := wire.NewHeadEntry(body)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := wire.SignHeadAttestation(wire.AttestationForHead(&head), set.Members[0], key)
	if err != nil {
		t.Fatal(err)
	}
	qc := wire.StableQC(&head, []wire.ControlConfigSignatureV1{signature})
	qcBytes, _ := wire.MarshalCanonical(qc)
	envelope.SignedCurrent.Head = head
	envelope.SignedCurrent.QuorumCertificate = json.RawMessage(qcBytes)
}

func runtimePlanHash(value string) string {
	return wire.HashRaw("linux-runtime-plan-test", []byte(value))
}
