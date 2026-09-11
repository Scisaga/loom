package clientv2

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"loom/internal/wire"
)

func TestOpenRejectsLooseOrNonCanonicalStateFile(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "state.json")
	body := []byte(` {"envelope":{},"floors":{"schema":2,"v2_latched":true},"schema":1}`)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil {
		t.Fatal("接受了非 canonical 的 v2 LKG")
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil {
		t.Fatal("接受了权限过宽的 v2 LKG")
	}
}

func TestEnvelopeReturnsDeepCopy(t *testing.T) {
	store := &Store{state: &State{Envelope: wire.DeviceViewEnvelopeV2{AuditPath: []string{"original"}}}}
	copy := store.Envelope()
	copy.AuditPath[0] = "mutated"
	if store.state.Envelope.AuditPath[0] != "original" {
		t.Fatal("调用方可通过 Envelope 返回值修改 durable state")
	}
}

func TestAcceptPersistsAndReopensExactEmptySecretRefs(t *testing.T) {
	set, key := clientControlSet(t)
	envelope := clientEnvelope(t, &set, key)
	directory := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "state.json")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	identityHash := envelope.Payload.Active.IdentitySPKIHash
	if _, err := store.Accept(&envelope, &set, envelope.Payload.DeviceID, identityHash); err == nil {
		t.Fatal("首次 v2 latch 未携 verified bootstrap/Invite evidence")
	}
	if _, err := store.acceptWithAdvance(&envelope, &set, nil, envelope.Payload.DeviceID, identityHash, wire.AdvanceFloors); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := reopened.Envelope(); got == nil || got.SecretArtifactRefs == nil || len(got.SecretArtifactRefs) != 0 {
		t.Fatalf("重启后未保留 exact empty secret refs: %#v", got)
	}
}

func clientControlSet(t *testing.T) (wire.ControlSetV1, ed25519.PrivateKey) {
	t.Helper()
	keys := make([]ed25519.PrivateKey, 3)
	ids := make([]string, 3)
	publics := make([]string, 3)
	for i := range keys {
		seed := make([]byte, ed25519.SeedSize)
		seed[len(seed)-1] = byte(i + 1)
		keys[i] = ed25519.NewKeyFromSeed(seed)
		publicKey := keys[i].Public().(ed25519.PublicKey)
		ids[i], _ = wire.ControlKeyID(publicKey)
		publics[i] = base64.RawURLEncoding.EncodeToString(publicKey)
	}
	set := wire.ControlSetV1{Schema: 1, ClusterID: "demo-cluster", Members: []wire.ControlMemberV1{{
		Schema: 1, ClusterID: "demo-cluster", MemberID: "00000000000000000000000001",
		MembershipKeyID: ids[0], MembershipPublicKey: publics[0], ConfigKeyID: ids[1], ConfigPublicKey: publics[1],
		EnrollmentKeyID: ids[2], EnrollmentPublicKey: publics[2], MinimumControlProtocol: 2,
	}}}
	if err := wire.ValidateControlSet(&set); err != nil {
		t.Fatal(err)
	}
	return set, keys[1]
}

func clientEnvelope(t *testing.T, set *wire.ControlSetV1, configKey ed25519.PrivateKey) wire.DeviceViewEnvelopeV2 {
	t.Helper()
	hash := func(value string) string { return wire.HashRaw("client-v2-test", []byte(value)) }
	membership := wire.EnrollmentMembershipV1{Schema: 1, DesiredState: "active_on_completion"}
	responsibilities := wire.EnrollmentResponsibilitiesV1{Schema: 1, Values: []string{"use_loom"}}
	grants := wire.EnrollmentDestinationGrantsV1{Schema: 1, Values: []wire.EnrollmentDestinationGrantV1{}}
	bundle := wire.DeviceEndpointBundleV1{Schema: 1, ClusterID: set.ClusterID, DeviceID: "linux-device-1", DeviceGeneration: 1, DataIngressSets: []wire.DeviceDataIngressBindingV1{}}
	membershipHash, _ := wire.HashObject("loom-enrollment-membership-v1", membership)
	responsibilitiesHash, _ := wire.HashObject("loom-enrollment-responsibilities-v1", responsibilities)
	grantsHash, _ := wire.HashObject("loom-enrollment-destination-grants-v1", grants)
	bundleHash, _ := wire.DeviceEndpointBundleHash(&bundle)
	secretRefsRoot, _ := wire.SecretArtifactRefsRoot([]wire.SecretArtifactRefV2{})
	payload := wire.DeviceViewPayloadV2{
		Schema: 2, ClusterID: set.ClusterID, DeviceID: bundle.DeviceID, DeviceGeneration: 1, State: "active",
		Active: &wire.DeviceActiveViewV1{
			IdentitySPKIHash: hash("identity"), Membership: membership, MembershipHash: membershipHash,
			Responsibilities: responsibilities, ResponsibilitiesHash: responsibilitiesHash, Grants: grants, GrantsHash: grantsHash,
			EndpointBundle: bundle, EndpointBundleHash: bundleHash, ConfigArtifactRefs: []wire.DeviceConfigArtifactRefV1{},
			SecretArtifactRefsRoot: secretRefsRoot,
		},
	}
	payloadHash, _ := wire.DeviceViewHash(&payload)
	leaf := wire.DeviceViewLeafV2{
		Schema: 2, ClusterID: set.ClusterID, ViewSchemaVersion: 2, DeviceID: payload.DeviceID, DeviceGeneration: 1,
		State: "active", PayloadHash: payloadHash, PreviousViewHash: wire.EmptyHashV1, EndpointSetHash: bundleHash, MinReaderVersion: 2,
	}
	leafBytes, _ := wire.MarshalCanonical(leaf)
	root := wire.MerkleRoot([][]byte{leafBytes})
	setHash, _ := wire.ControlSetHash(set)
	transition, _ := json.Marshal(wire.BootstrapHeadContextV1{Schema: 1, Kind: "bootstrap", InitialV2HeadPayloadHash: hash("initial-payload")})
	head, err := wire.NewHeadEntry(wire.HeadEntryBodyV2{Payload: wire.HeadEntryPayloadV2{
		Schema: 2, HeadKind: "bootstrap", ClusterID: set.ClusterID, RecoveryEpoch: 0,
		RecoveryStatementHash: hash("recovery"), RecoveryPolicyHash: hash("policy"), ControlEpoch: 0, ControlSetHash: setHash,
		ControlPeerDirectoryHash: hash("directory"), RaftTerm: 1, RaftIndex: 1, PreviousLogEntryHash: wire.EmptyHashV1,
		ControlRevision: 1, ParentHeadHash: wire.EmptyHashV1, OperationRoot: hash("operations"), SnapshotHash: hash("snapshot"),
		EffectiveSSOTHash: hash("ssot"), DeviceViewsRoot: "sha256:" + fmt.Sprintf("%x", root),
		AdminACLRoot: hash("admin"), CAProfileRoot: hash("ca"), BootstrapIssuerRegistryRoot: hash("issuer"),
		RenderContractVersion: 2, MinReaderVersion: 2, CommittedLogicalTime: "2026-09-11T00:00:00Z", MaxClockSkewSeconds: 30,
		TransitionContext: transition,
	}, TransitionProofHash: hash("transition")})
	if err != nil {
		t.Fatal(err)
	}
	signature, err := wire.SignHeadAttestation(wire.AttestationForHead(&head), set.Members[0], configKey)
	if err != nil {
		t.Fatal(err)
	}
	qc := wire.StableQC(&head, []wire.ControlConfigSignatureV1{signature})
	qcBytes, _ := wire.MarshalCanonical(qc)
	return wire.DeviceViewEnvelopeV2{
		Schema: 2, Payload: payload, Leaf: leaf, LeafIndex: 0, TreeSize: 1, AuditPath: []string{},
		SignedCurrent:      wire.SignedCurrentV2{Schema: 2, Head: head, QuorumCertificate: qcBytes, PublishedAt: "2026-09-11T00:00:01Z"},
		SecretArtifactRefs: []json.RawMessage{},
	}
}
