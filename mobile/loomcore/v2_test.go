package loomcore

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"loom/internal/wire"
)

func TestVerifyCanonicalGoldenUsesSharedStrictWire(t *testing.T) {
	body, err := os.ReadFile("../../testdata/wire/v2/canonical.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyCanonicalGolden(body); err != nil {
		t.Fatal(err)
	}
	if err := VerifyCanonicalGolden(bytes.Replace(body, []byte("sha256:8d52"), []byte("sha256:9d52"), 1)); err == nil {
		t.Fatal("篡改后的 shared golden 被接受")
	}
}

func TestAndroidV2StateRequiresInviteLatchAndExactSelfConsistentLKG(t *testing.T) {
	set, envelope := androidV2EnvelopeFixture(t)
	envelopeJSON, _ := wire.MarshalCanonical(envelope)
	setJSON, _ := wire.MarshalCanonical(set)
	identityHash := envelope.Payload.Active.IdentitySPKIHash
	if _, err := PrepareV2DeviceState(envelopeJSON, setJSON, envelope.Payload.DeviceID,
		identityHash, nil); err == nil || !strings.Contains(err.Error(), "Invite proof") {
		t.Fatalf("普通 update API 建立了首次 v2 latch: %v", err)
	}
	floors, err := wire.VerifyDeviceViewEnvelope(&envelope, &set)
	if err != nil {
		t.Fatal(err)
	}
	current, err := marshalAndroidV2DeviceState(androidV2DeviceState{Schema: 1, Floors: floors, Envelope: envelope})
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := PrepareV2DeviceState(envelopeJSON, setJSON, envelope.Payload.DeviceID,
		identityHash, current)
	if err != nil || !bytes.Equal(replayed, current) {
		t.Fatalf("exact Device LKG replay 失败: equal=%v err=%v", bytes.Equal(replayed, current), err)
	}
	if _, err := PrepareV2DeviceState(append([]byte{' '}, envelopeJSON...), setJSON,
		envelope.Payload.DeviceID, identityHash, current); err == nil || !strings.Contains(err.Error(), "exact canonical") {
		t.Fatalf("非 canonical Device view 被接受: %v", err)
	}
	var corrupted androidV2DeviceState
	if _, err := wire.DecodeStrict(current, 32<<20, &corrupted); err != nil {
		t.Fatal(err)
	}
	corrupted.Floors.DeviceViewHash = wire.HashRaw("android-v2-test", []byte("other-view"))
	corruptedJSON, _ := wire.MarshalCanonical(corrupted)
	if _, err := V2DeviceStateFloors(corruptedJSON); err == nil || !strings.Contains(err.Error(), "同一 Device LKG") {
		t.Fatalf("重启读取接受了 floors/envelope 分叉: %v", err)
	}
}

func androidV2EnvelopeFixture(t *testing.T) (wire.ControlSetV1, wire.DeviceViewEnvelopeV2) {
	return androidV2EnvelopeFixtureFor(t, "demo-android",
		wire.HashRaw("android-v2-test", []byte("identity")), []wire.SecretArtifactRefV2{})
}

func androidV2EnvelopeFixtureFor(t *testing.T, deviceID, identityHash string,
	secretRefs []wire.SecretArtifactRefV2,
) (wire.ControlSetV1, wire.DeviceViewEnvelopeV2) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	seed[len(seed)-1] = 1
	membershipKey := ed25519.NewKeyFromSeed(seed)
	seed[len(seed)-1] = 2
	configKey := ed25519.NewKeyFromSeed(seed)
	seed[len(seed)-1] = 3
	enrollmentKey := ed25519.NewKeyFromSeed(seed)
	key := func(private ed25519.PrivateKey) (string, string) {
		public := private.Public().(ed25519.PublicKey)
		id, _ := wire.ControlKeyID(public)
		return id, base64.RawURLEncoding.EncodeToString(public)
	}
	membershipID, membershipPublic := key(membershipKey)
	configID, configPublic := key(configKey)
	enrollmentID, enrollmentPublic := key(enrollmentKey)
	set := wire.ControlSetV1{Schema: 1, ClusterID: "demo-cluster", Members: []wire.ControlMemberV1{{
		Schema: 1, ClusterID: "demo-cluster", MemberID: "00000000000000000000000001",
		MembershipKeyID: membershipID, MembershipPublicKey: membershipPublic,
		ConfigKeyID: configID, ConfigPublicKey: configPublic,
		EnrollmentKeyID: enrollmentID, EnrollmentPublicKey: enrollmentPublic,
		MinimumControlProtocol: 2,
	}}}
	if err := wire.ValidateControlSet(&set); err != nil {
		t.Fatal(err)
	}
	hash := func(value string) string { return wire.HashRaw("android-v2-test", []byte(value)) }
	membership := wire.EnrollmentMembershipV1{Schema: 1, DesiredState: "active_on_completion"}
	responsibilities := wire.EnrollmentResponsibilitiesV1{Schema: 1, Values: []string{"use_loom"}}
	grants := wire.EnrollmentDestinationGrantsV1{Schema: 1, Values: []wire.EnrollmentDestinationGrantV1{}}
	bundle := wire.DeviceEndpointBundleV1{Schema: 1, ClusterID: set.ClusterID,
		DeviceID: deviceID, DeviceGeneration: 1, DataIngressSets: []wire.DeviceDataIngressBindingV1{}}
	membershipHash, _ := wire.HashObject("loom-enrollment-membership-v1", membership)
	responsibilitiesHash, _ := wire.HashObject("loom-enrollment-responsibilities-v1", responsibilities)
	grantsHash, _ := wire.HashObject("loom-enrollment-destination-grants-v1", grants)
	bundleHash, _ := wire.DeviceEndpointBundleHash(&bundle)
	secretRoot, _ := wire.SecretArtifactRefsRoot(secretRefs)
	payload := wire.DeviceViewPayloadV2{Schema: 2, ClusterID: set.ClusterID, DeviceID: bundle.DeviceID,
		DeviceGeneration: 1, State: "active", Active: &wire.DeviceActiveViewV1{
			IdentitySPKIHash: identityHash, Membership: membership, MembershipHash: membershipHash,
			Responsibilities: responsibilities, ResponsibilitiesHash: responsibilitiesHash,
			Grants: grants, GrantsHash: grantsHash, EndpointBundle: bundle, EndpointBundleHash: bundleHash,
			ConfigArtifactRefs: []wire.DeviceConfigArtifactRefV1{}, SecretArtifactRefsRoot: secretRoot,
		}}
	payloadHash, _ := wire.DeviceViewHash(&payload)
	leaf := wire.DeviceViewLeafV2{Schema: 2, ClusterID: set.ClusterID, ViewSchemaVersion: 2,
		DeviceID: payload.DeviceID, DeviceGeneration: 1, State: "active", PayloadHash: payloadHash,
		PreviousViewHash: wire.EmptyHashV1, EndpointSetHash: bundleHash, MinReaderVersion: 2}
	leafBytes, _ := wire.MarshalCanonical(leaf)
	root := wire.MerkleRoot([][]byte{leafBytes})
	setHash, _ := wire.ControlSetHash(&set)
	transition, _ := json.Marshal(wire.BootstrapHeadContextV1{Schema: 1, Kind: "bootstrap",
		InitialV2HeadPayloadHash: hash("initial-payload")})
	head, err := wire.NewHeadEntry(wire.HeadEntryBodyV2{Payload: wire.HeadEntryPayloadV2{
		Schema: 2, HeadKind: "bootstrap", ClusterID: set.ClusterID, RecoveryEpoch: 0,
		RecoveryStatementHash: hash("recovery"), RecoveryPolicyHash: hash("policy"),
		ControlEpoch: 0, ControlSetHash: setHash, ControlPeerDirectoryHash: hash("directory"),
		RaftTerm: 1, RaftIndex: 1, PreviousLogEntryHash: wire.EmptyHashV1, ControlRevision: 1,
		ParentHeadHash: wire.EmptyHashV1, OperationRoot: hash("operations"), SnapshotHash: hash("snapshot"),
		EffectiveSSOTHash: hash("ssot"), DeviceViewsRoot: "sha256:" + fmt.Sprintf("%x", root),
		AdminACLRoot: hash("admin"), CAProfileRoot: hash("ca"), BootstrapIssuerRegistryRoot: hash("issuer"),
		RenderContractVersion: 2, MinReaderVersion: 2, CommittedLogicalTime: "2026-09-11T00:00:00Z",
		MaxClockSkewSeconds: 30, TransitionContext: transition,
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
	rawRefs := make([]json.RawMessage, len(secretRefs))
	for index := range secretRefs {
		rawRefs[index], _ = wire.MarshalCanonical(secretRefs[index])
	}
	return set, wire.DeviceViewEnvelopeV2{Schema: 2, Payload: payload, Leaf: leaf,
		LeafIndex: 0, TreeSize: 1, AuditPath: []string{}, SignedCurrent: wire.SignedCurrentV2{
			Schema: 2, Head: head, QuorumCertificate: qcBytes, PublishedAt: "2026-09-11T00:00:01Z",
		}, SecretArtifactRefs: rawRefs}
}
