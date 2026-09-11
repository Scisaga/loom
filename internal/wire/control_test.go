package wire

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
)

func deterministicMember(t *testing.T, ordinal byte) (ControlMemberV1, ed25519.PrivateKey) {
	t.Helper()
	keys := make([]ed25519.PrivateKey, 3)
	ids := make([]string, 3)
	public := make([]string, 3)
	for purpose := range keys {
		seed := make([]byte, ed25519.SeedSize)
		seed[len(seed)-2], seed[len(seed)-1] = ordinal, byte(purpose+1)
		keys[purpose] = ed25519.NewKeyFromSeed(seed)
		public[purpose] = base64.RawURLEncoding.EncodeToString(keys[purpose].Public().(ed25519.PublicKey))
		ids[purpose], _ = ControlKeyID(keys[purpose].Public().(ed25519.PublicKey))
	}
	memberID := fmt.Sprintf("%025d%d", 0, ordinal)
	return ControlMemberV1{
		Schema: 1, ClusterID: "demo-cluster", MemberID: memberID,
		MembershipKeyID: ids[0], MembershipPublicKey: public[0],
		ConfigKeyID: ids[1], ConfigPublicKey: public[1],
		EnrollmentKeyID: ids[2], EnrollmentPublicKey: public[2], MinimumControlProtocol: 2,
	}, keys[1]
}

func testHead(t *testing.T, set *ControlSetV1) HeadEntryV2 {
	t.Helper()
	setHash, err := ControlSetHash(set)
	if err != nil {
		t.Fatal(err)
	}
	hash := func(value string) string { return HashRaw("test-v1", []byte(value)) }
	context, _ := json.Marshal(struct {
		Schema                   int    `json:"schema"`
		Kind                     string `json:"kind"`
		InitialV2HeadPayloadHash string `json:"initial_v2_head_payload_hash"`
	}{1, "bootstrap", hash("payload")})
	entry, err := NewHeadEntry(HeadEntryBodyV2{
		Payload: HeadEntryPayloadV2{
			Schema: 2, HeadKind: "bootstrap", ClusterID: set.ClusterID,
			RecoveryEpoch: 0, RecoveryStatementHash: hash("recovery-statement"), RecoveryPolicyHash: hash("recovery-policy"),
			ControlEpoch: 0, ControlSetHash: setHash, ControlPeerDirectoryHash: hash("private-directory"),
			RaftTerm: 1, RaftIndex: 1, PreviousLogEntryHash: EmptyHashV1, ControlRevision: 1, ParentHeadHash: EmptyHashV1,
			OperationRoot: hash("operations"), SnapshotHash: hash("snapshot"), EffectiveSSOTHash: hash("ssot"),
			DeviceViewsRoot: hash("views"), AdminACLRoot: hash("acl"), CAProfileRoot: hash("ca"),
			BootstrapIssuerRegistryRoot: hash("issuers"), RenderContractVersion: 2, MinReaderVersion: 2,
			CommittedLogicalTime: "2026-09-11T12:00:00Z", MaxClockSkewSeconds: 30, TransitionContext: context,
		},
		TransitionProofHash: hash("transition"),
	})
	if err != nil {
		t.Fatal(err)
	}
	return entry
}

func TestStableQCUsesCommittedSetQuorum(t *testing.T) {
	var members []ControlMemberV1
	var keys []ed25519.PrivateKey
	for ordinal := byte(1); ordinal <= 3; ordinal++ {
		member, key := deterministicMember(t, ordinal)
		members, keys = append(members, member), append(keys, key)
	}
	set := &ControlSetV1{Schema: 1, ClusterID: "demo-cluster", Members: members}
	entry := testHead(t, set)
	attestation := AttestationForHead(&entry)
	one, _ := SignHeadAttestation(attestation, members[0], keys[0])
	two, _ := SignHeadAttestation(attestation, members[1], keys[1])

	minority := StableQC(&entry, []ControlConfigSignatureV1{one})
	if err := VerifyStableHeadQC(&entry, set, &minority); err == nil {
		t.Fatal("one online signer changed the committed N=3 quorum")
	}
	majority := StableQC(&entry, []ControlConfigSignatureV1{two, one})
	if err := VerifyStableHeadQC(&entry, set, &majority); err != nil {
		t.Fatal(err)
	}
	majority.Signatures[1].Signature = majority.Signatures[0].Signature
	if err := VerifyStableHeadQC(&entry, set, &majority); err == nil {
		t.Fatal("accepted a signature copied between members")
	}
}

func TestSingleMemberControlSetCertifiesN1Head(t *testing.T) {
	member, key := deterministicMember(t, 1)
	set := &ControlSetV1{Schema: 1, ClusterID: "demo-cluster", Members: []ControlMemberV1{member}}
	entry := testHead(t, set)
	signature, err := SignHeadAttestation(AttestationForHead(&entry), member, key)
	if err != nil {
		t.Fatal(err)
	}
	qc := StableQC(&entry, []ControlConfigSignatureV1{signature})
	if err := VerifyStableHeadQC(&entry, set, &qc); err != nil {
		t.Fatal(err)
	}
	if hash, err := QCStableHash(&qc); err != nil || hash == "" {
		t.Fatalf("qc hash=%q err=%v", hash, err)
	}
}

func TestJointHeadQCRequiresOldAndNewMajority(t *testing.T) {
	members := make(map[byte]ControlMemberV1)
	keys := make(map[byte]ed25519.PrivateKey)
	for ordinal := byte(1); ordinal <= 4; ordinal++ {
		members[ordinal], keys[ordinal] = deterministicMember(t, ordinal)
	}
	oldSet := &ControlSetV1{Schema: 1, ClusterID: "demo-cluster", Members: []ControlMemberV1{members[1], members[2], members[3]}}
	newSet := &ControlSetV1{Schema: 1, ClusterID: "demo-cluster", Members: []ControlMemberV1{members[2], members[3], members[4]}}
	entry := testHead(t, newSet)
	attestation := AttestationForHead(&entry)
	two, _ := SignHeadAttestation(attestation, members[2], keys[2])
	three, _ := SignHeadAttestation(attestation, members[3], keys[3])
	valid := JointHeadQC(&entry, []ControlConfigSignatureV1{three, two}, oldSet, newSet)
	if err := VerifyJointHeadQC(&entry, oldSet, newSet, &valid); err != nil {
		t.Fatal(err)
	}
	minority := JointHeadQC(&entry, []ControlConfigSignatureV1{two}, oldSet, newSet)
	if err := VerifyJointHeadQC(&entry, oldSet, newSet, &minority); err == nil {
		t.Fatal("joint QC accepted without dual majority")
	}
}

func TestSpecialTransitionContextRejectsUnknownFields(t *testing.T) {
	member, _ := deterministicMember(t, 1)
	set := &ControlSetV1{Schema: 1, ClusterID: "demo-cluster", Members: []ControlMemberV1{member}}
	entry := testHead(t, set)
	body := entry.Body
	body.Payload.TransitionContext = json.RawMessage(`{"schema":1,"kind":"bootstrap","initial_v2_head_payload_hash":"` + HashRaw("test-v1", []byte("payload")) + `","extra":true}`)
	if _, err := NewHeadEntry(body); err == nil {
		t.Fatal("bootstrap transition context 接受了未知字段")
	}
}
