package clientv2

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"loom/internal/wire"
)

func TestOpenRejectsLooseOrNonCanonicalStateFile(t *testing.T) {
	requireLinuxStateModeSemantics(t)
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
	requireLinuxStateModeSemantics(t)
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
	currentSet, previousSet := reopened.ControlSets()
	if currentSet == nil || !wire.EqualCanonical(*currentSet, set) || previousSet != nil {
		t.Fatalf("重启后未保留 exact ControlSet: current=%#v previous=%#v", currentSet, previousSet)
	}
}

func TestAcceptDeviceConfigDeliveryReplaysCompleteWindowAtomically(t *testing.T) {
	requireLinuxStateModeSemantics(t)
	set, key := clientControlSet(t)
	current := clientEnvelope(t, &set, key)
	next := advanceClientEnvelope(t, current, &set, key)
	directory := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := Open(filepath.Join(directory, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	identityHash := current.Payload.Active.IdentitySPKIHash
	if _, err := store.acceptWithAdvance(&current, &set, nil, current.Payload.DeviceID,
		identityHash, wire.AdvanceFloors); err != nil {
		t.Fatal(err)
	}
	delivery := wire.DeviceConfigDeliveryV1{Schema: 1, ClusterID: current.Payload.ClusterID,
		DeviceID: current.Payload.DeviceID, Updates: []wire.DeviceConfigUpdateV1{
			{Schema: 1, Envelope: current, ControlSet: set},
			{Schema: 1, Envelope: next, ControlSet: set},
		}}
	floors, err := store.AcceptDeviceConfigDelivery(&delivery, nil, nil,
		current.Payload.DeviceID, identityHash)
	if err != nil || floors.DeviceGeneration != 2 || store.Envelope().Payload.DeviceGeneration != 2 {
		t.Fatalf("完整 delivery 未原子推进: floors=%#v err=%v", floors, err)
	}

	broken := delivery
	broken.Updates = append([]wire.DeviceConfigUpdateV1(nil), delivery.Updates...)
	broken.Updates[1].Envelope.Leaf.PreviousViewHash = wire.HashRaw("client-v2-test", []byte("fork"))
	before := store.Floors()
	if _, err := store.AcceptDeviceConfigDelivery(&broken, nil, nil,
		current.Payload.DeviceID, identityHash); err == nil {
		t.Fatal("接受了断裂的 previous_view_hash")
	}
	if after := store.Floors(); !wire.EqualCanonical(before, after) {
		t.Fatalf("失败 delivery 改写了 LKG: before=%#v after=%#v", before, after)
	}
}

func requireLinuxStateModeSemantics(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("Linux LKG 文件测试依赖 uid 与 0600/0700 mode；Windows 使用独立 DPAPI StateStore")
	}
}

func TestVerifyDeviceViewSuccessorRejectsGenerationGapAndTombstoneRevival(t *testing.T) {
	set, key := clientControlSet(t)
	current := clientEnvelope(t, &set, key)
	next := advanceClientEnvelope(t, current, &set, key)
	if err := wire.VerifyDeviceViewSuccessor(&current, &next); err != nil {
		t.Fatal(err)
	}
	gapped := next
	gapped.Payload.DeviceGeneration++
	if err := wire.VerifyDeviceViewSuccessor(&current, &gapped); err == nil {
		t.Fatal("接受了跳过 generation 的 Device view")
	}
	tombstone := current
	tombstone.Payload.State = "revoked"
	tombstone.Payload.Active = nil
	tombstone.Payload.Tombstone = &wire.DeviceTombstoneViewV1{Reason: "revoked"}
	if err := wire.VerifyDeviceViewSuccessor(&tombstone, &next); err == nil {
		t.Fatal("接受了 tombstone 后的 Device view 复活")
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
	return clientEnvelopeWithIdentity(t, set, configKey, hash("identity"))
}

func clientEnvelopeWithIdentity(t *testing.T, set *wire.ControlSetV1, configKey ed25519.PrivateKey,
	identityHash string) wire.DeviceViewEnvelopeV2 {
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
			IdentitySPKIHash: identityHash, Membership: membership, MembershipHash: membershipHash,
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

func advanceClientEnvelope(t *testing.T, previous wire.DeviceViewEnvelopeV2,
	set *wire.ControlSetV1, configKey ed25519.PrivateKey) wire.DeviceViewEnvelopeV2 {
	t.Helper()
	secretRefs, err := decodeLinuxSecretArtifactRefs(previous.SecretArtifactRefs)
	if err != nil {
		t.Fatal(err)
	}
	return advanceClientEnvelopeWithArtifacts(t, previous, set, configKey,
		previous.Payload.Active.ConfigArtifactRefs, secretRefs)
}

func advanceClientEnvelopeWithArtifacts(t *testing.T, previous wire.DeviceViewEnvelopeV2,
	set *wire.ControlSetV1, configKey ed25519.PrivateKey,
	configRefs []wire.DeviceConfigArtifactRefV1, secretRefs []wire.SecretArtifactRefV2,
) wire.DeviceViewEnvelopeV2 {
	t.Helper()
	body, err := wire.MarshalCanonical(previous)
	if err != nil {
		t.Fatal(err)
	}
	var next wire.DeviceViewEnvelopeV2
	if _, err := wire.DecodeStrict(body, 32<<20, &next); err != nil {
		t.Fatal(err)
	}
	previousViewHash, _ := wire.DeviceViewHash(&previous.Payload)
	next.Payload.DeviceGeneration++
	next.Payload.Active.EndpointBundle.DeviceGeneration = next.Payload.DeviceGeneration
	next.Payload.Active.EndpointBundleHash, _ = wire.DeviceEndpointBundleHash(&next.Payload.Active.EndpointBundle)
	next.Payload.Active.ConfigArtifactRefs = make([]wire.DeviceConfigArtifactRefV1, len(configRefs))
	copy(next.Payload.Active.ConfigArtifactRefs, configRefs)
	next.Payload.Active.SecretArtifactRefsRoot, _ = wire.SecretArtifactRefsRoot(secretRefs)
	next.SecretArtifactRefs = make([]json.RawMessage, len(secretRefs))
	for index := range secretRefs {
		next.SecretArtifactRefs[index], _ = wire.MarshalCanonical(secretRefs[index])
	}
	next.Leaf.DeviceGeneration = next.Payload.DeviceGeneration
	next.Leaf.PreviousViewHash = previousViewHash
	next.Leaf.EndpointSetHash = next.Payload.Active.EndpointBundleHash
	next.Leaf.PayloadHash, _ = wire.DeviceViewHash(&next.Payload)
	leafBytes, _ := wire.MarshalCanonical(next.Leaf)
	root := wire.MerkleRoot([][]byte{leafBytes})
	headBody := previous.SignedCurrent.Head.Body
	headBody.Payload.HeadKind = "ordinary"
	headBody.Payload.RaftIndex++
	headBody.Payload.ControlRevision = headBody.Payload.RaftIndex
	headBody.Payload.PreviousLogEntryHash = previous.SignedCurrent.Head.EntryHash
	headBody.Payload.ParentHeadHash = previous.SignedCurrent.Head.HeadHash
	headBody.Payload.DeviceViewsRoot = "sha256:" + fmt.Sprintf("%x", root)
	headBody.Payload.OperationRoot = wire.HashRaw("client-v2-test", []byte("advanced-operations"))
	headBody.Payload.CommittedLogicalTime = "2026-09-11T00:01:00Z"
	headBody.Payload.TransitionContext, _ = json.Marshal(wire.OrdinaryHeadContextV1{Schema: 1, Kind: "ordinary"})
	head, err := wire.NewHeadEntry(headBody)
	if err != nil {
		t.Fatal(err)
	}
	if err := wire.ValidateHeadEntry(&head, &previous.SignedCurrent.Head); err != nil {
		t.Fatal(err)
	}
	signature, err := wire.SignHeadAttestation(wire.AttestationForHead(&head), set.Members[0], configKey)
	if err != nil {
		t.Fatal(err)
	}
	qc := wire.StableQC(&head, []wire.ControlConfigSignatureV1{signature})
	next.SignedCurrent.Head = head
	next.SignedCurrent.QuorumCertificate, _ = wire.MarshalCanonical(qc)
	next.SignedCurrent.PublishedAt = "2026-09-11T00:01:01Z"
	return next
}

func revokeClientEnvelope(t *testing.T, previous wire.DeviceViewEnvelopeV2,
	set *wire.ControlSetV1, configKey ed25519.PrivateKey,
) wire.DeviceViewEnvelopeV2 {
	t.Helper()
	body, err := wire.MarshalCanonical(previous)
	if err != nil {
		t.Fatal(err)
	}
	var next wire.DeviceViewEnvelopeV2
	if _, err := wire.DecodeStrict(body, 32<<20, &next); err != nil {
		t.Fatal(err)
	}
	previousViewHash, _ := wire.DeviceViewHash(&previous.Payload)
	next.Payload.DeviceGeneration++
	next.Payload.State = "revoked"
	next.Payload.Active = nil
	next.Payload.Tombstone = &wire.DeviceTombstoneViewV1{Reason: "revoked"}
	next.SecretArtifactRefs = nil
	next.Leaf.DeviceGeneration = next.Payload.DeviceGeneration
	next.Leaf.State = "revoked"
	next.Leaf.PreviousViewHash = previousViewHash
	next.Leaf.EndpointSetHash = wire.EmptyHashV1
	next.Leaf.PayloadHash, _ = wire.DeviceViewHash(&next.Payload)
	leafBytes, _ := wire.MarshalCanonical(next.Leaf)
	root := wire.MerkleRoot([][]byte{leafBytes})
	headBody := previous.SignedCurrent.Head.Body
	headBody.Payload.HeadKind = "ordinary"
	headBody.Payload.RaftIndex++
	headBody.Payload.ControlRevision = headBody.Payload.RaftIndex
	headBody.Payload.PreviousLogEntryHash = previous.SignedCurrent.Head.EntryHash
	headBody.Payload.ParentHeadHash = previous.SignedCurrent.Head.HeadHash
	headBody.Payload.DeviceViewsRoot = "sha256:" + fmt.Sprintf("%x", root)
	headBody.Payload.OperationRoot = wire.HashRaw("client-v2-test", []byte("revocation-operation"))
	headBody.Payload.CommittedLogicalTime = "2026-09-11T00:02:00Z"
	headBody.Payload.TransitionContext, _ = json.Marshal(wire.OrdinaryHeadContextV1{Schema: 1, Kind: "ordinary"})
	head, err := wire.NewHeadEntry(headBody)
	if err != nil {
		t.Fatal(err)
	}
	if err := wire.ValidateHeadEntry(&head, &previous.SignedCurrent.Head); err != nil {
		t.Fatal(err)
	}
	signature, err := wire.SignHeadAttestation(wire.AttestationForHead(&head), set.Members[0], configKey)
	if err != nil {
		t.Fatal(err)
	}
	qc := wire.StableQC(&head, []wire.ControlConfigSignatureV1{signature})
	next.SignedCurrent.Head = head
	next.SignedCurrent.QuorumCertificate, _ = wire.MarshalCanonical(qc)
	next.SignedCurrent.PublishedAt = "2026-09-11T00:02:01Z"
	return next
}
