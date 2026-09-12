package wire

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestBootstrapTransitionBundleEstablishesExactLatchAuthority(t *testing.T) {
	bundle, platformPublic, platformID, anchor := bootstrapBundleFixture(t)
	transitionHash, err := VerifyBootstrapTransitionBundle(&bundle, platformPublic, platformID, anchor)
	if err != nil {
		t.Fatal(err)
	}
	if transitionHash != bundle.InitialHeadEntry.Head.Body.TransitionProofHash {
		t.Fatal("bootstrap transition hash 未绑定 initial head")
	}

	spliced := bundle
	spliced.InitialHeadEntry.InitialPayload.AdminACLRoot = recoveryTestHash("other-admin")
	if _, err := VerifyBootstrapTransitionBundle(&spliced, platformPublic, platformID, anchor); err == nil {
		t.Fatal("接受了 transition A 与 initial payload B 的拼接")
	}
	if _, err := VerifyBootstrapTransitionBundle(&bundle, platformPublic, platformID, recoveryTestHash("wrong-anchor")); err == nil {
		t.Fatal("接受了不匹配的 deployment migration anchor")
	}
}

func TestEmergencyRecoveryRequiresOldThresholdAndNewQC(t *testing.T) {
	bootstrap, platformPublic, platformID, anchor := bootstrapBundleFixture(t)
	if _, err := VerifyBootstrapTransitionBundle(&bootstrap, platformPublic, platformID, anchor); err != nil {
		t.Fatal(err)
	}
	previousHead := bootstrap.InitialHeadEntry.Head
	previousPolicy := bootstrap.InitialRecoveryPolicy

	newPolicy, _, newRecoveryPoPs := recoveryPolicyFixture(t, "recovery-policy-2", 2, 0x61)
	newPolicyHash, _ := RecoveryPolicyHash(&newPolicy)
	newPolicyPoPRoot, _ := RecoveryKeyPossessionRoot(&newPolicy, newRecoveryPoPs)
	newSet, newConfigPrivate, newControlPoPs := controlSetAndPoPsFixture(t, 0x71)
	newSetHash, _ := ControlSetHash(&newSet)
	newControlPoPRoot, _ := ControlKeyPossessionRoot(&newSet, newControlPoPs)
	genesisPayload := RecoveryGenesisPayloadV1{
		Schema: 1, ClusterID: "demo-cluster", NewRecoveryEpoch: 1, NewRecoveryPolicyHash: newPolicyHash,
		NewPolicyPoPRoot: newPolicyPoPRoot, NewControlEpoch: 0, NewControlSetHash: newSetHash,
		NewControlPeerDirectoryHash: recoveryTestHash("directory-2"), NewControlKeyPoPRoot: newControlPoPRoot,
		ParentRecoveryHeadHash: previousHead.HeadHash, InitialAdminACLHash: recoveryTestHash("admin-2"),
		InternalCAProfileAndAnchorHash: recoveryTestHash("ca-2"), InitialBootstrapIssuerRegistryRoot: recoveryTestHash("issuer-2"),
		OperationRoot: recoveryTestHash("operations-2"), SnapshotHash: recoveryTestHash("snapshot-2"),
		EffectiveSSOTHash: recoveryTestHash("ssot-2"), DeviceViewsRoot: recoveryTestHash("views-2"),
		RenderContractVersion: 2, MinReaderVersion: 2, MaxClockSkewSeconds: 30,
	}
	genesisPayloadHash, _ := recoveryGenesisPayloadHash(&genesisPayload)
	body := RecoveryTransitionBodyV1{
		Schema: 1, StatementType: "emergency", ClusterID: "demo-cluster",
		PreviousRecoveryEpoch: 0, PreviousRecoveryStatementHash: previousHead.Body.Payload.RecoveryStatementHash,
		PreviousRecoveryPolicyHash: previousHead.Body.Payload.RecoveryPolicyHash, PreviousTrustedHeadHash: previousHead.HeadHash,
		NewRecoveryEpoch: 1, NewRecoveryPolicyHash: newPolicyHash, NewPolicyPoPRoot: newPolicyPoPRoot,
		NewControlEpoch: 0, NewControlSetHash: newSetHash, NewControlPeerDirectoryHash: genesisPayload.NewControlPeerDirectoryHash,
		NewControlKeyPoPRoot: newControlPoPRoot, InitialAdminACLHash: genesisPayload.InitialAdminACLHash,
		InternalCAProfileAndAnchorHash:     genesisPayload.InternalCAProfileAndAnchorHash,
		InitialBootstrapIssuerRegistryRoot: genesisPayload.InitialBootstrapIssuerRegistryRoot,
		NewLineageGenesisPayloadHash:       genesisPayloadHash, Reason: "lost old quorum", IssuedAt: "2026-09-11T01:00:00Z",
	}
	statementHash, _ := RecoveryStatementHash(&body)
	oldRecoveryPrivate := recoveryPrivateFromSeed(0x31)
	thresholdSignature := recoveryThresholdSignature(t, previousPolicy.Keys[0].KeyID, oldRecoveryPrivate, DomainRecoveryEmergencySignature, body)
	proof := RecoveryTransitionProofV1{
		Schema: 1, Body: body, RecoveryStatementHash: statementHash,
		OldPolicyThresholdSignatures: []RecoveryThresholdSignatureV1{thresholdSignature},
	}
	transitionHash, err := RecoveryTransitionProofHash(&proof, &previousPolicy)
	if err != nil {
		t.Fatal(err)
	}
	context, _ := MarshalCanonical(RecoveryGenesisContextV1{Schema: 1, Kind: "emergency_recovery", GenesisPayloadHash: genesisPayloadHash})
	head, err := NewHeadEntry(HeadEntryBodyV2{Payload: HeadEntryPayloadV2{
		Schema: 2, HeadKind: "emergency_recovery", ClusterID: "demo-cluster", RecoveryEpoch: 1,
		RecoveryStatementHash: statementHash, RecoveryPolicyHash: newPolicyHash, ControlEpoch: 0,
		ControlSetHash: newSetHash, ControlPeerDirectoryHash: genesisPayload.NewControlPeerDirectoryHash,
		RaftTerm: 1, RaftIndex: 1, PreviousLogEntryHash: EmptyHashV1, ControlRevision: 1,
		ParentHeadHash: previousHead.HeadHash, OperationRoot: genesisPayload.OperationRoot,
		SnapshotHash: genesisPayload.SnapshotHash, EffectiveSSOTHash: genesisPayload.EffectiveSSOTHash,
		DeviceViewsRoot: genesisPayload.DeviceViewsRoot, AdminACLRoot: genesisPayload.InitialAdminACLHash,
		CAProfileRoot:               genesisPayload.InternalCAProfileAndAnchorHash,
		BootstrapIssuerRegistryRoot: genesisPayload.InitialBootstrapIssuerRegistryRoot,
		RenderContractVersion:       2, MinReaderVersion: 2, CommittedLogicalTime: "2026-09-11T01:00:01Z",
		MaxClockSkewSeconds: 30, TransitionContext: context,
	}, TransitionProofHash: transitionHash})
	if err != nil {
		t.Fatal(err)
	}
	signature, _ := SignHeadAttestation(AttestationForHead(&head), newSet.Members[0], newConfigPrivate)
	bundle := EmergencyRecoveryBundleV1{
		Schema: 1, TransitionProof: proof, NewRecoveryPolicy: newPolicy,
		NewRecoveryKeyPossessionProofs: newRecoveryPoPs, NewControlSet: newSet,
		NewControlKeyPossessionProofs: newControlPoPs,
		Genesis: RecoveryGenesisV1{Schema: 1, GenesisPayload: genesisPayload, GenesisPayloadHash: genesisPayloadHash,
			Head: head, ReplicationQC: StableQC(&head, []ControlConfigSignatureV1{signature})},
	}
	verified, err := VerifyEmergencyRecoveryBundle(&bundle, &previousPolicy, &previousHead)
	if err != nil {
		t.Fatal(err)
	}
	current := floorAt(0, 0, previousHead.Body.Payload.ControlRevision, 1)
	current.ClusterID = previousHead.Body.Payload.ClusterID
	current.RecoveryStatementHash = previousHead.Body.Payload.RecoveryStatementHash
	current.RecoveryPolicyHash = previousHead.Body.Payload.RecoveryPolicyHash
	current.ControlSetHash = previousHead.Body.Payload.ControlSetHash
	current.HeadHash = previousHead.HeadHash
	candidate := floorAt(1, 0, bundle.Genesis.Head.Body.Payload.ControlRevision, 2)
	candidate.ClusterID = bundle.Genesis.Head.Body.Payload.ClusterID
	candidate.RecoveryStatementHash = verified.RecoveryStatementHash()
	candidate.RecoveryPolicyHash = newPolicyHash
	candidate.ControlSetHash = newSetHash
	candidate.HeadHash = bundle.Genesis.Head.HeadHash
	candidate.BootstrapTransitionHash = bundle.Genesis.Head.Body.TransitionProofHash
	next, err := AdvanceFloorsWithRecovery(current, candidate, verified)
	if err != nil {
		t.Fatal(err)
	}
	if next.BootstrapTransitionHash != current.BootstrapTransitionHash {
		t.Fatal("emergency recovery 改写了 bootstrap latch")
	}
	currentPayload := recoveryDeliveryPayload(t, body.ClusterID, "recovery-device", 1)
	currentPayloadHash, _ := DeviceViewHash(&currentPayload)
	candidatePayload := recoveryDeliveryPayload(t, body.ClusterID, "recovery-device", 2)
	recoveryUpdate := DeviceConfigUpdateV1{
		Schema: 1,
		Envelope: DeviceViewEnvelopeV2{Payload: candidatePayload,
			Leaf:          DeviceViewLeafV2{PreviousViewHash: currentPayloadHash},
			SignedCurrent: SignedCurrentV2{Head: bundle.Genesis.Head}},
		ControlSet: bundle.NewControlSet, RecoveryPolicy: &bundle.NewRecoveryPolicy,
		EmergencyRecoveryTransition: &bundle,
	}
	_, deliveredSet, deliveredPrevious, _, deliveredPolicy, err := advanceDeviceConfigUpdate(
		current, bootstrap.InitialControlSet, nil,
		DeviceViewEnvelopeV2{Payload: currentPayload, SignedCurrent: SignedCurrentV2{Head: previousHead}},
		&recoveryUpdate, &previousPolicy, candidate,
	)
	if err != nil {
		t.Fatal(err)
	}
	if deliveredPrevious != nil || deliveredPolicy == nil ||
		!EqualCanonical(deliveredSet, bundle.NewControlSet) ||
		!EqualCanonical(*deliveredPolicy, bundle.NewRecoveryPolicy) {
		t.Fatal("device_config 未原子切换 recovery policy/ControlSet")
	}
	recoveryUpdate.ControlSetTransition = &ControlSetTransitionBundleV1{}
	if deviceConfigTransitionCount(&recoveryUpdate) != 2 {
		t.Fatal("device_config authority transition union 未拒绝双重 tag")
	}

	wrongOldPolicy := previousPolicy
	wrongOldPolicy.PolicyID = "other-policy"
	if _, err := VerifyEmergencyRecoveryBundle(&bundle, &wrongOldPolicy, &previousHead); err == nil {
		t.Fatal("接受了错误 old recovery policy 的 emergency transition")
	}
	tampered := bundle
	tampered.Genesis.GenesisPayload.NewControlPeerDirectoryHash = recoveryTestHash("tampered-directory")
	if _, err := VerifyEmergencyRecoveryBundle(&tampered, &previousPolicy, &previousHead); err == nil {
		t.Fatal("接受了 transition 与 Genesis 不同的 private directory hash")
	}
}

func recoveryDeliveryPayload(t *testing.T, clusterID, deviceID string, generation int64) DeviceViewPayloadV2 {
	t.Helper()
	payload := validDeviceViewPayloadForResponsibilities(t)
	payload.ClusterID, payload.DeviceID, payload.DeviceGeneration = clusterID, deviceID, generation
	payload.Active.EndpointBundle.ClusterID = clusterID
	payload.Active.EndpointBundle.DeviceID = deviceID
	payload.Active.EndpointBundle.DeviceGeneration = generation
	payload.Active.EndpointBundleHash, _ = DeviceEndpointBundleHash(&payload.Active.EndpointBundle)
	if _, err := DeviceViewHash(&payload); err != nil {
		t.Fatal(err)
	}
	return payload
}

func TestAdvanceFloorsRequiresVerifiedRecoveryTransition(t *testing.T) {
	current := floorAt(0, 0, 1, 1)
	candidate := floorAt(1, 0, 1, 2)
	candidate.RecoveryStatementHash = recoveryTestHash("new-statement")
	candidate.RecoveryPolicyHash = recoveryTestHash("new-policy")
	candidate.ControlSetHash = recoveryTestHash("new-set")
	candidate.HeadHash = recoveryTestHash("new-head")
	candidate.DeviceLeafHash = recoveryTestHash("new-leaf")
	candidate.DeviceViewHash = recoveryTestHash("new-view")
	if _, err := AdvanceFloors(current, candidate); err == nil {
		t.Fatal("只凭 recovery epoch +1 提高了 floor")
	}
}

func bootstrapBundleFixture(t *testing.T) (BootstrapTransitionBundleV1ToV2, ed25519.PublicKey, string, string) {
	return bootstrapBundleFixtureWithIssuerRoot(t, recoveryTestHash("issuer-1"))
}

func bootstrapBundleFixtureWithIssuerRoot(t *testing.T, issuerRoot string) (BootstrapTransitionBundleV1ToV2, ed25519.PublicKey, string, string) {
	t.Helper()
	policy, _, recoveryPoPs := recoveryPolicyFixture(t, "recovery-policy-1", 1, 0x31)
	policyHash, _ := RecoveryPolicyHash(&policy)
	recoveryPoPRoot, _ := RecoveryKeyPossessionRoot(&policy, recoveryPoPs)
	set, configPrivate, controlPoPs := controlSetAndPoPsFixture(t, 0x41)
	setHash, _ := ControlSetHash(&set)
	controlPoPRoot, _ := ControlKeyPossessionRoot(&set, controlPoPs)
	statement := RecoveryBootstrapStatementV1{
		Schema: 1, StatementType: "bootstrap", ClusterID: "demo-cluster", RecoveryEpoch: 0,
		RecoveryPolicyHash: policyHash, InitialRecoveryKeyPoPRoot: recoveryPoPRoot, InitialControlEpoch: 0,
		InitialControlSetHash: setHash, InitialControlPeerDirectoryHash: recoveryTestHash("directory-1"),
		InitialControlKeyPoPRoot: controlPoPRoot, InitialAdminACLHash: recoveryTestHash("admin-1"),
		InternalCAProfileAndAnchorHash:     recoveryTestHash("ca-1"),
		InitialBootstrapIssuerRegistryRoot: issuerRoot,
	}
	statementHash, _ := RecoveryStatementHash(&statement)
	initialPayload := InitialV2HeadPayloadV1{
		Schema: 1, ClusterID: "demo-cluster", RecoveryEpoch: 0, RecoveryStatementHash: statementHash,
		RecoveryPolicyHash: policyHash, ControlEpoch: 0, ControlSetHash: setHash,
		ControlPeerDirectoryHash: statement.InitialControlPeerDirectoryHash, ControlRevision: 1,
		SnapshotHash: recoveryTestHash("snapshot-1"), OperationRoot: recoveryTestHash("operations-1"),
		EffectiveSSOTHash: recoveryTestHash("ssot-1"), DeviceViewsRoot: recoveryTestHash("views-1"),
		AdminACLRoot: statement.InitialAdminACLHash, CAProfileRoot: statement.InternalCAProfileAndAnchorHash,
		BootstrapIssuerRegistryRoot: statement.InitialBootstrapIssuerRegistryRoot,
		RenderContractVersion:       2, MinReaderVersion: 2, MaxClockSkewSeconds: 30,
	}
	initialPayloadHash, _ := InitialV2HeadPayloadHash(&initialPayload)
	platformPublic, platformPrivate := deterministicEd25519(0x21)
	platformDigestRaw := sha256.Sum256(platformPublic)
	platformDigest := "sha256:" + fmtHex(platformDigestRaw[:])
	platformID := "v1-platform-key-1"
	body := BootstrapTransitionBodyV1ToV2{
		Schema: 1, ClusterID: "demo-cluster", V1PlatformKeyID: platformID, V1PlatformKeyDigest: platformDigest,
		V1DeviceFloorMerkleRoot: recoveryTestHash("v1-floor-root"), RecoveryBootstrapStatement: statement,
		RecoveryStatementHash: statementHash, InitialRecoveryKeyPoPRoot: recoveryPoPRoot,
		InitialControlSetHash: setHash, InitialControlPeerDirectoryHash: statement.InitialControlPeerDirectoryHash,
		InitialControlKeyPoPRoot: controlPoPRoot, InitialAdminACLHash: statement.InitialAdminACLHash,
		InternalCAProfileAndAnchorHash:     statement.InternalCAProfileAndAnchorHash,
		InitialBootstrapIssuerRegistryRoot: statement.InitialBootstrapIssuerRegistryRoot,
		InitialV2HeadPayloadHash:           initialPayloadHash, InitialV2RaftIndex: 1, MinimumReaderVersion: 2,
	}
	bodyHash, _ := BootstrapTransitionBodyHash(&body)
	canonicalBody, _ := MarshalCanonical(body)
	message, _ := Frame(DomainBootstrapTransitionSignature, canonicalBody)
	proof := BootstrapTransitionProofV1ToV2{
		Body: body, BodyHash: bodyHash,
		V1PlatformSignature: V1PlatformSignatureV1{KeyID: platformID, Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(platformPrivate, message))},
	}
	transitionHash, _ := BootstrapTransitionProofHash(&proof)
	context, _ := json.Marshal(BootstrapHeadContextV1{Schema: 1, Kind: "bootstrap", InitialV2HeadPayloadHash: initialPayloadHash})
	head, err := NewHeadEntry(HeadEntryBodyV2{Payload: HeadEntryPayloadV2{
		Schema: 2, HeadKind: "bootstrap", ClusterID: "demo-cluster", RecoveryEpoch: 0,
		RecoveryStatementHash: statementHash, RecoveryPolicyHash: policyHash, ControlEpoch: 0,
		ControlSetHash: setHash, ControlPeerDirectoryHash: statement.InitialControlPeerDirectoryHash,
		RaftTerm: 1, RaftIndex: 1, PreviousLogEntryHash: EmptyHashV1, ControlRevision: 1, ParentHeadHash: EmptyHashV1,
		OperationRoot: initialPayload.OperationRoot, SnapshotHash: initialPayload.SnapshotHash,
		EffectiveSSOTHash: initialPayload.EffectiveSSOTHash, DeviceViewsRoot: initialPayload.DeviceViewsRoot,
		AdminACLRoot: initialPayload.AdminACLRoot, CAProfileRoot: initialPayload.CAProfileRoot,
		BootstrapIssuerRegistryRoot: initialPayload.BootstrapIssuerRegistryRoot,
		RenderContractVersion:       2, MinReaderVersion: 2, CommittedLogicalTime: "2026-09-11T00:00:00Z",
		MaxClockSkewSeconds: 30, TransitionContext: context,
	}, TransitionProofHash: transitionHash})
	if err != nil {
		t.Fatal(err)
	}
	signature, _ := SignHeadAttestation(AttestationForHead(&head), set.Members[0], configPrivate)
	return BootstrapTransitionBundleV1ToV2{
		Schema: 1, TransitionProof: proof, InitialRecoveryPolicy: policy,
		InitialRecoveryKeyPossessionProofs: recoveryPoPs, InitialControlSet: set,
		InitialControlKeyPossessionProofs: controlPoPs,
		InitialHeadEntry: InitialV2HeadEntryV1{Schema: 1, InitialPayload: initialPayload, Head: head,
			ReplicationQC: StableQC(&head, []ControlConfigSignatureV1{signature})},
	}, platformPublic, platformID, platformDigest
}

func recoveryPolicyFixture(t *testing.T, policyID string, generation int64, seed byte) (RecoveryPolicyV1, ed25519.PrivateKey, []RecoveryKeyPossessionProofV1) {
	t.Helper()
	public, private := deterministicEd25519(seed)
	keyID, _ := ControlKeyID(public)
	policy := RecoveryPolicyV1{
		Schema: 1, ClusterID: "demo-cluster", PolicyID: policyID, Generation: generation,
		Algorithm: "ed25519-multisig-v1", Keys: []RecoveryPolicyKeyV1{{KeyID: keyID, Algorithm: "ed25519", PublicKey: base64.RawURLEncoding.EncodeToString(public)}},
		Threshold: 1, PrivateKeyCustodyRoot: recoveryTestHash("custody-" + policyID), CeremonyProfile: "offline-independent-keys-v1",
	}
	body := RecoveryKeyPossessionProofBodyV1{
		Schema: 1, ClusterID: policy.ClusterID, PolicyID: policy.PolicyID, PolicyGeneration: policy.Generation,
		KeyID: keyID, PublicKey: policy.Keys[0].PublicKey,
	}
	proof, err := NewRecoveryKeyPossessionProof(body, private)
	if err != nil {
		t.Fatal(err)
	}
	return policy, private, []RecoveryKeyPossessionProofV1{proof}
}

func controlSetAndPoPsFixture(t *testing.T, seed byte) (ControlSetV1, ed25519.PrivateKey, []ControlKeyPossessionProofV1) {
	t.Helper()
	publics := make([]ed25519.PublicKey, 3)
	privates := make([]ed25519.PrivateKey, 3)
	ids := make([]string, 3)
	for i := range publics {
		publics[i], privates[i] = deterministicEd25519(seed + byte(i))
		ids[i], _ = ControlKeyID(publics[i])
	}
	member := ControlMemberV1{
		Schema: 1, ClusterID: "demo-cluster", MemberID: "00000000000000000000000001",
		MembershipKeyID: ids[0], MembershipPublicKey: base64.RawURLEncoding.EncodeToString(publics[0]),
		ConfigKeyID: ids[1], ConfigPublicKey: base64.RawURLEncoding.EncodeToString(publics[1]),
		EnrollmentKeyID: ids[2], EnrollmentPublicKey: base64.RawURLEncoding.EncodeToString(publics[2]), MinimumControlProtocol: 2,
	}
	set := ControlSetV1{Schema: 1, ClusterID: "demo-cluster", Members: []ControlMemberV1{member}}
	setHash, _ := ControlSetHash(&set)
	purposes := []string{"membership", "config", "enrollment"}
	proofs := make([]ControlKeyPossessionProofV1, 3)
	for i, purpose := range purposes {
		body := ControlKeyPossessionProofBodyV1{
			Schema: 1, ClusterID: set.ClusterID, ControlSetHash: setHash, MemberID: member.MemberID,
			KeyPurpose: purpose, KeyID: ids[i], PublicKey: base64.RawURLEncoding.EncodeToString(publics[i]),
		}
		proofs[i], _ = NewControlKeyPossessionProof(body, privates[i])
	}
	return set, privates[1], proofs
}

func deterministicEd25519(last byte) (ed25519.PublicKey, ed25519.PrivateKey) {
	seed := make([]byte, ed25519.SeedSize)
	seed[len(seed)-1] = last
	private := ed25519.NewKeyFromSeed(seed)
	return private.Public().(ed25519.PublicKey), private
}

func recoveryPrivateFromSeed(last byte) ed25519.PrivateKey {
	_, private := deterministicEd25519(last)
	return private
}

func recoveryThresholdSignature(t *testing.T, keyID string, private ed25519.PrivateKey, domain string, body any) RecoveryThresholdSignatureV1 {
	t.Helper()
	canonical, err := MarshalCanonical(body)
	if err != nil {
		t.Fatal(err)
	}
	message, _ := Frame(domain, canonical)
	return RecoveryThresholdSignatureV1{KeyID: keyID, Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, message))}
}

func recoveryTestHash(value string) string { return HashRaw("recovery-test", []byte(value)) }

func fmtHex(value []byte) string {
	const alphabet = "0123456789abcdef"
	out := make([]byte, len(value)*2)
	for i, octet := range value {
		out[i*2], out[i*2+1] = alphabet[octet>>4], alphabet[octet&15]
	}
	return string(out)
}
