package wire

import (
	"testing"
)

func TestRecoveryPolicyActivationRequiresIntentThresholdAndActivationQC(t *testing.T) {
	bootstrap, _, _, _ := bootstrapBundleFixture(t)
	parent := bootstrap.InitialHeadEntry.Head
	set := bootstrap.InitialControlSet
	oldPolicy := bootstrap.InitialRecoveryPolicy
	newPolicy, _, newPoPs := recoveryPolicyFixture(t, "recovery-policy-2", 2, 0x61)
	newPolicyHash, _ := RecoveryPolicyHash(&newPolicy)
	newPoPRoot, _ := RecoveryKeyPossessionRoot(&newPolicy, newPoPs)
	intent := RecoveryPolicyIntentV1{
		Schema: 1, ClusterID: "demo-cluster", IntentID: "policy-intent-1",
		PreviousRecoveryEpoch:             parent.Body.Payload.RecoveryEpoch,
		PreviousRecoveryStatementHash:     parent.Body.Payload.RecoveryStatementHash,
		PreviousRecoveryPolicyHash:        parent.Body.Payload.RecoveryPolicyHash,
		PreviousControlEpoch:              parent.Body.Payload.ControlEpoch,
		UnchangedControlSetHash:           parent.Body.Payload.ControlSetHash,
		UnchangedControlPeerDirectoryHash: parent.Body.Payload.ControlPeerDirectoryHash,
		ParentHeadHash:                    parent.HeadHash, NewRecoveryEpoch: 1, NewRecoveryPolicyHash: newPolicyHash,
		NewPolicyPoPRoot: newPoPRoot, CeremonyID: "ceremony-2", Reason: "scheduled recovery key rotation",
	}
	intentHash, _ := RecoveryPolicyIntentHash(&intent)
	_, adminPrivate := deterministicEd25519(0x23)
	operation, err := NewControlOperation(ControlOperationBodyV1{
		Schema: 1, ClusterID: intent.ClusterID, OperationID: intent.IntentID, AuthorID: "demo-admin",
		AdminCertDigest: recoveryTestHash("admin-cert"), CreatedAt: "2026-09-11T01:00:00Z",
		BaseRecoveryEpoch: intent.PreviousRecoveryEpoch, BaseRecoveryStatementHash: intent.PreviousRecoveryStatementHash,
		BaseRecoveryPolicyHash: intent.PreviousRecoveryPolicyHash, BaseControlEpoch: intent.PreviousControlEpoch,
		BaseControlSetHash: intent.UnchangedControlSetHash, BaseControlRevision: parent.Body.Payload.ControlRevision,
		ParentHeadHash: parent.HeadHash, Kind: "recovery_policy_intent", PayloadSchema: 1,
		PayloadHash: intentHash, Reason: intent.Reason,
	}, adminPrivate, OperationSchemaRegistry{"recovery_policy_intent": 1})
	if err != nil {
		t.Fatal(err)
	}
	operationID, _ := HashObject(DomainControlOperation, &operation)
	operationLeaf := ControlOperationLeafV1{Schema: 1, OperationID: intent.IntentID, ObjectID: operationID}
	leafBytes, _ := MarshalCanonical(operationLeaf)
	operationRoot := hashMerkleRoot(leafBytes)
	ordinaryContext, _ := MarshalCanonical(OrdinaryHeadContextV1{Schema: 1, Kind: "ordinary"})
	p := parent.Body.Payload
	intentHead, err := NewHeadEntry(HeadEntryBodyV2{Payload: HeadEntryPayloadV2{
		Schema: 2, HeadKind: "ordinary", ClusterID: p.ClusterID, RecoveryEpoch: p.RecoveryEpoch,
		RecoveryStatementHash: p.RecoveryStatementHash, RecoveryPolicyHash: p.RecoveryPolicyHash,
		ControlEpoch: p.ControlEpoch, ControlSetHash: p.ControlSetHash, ControlPeerDirectoryHash: p.ControlPeerDirectoryHash,
		RaftTerm: p.RaftTerm, RaftIndex: 2, PreviousLogEntryHash: parent.EntryHash, ControlRevision: 2,
		ParentHeadHash: parent.HeadHash, OperationRoot: operationRoot, SnapshotHash: recoveryTestHash("intent-snapshot"),
		EffectiveSSOTHash: recoveryTestHash("intent-ssot"), DeviceViewsRoot: p.DeviceViewsRoot,
		AdminACLRoot: p.AdminACLRoot, CAProfileRoot: p.CAProfileRoot, BootstrapIssuerRegistryRoot: p.BootstrapIssuerRegistryRoot,
		RenderContractVersion: p.RenderContractVersion, MinReaderVersion: p.MinReaderVersion,
		CommittedLogicalTime: "2026-09-11T01:00:01Z", MaxClockSkewSeconds: p.MaxClockSkewSeconds,
		TransitionContext: ordinaryContext,
	}, TransitionProofHash: parent.Body.TransitionProofHash})
	if err != nil {
		t.Fatal(err)
	}
	configPrivate := privateForSeed(0x42)
	intentSignature, _ := SignHeadAttestation(AttestationForHead(&intentHead), set.Members[0], configPrivate)
	intentQCRaw, _ := MarshalCanonical(StableQC(&intentHead, []ControlConfigSignatureV1{intentSignature}))
	intentQCHash, _ := HashCanonical(DomainQuorumCertificate, intentQCRaw)
	body := RecoveryPolicyTransitionBodyV1{
		Schema: 1, StatementType: "policy_rotation", ClusterID: intent.ClusterID, IntentID: intent.IntentID,
		IntentHash: intentHash, IntentHeadHash: intentHead.HeadHash, IntentQCHash: intentQCHash,
		PreviousRecoveryEpoch: intent.PreviousRecoveryEpoch, PreviousRecoveryStatementHash: intent.PreviousRecoveryStatementHash,
		PreviousRecoveryPolicyHash: intent.PreviousRecoveryPolicyHash, PreviousControlEpoch: intent.PreviousControlEpoch,
		UnchangedControlSetHash:           intent.UnchangedControlSetHash,
		UnchangedControlPeerDirectoryHash: intent.UnchangedControlPeerDirectoryHash,
		LastCertifiedHeadHash:             intentHead.HeadHash, NewRecoveryEpoch: intent.NewRecoveryEpoch,
		NewRecoveryPolicyHash: intent.NewRecoveryPolicyHash, NewPolicyPoPRoot: intent.NewPolicyPoPRoot,
		NewControlEpoch: 0, CeremonyID: intent.CeremonyID, Reason: intent.Reason, IssuedAt: "2026-09-11T01:00:02Z",
	}
	statementHash, _ := RecoveryStatementHash(&body)
	thresholdSignature := recoveryThresholdSignature(t, oldPolicy.Keys[0].KeyID, recoveryPrivateFromSeed(0x31), DomainRecoveryPolicyRotationSignature, body)
	proof := RecoveryPolicyTransitionProofV1{Schema: 1, Body: body, RecoveryStatementHash: statementHash,
		OldPolicyThresholdSignatures: []RecoveryThresholdSignatureV1{thresholdSignature}}
	transitionHash, err := RecoveryPolicyTransitionProofHash(&proof, &oldPolicy)
	if err != nil {
		t.Fatal(err)
	}
	activationContext, _ := MarshalCanonical(RecoveryPolicyActivationContextV1{Schema: 1, Kind: "recovery_policy_activation",
		IntentHash: intentHash, IntentHeadHash: intentHead.HeadHash, IntentQCHash: intentQCHash})
	ip := intentHead.Body.Payload
	activationHead, err := NewHeadEntry(HeadEntryBodyV2{Payload: HeadEntryPayloadV2{
		Schema: 2, HeadKind: "recovery_policy_activation", ClusterID: ip.ClusterID, RecoveryEpoch: 1,
		RecoveryStatementHash: statementHash, RecoveryPolicyHash: newPolicyHash, ControlEpoch: 0,
		ControlSetHash: ip.ControlSetHash, ControlPeerDirectoryHash: ip.ControlPeerDirectoryHash,
		RaftTerm: ip.RaftTerm, RaftIndex: 3, PreviousLogEntryHash: intentHead.EntryHash, ControlRevision: 3,
		ParentHeadHash: intentHead.HeadHash, OperationRoot: ip.OperationRoot, SnapshotHash: recoveryTestHash("activation-snapshot"),
		EffectiveSSOTHash: recoveryTestHash("activation-ssot"), DeviceViewsRoot: ip.DeviceViewsRoot,
		AdminACLRoot: ip.AdminACLRoot, CAProfileRoot: ip.CAProfileRoot, BootstrapIssuerRegistryRoot: ip.BootstrapIssuerRegistryRoot,
		RenderContractVersion: ip.RenderContractVersion, MinReaderVersion: ip.MinReaderVersion,
		CommittedLogicalTime: "2026-09-11T01:00:03Z", MaxClockSkewSeconds: ip.MaxClockSkewSeconds,
		TransitionContext: activationContext,
	}, TransitionProofHash: transitionHash})
	if err != nil {
		t.Fatal(err)
	}
	activationSignature, _ := SignHeadAttestation(AttestationForHead(&activationHead), set.Members[0], configPrivate)
	bundle := RecoveryPolicyActivationBundleV1{
		Schema: 1, Intent: intent, NewRecoveryPolicy: newPolicy, NewPolicyPossessionProofs: newPoPs,
		IntentOperation: operation, IntentOperationLeaf: operationLeaf, IntentLeafIndex: 0, IntentOperationTreeSize: 1,
		IntentOperationAuditPath: []string{}, IntentHead: intentHead, IntentHeadQC: intentQCRaw,
		ContinuityHeads: []CertifiedHeadV1{}, TransitionProof: proof,
		Activation: RecoveryActivationHeadV1{Schema: 1, Head: activationHead,
			ReplicationQC: StableQC(&activationHead, []ControlConfigSignatureV1{activationSignature})},
	}
	verified, err := VerifyRecoveryPolicyActivationBundle(&bundle, &oldPolicy, &set, &parent)
	if err != nil {
		t.Fatal(err)
	}
	current := ClientFloorsV2{Schema: 2, ClusterID: intent.ClusterID, AcceptedRecoveryEpoch: intent.PreviousRecoveryEpoch,
		RecoveryStatementHash: intent.PreviousRecoveryStatementHash, RecoveryPolicyHash: intent.PreviousRecoveryPolicyHash,
		AcceptedControlEpoch: intent.PreviousControlEpoch, ControlSetHash: intent.UnchangedControlSetHash,
		AcceptedControlRevision: intentHead.Body.Payload.ControlRevision, HeadHash: intentHead.HeadHash,
		DeviceGeneration: 1, DeviceLeafHash: recoveryTestHash("leaf"), DeviceViewHash: recoveryTestHash("view"),
		BootstrapTransitionHash: parent.Body.TransitionProofHash, V2Latched: true}
	candidate := current
	candidate.AcceptedRecoveryEpoch = 1
	candidate.RecoveryStatementHash = statementHash
	candidate.RecoveryPolicyHash = newPolicyHash
	candidate.AcceptedControlEpoch = 0
	candidate.AcceptedControlRevision = activationHead.Body.Payload.ControlRevision
	candidate.HeadHash = activationHead.HeadHash
	candidate.BootstrapTransitionHash = activationHead.Body.TransitionProofHash
	next, err := AdvanceFloorsWithRecoveryPolicy(current, candidate, verified)
	if err != nil {
		t.Fatal(err)
	}
	if next.BootstrapTransitionHash != current.BootstrapTransitionHash {
		t.Fatal("recovery policy rotation 改写了 bootstrap latch")
	}

	tampered := bundle
	tampered.TransitionProof.Body.IntentQCHash = recoveryTestHash("wrong-intent-qc")
	if _, err := VerifyRecoveryPolicyActivationBundle(&tampered, &oldPolicy, &set, &parent); err == nil {
		t.Fatal("接受了 threshold transition 与实际 intent QC 的拼接")
	}
}

func hashMerkleRoot(leaves ...[]byte) string {
	return "sha256:" + fmtHex(MerkleRoot(leaves))
}
