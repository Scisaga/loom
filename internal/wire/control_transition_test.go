package wire

import (
	"crypto/ed25519"
	"sort"
	"testing"
)

func TestControlSetTransitionRequiresMembershipJointAndFinalQuorums(t *testing.T) {
	bootstrap, _, _, _ := bootstrapBundleFixture(t)
	parent := bootstrap.InitialHeadEntry.Head
	oldSet := bootstrap.InitialControlSet
	oldMembershipPrivate := privateForSeed(0x41)
	oldConfigPrivate := privateForSeed(0x42)
	newSet, newConfigPrivate, newPoPs := controlSetAndPoPsFixture(t, 0x51)
	newMembershipPrivate := privateForSeed(0x51)
	oldSetHash, _ := ControlSetHash(&oldSet)
	newSetHash, _ := ControlSetHash(&newSet)

	intent := ControlSetTransitionIntentV1{
		Schema: 1, ClusterID: "demo-cluster", TransitionID: "transition-1",
		RecoveryEpoch:         parent.Body.Payload.RecoveryEpoch,
		RecoveryStatementHash: parent.Body.Payload.RecoveryStatementHash,
		RecoveryPolicyHash:    parent.Body.Payload.RecoveryPolicyHash,
		OldControlEpoch:       0, OldControlSetHash: oldSetHash,
		OldControlPeerDirectoryHash: parent.Body.Payload.ControlPeerDirectoryHash,
		TargetControlEpoch:          1, NewControlSetHash: newSetHash,
		NewControlPeerDirectoryHash: recoveryTestHash("directory-next"),
		ParentCertifiedHeadHash:     parent.HeadHash, OperationID: "operation-1", Reason: "rotate control keys",
	}
	intentHash, _ := ControlSetTransitionIntentHash(&intent)
	_, adminPrivate := deterministicEd25519(0x22)
	operation, err := NewControlOperation(ControlOperationBodyV1{
		Schema: 1, ClusterID: intent.ClusterID, OperationID: intent.OperationID,
		AuthorID: "demo-admin", AdminCertDigest: recoveryTestHash("admin-cert"),
		CreatedAt: "2026-09-11T00:00:01Z", BaseRecoveryEpoch: intent.RecoveryEpoch,
		BaseRecoveryStatementHash: intent.RecoveryStatementHash, BaseRecoveryPolicyHash: intent.RecoveryPolicyHash,
		BaseControlEpoch: intent.OldControlEpoch, BaseControlSetHash: intent.OldControlSetHash,
		BaseControlRevision: parent.Body.Payload.ControlRevision, ParentHeadHash: parent.HeadHash,
		Kind: "control_set_transition_intent", PayloadSchema: 1, PayloadHash: intentHash, Reason: intent.Reason,
	}, adminPrivate, OperationSchemaRegistry{"control_set_transition_intent": 1})
	if err != nil {
		t.Fatal(err)
	}
	oldMembershipSignature, _ := SignControlMembershipApproval(intent, oldSet.Members[0], oldMembershipPrivate)
	newMembershipSignature, _ := SignControlMembershipApproval(intent, newSet.Members[0], newMembershipPrivate)
	membershipSignatures := []ControlMembershipSignatureV1{oldMembershipSignature, newMembershipSignature}
	sort.Slice(membershipSignatures, func(i, j int) bool {
		return compareSigner(membershipSignatures[i].MemberID, membershipSignatures[i].MembershipKeyID,
			membershipSignatures[j].MemberID, membershipSignatures[j].MembershipKeyID) < 0
	})
	approval := ControlMembershipApprovalProofV1{
		Schema: 1, Intent: intent, AdminIntentOperation: operation, NewControlKeyPossessionProofs: newPoPs,
		Signatures:    membershipSignatures,
		OldSignerRefs: []ControlMembershipSignerRefV1{{MemberID: oldSet.Members[0].MemberID, MembershipKeyID: oldSet.Members[0].MembershipKeyID}},
		NewSignerRefs: []ControlMembershipSignerRefV1{{MemberID: newSet.Members[0].MemberID, MembershipKeyID: newSet.Members[0].MembershipKeyID}},
	}
	approvalHash, _ := ControlMembershipApprovalProofHash(&approval)
	jointBody := JointControlSetEntryBodyV1{
		Schema: 1, ClusterID: intent.ClusterID, TransitionID: intent.TransitionID,
		RecoveryEpoch: intent.RecoveryEpoch, RecoveryStatementHash: intent.RecoveryStatementHash,
		RecoveryPolicyHash: intent.RecoveryPolicyHash, OldControlEpoch: intent.OldControlEpoch,
		OldControlSetHash: intent.OldControlSetHash, OldControlPeerDirectoryHash: intent.OldControlPeerDirectoryHash,
		TargetControlEpoch: intent.TargetControlEpoch, NewControlSetHash: intent.NewControlSetHash,
		NewControlPeerDirectoryHash: intent.NewControlPeerDirectoryHash, ParentCertifiedHeadHash: parent.HeadHash,
		MembershipApprovalProofHash: approvalHash, RaftTerm: 1, RaftIndex: 2,
		PreviousLogEntryHash: parent.EntryHash, OperationID: intent.OperationID, Reason: intent.Reason,
		CommittedLogicalTime: "2026-09-11T00:00:02Z",
	}
	jointEntryHash, _ := JointControlSetEntryHash(&jointBody)
	if candidateHash, err := VerifyJointControlSetCandidate(&oldSet, &newSet, &approval, &jointBody, &parent); err != nil || candidateHash != jointEntryHash {
		t.Fatalf("合法 Joint candidate 未通过 pre-commit 验证: hash=%q err=%v", candidateHash, err)
	}
	jointAttestation := JointConfigAttestationForEntry(&jointBody, jointEntryHash)
	oldJointSignature, _ := SignJointConfigAttestation(jointAttestation, oldSet.Members[0], oldConfigPrivate)
	newJointSignature, _ := SignJointConfigAttestation(jointAttestation, newSet.Members[0], newConfigPrivate)
	jointProof := JointControlSetProofV1{
		Schema: 1, JointBody: jointBody, JointEntryHash: jointEntryHash,
		JointReplicationQC: JointConfigQC(jointAttestation, []ControlConfigSignatureV1{oldJointSignature, newJointSignature}, &oldSet, &newSet),
	}
	jointProofHash, err := JointControlSetProofHash(&jointProof, &oldSet, &newSet)
	if err != nil {
		t.Fatal(err)
	}
	context, _ := MarshalCanonical(FinalControlSetContextV1{
		Schema: 1, Kind: "control_set_final", TransitionID: intent.TransitionID,
		OldControlEpoch: intent.OldControlEpoch, OldControlSetHash: intent.OldControlSetHash,
		OldControlPeerDirectoryHash: intent.OldControlPeerDirectoryHash, NewControlEpoch: intent.TargetControlEpoch,
		NewControlSetHash: intent.NewControlSetHash, NewControlPeerDirectoryHash: intent.NewControlPeerDirectoryHash,
		MembershipApprovalProofHash: approvalHash, JointEntryHash: jointEntryHash, JointProofHash: jointProofHash,
	})
	p := parent.Body.Payload
	finalPayload := HeadEntryPayloadV2{
		Schema: 2, HeadKind: "control_set_final", ClusterID: intent.ClusterID, RecoveryEpoch: intent.RecoveryEpoch,
		RecoveryStatementHash: intent.RecoveryStatementHash, RecoveryPolicyHash: intent.RecoveryPolicyHash,
		ControlEpoch: intent.TargetControlEpoch, ControlSetHash: intent.NewControlSetHash,
		ControlPeerDirectoryHash: intent.NewControlPeerDirectoryHash, RaftTerm: 1, RaftIndex: 3,
		PreviousLogEntryHash: jointEntryHash, ControlRevision: 3, ParentHeadHash: parent.HeadHash,
		OperationRoot: p.OperationRoot, SnapshotHash: recoveryTestHash("snapshot-after-control"),
		EffectiveSSOTHash: recoveryTestHash("ssot-after-control"), DeviceViewsRoot: p.DeviceViewsRoot,
		AdminACLRoot: p.AdminACLRoot, CAProfileRoot: p.CAProfileRoot,
		BootstrapIssuerRegistryRoot: p.BootstrapIssuerRegistryRoot, RenderContractVersion: p.RenderContractVersion,
		MinReaderVersion: p.MinReaderVersion, CommittedLogicalTime: "2026-09-11T00:00:03Z",
		MaxClockSkewSeconds: p.MaxClockSkewSeconds, TransitionContext: context,
	}
	transitionHash, _ := ControlSetTransitionProofHash(&ControlSetTransitionProofV1{Schema: 1, JointProofHash: jointProofHash, FinalPayload: finalPayload})
	finalHead, err := NewHeadEntry(HeadEntryBodyV2{Payload: finalPayload, TransitionProofHash: transitionHash})
	if err != nil {
		t.Fatal(err)
	}
	if candidateHash, err := VerifyControlSetFinalCandidate(&oldSet, &newSet, &approval, &jointProof,
		&finalHead, &parent); err != nil || candidateHash != transitionHash {
		t.Fatalf("合法 Final candidate 未通过 pre-commit 验证: hash=%q err=%v", candidateHash, err)
	}
	oldFinalSignature, _ := SignHeadAttestation(AttestationForHead(&finalHead), oldSet.Members[0], oldConfigPrivate)
	newFinalSignature, _ := SignHeadAttestation(AttestationForHead(&finalHead), newSet.Members[0], newConfigPrivate)
	bundle := ControlSetTransitionBundleV1{
		Schema: 1, OldControlSet: oldSet, NewControlSet: newSet, MembershipApprovalProof: approval,
		JointProof: jointProof, Final: FinalControlSetHeadV1{Schema: 1, Head: finalHead,
			FinalJointReplicationQC: JointHeadQC(&finalHead, []ControlConfigSignatureV1{oldFinalSignature, newFinalSignature}, &oldSet, &newSet)},
	}
	verified, err := VerifyControlSetTransitionBundle(&bundle, &parent)
	if err != nil {
		t.Fatal(err)
	}
	if verified.TransitionProofHash() != transitionHash {
		t.Fatal("verified transition hash 未绑定 Final head")
	}
	current := ClientFloorsV2{Schema: 2, ClusterID: intent.ClusterID, AcceptedRecoveryEpoch: intent.RecoveryEpoch,
		RecoveryStatementHash: intent.RecoveryStatementHash, RecoveryPolicyHash: intent.RecoveryPolicyHash,
		AcceptedControlEpoch: intent.OldControlEpoch, ControlSetHash: intent.OldControlSetHash,
		AcceptedControlRevision: p.ControlRevision, HeadHash: parent.HeadHash, DeviceGeneration: 1,
		DeviceLeafHash: recoveryTestHash("device-leaf"), DeviceViewHash: recoveryTestHash("device-view"),
		BootstrapTransitionHash: parent.Body.TransitionProofHash, V2Latched: true}
	candidate := current
	candidate.AcceptedControlEpoch = intent.TargetControlEpoch
	candidate.ControlSetHash = intent.NewControlSetHash
	candidate.AcceptedControlRevision = finalPayload.ControlRevision
	candidate.HeadHash = finalHead.HeadHash
	if _, err := AdvanceFloors(current, candidate); err == nil {
		t.Fatal("未经 Joint→Final evidence 提高了 control floor")
	}
	if _, err := AdvanceFloorsWithControl(current, candidate, verified); err != nil {
		t.Fatal(err)
	}

	tampered := bundle
	tampered.JointProof.JointReplicationQC.Attestation.NewControlPeerDirectoryHash = recoveryTestHash("spliced-directory")
	if _, err := VerifyControlSetTransitionBundle(&tampered, &parent); err == nil {
		t.Fatal("接受了 Joint entry 与 QC 的拼接")
	}
	tamperedFinal := finalHead
	tamperedFinal.Body.Payload.OperationRoot = recoveryTestHash("spliced-operation")
	tamperedProofHash, _ := ControlSetTransitionProofHash(&ControlSetTransitionProofV1{
		Schema: 1, JointProofHash: jointProofHash, FinalPayload: tamperedFinal.Body.Payload,
	})
	tamperedFinal.Body.TransitionProofHash = tamperedProofHash
	tamperedFinal, _ = NewHeadEntry(tamperedFinal.Body)
	if _, err := VerifyControlSetFinalCandidate(&oldSet, &newSet, &approval, &jointProof,
		&tamperedFinal, &parent); err == nil {
		t.Fatal("pre-commit verifier 接受了 Final 夹带的普通业务状态")
	}
}

func privateForSeed(seed byte) ed25519.PrivateKey {
	_, private := deterministicEd25519(seed)
	return private
}
