package wire

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"sort"
)

const (
	DomainControlSetTransitionIntent        = "loom-control-set-transition-intent-v1"
	DomainControlMembershipApproval         = "loom-control-membership-approval-v1"
	DomainControlMembershipSignature        = "loom-control-membership-approval-signature-v1"
	DomainJointControlSetEntry              = "loom-joint-control-set-entry-v1"
	DomainJointConfigReplicationAttestation = "loom-joint-config-replication-attestation-v1"
	DomainJointControlSetProof              = "loom-joint-control-set-proof-v1"
	DomainControlSetTransitionProof         = "loom-control-set-transition-proof-v1"
)

type ControlMembershipSignatureV1 struct {
	Algorithm       string `json:"algorithm"`
	MemberID        string `json:"member_id"`
	MembershipKeyID string `json:"membership_key_id"`
	Signature       string `json:"signature"`
}

type ControlMembershipSignerRefV1 struct {
	MemberID        string `json:"member_id"`
	MembershipKeyID string `json:"membership_key_id"`
}

type ControlSetTransitionIntentV1 struct {
	Schema                      int    `json:"schema"`
	ClusterID                   string `json:"cluster_id"`
	TransitionID                string `json:"transition_id"`
	RecoveryEpoch               int64  `json:"recovery_epoch"`
	RecoveryStatementHash       string `json:"recovery_statement_hash"`
	RecoveryPolicyHash          string `json:"recovery_policy_hash"`
	OldControlEpoch             int64  `json:"old_control_epoch"`
	OldControlSetHash           string `json:"old_control_set_hash"`
	OldControlPeerDirectoryHash string `json:"old_control_peer_directory_hash"`
	TargetControlEpoch          int64  `json:"target_control_epoch"`
	NewControlSetHash           string `json:"new_control_set_hash"`
	NewControlPeerDirectoryHash string `json:"new_control_peer_directory_hash"`
	ParentCertifiedHeadHash     string `json:"parent_certified_head_hash"`
	OperationID                 string `json:"operation_id"`
	Reason                      string `json:"reason"`
}

type ControlMembershipApprovalProofV1 struct {
	Schema                        int                            `json:"schema"`
	Intent                        ControlSetTransitionIntentV1   `json:"intent"`
	AdminIntentOperation          ControlOperationV1             `json:"admin_intent_operation"`
	NewControlKeyPossessionProofs []ControlKeyPossessionProofV1  `json:"new_control_key_possession_proofs"`
	Signatures                    []ControlMembershipSignatureV1 `json:"signatures"`
	OldSignerRefs                 []ControlMembershipSignerRefV1 `json:"old_signer_refs"`
	NewSignerRefs                 []ControlMembershipSignerRefV1 `json:"new_signer_refs"`
}

type JointControlSetEntryBodyV1 struct {
	Schema                      int    `json:"schema"`
	ClusterID                   string `json:"cluster_id"`
	TransitionID                string `json:"transition_id"`
	RecoveryEpoch               int64  `json:"recovery_epoch"`
	RecoveryStatementHash       string `json:"recovery_statement_hash"`
	RecoveryPolicyHash          string `json:"recovery_policy_hash"`
	OldControlEpoch             int64  `json:"old_control_epoch"`
	OldControlSetHash           string `json:"old_control_set_hash"`
	OldControlPeerDirectoryHash string `json:"old_control_peer_directory_hash"`
	TargetControlEpoch          int64  `json:"target_control_epoch"`
	NewControlSetHash           string `json:"new_control_set_hash"`
	NewControlPeerDirectoryHash string `json:"new_control_peer_directory_hash"`
	ParentCertifiedHeadHash     string `json:"parent_certified_head_hash"`
	MembershipApprovalProofHash string `json:"membership_approval_proof_hash"`
	RaftTerm                    int64  `json:"raft_term"`
	RaftIndex                   int64  `json:"raft_index"`
	PreviousLogEntryHash        string `json:"previous_log_entry_hash"`
	OperationID                 string `json:"operation_id"`
	Reason                      string `json:"reason"`
	CommittedLogicalTime        string `json:"committed_logical_time"`
}

type JointConfigAttestationBodyV1 struct {
	Schema                      int    `json:"schema"`
	AttestationType             string `json:"attestation_type"`
	ClusterID                   string `json:"cluster_id"`
	RecoveryEpoch               int64  `json:"recovery_epoch"`
	RecoveryStatementHash       string `json:"recovery_statement_hash"`
	RecoveryPolicyHash          string `json:"recovery_policy_hash"`
	OldControlEpoch             int64  `json:"old_control_epoch"`
	OldControlSetHash           string `json:"old_control_set_hash"`
	OldControlPeerDirectoryHash string `json:"old_control_peer_directory_hash"`
	TargetControlEpoch          int64  `json:"target_control_epoch"`
	NewControlSetHash           string `json:"new_control_set_hash"`
	NewControlPeerDirectoryHash string `json:"new_control_peer_directory_hash"`
	RaftTerm                    int64  `json:"raft_term"`
	RaftIndex                   int64  `json:"raft_index"`
	PreviousLogEntryHash        string `json:"previous_log_entry_hash"`
	JointEntryHash              string `json:"joint_entry_hash"`
	MembershipApprovalProofHash string `json:"membership_approval_proof_hash"`
}

type JointConfigReplicationQCV1 struct {
	Schema        int                          `json:"schema"`
	QCType        string                       `json:"qc_type"`
	Attestation   JointConfigAttestationBodyV1 `json:"attestation"`
	Signatures    []ControlConfigSignatureV1   `json:"signatures"`
	OldSignerRefs []ControlConfigSignerRefV1   `json:"old_signer_refs"`
	NewSignerRefs []ControlConfigSignerRefV1   `json:"new_signer_refs"`
}

type JointControlSetProofV1 struct {
	Schema             int                        `json:"schema"`
	JointBody          JointControlSetEntryBodyV1 `json:"joint_body"`
	JointEntryHash     string                     `json:"joint_entry_hash"`
	JointReplicationQC JointConfigReplicationQCV1 `json:"joint_replication_qc"`
}

type FinalControlSetHeadV1 struct {
	Schema                  int                      `json:"schema"`
	Head                    HeadEntryV2              `json:"head"`
	FinalJointReplicationQC JointHeadReplicationQCV1 `json:"final_joint_replication_qc"`
}

type ControlSetTransitionProofV1 struct {
	Schema         int                `json:"schema"`
	JointProofHash string             `json:"joint_proof_hash"`
	FinalPayload   HeadEntryPayloadV2 `json:"final_payload"`
}

type ControlSetTransitionBundleV1 struct {
	Schema                  int                              `json:"schema"`
	OldControlSet           ControlSetV1                     `json:"old_control_set"`
	NewControlSet           ControlSetV1                     `json:"new_control_set"`
	MembershipApprovalProof ControlMembershipApprovalProofV1 `json:"membership_approval_proof"`
	JointProof              JointControlSetProofV1           `json:"joint_proof"`
	Final                   FinalControlSetHeadV1            `json:"final"`
}

// VerifiedControlSetTransitionV1 是 Joint→Final 全链验证成功后才会生成的 floor authority。
type VerifiedControlSetTransitionV1 struct {
	clusterID             string
	recoveryEpoch         int64
	recoveryStatementHash string
	recoveryPolicyHash    string
	oldControlEpoch       int64
	oldControlSetHash     string
	parentHeadHash        string
	parentControlRevision int64
	newControlEpoch       int64
	newControlSetHash     string
	finalHeadHash         string
	finalControlRevision  int64
	transitionProofHash   string
}

func (verified VerifiedControlSetTransitionV1) TransitionProofHash() string {
	return verified.transitionProofHash
}

func validateControlSetTransitionIntent(intent *ControlSetTransitionIntentV1) error {
	if intent == nil || intent.Schema != 1 || !validIdentifier(intent.ClusterID, 128) ||
		!validIdentifier(intent.TransitionID, 128) || !validIdentifier(intent.OperationID, 128) ||
		intent.RecoveryEpoch < 0 || intent.OldControlEpoch < 0 || !validRecoveryReason(intent.Reason) {
		return errors.New("[D112 joint] transition intent header 无效")
	}
	nextEpoch, err := CheckedAdd(intent.OldControlEpoch, 1)
	if err != nil || intent.TargetControlEpoch != nextEpoch {
		return errors.New("[D112 joint] target control epoch 必须精确加一")
	}
	return requireCanonicalHashes(intent.RecoveryStatementHash, intent.RecoveryPolicyHash,
		intent.OldControlSetHash, intent.OldControlPeerDirectoryHash, intent.NewControlSetHash,
		intent.NewControlPeerDirectoryHash, intent.ParentCertifiedHeadHash)
}

func ControlSetTransitionIntentHash(intent *ControlSetTransitionIntentV1) (string, error) {
	if err := validateControlSetTransitionIntent(intent); err != nil {
		return "", err
	}
	return HashObject(DomainControlSetTransitionIntent, intent)
}

func ControlMembershipApprovalProofHash(proof *ControlMembershipApprovalProofV1) (string, error) {
	if proof == nil || proof.Schema != 1 {
		return "", errors.New("[D112 joint] membership approval proof schema 无效")
	}
	return HashObject(DomainControlMembershipApproval, proof)
}

func SignControlMembershipApproval(intent ControlSetTransitionIntentV1, member ControlMemberV1, privateKey ed25519.PrivateKey) (ControlMembershipSignatureV1, error) {
	if err := validateControlSetTransitionIntent(&intent); err != nil {
		return ControlMembershipSignatureV1{}, err
	}
	if len(privateKey) != ed25519.PrivateKeySize || base64.RawURLEncoding.EncodeToString(privateKey.Public().(ed25519.PublicKey)) != member.MembershipPublicKey {
		return ControlMembershipSignatureV1{}, errors.New("[D112 joint] membership private key 与 member 不匹配")
	}
	canonical, err := MarshalCanonical(intent)
	if err != nil {
		return ControlMembershipSignatureV1{}, err
	}
	message, _ := Frame(DomainControlMembershipSignature, canonical)
	return ControlMembershipSignatureV1{
		Algorithm: "ed25519", MemberID: member.MemberID, MembershipKeyID: member.MembershipKeyID,
		Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, message)),
	}, nil
}

func VerifyControlMembershipApprovalProof(proof *ControlMembershipApprovalProofV1, oldSet, newSet *ControlSetV1, parent *HeadEntryV2) error {
	if proof == nil || proof.Schema != 1 || parent == nil || ValidateHeadEntry(parent, nil) != nil {
		return errors.New("[D112 joint] membership approval proof/parent 无效")
	}
	if err := ValidateControlSet(oldSet); err != nil {
		return err
	}
	if err := ValidateControlSet(newSet); err != nil {
		return err
	}
	if err := ValidateControlSetSuccessorKeySeparation(oldSet, newSet); err != nil {
		return err
	}
	intent := &proof.Intent
	if err := validateControlSetTransitionIntent(intent); err != nil {
		return err
	}
	oldHash, _ := ControlSetHash(oldSet)
	newHash, _ := ControlSetHash(newSet)
	p := &parent.Body.Payload
	if oldSet.ClusterID != newSet.ClusterID || intent.ClusterID != oldSet.ClusterID ||
		intent.OldControlSetHash != oldHash || intent.NewControlSetHash != newHash ||
		p.ClusterID != intent.ClusterID || p.RecoveryEpoch != intent.RecoveryEpoch ||
		p.RecoveryStatementHash != intent.RecoveryStatementHash || p.RecoveryPolicyHash != intent.RecoveryPolicyHash ||
		p.ControlEpoch != intent.OldControlEpoch || p.ControlSetHash != intent.OldControlSetHash ||
		p.ControlPeerDirectoryHash != intent.OldControlPeerDirectoryHash || parent.HeadHash != intent.ParentCertifiedHeadHash {
		return errors.New("[D112 joint] intent 与 old/new set/parent head 不匹配")
	}
	if err := VerifyControlKeyPossessionProofs(newSet, proof.NewControlKeyPossessionProofs); err != nil {
		return err
	}
	intentHash, _ := ControlSetTransitionIntentHash(intent)
	op := &proof.AdminIntentOperation
	if err := ValidateControlOperationBody(&op.Body, OperationSchemaRegistry{"control_set_transition_intent": 1}); err != nil {
		return err
	}
	if op.Body.ClusterID != intent.ClusterID || op.Body.OperationID != intent.OperationID ||
		op.Body.Kind != "control_set_transition_intent" || op.Body.PayloadSchema != 1 || op.Body.PayloadHash != intentHash ||
		op.Body.BaseRecoveryEpoch != intent.RecoveryEpoch || op.Body.BaseRecoveryStatementHash != intent.RecoveryStatementHash ||
		op.Body.BaseRecoveryPolicyHash != intent.RecoveryPolicyHash || op.Body.BaseControlEpoch != intent.OldControlEpoch ||
		op.Body.BaseControlSetHash != intent.OldControlSetHash || op.Body.BaseControlRevision != p.ControlRevision ||
		op.Body.ParentHeadHash != intent.ParentCertifiedHeadHash || op.Body.Reason != intent.Reason ||
		op.AuthorSignature.Algorithm != "ed25519" {
		return errors.New("[D112 joint] admin intent operation 未 exact-bind transition")
	}
	if _, err := ParseHash(op.AuthorSignature.AdminKeyID); err != nil {
		return errors.New("[D112 joint] admin intent key ID 无效")
	}
	if _, err := decodeRawURL(op.AuthorSignature.Signature, ed25519.SignatureSize); err != nil {
		return errors.New("[D112 joint] admin intent signature 编码无效")
	}
	return verifyMembershipApprovalSignatures(intent, proof.Signatures, proof.OldSignerRefs, proof.NewSignerRefs, oldSet, newSet)
}

func verifyMembershipApprovalSignatures(intent *ControlSetTransitionIntentV1, signatures []ControlMembershipSignatureV1, oldRefs, newRefs []ControlMembershipSignerRefV1, oldSet, newSet *ControlSetV1) error {
	keys := make(map[string]ControlMemberV1, len(oldSet.Members)+len(newSet.Members))
	for _, set := range []*ControlSetV1{oldSet, newSet} {
		for _, member := range set.Members {
			keys[member.MemberID+"\x00"+member.MembershipKeyID] = member
		}
	}
	canonical, _ := MarshalCanonical(intent)
	message, _ := Frame(DomainControlMembershipSignature, canonical)
	for i, signature := range signatures {
		if i > 0 && compareSigner(signatures[i-1].MemberID, signatures[i-1].MembershipKeyID, signature.MemberID, signature.MembershipKeyID) >= 0 {
			return errors.New("[D112 joint] membership signatures 必须严格排序且不重复")
		}
		member, ok := keys[signature.MemberID+"\x00"+signature.MembershipKeyID]
		public, keyErr := decodeRawURL(member.MembershipPublicKey, ed25519.PublicKeySize)
		rawSignature, signatureErr := decodeRawURL(signature.Signature, ed25519.SignatureSize)
		if !ok || signature.Algorithm != "ed25519" || keyErr != nil || signatureErr != nil || !ed25519.Verify(public, message, rawSignature) {
			return errors.New("[D112 joint] membership approval signature 无效")
		}
	}
	used := make(map[string]struct{}, len(signatures))
	if err := verifyMembershipRefs(oldRefs, signatures, oldSet, used); err != nil {
		return err
	}
	if err := verifyMembershipRefs(newRefs, signatures, newSet, used); err != nil {
		return err
	}
	if len(used) != len(signatures) {
		return errors.New("[D112 joint] membership signatures 含未被 old/new 投影引用的额外签名")
	}
	return nil
}

func verifyMembershipRefs(refs []ControlMembershipSignerRefV1, signatures []ControlMembershipSignatureV1, set *ControlSetV1, used map[string]struct{}) error {
	quorum, _ := Quorum(len(set.Members))
	if len(refs) < quorum {
		return errors.New("[D112 joint] 一侧 membership refs 未达到多数")
	}
	members := make(map[string]string, len(set.Members))
	for _, member := range set.Members {
		members[member.MemberID] = member.MembershipKeyID
	}
	signed := make(map[string]struct{}, len(signatures))
	for _, signature := range signatures {
		signed[signature.MemberID+"\x00"+signature.MembershipKeyID] = struct{}{}
	}
	for i, ref := range refs {
		key := ref.MemberID + "\x00" + ref.MembershipKeyID
		_, hasSignature := signed[key]
		if i > 0 && compareSigner(refs[i-1].MemberID, refs[i-1].MembershipKeyID, ref.MemberID, ref.MembershipKeyID) >= 0 ||
			members[ref.MemberID] != ref.MembershipKeyID || !hasSignature {
			return errors.New("[D112 joint] membership refs 未排序、重复或未绑定 signature/set")
		}
		used[key] = struct{}{}
	}
	return nil
}

func validateJointControlSetEntryBody(body *JointControlSetEntryBodyV1) error {
	if body == nil || body.Schema != 1 || !validIdentifier(body.ClusterID, 128) ||
		!validIdentifier(body.TransitionID, 128) || !validIdentifier(body.OperationID, 128) ||
		body.RecoveryEpoch < 0 || body.OldControlEpoch < 0 || body.RaftTerm < 1 || body.RaftIndex < 1 ||
		!validRecoveryReason(body.Reason) {
		return errors.New("[D112 joint] Joint entry header 无效")
	}
	nextEpoch, err := CheckedAdd(body.OldControlEpoch, 1)
	if err != nil || body.TargetControlEpoch != nextEpoch {
		return errors.New("[D112 joint] Joint target control epoch 必须精确加一")
	}
	if _, err := ParseTimeZ(body.CommittedLogicalTime); err != nil {
		return err
	}
	return requireCanonicalHashes(body.RecoveryStatementHash, body.RecoveryPolicyHash, body.OldControlSetHash,
		body.OldControlPeerDirectoryHash, body.NewControlSetHash, body.NewControlPeerDirectoryHash,
		body.ParentCertifiedHeadHash, body.MembershipApprovalProofHash, body.PreviousLogEntryHash)
}

func JointControlSetEntryHash(body *JointControlSetEntryBodyV1) (string, error) {
	if err := validateJointControlSetEntryBody(body); err != nil {
		return "", err
	}
	return HashObject(DomainJointControlSetEntry, body)
}

func JointConfigAttestationForEntry(body *JointControlSetEntryBodyV1, entryHash string) JointConfigAttestationBodyV1 {
	return JointConfigAttestationBodyV1{
		Schema: 1, AttestationType: "joint_config", ClusterID: body.ClusterID,
		RecoveryEpoch: body.RecoveryEpoch, RecoveryStatementHash: body.RecoveryStatementHash,
		RecoveryPolicyHash: body.RecoveryPolicyHash, OldControlEpoch: body.OldControlEpoch,
		OldControlSetHash: body.OldControlSetHash, OldControlPeerDirectoryHash: body.OldControlPeerDirectoryHash,
		TargetControlEpoch: body.TargetControlEpoch, NewControlSetHash: body.NewControlSetHash,
		NewControlPeerDirectoryHash: body.NewControlPeerDirectoryHash, RaftTerm: body.RaftTerm,
		RaftIndex: body.RaftIndex, PreviousLogEntryHash: body.PreviousLogEntryHash,
		JointEntryHash: entryHash, MembershipApprovalProofHash: body.MembershipApprovalProofHash,
	}
}

func SignJointConfigAttestation(attestation JointConfigAttestationBodyV1, member ControlMemberV1, privateKey ed25519.PrivateKey) (ControlConfigSignatureV1, error) {
	if len(privateKey) != ed25519.PrivateKeySize || base64.RawURLEncoding.EncodeToString(privateKey.Public().(ed25519.PublicKey)) != member.ConfigPublicKey {
		return ControlConfigSignatureV1{}, errors.New("[D112 joint] config private key 与 member 不匹配")
	}
	canonical, err := MarshalCanonical(attestation)
	if err != nil {
		return ControlConfigSignatureV1{}, err
	}
	message, _ := Frame(DomainJointConfigReplicationAttestation, canonical)
	return ControlConfigSignatureV1{Algorithm: "ed25519", MemberID: member.MemberID, ConfigKeyID: member.ConfigKeyID,
		Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, message))}, nil
}

func JointConfigQC(attestation JointConfigAttestationBodyV1, signatures []ControlConfigSignatureV1, oldSet, newSet *ControlSetV1) JointConfigReplicationQCV1 {
	sorted := append([]ControlConfigSignatureV1(nil), signatures...)
	sort.Slice(sorted, func(i, j int) bool {
		return compareSigner(sorted[i].MemberID, sorted[i].ConfigKeyID, sorted[j].MemberID, sorted[j].ConfigKeyID) < 0
	})
	refsFor := func(set *ControlSetV1) []ControlConfigSignerRefV1 {
		members := make(map[string]string, len(set.Members))
		for _, member := range set.Members {
			members[member.MemberID] = member.ConfigKeyID
		}
		refs := make([]ControlConfigSignerRefV1, 0, len(sorted))
		for _, signature := range sorted {
			if members[signature.MemberID] == signature.ConfigKeyID {
				refs = append(refs, ControlConfigSignerRefV1{MemberID: signature.MemberID, ConfigKeyID: signature.ConfigKeyID})
			}
		}
		return refs
	}
	return JointConfigReplicationQCV1{Schema: 1, QCType: "joint_config", Attestation: attestation,
		Signatures: sorted, OldSignerRefs: refsFor(oldSet), NewSignerRefs: refsFor(newSet)}
}

func VerifyJointConfigQC(body *JointControlSetEntryBodyV1, entryHash string, oldSet, newSet *ControlSetV1, qc *JointConfigReplicationQCV1) error {
	if err := validateJointControlSetEntryBody(body); err != nil {
		return err
	}
	wantHash, _ := JointControlSetEntryHash(body)
	oldHash, oldHashErr := ControlSetHash(oldSet)
	newHash, newHashErr := ControlSetHash(newSet)
	if oldHashErr != nil || newHashErr != nil || oldSet.ClusterID != newSet.ClusterID ||
		body.ClusterID != oldSet.ClusterID || body.OldControlSetHash != oldHash || body.NewControlSetHash != newHash ||
		entryHash != wantHash || qc == nil || qc.Schema != 1 || qc.QCType != "joint_config" {
		return errors.New("[D112 joint QC] Joint entry/QC binding 无效")
	}
	want := JointConfigAttestationForEntry(body, entryHash)
	wantCanonical, _ := MarshalCanonical(want)
	gotCanonical, err := MarshalCanonical(qc.Attestation)
	if err != nil || !bytes.Equal(wantCanonical, gotCanonical) {
		return errors.New("[D112 joint QC] joint attestation 与 entry 不一致")
	}
	keys := make(map[string]ControlMemberV1, len(oldSet.Members)+len(newSet.Members))
	for _, set := range []*ControlSetV1{oldSet, newSet} {
		if err := ValidateControlSet(set); err != nil {
			return err
		}
		for _, member := range set.Members {
			keys[member.MemberID+"\x00"+member.ConfigKeyID] = member
		}
	}
	message, _ := Frame(DomainJointConfigReplicationAttestation, wantCanonical)
	for i, signature := range qc.Signatures {
		if i > 0 && compareSigner(qc.Signatures[i-1].MemberID, qc.Signatures[i-1].ConfigKeyID, signature.MemberID, signature.ConfigKeyID) >= 0 {
			return errors.New("[D112 joint QC] signatures 必须严格排序且不重复")
		}
		member, ok := keys[signature.MemberID+"\x00"+signature.ConfigKeyID]
		public, keyErr := decodeRawURL(member.ConfigPublicKey, ed25519.PublicKeySize)
		rawSignature, signatureErr := decodeRawURL(signature.Signature, ed25519.SignatureSize)
		if !ok || signature.Algorithm != "ed25519" || keyErr != nil || signatureErr != nil || !ed25519.Verify(public, message, rawSignature) {
			return errors.New("[D112 joint QC] config signature 无效")
		}
	}
	if err := verifyJointRefs(qc.OldSignerRefs, qc.Signatures, oldSet); err != nil {
		return err
	}
	if err := verifyJointRefs(qc.NewSignerRefs, qc.Signatures, newSet); err != nil {
		return err
	}
	return rejectUnprojectedConfigSignatures(qc.Signatures, qc.OldSignerRefs, qc.NewSignerRefs)
}

func rejectUnprojectedConfigSignatures(signatures []ControlConfigSignatureV1, oldRefs, newRefs []ControlConfigSignerRefV1) error {
	used := make(map[string]struct{}, len(oldRefs)+len(newRefs))
	for _, refs := range [][]ControlConfigSignerRefV1{oldRefs, newRefs} {
		for _, ref := range refs {
			used[ref.MemberID+"\x00"+ref.ConfigKeyID] = struct{}{}
		}
	}
	for _, signature := range signatures {
		if _, found := used[signature.MemberID+"\x00"+signature.ConfigKeyID]; !found {
			return errors.New("[D112 joint QC] signatures 含未被 old/new 投影引用的额外签名")
		}
	}
	return nil
}

func JointConfigQCHash(qc *JointConfigReplicationQCV1) (string, error) {
	return HashObject(DomainQuorumCertificate, qc)
}

func JointControlSetProofHash(proof *JointControlSetProofV1, oldSet, newSet *ControlSetV1) (string, error) {
	if proof == nil || proof.Schema != 1 {
		return "", errors.New("[D112 joint] Joint proof schema 无效")
	}
	if err := VerifyJointConfigQC(&proof.JointBody, proof.JointEntryHash, oldSet, newSet, &proof.JointReplicationQC); err != nil {
		return "", err
	}
	return HashObject(DomainJointControlSetProof, proof)
}

func ControlSetTransitionProofHash(proof *ControlSetTransitionProofV1) (string, error) {
	if proof == nil || proof.Schema != 1 || proof.FinalPayload.Schema != 2 {
		return "", errors.New("[D112 joint] control transition proof schema 无效")
	}
	if _, err := ParseHash(proof.JointProofHash); err != nil {
		return "", err
	}
	if err := validateTransitionContext(proof.FinalPayload.HeadKind, proof.FinalPayload.TransitionContext); err != nil {
		return "", err
	}
	return HashObject(DomainControlSetTransitionProof, proof)
}

func VerifyControlSetTransitionBundle(bundle *ControlSetTransitionBundleV1, parent *HeadEntryV2) (VerifiedControlSetTransitionV1, error) {
	if bundle == nil || bundle.Schema != 1 || bundle.Final.Schema != 1 || parent == nil {
		return VerifiedControlSetTransitionV1{}, errors.New("[D112 joint] transition bundle/parent 无效")
	}
	if err := VerifyControlMembershipApprovalProof(&bundle.MembershipApprovalProof, &bundle.OldControlSet, &bundle.NewControlSet, parent); err != nil {
		return VerifiedControlSetTransitionV1{}, err
	}
	approvalHash, _ := ControlMembershipApprovalProofHash(&bundle.MembershipApprovalProof)
	intent := &bundle.MembershipApprovalProof.Intent
	joint := &bundle.JointProof.JointBody
	if !jointMatchesIntent(joint, intent, approvalHash) {
		return VerifiedControlSetTransitionV1{}, errors.New("[D112 joint] Joint entry 未 exact-bind intent/approval")
	}
	parentTime, _ := ParseTimeZ(parent.Body.Payload.CommittedLogicalTime)
	jointTime, err := ParseTimeZ(joint.CommittedLogicalTime)
	nextJointIndex, indexErr := CheckedAdd(parent.Body.Payload.RaftIndex, 1)
	if err != nil || indexErr != nil || !jointTime.After(parentTime) || joint.RaftTerm < parent.Body.Payload.RaftTerm ||
		joint.RaftIndex != nextJointIndex || joint.PreviousLogEntryHash != parent.EntryHash {
		return VerifiedControlSetTransitionV1{}, errors.New("[D112 joint] Joint entry 未直接连续 parent certified head")
	}
	jointProofHash, err := JointControlSetProofHash(&bundle.JointProof, &bundle.OldControlSet, &bundle.NewControlSet)
	if err != nil {
		return VerifiedControlSetTransitionV1{}, err
	}
	proof := ControlSetTransitionProofV1{Schema: 1, JointProofHash: jointProofHash, FinalPayload: bundle.Final.Head.Body.Payload}
	transitionHash, err := ControlSetTransitionProofHash(&proof)
	if err != nil {
		return VerifiedControlSetTransitionV1{}, err
	}
	finalHead := &bundle.Final.Head
	if finalHead.Body.TransitionProofHash != transitionHash || ValidateHeadEntry(finalHead, nil) != nil {
		return VerifiedControlSetTransitionV1{}, errors.New("[D112 joint] Final head/transition proof hash 无效")
	}
	if err := VerifyJointHeadQC(finalHead, &bundle.OldControlSet, &bundle.NewControlSet, &bundle.Final.FinalJointReplicationQC); err != nil {
		return VerifiedControlSetTransitionV1{}, err
	}
	if err := validateFinalControlSetPayload(&finalHead.Body.Payload, parent, joint, intent, approvalHash, bundle.JointProof.JointEntryHash, jointProofHash); err != nil {
		return VerifiedControlSetTransitionV1{}, err
	}
	return VerifiedControlSetTransitionV1{
		clusterID: intent.ClusterID, recoveryEpoch: intent.RecoveryEpoch,
		recoveryStatementHash: intent.RecoveryStatementHash, recoveryPolicyHash: intent.RecoveryPolicyHash,
		oldControlEpoch: intent.OldControlEpoch, oldControlSetHash: intent.OldControlSetHash,
		parentHeadHash: parent.HeadHash, parentControlRevision: parent.Body.Payload.ControlRevision,
		newControlEpoch: intent.TargetControlEpoch, newControlSetHash: intent.NewControlSetHash,
		finalHeadHash: finalHead.HeadHash, finalControlRevision: finalHead.Body.Payload.ControlRevision,
		transitionProofHash: transitionHash,
	}, nil
}

func jointMatchesIntent(joint *JointControlSetEntryBodyV1, intent *ControlSetTransitionIntentV1, approvalHash string) bool {
	return joint != nil && validateJointControlSetEntryBody(joint) == nil && joint.ClusterID == intent.ClusterID &&
		joint.TransitionID == intent.TransitionID && joint.RecoveryEpoch == intent.RecoveryEpoch &&
		joint.RecoveryStatementHash == intent.RecoveryStatementHash && joint.RecoveryPolicyHash == intent.RecoveryPolicyHash &&
		joint.OldControlEpoch == intent.OldControlEpoch && joint.OldControlSetHash == intent.OldControlSetHash &&
		joint.OldControlPeerDirectoryHash == intent.OldControlPeerDirectoryHash &&
		joint.TargetControlEpoch == intent.TargetControlEpoch && joint.NewControlSetHash == intent.NewControlSetHash &&
		joint.NewControlPeerDirectoryHash == intent.NewControlPeerDirectoryHash &&
		joint.ParentCertifiedHeadHash == intent.ParentCertifiedHeadHash && joint.MembershipApprovalProofHash == approvalHash &&
		joint.OperationID == intent.OperationID && joint.Reason == intent.Reason
}

func validateFinalControlSetPayload(payload *HeadEntryPayloadV2, parent *HeadEntryV2, joint *JointControlSetEntryBodyV1, intent *ControlSetTransitionIntentV1, approvalHash, jointEntryHash, jointProofHash string) error {
	var context FinalControlSetContextV1
	if _, err := DecodeStrict(payload.TransitionContext, 16<<10, &context); err != nil {
		return errors.New("[D112 joint] Final context strict decode 失败")
	}
	nextIndex, indexErr := CheckedAdd(joint.RaftIndex, 1)
	jointTime, jointTimeErr := ParseTimeZ(joint.CommittedLogicalTime)
	finalTime, finalTimeErr := ParseTimeZ(payload.CommittedLogicalTime)
	p := &parent.Body.Payload
	if indexErr != nil || jointTimeErr != nil || finalTimeErr != nil || !finalTime.After(jointTime) || payload.RaftIndex != nextIndex ||
		payload.PreviousLogEntryHash != jointEntryHash || payload.RaftTerm < joint.RaftTerm || payload.ControlRevision != payload.RaftIndex ||
		payload.HeadKind != "control_set_final" || payload.ClusterID != intent.ClusterID ||
		payload.RecoveryEpoch != intent.RecoveryEpoch || payload.RecoveryStatementHash != intent.RecoveryStatementHash ||
		payload.RecoveryPolicyHash != intent.RecoveryPolicyHash || payload.ControlEpoch != intent.TargetControlEpoch ||
		payload.ControlSetHash != intent.NewControlSetHash || payload.ControlPeerDirectoryHash != intent.NewControlPeerDirectoryHash ||
		payload.ParentHeadHash != intent.ParentCertifiedHeadHash || context.Schema != 1 || context.Kind != "control_set_final" ||
		context.TransitionID != intent.TransitionID || context.OldControlEpoch != intent.OldControlEpoch ||
		context.OldControlSetHash != intent.OldControlSetHash || context.OldControlPeerDirectoryHash != intent.OldControlPeerDirectoryHash ||
		context.NewControlEpoch != intent.TargetControlEpoch || context.NewControlSetHash != intent.NewControlSetHash ||
		context.NewControlPeerDirectoryHash != intent.NewControlPeerDirectoryHash ||
		context.MembershipApprovalProofHash != approvalHash || context.JointEntryHash != jointEntryHash || context.JointProofHash != jointProofHash {
		return errors.New("[D112 joint] Final payload/context 未 exact-bind Joint/intent")
	}
	if payload.OperationRoot != p.OperationRoot || payload.DeviceViewsRoot != p.DeviceViewsRoot ||
		payload.AdminACLRoot != p.AdminACLRoot || payload.CAProfileRoot != p.CAProfileRoot ||
		payload.BootstrapIssuerRegistryRoot != p.BootstrapIssuerRegistryRoot ||
		payload.RenderContractVersion != p.RenderContractVersion || payload.MinReaderVersion != p.MinReaderVersion ||
		payload.MaxClockSkewSeconds != p.MaxClockSkewSeconds {
		return errors.New("[D112 joint] Final 夹带了非 control projection 状态变更")
	}
	return nil
}

// VerifyControlSetTransitionMaterialization 供 control voter 在签 Final 前把唯一 reducer
// 输出注入验证；普通 reader 依靠 Joint QC 验证被认证的两个 hash（D112）。
func VerifyControlSetTransitionMaterialization(final *HeadEntryV2, expectedSnapshotHash, expectedEffectiveSSOTHash string) error {
	if final == nil || requireCanonicalHashes(expectedSnapshotHash, expectedEffectiveSSOTHash) != nil ||
		final.Body.Payload.SnapshotHash != expectedSnapshotHash || final.Body.Payload.EffectiveSSOTHash != expectedEffectiveSSOTHash {
		return errors.New("[D112 joint] Final materialization hash 与确定性 reducer 输出不匹配")
	}
	return nil
}

func AdvanceFloorsWithControl(current, candidate ClientFloorsV2, verified VerifiedControlSetTransitionV1) (ClientFloorsV2, error) {
	if verified.clusterID == "" || current.ClusterID != verified.clusterID || candidate.ClusterID != verified.clusterID ||
		current.AcceptedRecoveryEpoch != verified.recoveryEpoch || candidate.AcceptedRecoveryEpoch != verified.recoveryEpoch ||
		current.RecoveryStatementHash != verified.recoveryStatementHash || candidate.RecoveryStatementHash != verified.recoveryStatementHash ||
		current.RecoveryPolicyHash != verified.recoveryPolicyHash || candidate.RecoveryPolicyHash != verified.recoveryPolicyHash ||
		current.AcceptedControlEpoch != verified.oldControlEpoch || current.ControlSetHash != verified.oldControlSetHash ||
		current.HeadHash != verified.parentHeadHash || current.AcceptedControlRevision != verified.parentControlRevision ||
		candidate.AcceptedControlEpoch != verified.newControlEpoch || candidate.ControlSetHash != verified.newControlSetHash ||
		candidate.HeadHash != verified.finalHeadHash || candidate.AcceptedControlRevision != verified.finalControlRevision {
		return current, errors.New("[D112 floor] control evidence 与 parent/Final floor 不匹配")
	}
	return advanceFloors(current, candidate, floorAdvanceAuthority{control: true})
}
