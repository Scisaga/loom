package wire

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"time"
)

const (
	DomainRecoveryPolicyIntent            = "loom-recovery-policy-intent-v1"
	DomainRecoveryPolicyRotationSignature = "loom-recovery-policy-rotation-signature-v1"
	DomainRecoveryPolicyTransitionProof   = "loom-recovery-policy-transition-proof-v1"
)

type RecoveryPolicyIntentV1 struct {
	Schema                            int    `json:"schema"`
	ClusterID                         string `json:"cluster_id"`
	IntentID                          string `json:"intent_id"`
	PreviousRecoveryEpoch             int64  `json:"previous_recovery_epoch"`
	PreviousRecoveryStatementHash     string `json:"previous_recovery_statement_hash"`
	PreviousRecoveryPolicyHash        string `json:"previous_recovery_policy_hash"`
	PreviousControlEpoch              int64  `json:"previous_control_epoch"`
	UnchangedControlSetHash           string `json:"unchanged_control_set_hash"`
	UnchangedControlPeerDirectoryHash string `json:"unchanged_control_peer_directory_hash"`
	ParentHeadHash                    string `json:"parent_head_hash"`
	NewRecoveryEpoch                  int64  `json:"new_recovery_epoch"`
	NewRecoveryPolicyHash             string `json:"new_recovery_policy_hash"`
	NewPolicyPoPRoot                  string `json:"new_policy_pop_root"`
	CeremonyID                        string `json:"ceremony_id"`
	Reason                            string `json:"reason"`
}

type RecoveryPolicyTransitionBodyV1 struct {
	Schema                            int    `json:"schema"`
	StatementType                     string `json:"statement_type"`
	ClusterID                         string `json:"cluster_id"`
	IntentID                          string `json:"intent_id"`
	IntentHash                        string `json:"intent_hash"`
	IntentHeadHash                    string `json:"intent_head_hash"`
	IntentQCHash                      string `json:"intent_qc_hash"`
	PreviousRecoveryEpoch             int64  `json:"previous_recovery_epoch"`
	PreviousRecoveryStatementHash     string `json:"previous_recovery_statement_hash"`
	PreviousRecoveryPolicyHash        string `json:"previous_recovery_policy_hash"`
	PreviousControlEpoch              int64  `json:"previous_control_epoch"`
	UnchangedControlSetHash           string `json:"unchanged_control_set_hash"`
	UnchangedControlPeerDirectoryHash string `json:"unchanged_control_peer_directory_hash"`
	LastCertifiedHeadHash             string `json:"last_certified_head_hash"`
	NewRecoveryEpoch                  int64  `json:"new_recovery_epoch"`
	NewRecoveryPolicyHash             string `json:"new_recovery_policy_hash"`
	NewPolicyPoPRoot                  string `json:"new_policy_pop_root"`
	NewControlEpoch                   int64  `json:"new_control_epoch"`
	CeremonyID                        string `json:"ceremony_id"`
	Reason                            string `json:"reason"`
	IssuedAt                          string `json:"issued_at"`
}

type RecoveryPolicyTransitionProofV1 struct {
	Schema                       int                            `json:"schema"`
	Body                         RecoveryPolicyTransitionBodyV1 `json:"body"`
	RecoveryStatementHash        string                         `json:"recovery_statement_hash"`
	OldPolicyThresholdSignatures []RecoveryThresholdSignatureV1 `json:"old_policy_threshold_signatures"`
}

type CertifiedHeadV1 struct {
	Head HeadEntryV2     `json:"head"`
	QC   json.RawMessage `json:"qc"`
}

type RecoveryActivationHeadV1 struct {
	Schema        int                       `json:"schema"`
	Head          HeadEntryV2               `json:"head"`
	ReplicationQC StableHeadReplicationQCV1 `json:"replication_qc"`
}

type RecoveryPolicyActivationBundleV1 struct {
	Schema                    int                             `json:"schema"`
	Intent                    RecoveryPolicyIntentV1          `json:"intent"`
	NewRecoveryPolicy         RecoveryPolicyV1                `json:"new_recovery_policy"`
	NewPolicyPossessionProofs []RecoveryKeyPossessionProofV1  `json:"new_policy_possession_proofs"`
	IntentOperation           ControlOperationV1              `json:"intent_operation"`
	IntentOperationLeaf       ControlOperationLeafV1          `json:"intent_operation_leaf"`
	IntentLeafIndex           int64                           `json:"intent_leaf_index"`
	IntentOperationTreeSize   int64                           `json:"intent_operation_tree_size"`
	IntentOperationAuditPath  []string                        `json:"intent_operation_audit_path"`
	IntentHead                HeadEntryV2                     `json:"intent_head"`
	IntentHeadQC              json.RawMessage                 `json:"intent_head_qc"`
	ContinuityHeads           []CertifiedHeadV1               `json:"continuity_heads"`
	TransitionProof           RecoveryPolicyTransitionProofV1 `json:"transition_proof"`
	Activation                RecoveryActivationHeadV1        `json:"activation"`
	InitialDeviceViewProof    *DeviceViewEnvelopeV2           `json:"initial_device_view_proof,omitempty"`
}

type VerifiedRecoveryPolicyTransitionV1 struct {
	clusterID                     string
	previousRecoveryEpoch         int64
	previousRecoveryStatementHash string
	previousRecoveryPolicyHash    string
	previousControlEpoch          int64
	controlSetHash                string
	lastCertifiedHeadHash         string
	lastCertifiedControlRevision  int64
	newRecoveryEpoch              int64
	newRecoveryStatementHash      string
	newRecoveryPolicyHash         string
	newControlEpoch               int64
	activationHeadHash            string
	activationControlRevision     int64
	transitionProofHash           string
}

func (verified VerifiedRecoveryPolicyTransitionV1) TransitionProofHash() string {
	return verified.transitionProofHash
}

func validateRecoveryPolicyIntent(intent *RecoveryPolicyIntentV1) error {
	if intent == nil || intent.Schema != 1 || !validIdentifier(intent.ClusterID, 128) ||
		!validIdentifier(intent.IntentID, 128) || !validIdentifier(intent.CeremonyID, 128) ||
		intent.PreviousRecoveryEpoch < 0 || intent.PreviousControlEpoch < 0 || !validRecoveryReason(intent.Reason) {
		return errors.New("[D116 recovery] policy intent header 无效")
	}
	nextEpoch, err := CheckedAdd(intent.PreviousRecoveryEpoch, 1)
	if err != nil || intent.NewRecoveryEpoch != nextEpoch {
		return errors.New("[D116 recovery] planned recovery epoch 必须精确加一")
	}
	return requireCanonicalHashes(intent.PreviousRecoveryStatementHash, intent.PreviousRecoveryPolicyHash,
		intent.UnchangedControlSetHash, intent.UnchangedControlPeerDirectoryHash, intent.ParentHeadHash,
		intent.NewRecoveryPolicyHash, intent.NewPolicyPoPRoot)
}

func RecoveryPolicyIntentHash(intent *RecoveryPolicyIntentV1) (string, error) {
	if err := validateRecoveryPolicyIntent(intent); err != nil {
		return "", err
	}
	return HashObject(DomainRecoveryPolicyIntent, intent)
}

func validateRecoveryPolicyTransitionBody(body *RecoveryPolicyTransitionBodyV1) error {
	if body == nil || body.Schema != 1 || body.StatementType != "policy_rotation" ||
		!validIdentifier(body.ClusterID, 128) || !validIdentifier(body.IntentID, 128) ||
		!validIdentifier(body.CeremonyID, 128) || body.PreviousRecoveryEpoch < 0 ||
		body.PreviousControlEpoch < 0 || body.NewControlEpoch != 0 || !validRecoveryReason(body.Reason) {
		return errors.New("[D116 recovery] policy transition body header 无效")
	}
	nextEpoch, err := CheckedAdd(body.PreviousRecoveryEpoch, 1)
	if err != nil || body.NewRecoveryEpoch != nextEpoch {
		return errors.New("[D116 recovery] policy transition epoch 必须精确加一")
	}
	if _, err := ParseTimeZ(body.IssuedAt); err != nil {
		return err
	}
	return requireCanonicalHashes(body.IntentHash, body.IntentHeadHash, body.IntentQCHash,
		body.PreviousRecoveryStatementHash, body.PreviousRecoveryPolicyHash, body.UnchangedControlSetHash,
		body.UnchangedControlPeerDirectoryHash, body.LastCertifiedHeadHash, body.NewRecoveryPolicyHash, body.NewPolicyPoPRoot)
}

func RecoveryPolicyTransitionProofHash(proof *RecoveryPolicyTransitionProofV1, previousPolicy *RecoveryPolicyV1) (string, error) {
	if proof == nil || proof.Schema != 1 {
		return "", errors.New("[D116 recovery] policy transition proof schema 无效")
	}
	statementHash, err := RecoveryStatementHash(&proof.Body)
	if err != nil || statementHash != proof.RecoveryStatementHash {
		return "", errors.New("[D116 recovery] policy transition statement hash 不匹配")
	}
	if err := VerifyRecoveryThresholdSignatures(previousPolicy, &proof.Body, DomainRecoveryPolicyRotationSignature, proof.OldPolicyThresholdSignatures); err != nil {
		return "", err
	}
	return HashObject(DomainRecoveryPolicyTransitionProof, proof)
}

func VerifyRecoveryPolicyActivationBundle(bundle *RecoveryPolicyActivationBundleV1, previousPolicy *RecoveryPolicyV1, set *ControlSetV1, parent *HeadEntryV2) (VerifiedRecoveryPolicyTransitionV1, error) {
	if bundle == nil || bundle.Schema != 1 || parent == nil || ValidateHeadEntry(parent, nil) != nil {
		return VerifiedRecoveryPolicyTransitionV1{}, errors.New("[D116 recovery] activation bundle/parent 无效")
	}
	if err := ValidateControlSet(set); err != nil {
		return VerifiedRecoveryPolicyTransitionV1{}, err
	}
	intent := &bundle.Intent
	if err := validateRecoveryPolicyIntent(intent); err != nil {
		return VerifiedRecoveryPolicyTransitionV1{}, err
	}
	setHash, _ := ControlSetHash(set)
	oldPolicyHash, err := RecoveryPolicyHash(previousPolicy)
	p := &parent.Body.Payload
	if err != nil || previousPolicy.ClusterID != intent.ClusterID || set.ClusterID != intent.ClusterID ||
		oldPolicyHash != intent.PreviousRecoveryPolicyHash || p.ClusterID != intent.ClusterID ||
		p.RecoveryEpoch != intent.PreviousRecoveryEpoch || p.RecoveryStatementHash != intent.PreviousRecoveryStatementHash ||
		p.RecoveryPolicyHash != intent.PreviousRecoveryPolicyHash || p.ControlEpoch != intent.PreviousControlEpoch ||
		p.ControlSetHash != setHash || p.ControlSetHash != intent.UnchangedControlSetHash ||
		p.ControlPeerDirectoryHash != intent.UnchangedControlPeerDirectoryHash || parent.HeadHash != intent.ParentHeadHash {
		return VerifiedRecoveryPolicyTransitionV1{}, errors.New("[D116 recovery] intent 与 old authority/parent 不匹配")
	}
	newPolicyHash, err := RecoveryPolicyHash(&bundle.NewRecoveryPolicy)
	if err != nil || bundle.NewRecoveryPolicy.ClusterID != intent.ClusterID || newPolicyHash != intent.NewRecoveryPolicyHash {
		return VerifiedRecoveryPolicyTransitionV1{}, errors.New("[D116 recovery] new policy hash/cluster 不匹配")
	}
	newPoPRoot, err := RecoveryKeyPossessionRoot(&bundle.NewRecoveryPolicy, bundle.NewPolicyPossessionProofs)
	if err != nil || newPoPRoot != intent.NewPolicyPoPRoot {
		return VerifiedRecoveryPolicyTransitionV1{}, errors.New("[D116 recovery] new policy PoP root 不匹配")
	}
	if err := ValidateRecoveryControlKeySeparation(&bundle.NewRecoveryPolicy, set); err != nil {
		return VerifiedRecoveryPolicyTransitionV1{}, err
	}
	intentHash, _ := RecoveryPolicyIntentHash(intent)
	if err := verifyRecoveryPolicyIntentOperation(bundle, intentHash, parent); err != nil {
		return VerifiedRecoveryPolicyTransitionV1{}, err
	}
	if err := ValidateHeadEntry(&bundle.IntentHead, parent); err != nil || bundle.IntentHead.Body.Payload.HeadKind != "ordinary" {
		return VerifiedRecoveryPolicyTransitionV1{}, errors.New("[D116 recovery] intent head 不是 parent 的 ordinary 直接后继")
	}
	if err := VerifyConfigQCAuthority(bundle.IntentHead.HeadHash, bundle.IntentHeadQC, &bundle.IntentHead, set, nil); err != nil {
		return VerifiedRecoveryPolicyTransitionV1{}, err
	}
	operationID, err := HashObject(DomainControlOperation, &bundle.IntentOperation)
	if err != nil || bundle.IntentOperationLeaf.Schema != 1 || bundle.IntentOperationLeaf.OperationID != intent.IntentID ||
		bundle.IntentOperationLeaf.ObjectID != operationID {
		return VerifiedRecoveryPolicyTransitionV1{}, errors.New("[D116 recovery] intent operation leaf binding 无效")
	}
	if err := VerifyControlOperationInclusion(&bundle.IntentOperationLeaf, bundle.IntentLeafIndex,
		bundle.IntentOperationTreeSize, bundle.IntentOperationAuditPath, &bundle.IntentHead); err != nil {
		return VerifiedRecoveryPolicyTransitionV1{}, err
	}
	intentQCCanonical, err := CanonicalizeStrict(bundle.IntentHeadQC)
	if err != nil || !bytes.Equal(intentQCCanonical, bundle.IntentHeadQC) {
		return VerifiedRecoveryPolicyTransitionV1{}, errors.New("[D116 recovery] intent QC 必须是 exact canonical wire")
	}
	intentQCHash, _ := HashCanonical(DomainQuorumCertificate, intentQCCanonical)
	last := bundle.IntentHead
	for _, certified := range bundle.ContinuityHeads {
		if err := ValidateHeadEntry(&certified.Head, &last); err != nil || certified.Head.Body.Payload.HeadKind != "ordinary" {
			return VerifiedRecoveryPolicyTransitionV1{}, errors.New("[D116 recovery] continuity head 链不连续")
		}
		if err := VerifyConfigQCAuthority(certified.Head.HeadHash, certified.QC, &certified.Head, set, nil); err != nil {
			return VerifiedRecoveryPolicyTransitionV1{}, err
		}
		last = certified.Head
	}
	body := &bundle.TransitionProof.Body
	if err := validateRecoveryPolicyTransitionBody(body); err != nil || !policyTransitionMatchesIntent(body, intent, intentHash, bundle.IntentHead.HeadHash, intentQCHash, last.HeadHash) {
		return VerifiedRecoveryPolicyTransitionV1{}, errors.New("[D116 recovery] policy transition 未 exact-bind intent/head/QC/continuity")
	}
	transitionHash, err := RecoveryPolicyTransitionProofHash(&bundle.TransitionProof, previousPolicy)
	if err != nil {
		return VerifiedRecoveryPolicyTransitionV1{}, err
	}
	activation := &bundle.Activation
	if activation.Schema != 1 || !recoveryPolicyTransitionIssuedBeforeActivation(body, &activation.Head) ||
		!activationMatchesTransition(&activation.Head, &last, body, bundle.TransitionProof.RecoveryStatementHash, transitionHash) {
		return VerifiedRecoveryPolicyTransitionV1{}, errors.New("[D116 recovery] Activation head 未 exact-bind transition/last head")
	}
	if err := VerifyStableHeadQC(&activation.Head, set, &activation.ReplicationQC); err != nil {
		return VerifiedRecoveryPolicyTransitionV1{}, err
	}
	if bundle.InitialDeviceViewProof != nil {
		floors, err := VerifyDeviceViewEnvelope(bundle.InitialDeviceViewProof, set)
		if err != nil || floors.HeadHash != activation.Head.HeadHash {
			return VerifiedRecoveryPolicyTransitionV1{}, errors.New("[D116 recovery] initial Device view proof 未绑定 Activation head")
		}
	}
	return VerifiedRecoveryPolicyTransitionV1{
		clusterID: intent.ClusterID, previousRecoveryEpoch: intent.PreviousRecoveryEpoch,
		previousRecoveryStatementHash: intent.PreviousRecoveryStatementHash, previousRecoveryPolicyHash: intent.PreviousRecoveryPolicyHash,
		previousControlEpoch: intent.PreviousControlEpoch, controlSetHash: intent.UnchangedControlSetHash,
		lastCertifiedHeadHash: last.HeadHash, lastCertifiedControlRevision: last.Body.Payload.ControlRevision,
		newRecoveryEpoch: body.NewRecoveryEpoch, newRecoveryStatementHash: bundle.TransitionProof.RecoveryStatementHash,
		newRecoveryPolicyHash: body.NewRecoveryPolicyHash, newControlEpoch: body.NewControlEpoch,
		activationHeadHash: activation.Head.HeadHash, activationControlRevision: activation.Head.Body.Payload.ControlRevision,
		transitionProofHash: transitionHash,
	}, nil
}

// VerifyAuthorizedRecoveryPolicyActivationBundle 是计划内 recovery policy 变更的
// server-side 入口；旧 policy threshold 不能替代发起操作的 certified admin ACL（D116）。
func VerifyAuthorizedRecoveryPolicyActivationBundle(bundle *RecoveryPolicyActivationBundleV1, previousPolicy *RecoveryPolicyV1,
	set, previousSet *ControlSetV1, parent *HeadEntryV2, parentQC json.RawMessage,
	peerCertificateDER []byte, trustedTime time.Time, authorizations []AdminAuthorizationV1,
	profiles map[string]AdminCertificateProfileV1) (VerifiedRecoveryPolicyTransitionV1, VerifiedAdminOperationV1, error) {
	verified, err := VerifyRecoveryPolicyActivationBundle(bundle, previousPolicy, set, parent)
	if err != nil {
		return VerifiedRecoveryPolicyTransitionV1{}, VerifiedAdminOperationV1{}, err
	}
	scope := AdminResourceScopeV1{ScopeKind: "recovery_policy", RecoveryPolicy: &struct{}{}}
	admin, err := AuthorizeControlOperationAtHead(&bundle.IntentOperation, peerCertificateDER, &scope,
		trustedTime, OperationSchemaRegistry{"recovery_policy_intent": 1}, parent, parentQC, set,
		previousSet, authorizations, profiles)
	if err != nil {
		return VerifiedRecoveryPolicyTransitionV1{}, VerifiedAdminOperationV1{}, err
	}
	return verified, admin, nil
}

func verifyRecoveryPolicyIntentOperation(bundle *RecoveryPolicyActivationBundleV1, intentHash string, parent *HeadEntryV2) error {
	op := &bundle.IntentOperation
	intent := &bundle.Intent
	if err := ValidateControlOperationBody(&op.Body, OperationSchemaRegistry{"recovery_policy_intent": 1}); err != nil {
		return err
	}
	p := &parent.Body.Payload
	if op.Body.ClusterID != intent.ClusterID || op.Body.OperationID != intent.IntentID ||
		op.Body.Kind != "recovery_policy_intent" || op.Body.PayloadSchema != 1 || op.Body.PayloadHash != intentHash ||
		op.Body.BaseRecoveryEpoch != intent.PreviousRecoveryEpoch || op.Body.BaseRecoveryStatementHash != intent.PreviousRecoveryStatementHash ||
		op.Body.BaseRecoveryPolicyHash != intent.PreviousRecoveryPolicyHash || op.Body.BaseControlEpoch != intent.PreviousControlEpoch ||
		op.Body.BaseControlSetHash != intent.UnchangedControlSetHash || op.Body.BaseControlRevision != p.ControlRevision ||
		op.Body.ParentHeadHash != intent.ParentHeadHash || op.Body.Reason != intent.Reason || op.AuthorSignature.Algorithm != "ed25519" {
		return errors.New("[D116 recovery] intent operation 未 exact-bind policy intent")
	}
	if _, err := ParseHash(op.AuthorSignature.AdminKeyID); err != nil {
		return errors.New("[D116 recovery] intent operation admin key ID 无效")
	}
	if _, err := decodeRawURL(op.AuthorSignature.Signature, ed25519.SignatureSize); err != nil {
		return errors.New("[D116 recovery] intent operation signature 编码无效")
	}
	return nil
}

func policyTransitionMatchesIntent(body *RecoveryPolicyTransitionBodyV1, intent *RecoveryPolicyIntentV1, intentHash, intentHeadHash, intentQCHash, lastHeadHash string) bool {
	return body.ClusterID == intent.ClusterID && body.IntentID == intent.IntentID && body.IntentHash == intentHash &&
		body.IntentHeadHash == intentHeadHash && body.IntentQCHash == intentQCHash &&
		body.PreviousRecoveryEpoch == intent.PreviousRecoveryEpoch &&
		body.PreviousRecoveryStatementHash == intent.PreviousRecoveryStatementHash &&
		body.PreviousRecoveryPolicyHash == intent.PreviousRecoveryPolicyHash &&
		body.PreviousControlEpoch == intent.PreviousControlEpoch && body.UnchangedControlSetHash == intent.UnchangedControlSetHash &&
		body.UnchangedControlPeerDirectoryHash == intent.UnchangedControlPeerDirectoryHash && body.LastCertifiedHeadHash == lastHeadHash &&
		body.NewRecoveryEpoch == intent.NewRecoveryEpoch && body.NewRecoveryPolicyHash == intent.NewRecoveryPolicyHash &&
		body.NewPolicyPoPRoot == intent.NewPolicyPoPRoot && body.NewControlEpoch == 0 &&
		body.CeremonyID == intent.CeremonyID && body.Reason == intent.Reason
}

func activationMatchesTransition(head, last *HeadEntryV2, body *RecoveryPolicyTransitionBodyV1, statementHash, transitionHash string) bool {
	if head == nil || last == nil || ValidateHeadEntry(head, last) != nil || head.Body.TransitionProofHash != transitionHash {
		return false
	}
	payload := &head.Body.Payload
	previous := &last.Body.Payload
	var context RecoveryPolicyActivationContextV1
	if _, err := DecodeStrict(payload.TransitionContext, 4096, &context); err != nil {
		return false
	}
	lastTime, _ := ParseTimeZ(previous.CommittedLogicalTime)
	activationTime, _ := ParseTimeZ(payload.CommittedLogicalTime)
	return activationTime.After(lastTime) && payload.HeadKind == "recovery_policy_activation" &&
		payload.ClusterID == body.ClusterID && payload.RecoveryEpoch == body.NewRecoveryEpoch &&
		payload.RecoveryStatementHash == statementHash && payload.RecoveryPolicyHash == body.NewRecoveryPolicyHash &&
		payload.ControlEpoch == body.NewControlEpoch && payload.ControlSetHash == body.UnchangedControlSetHash &&
		payload.ControlPeerDirectoryHash == body.UnchangedControlPeerDirectoryHash && payload.ParentHeadHash == body.LastCertifiedHeadHash &&
		payload.OperationRoot == previous.OperationRoot && payload.DeviceViewsRoot == previous.DeviceViewsRoot &&
		payload.AdminACLRoot == previous.AdminACLRoot && payload.CAProfileRoot == previous.CAProfileRoot &&
		payload.BootstrapIssuerRegistryRoot == previous.BootstrapIssuerRegistryRoot &&
		payload.RenderContractVersion == previous.RenderContractVersion && payload.MinReaderVersion == previous.MinReaderVersion &&
		payload.MaxClockSkewSeconds == previous.MaxClockSkewSeconds && context.Schema == 1 && context.Kind == "recovery_policy_activation" &&
		context.IntentHash == body.IntentHash && context.IntentHeadHash == body.IntentHeadHash && context.IntentQCHash == body.IntentQCHash
}

func VerifyRecoveryPolicyActivationMaterialization(activation *HeadEntryV2, expectedSnapshotHash, expectedEffectiveSSOTHash string) error {
	if activation == nil || requireCanonicalHashes(expectedSnapshotHash, expectedEffectiveSSOTHash) != nil ||
		activation.Body.Payload.SnapshotHash != expectedSnapshotHash || activation.Body.Payload.EffectiveSSOTHash != expectedEffectiveSSOTHash {
		return errors.New("[D116 recovery] Activation materialization hash 与确定性 reducer 输出不匹配")
	}
	return nil
}

func AdvanceFloorsWithRecoveryPolicy(current, candidate ClientFloorsV2, verified VerifiedRecoveryPolicyTransitionV1) (ClientFloorsV2, error) {
	if verified.clusterID == "" || current.ClusterID != verified.clusterID || candidate.ClusterID != verified.clusterID ||
		current.AcceptedRecoveryEpoch != verified.previousRecoveryEpoch ||
		current.RecoveryStatementHash != verified.previousRecoveryStatementHash || current.RecoveryPolicyHash != verified.previousRecoveryPolicyHash ||
		current.AcceptedControlEpoch != verified.previousControlEpoch || current.ControlSetHash != verified.controlSetHash ||
		current.HeadHash != verified.lastCertifiedHeadHash || current.AcceptedControlRevision != verified.lastCertifiedControlRevision ||
		candidate.AcceptedRecoveryEpoch != verified.newRecoveryEpoch || candidate.RecoveryStatementHash != verified.newRecoveryStatementHash ||
		candidate.RecoveryPolicyHash != verified.newRecoveryPolicyHash || candidate.AcceptedControlEpoch != verified.newControlEpoch ||
		candidate.ControlSetHash != verified.controlSetHash || candidate.HeadHash != verified.activationHeadHash ||
		candidate.AcceptedControlRevision != verified.activationControlRevision ||
		candidate.BootstrapTransitionHash != verified.transitionProofHash &&
			candidate.BootstrapTransitionHash != current.BootstrapTransitionHash {
		return current, errors.New("[D116 floor] policy rotation evidence 与 last head/Activation candidate 不匹配")
	}
	candidate.BootstrapTransitionHash = current.BootstrapTransitionHash
	return advanceFloors(current, candidate, floorAdvanceAuthority{recovery: true})
}

// recoveryPolicyTransitionIssuedBeforeActivation 供 coordinator 在提交前检查审计时间；
// 时间由调用方已验证的 head 注入，不读取本机时钟。
func recoveryPolicyTransitionIssuedBeforeActivation(body *RecoveryPolicyTransitionBodyV1, activation *HeadEntryV2) bool {
	issued, issueErr := ParseTimeZ(body.IssuedAt)
	committed, commitErr := ParseTimeZ(activation.Body.Payload.CommittedLogicalTime)
	return issueErr == nil && commitErr == nil && !issued.After(committed)
}
