package wire

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"time"
)

const DomainInviteProofBundle = "loom-invite-proof-bundle-v2"

// InviteProofBundleV2 只含 public-safe bytes。authority_transitions 使用严格 union：
// 每项必须恰好解码为 ControlSet 或 emergency recovery bundle（D115、D119）。
type InviteProofBundleV2 struct {
	Schema                            int                                 `json:"schema"`
	ClusterID                         string                              `json:"cluster_id"`
	InviteID                          string                              `json:"invite_id"`
	BootstrapTransitionBundle         BootstrapTransitionBundleV1ToV2     `json:"bootstrap_transition_bundle"`
	AuthorityTransitions              []json.RawMessage                   `json:"authority_transitions"`
	CertifiedInviteRecord             CertifiedInviteRecordV2             `json:"certified_invite_record"`
	InviteIssuancePolicy              InviteIssuancePolicyV2              `json:"invite_issuance_policy"`
	DeviceEnrollmentIntentCommitment  DeviceEnrollmentIntentCommitmentV1  `json:"device_enrollment_intent_commitment"`
	InviteOperationLeaf               ControlOperationLeafV1              `json:"invite_operation_leaf"`
	InviteLeafIndex                   int64                               `json:"invite_leaf_index"`
	InviteOperationTreeSize           int64                               `json:"invite_operation_tree_size"`
	InviteOperationAuditPath          []string                            `json:"invite_operation_audit_path"`
	RecordHead                        HeadEntryV2                         `json:"record_head"`
	RecordHeadQC                      json.RawMessage                     `json:"record_head_qc"`
	BootstrapIssuerAuthorizationProof BootstrapIssuerAuthorizationProofV1 `json:"bootstrap_issuer_authorization_proof"`
	BootstrapCatalogHash              string                              `json:"bootstrap_catalog_hash"`
}

type InviteProofTrustV2 struct {
	V1PlatformKey           ed25519.PublicKey
	V1PlatformKeyID         string
	V1MigrationAnchorDigest string
}

// VerifiedInviteProofV2 保存后续 preflight/claim 所需的 exact authority 坐标；字段私有，
// 防止网络状态机把未验证 bundle 误当成已验证结果（D115）。
type VerifiedInviteProofV2 struct {
	recordHash       string
	head             HeadEntryV2
	controlSet       ControlSetV1
	recoveryPolicy   RecoveryPolicyV1
	transitionHashes []string
	authorities      []verifiedHeadAuthorityV2
}

type verifiedHeadAuthorityV2 struct {
	head        HeadEntryV2
	currentSet  ControlSetV1
	previousSet *ControlSetV1
}

func (verified VerifiedInviteProofV2) CertifiedInviteRecordHash() string {
	return verified.recordHash
}

func (verified VerifiedInviteProofV2) Head() HeadEntryV2 {
	return cloneInviteProofValue(verified.head)
}

func (verified VerifiedInviteProofV2) ControlSet() ControlSetV1 {
	return cloneInviteProofValue(verified.controlSet)
}

func (verified VerifiedInviteProofV2) RecoveryPolicy() RecoveryPolicyV1 {
	return cloneInviteProofValue(verified.recoveryPolicy)
}

// AuthorityForHead 返回 proof lineage 中 exact Head 的已验 config authority。
// previous 只会在 control_set_final 的 joint QC 坐标出现（D112、D115）。
func (verified VerifiedInviteProofV2) AuthorityForHead(headHash string) (HeadEntryV2, ControlSetV1, *ControlSetV1, bool) {
	for _, authority := range verified.authorities {
		if authority.head.HeadHash != headHash {
			continue
		}
		head := cloneInviteProofValue(authority.head)
		current := cloneInviteProofValue(authority.currentSet)
		var previous *ControlSetV1
		if authority.previousSet != nil {
			value := cloneInviteProofValue(*authority.previousSet)
			previous = &value
		}
		return head, current, previous, true
	}
	return HeadEntryV2{}, ControlSetV1{}, nil, false
}

func InviteProofBundleHash(bundle *InviteProofBundleV2) (string, error) {
	if bundle == nil || bundle.Schema != 2 || !validIdentifier(bundle.ClusterID, 128) || !validIdentifier(bundle.InviteID, 128) {
		return "", errors.New("[D115 Invite proof] bundle header 无效")
	}
	return HashObject(DomainInviteProofBundle, bundle)
}

// VerifyInviteProofBundle 按协议固定顺序验证 bootstrap/authority lineage、record head QC、
// operation inclusion，再核对 record、issuer、descriptor 的全部重复承诺（D115）。
func VerifyInviteProofBundle(bundle *InviteProofBundleV2, descriptor *InviteBootstrapDescriptorV2, trustedTime time.Time, trust InviteProofTrustV2) (VerifiedInviteProofV2, error) {
	if descriptor == nil {
		return VerifiedInviteProofV2{}, errors.New("[D115 Invite proof] bundle/descriptor header 无效")
	}
	verified, err := verifyInviteProofAuthority(bundle, descriptor.ClusterID, descriptor.InviteID,
		descriptor.ProofBundleHash, trustedTime, trust, descriptor.TrustedCheckpointHash,
		descriptor.MinimumRecoveryEpoch, false)
	if err != nil {
		return VerifiedInviteProofV2{}, err
	}
	if bundle.BootstrapCatalogHash != descriptor.BootstrapCatalogHash {
		return VerifiedInviteProofV2{}, errors.New("[D115 Invite proof] descriptor 未绑定 exact bootstrap catalog")
	}
	if err := VerifyInviteDescriptorBindings(descriptor, &bundle.CertifiedInviteRecord,
		&bundle.InviteIssuancePolicy, &bundle.DeviceEnrollmentIntentCommitment,
		&bundle.BootstrapIssuerAuthorizationProof, trustedTime); err != nil {
		return VerifiedInviteProofV2{}, err
	}
	return verified, nil
}

// VerifyResumeInviteProofBundle 从 v1 migration root 重验 `.loom-resume` 指向的
// Invite proof。resume 没有用户可抄录的 checkpoint，因此必须提供原 v1 platform key/anchor，
// 不能把 descriptor 自报的 Head 当作 trust root（D115、D130）。
func VerifyResumeInviteProofBundle(bundle *InviteProofBundleV2,
	descriptor *EnrollmentResumeDescriptorV1, trustedTime time.Time,
	trust InviteProofTrustV2) (VerifiedInviteProofV2, error) {
	if descriptor == nil {
		return VerifiedInviteProofV2{}, errors.New("[D130 resume] proof/descriptor header 无效")
	}
	verified, err := verifyInviteProofAuthority(bundle, descriptor.ClusterID, descriptor.InviteID,
		descriptor.ProofBundleHash, trustedTime, trust, "", 0, true)
	if err != nil {
		return VerifiedInviteProofV2{}, err
	}
	proof := &bundle.BootstrapIssuerAuthorizationProof
	if proof.Authorization.Active == nil {
		return VerifiedInviteProofV2{}, errors.New("[D130 resume] issuer authorization 非 active")
	}
	publicKey, err := decodeRawURL(proof.Authorization.Active.IssuerPublicKey, ed25519.PublicKeySize)
	if err != nil {
		return VerifiedInviteProofV2{}, errors.New("[D130 resume] issuer public key 无效")
	}
	if err := ValidateEnrollmentResumeDescriptor(descriptor, ed25519.PublicKey(publicKey)); err != nil {
		return VerifiedInviteProofV2{}, err
	}
	if err := VerifyCapabilityAuthorization(&descriptor.ResumeTunnelCapability, proof,
		&bundle.InviteIssuancePolicy, trustedTime); err != nil {
		return VerifiedInviteProofV2{}, err
	}
	record := &bundle.CertifiedInviteRecord
	recordHash, _ := CertifiedInviteRecordHash(record, &bundle.InviteIssuancePolicy)
	policyHash, _ := InviteIssuancePolicyHash(&bundle.InviteIssuancePolicy)
	serviceHash, serviceErr := PrivateEnrollmentServiceRefHash(&descriptor.EnrollmentServiceRef)
	body := descriptor.ResumeTunnelCapability.Body
	if serviceErr != nil || bundle.BootstrapCatalogHash != descriptor.BootstrapCatalogHash ||
		record.BootstrapCatalogHash != descriptor.BootstrapCatalogHash ||
		recordHash != body.CommittedInviteRecordHash || record.InviteIssuancePolicyHash != policyHash ||
		body.InviteIssuancePolicyHash != policyHash ||
		record.BootstrapIssuerAuthorizationHash != proof.AuthorizationHash ||
		record.BootstrapIssuerRegistryRoot != proof.RegistryRoot ||
		body.BootstrapIssuerAuthorizationHash != proof.AuthorizationHash ||
		body.BootstrapIssuerRegistryRoot != proof.RegistryRoot ||
		record.EnrollmentServiceRefHash != serviceHash || body.EnrollmentServiceRefHash != serviceHash {
		return VerifiedInviteProofV2{}, errors.New("[D130 resume] proof/record/catalog/issuer/service binding 无效")
	}
	encoded, err := MarshalCanonical(descriptor)
	policy := &bundle.InviteIssuancePolicy
	if err != nil || int64(len(encoded)) > policy.MaximumDescriptorBytes ||
		int64(len(descriptor.DistributionMirrors)) < policy.MinimumDistributionMirrors ||
		int64(len(descriptor.DistributionMirrors)) > policy.MaximumDistributionMirrors {
		return VerifiedInviteProofV2{}, errors.New("[D130 resume] descriptor size/mirror count 超出 certified policy")
	}
	return verified, nil
}

func verifyInviteProofAuthority(bundle *InviteProofBundleV2, clusterID, inviteID,
	expectedBundleHash string, trustedTime time.Time, trust InviteProofTrustV2,
	trustedCheckpointHash string, minimumRecoveryEpoch int64,
	requirePlatformRoot bool) (VerifiedInviteProofV2, error) {
	if bundle == nil || bundle.Schema != 2 || bundle.AuthorityTransitions == nil ||
		bundle.ClusterID != clusterID || bundle.InviteID != inviteID || trustedTime.IsZero() {
		return VerifiedInviteProofV2{}, errors.New("[D115 Invite proof] bundle/descriptor header 无效")
	}
	bundleHash, err := InviteProofBundleHash(bundle)
	if err != nil || bundleHash != expectedBundleHash {
		return VerifiedInviteProofV2{}, errors.New("[D115 Invite proof] descriptor 未绑定 exact proof bundle")
	}
	bootstrap := &bundle.BootstrapTransitionBundle
	var bootstrapHash string
	if len(trust.V1PlatformKey) == ed25519.PublicKeySize {
		bootstrapHash, err = VerifyBootstrapTransitionBundle(bootstrap, trust.V1PlatformKey,
			trust.V1PlatformKeyID, trust.V1MigrationAnchorDigest)
		if err == nil && trustedCheckpointHash != "" &&
			trustedCheckpointHash != bootstrap.InitialHeadEntry.Head.HeadHash {
			err = errors.New("[D115 Invite proof] descriptor trusted checkpoint 与 v1-verified initial head 不一致")
		}
	} else if requirePlatformRoot {
		err = errors.New("[D130 resume] 缺 v1 platform key/migration anchor trust root")
	} else {
		bootstrapHash, err = VerifyBootstrapTransitionBundleFromCheckpoint(bootstrap, trustedCheckpointHash)
	}
	if err != nil {
		return VerifiedInviteProofV2{}, err
	}
	currentHead := bootstrap.InitialHeadEntry.Head
	currentSet := bootstrap.InitialControlSet
	currentPolicy := bootstrap.InitialRecoveryPolicy
	transitionHashes := []string{bootstrapHash}
	authorities := []verifiedHeadAuthorityV2{{
		head: cloneInviteProofValue(currentHead), currentSet: cloneInviteProofValue(currentSet),
	}}
	for _, raw := range bundle.AuthorityTransitions {
		canonical, canonicalErr := CanonicalizeStrict(raw)
		if canonicalErr != nil || !bytes.Equal(canonical, raw) {
			return VerifiedInviteProofV2{}, errors.New("[D115 Invite proof] authority transition 必须是 exact canonical JSON")
		}
		var controlTransition ControlSetTransitionBundleV1
		if _, decodeErr := DecodeStrict(raw, 32<<20, &controlTransition); decodeErr == nil {
			verified, verifyErr := VerifyControlSetTransitionBundle(&controlTransition, &currentHead)
			if verifyErr != nil {
				return VerifiedInviteProofV2{}, verifyErr
			}
			transitionHashes = append(transitionHashes, verified.TransitionProofHash())
			previousSet := cloneInviteProofValue(currentSet)
			currentHead = controlTransition.Final.Head
			currentSet = controlTransition.NewControlSet
			authorities = append(authorities, verifiedHeadAuthorityV2{
				head: cloneInviteProofValue(currentHead), currentSet: cloneInviteProofValue(currentSet),
				previousSet: &previousSet,
			})
			continue
		}
		var recoveryTransition EmergencyRecoveryBundleV1
		if _, decodeErr := DecodeStrict(raw, 64<<20, &recoveryTransition); decodeErr == nil {
			verified, verifyErr := VerifyEmergencyRecoveryBundle(&recoveryTransition, &currentPolicy, &currentHead)
			if verifyErr != nil {
				return VerifiedInviteProofV2{}, verifyErr
			}
			transitionHashes = append(transitionHashes, verified.TransitionProofHash())
			currentHead = recoveryTransition.Genesis.Head
			currentSet = recoveryTransition.NewControlSet
			currentPolicy = recoveryTransition.NewRecoveryPolicy
			authorities = append(authorities, verifiedHeadAuthorityV2{
				head: cloneInviteProofValue(currentHead), currentSet: cloneInviteProofValue(currentSet),
			})
			continue
		}
		var policyTransition RecoveryPolicyActivationBundleV1
		if _, decodeErr := DecodeStrict(raw, 64<<20, &policyTransition); decodeErr == nil {
			verified, verifyErr := VerifyRecoveryPolicyActivationBundle(&policyTransition, &currentPolicy, &currentSet, &currentHead)
			if verifyErr != nil {
				return VerifiedInviteProofV2{}, verifyErr
			}
			transitionHashes = append(transitionHashes, verified.TransitionProofHash())
			currentHead = policyTransition.Activation.Head
			currentPolicy = policyTransition.NewRecoveryPolicy
			authorities = append(authorities, verifiedHeadAuthorityV2{
				head: cloneInviteProofValue(currentHead), currentSet: cloneInviteProofValue(currentSet),
			})
			continue
		}
		return VerifiedInviteProofV2{}, errors.New("[D115 Invite proof] authority transition union 未获协议授权（index 非法）")
	}
	if minimumRecoveryEpoch > currentHead.Body.Payload.RecoveryEpoch {
		return VerifiedInviteProofV2{}, errors.New("[D115 Invite proof] proof lineage 未达到 descriptor minimum recovery epoch")
	}
	if err := ValidateHeadEntry(&bundle.RecordHead, &currentHead); err != nil || bundle.RecordHead.Body.Payload.HeadKind != "ordinary" {
		return VerifiedInviteProofV2{}, errors.New("[D115 Invite proof] record head 不在已验 authority lineage 的直接后继")
	}
	if err := VerifyConfigQCAuthority(bundle.RecordHead.HeadHash, bundle.RecordHeadQC, &bundle.RecordHead, &currentSet, nil); err != nil {
		return VerifiedInviteProofV2{}, err
	}
	record := &bundle.CertifiedInviteRecord
	recordHash, err := CertifiedInviteRecordHash(record, &bundle.InviteIssuancePolicy)
	if err != nil {
		return VerifiedInviteProofV2{}, err
	}
	leaf := &bundle.InviteOperationLeaf
	if leaf.Schema != 1 || leaf.OperationID != record.OperationID || leaf.ObjectID != recordHash ||
		record.ClusterID != bundle.ClusterID || record.InviteID != bundle.InviteID ||
		record.ParentHeadHash != bundle.RecordHead.Body.Payload.ParentHeadHash {
		return VerifiedInviteProofV2{}, errors.New("[D115 Invite proof] invite record/operation leaf/head binding 无效")
	}
	if err := VerifyControlOperationInclusion(leaf, bundle.InviteLeafIndex, bundle.InviteOperationTreeSize, bundle.InviteOperationAuditPath, &bundle.RecordHead); err != nil {
		return VerifiedInviteProofV2{}, err
	}
	commitmentHash, err := HashObject(DomainEnrollmentIntentCommitment, &bundle.DeviceEnrollmentIntentCommitment)
	if err != nil || commitmentHash != record.DeviceEnrollmentIntentCommitmentHash ||
		bundle.BootstrapCatalogHash != record.BootstrapCatalogHash ||
		record.BootstrapIssuerRegistryRoot != bundle.RecordHead.Body.Payload.BootstrapIssuerRegistryRoot ||
		bundle.BootstrapIssuerAuthorizationProof.RegistryRoot != record.BootstrapIssuerRegistryRoot ||
		bundle.BootstrapIssuerAuthorizationProof.AuthorizationHash != record.BootstrapIssuerAuthorizationHash {
		return VerifiedInviteProofV2{}, errors.New("[D115 Invite proof] record commitment/catalog/issuer root 不匹配")
	}
	if err := VerifyBootstrapIssuerAuthorizationProof(&bundle.BootstrapIssuerAuthorizationProof, trustedTime); err != nil {
		return VerifiedInviteProofV2{}, err
	}
	active := bundle.BootstrapIssuerAuthorizationProof.Authorization.Active
	policyHash, _ := InviteIssuancePolicyHash(&bundle.InviteIssuancePolicy)
	if active == nil || active.InviteIssuancePolicyHash != policyHash || record.InviteIssuancePolicyHash != policyHash {
		return VerifiedInviteProofV2{}, errors.New("[D115 Invite proof] issuer/record 未绑定 exact Invite policy")
	}
	authorities = append(authorities, verifiedHeadAuthorityV2{
		head: cloneInviteProofValue(bundle.RecordHead), currentSet: cloneInviteProofValue(currentSet),
	})
	return VerifiedInviteProofV2{recordHash: recordHash, head: cloneInviteProofValue(bundle.RecordHead),
		controlSet: cloneInviteProofValue(currentSet), recoveryPolicy: cloneInviteProofValue(currentPolicy),
		transitionHashes: append([]string(nil), transitionHashes...), authorities: authorities}, nil
}

func cloneInviteProofValue[T any](value T) T {
	body, _ := MarshalCanonical(value)
	var clone T
	_, _ = DecodeStrict(body, 64<<20, &clone)
	return clone
}
