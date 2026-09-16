package wire

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"time"
)

const (
	DomainRecoveryCustodyProposal         = "loom-recovery-custody-proposal-id-v1"
	DomainRecoveryCustodyArtifact         = "loom-recovery-custody-artifact-v1"
	DomainRecoveryCustodyReceipt          = "loom-recovery-custody-availability-receipt-v1"
	DomainRecoveryCustodyReceiptSignature = "loom-recovery-custody-availability-signature-v1"
	DomainRecoveryCustodyKeyTest          = "loom-recovery-custody-key-test-v1"
	DomainRecoveryCustodyBinding          = "loom-recovery-custody-binding-v1"
)

type RecoveryCustodianRefV1 struct {
	CustodianID         string                       `json:"custodian_id"`
	ReceiptKeyAlgorithm string                       `json:"receipt_key_algorithm"`
	ReceiptKeyID        string                       `json:"receipt_key_id"`
	ReceiptPublicKey    string                       `json:"receipt_public_key"`
	RecipientKey        *SealedBlobRecipientKeyRefV1 `json:"recipient_key,omitempty"`
	FaultDomain         string                       `json:"fault_domain"`
}

type RecoveryKeyCustodyArtifactV1 struct {
	Schema                   int                      `json:"schema"`
	ClusterID                string                   `json:"cluster_id"`
	PolicyID                 string                   `json:"policy_id"`
	PolicyGeneration         int64                    `json:"policy_generation"`
	KeyID                    string                   `json:"key_id"`
	PublicKey                string                   `json:"public_key"`
	HidingNonce              string                   `json:"hiding_nonce"`
	KeyArtifactRef           SecretArtifactRefV2      `json:"key_artifact_ref"`
	Custodians               []RecoveryCustodianRefV1 `json:"custodians"`
	RequiredReceiptCount     int64                    `json:"required_receipt_count"`
	RequiredFaultDomainCount int64                    `json:"required_fault_domain_count"`
	MaxReceiptAgeSeconds     int64                    `json:"max_receipt_age_seconds"`
}

type RecoveryKeyCustodyAvailabilityReceiptBodyV1 struct {
	Schema                   int                          `json:"schema"`
	ClusterID                string                       `json:"cluster_id"`
	PolicyID                 string                       `json:"policy_id"`
	PolicyGeneration         int64                        `json:"policy_generation"`
	KeyID                    string                       `json:"key_id"`
	CustodyArtifactHash      string                       `json:"custody_artifact_hash"`
	CustodianID              string                       `json:"custodian_id"`
	RecipientKey             *SealedBlobRecipientKeyRefV1 `json:"recipient_key,omitempty"`
	ArtifactOrVersionDigest  string                       `json:"artifact_or_version_digest"`
	ObservedAt               string                       `json:"observed_at"`
	RecoveryKeyTestSignature string                       `json:"recovery_key_test_signature"`
}

type RecoveryKeyCustodyAvailabilityReceiptV1 struct {
	Body                RecoveryKeyCustodyAvailabilityReceiptBodyV1 `json:"body"`
	ReceiptKeyAlgorithm string                                      `json:"receipt_key_algorithm"`
	ReceiptKeyID        string                                      `json:"receipt_key_id"`
	ReceiptSignature    string                                      `json:"receipt_signature"`
}

type RecoveryKeyCustodyAvailabilityLeafV1 struct {
	Schema      int    `json:"schema"`
	CustodianID string `json:"custodian_id"`
	ReceiptHash string `json:"receipt_hash"`
}

type RecoveryKeyCustodyBindingV1 struct {
	Schema                   int                                       `json:"schema"`
	Artifact                 RecoveryKeyCustodyArtifactV1              `json:"artifact"`
	CustodyArtifactHash      string                                    `json:"custody_artifact_hash"`
	AvailabilityReceipts     []RecoveryKeyCustodyAvailabilityReceiptV1 `json:"availability_receipts"`
	AvailabilityReceiptsRoot string                                    `json:"availability_receipts_root"`
}

type RecoveryKeyCustodyLeafV1 struct {
	Schema             int    `json:"schema"`
	KeyID              string `json:"key_id"`
	CustodyBindingHash string `json:"custody_binding_hash"`
}

// 该对象只进入控制私有日志。公开 policy 和客户端证明只包含 root。
type RecoveryPrivateCustodyObjectV1 struct {
	Schema                int                           `json:"schema"`
	ClusterID             string                        `json:"cluster_id"`
	PolicyID              string                        `json:"policy_id"`
	PolicyGeneration      int64                         `json:"policy_generation"`
	Bindings              []RecoveryKeyCustodyBindingV1 `json:"bindings"`
	PrivateKeyCustodyRoot string                        `json:"private_key_custody_root"`
}

func RecoveryCustodyProposalID(clusterID, policyID string, generation int64) (string, error) {
	if !validIdentifier(clusterID, 128) || !validIdentifier(policyID, 128) || generation < 1 {
		return "", errors.New("[恢复密钥保管] policy 标识无效")
	}
	return HashObject(DomainRecoveryCustodyProposal, struct {
		Schema           int    `json:"schema"`
		ClusterID        string `json:"cluster_id"`
		PolicyID         string `json:"policy_id"`
		PolicyGeneration int64  `json:"policy_generation"`
	}{1, clusterID, policyID, generation})
}

func ValidateRecoveryCustodyArtifact(artifact *RecoveryKeyCustodyArtifactV1) error {
	if artifact == nil || artifact.Schema != 1 || artifact.RequiredReceiptCount < 1 ||
		artifact.RequiredReceiptCount > int64(len(artifact.Custodians)) || artifact.RequiredFaultDomainCount < 1 ||
		artifact.RequiredFaultDomainCount > artifact.RequiredReceiptCount || artifact.MaxReceiptAgeSeconds < 1 {
		return errors.New("[恢复密钥保管] artifact 或回执门槛无效")
	}
	proposal, err := RecoveryCustodyProposalID(artifact.ClusterID, artifact.PolicyID, artifact.PolicyGeneration)
	if err != nil {
		return err
	}
	if _, err := decodeRawURL(artifact.HidingNonce, 32); err != nil {
		return err
	}
	public, err := decodeRawURL(artifact.PublicKey, ed25519.PublicKeySize)
	keyID, _ := ControlKeyID(public)
	if err != nil || keyID != artifact.KeyID {
		return errors.New("[恢复密钥保管] key ID 与原始公钥不匹配")
	}
	ref := &artifact.KeyArtifactRef
	if err := ValidateSecretArtifactRef(ref); err != nil {
		return err
	}
	owner := ref.Owner.RecoveryPolicy
	if ref.ClusterID != artifact.ClusterID || ref.ProposalID != proposal || ref.SecretID != artifact.KeyID ||
		ref.Purpose != "recovery_private_key" || owner == nil || owner.PolicyID != artifact.PolicyID ||
		owner.PolicyGeneration != artifact.PolicyGeneration || owner.KeyID != artifact.KeyID ||
		ref.BackendKind != "sealed_blob" || ref.SealedBlob == nil || ref.ImmutableRef != "sealed:"+ref.SealedBlob.CiphertextDigest {
		return errors.New("[恢复密钥保管] 封装引用未绑定 exact policy/key/ciphertext")
	}
	parsed, err := ParseAuthorityProofKey(ref.PublicKey)
	spkiPublic, ok := parsed.(ed25519.PublicKey)
	if err != nil || !ok || !bytes.Equal(spkiPublic, public) {
		return errors.New("[恢复密钥保管] SPKI 与 recovery 原始公钥不同")
	}
	if len(artifact.Custodians) != len(ref.SealedBlob.RecipientKeyVersions) {
		return errors.New("[恢复密钥保管] 保管人和解封接收者须一一对应")
	}
	receiptKeys, domains, recipients := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for i, custodian := range artifact.Custodians {
		public, err := decodeRawURL(custodian.ReceiptPublicKey, ed25519.PublicKeySize)
		id, _ := ControlKeyID(public)
		if err != nil || !validIdentifier(custodian.CustodianID, 128) || !validIdentifier(custodian.FaultDomain, 128) ||
			custodian.ReceiptKeyAlgorithm != "ed25519" || custodian.ReceiptKeyID != id ||
			i > 0 && artifact.Custodians[i-1].CustodianID >= custodian.CustodianID ||
			receiptKeys[id] || domains[custodian.FaultDomain] || custodian.RecipientKey == nil ||
			!recipientPresent(ref.SealedBlob.RecipientKeyVersions, custodian.RecipientKey) || recipients[custodian.RecipientKey.RecipientKeyID] {
			return errors.New("[恢复密钥保管] 保管人、回执密钥、故障域或解封接收者无效/重复")
		}
		receiptKeys[id], domains[custodian.FaultDomain], recipients[custodian.RecipientKey.RecipientKeyID] = true, true, true
	}
	return nil
}

func RecoveryCustodyArtifactHash(artifact *RecoveryKeyCustodyArtifactV1) (string, error) {
	if err := ValidateRecoveryCustodyArtifact(artifact); err != nil {
		return "", err
	}
	return HashObject(DomainRecoveryCustodyArtifact, artifact)
}

func recoveryCustodyKeyTestMessage(artifactHash, custodianID, observedAt string) ([]byte, error) {
	if _, err := ParseHash(artifactHash); err != nil {
		return nil, err
	}
	if !validIdentifier(custodianID, 128) {
		return nil, errors.New("[恢复密钥保管] 保管人标识无效")
	}
	if _, err := ParseTimeZ(observedAt); err != nil {
		return nil, err
	}
	canonical, err := MarshalCanonical(struct {
		Schema              int    `json:"schema"`
		CustodyArtifactHash string `json:"custody_artifact_hash"`
		CustodianID         string `json:"custodian_id"`
		ObservedAt          string `json:"observed_at"`
	}{1, artifactHash, custodianID, observedAt})
	if err != nil {
		return nil, err
	}
	return Frame(DomainRecoveryCustodyKeyTest, canonical)
}

// 调用方必须从实际保管介质读回并解封 recoveryKey；这里同时绑定密钥测试和回执签名。
func NewRecoveryCustodyReceipt(artifact *RecoveryKeyCustodyArtifactV1, custodianID string,
	recoveryKey, receiptKey ed25519.PrivateKey, observedAt time.Time) (RecoveryKeyCustodyAvailabilityReceiptV1, error) {
	var result RecoveryKeyCustodyAvailabilityReceiptV1
	hash, err := RecoveryCustodyArtifactHash(artifact)
	if err != nil {
		return result, err
	}
	if len(recoveryKey) != ed25519.PrivateKeySize || len(receiptKey) != ed25519.PrivateKeySize ||
		observedAt.IsZero() || observedAt != observedAt.UTC().Truncate(time.Second) ||
		base64.RawURLEncoding.EncodeToString(recoveryKey.Public().(ed25519.PublicKey)) != artifact.PublicKey {
		return result, errors.New("[恢复密钥保管] 解封密钥或回执时间无效")
	}
	var custodian *RecoveryCustodianRefV1
	for i := range artifact.Custodians {
		if artifact.Custodians[i].CustodianID == custodianID {
			custodian = &artifact.Custodians[i]
		}
	}
	if custodian == nil || base64.RawURLEncoding.EncodeToString(receiptKey.Public().(ed25519.PublicKey)) != custodian.ReceiptPublicKey {
		return result, errors.New("[恢复密钥保管] 回执签名人不属于当前保管人")
	}
	at := observedAt.Format(time.RFC3339)
	message, err := recoveryCustodyKeyTestMessage(hash, custodianID, at)
	if err != nil {
		return result, err
	}
	result.Body = RecoveryKeyCustodyAvailabilityReceiptBodyV1{Schema: 1, ClusterID: artifact.ClusterID,
		PolicyID: artifact.PolicyID, PolicyGeneration: artifact.PolicyGeneration, KeyID: artifact.KeyID,
		CustodyArtifactHash: hash, CustodianID: custodianID, RecipientKey: custodian.RecipientKey,
		ArtifactOrVersionDigest: artifact.KeyArtifactRef.SealedBlob.CiphertextDigest, ObservedAt: at,
		RecoveryKeyTestSignature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(recoveryKey, message))}
	canonical, err := MarshalCanonical(result.Body)
	if err != nil {
		return result, err
	}
	message, err = Frame(DomainRecoveryCustodyReceiptSignature, canonical)
	if err != nil {
		return result, err
	}
	result.ReceiptKeyAlgorithm, result.ReceiptKeyID = "ed25519", custodian.ReceiptKeyID
	result.ReceiptSignature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(receiptKey, message))
	return result, nil
}

func NewRecoveryCustodyBinding(artifact RecoveryKeyCustodyArtifactV1, receipts []RecoveryKeyCustodyAvailabilityReceiptV1) (RecoveryKeyCustodyBindingV1, error) {
	hash, err := RecoveryCustodyArtifactHash(&artifact)
	if err != nil {
		return RecoveryKeyCustodyBindingV1{}, err
	}
	root, err := recoveryCustodyReceiptRoot(receipts)
	if err != nil {
		return RecoveryKeyCustodyBindingV1{}, err
	}
	binding := RecoveryKeyCustodyBindingV1{1, artifact, hash, receipts, root}
	return binding, validateRecoveryCustodyBinding(&binding)
}

func recoveryCustodyReceiptRoot(receipts []RecoveryKeyCustodyAvailabilityReceiptV1) (string, error) {
	leaves := make([][]byte, len(receipts))
	for i, receipt := range receipts {
		if i > 0 && receipts[i-1].Body.CustodianID >= receipt.Body.CustodianID {
			return "", errors.New("[恢复密钥保管] 回执必须按保管人唯一排序")
		}
		hash, err := HashObject(DomainRecoveryCustodyReceipt, receipt)
		if err != nil {
			return "", err
		}
		leaves[i], err = MarshalCanonical(RecoveryKeyCustodyAvailabilityLeafV1{1, receipt.Body.CustodianID, hash})
		if err != nil {
			return "", err
		}
	}
	return fmt.Sprintf("sha256:%x", MerkleRoot(leaves)), nil
}

func validateRecoveryCustodyBinding(binding *RecoveryKeyCustodyBindingV1) error {
	if binding == nil || binding.Schema != 1 {
		return errors.New("[恢复密钥保管] binding 缺失")
	}
	artifact := &binding.Artifact
	hash, err := RecoveryCustodyArtifactHash(artifact)
	if err != nil {
		return err
	}
	if hash != binding.CustodyArtifactHash || int64(len(binding.AvailabilityReceipts)) < artifact.RequiredReceiptCount {
		return errors.New("[恢复密钥保管] artifact hash 或回执数不足")
	}
	public, _ := decodeRawURL(artifact.PublicKey, ed25519.PublicKeySize)
	domains := map[string]bool{}
	for _, receipt := range binding.AvailabilityReceipts {
		body := &receipt.Body
		var custodian *RecoveryCustodianRefV1
		for i := range artifact.Custodians {
			if artifact.Custodians[i].CustodianID == body.CustodianID {
				custodian = &artifact.Custodians[i]
			}
		}
		if custodian == nil || body.Schema != 1 || body.ClusterID != artifact.ClusterID || body.PolicyID != artifact.PolicyID ||
			body.PolicyGeneration != artifact.PolicyGeneration || body.KeyID != artifact.KeyID || body.CustodyArtifactHash != hash ||
			body.ArtifactOrVersionDigest != artifact.KeyArtifactRef.SealedBlob.CiphertextDigest ||
			body.RecipientKey == nil || !EqualCanonical(body.RecipientKey, custodian.RecipientKey) ||
			receipt.ReceiptKeyAlgorithm != custodian.ReceiptKeyAlgorithm || receipt.ReceiptKeyID != custodian.ReceiptKeyID {
			return errors.New("[恢复密钥保管] 回执没有绑定 exact artifact/custodian/recipient")
		}
		message, err := recoveryCustodyKeyTestMessage(hash, body.CustodianID, body.ObservedAt)
		signature, sigErr := decodeRawURL(body.RecoveryKeyTestSignature, ed25519.SignatureSize)
		if err != nil || sigErr != nil || !ed25519.Verify(public, message, signature) {
			return errors.New("[恢复密钥保管] 解封签名测试无效")
		}
		canonical, err := MarshalCanonical(body)
		if err != nil {
			return err
		}
		message, err = Frame(DomainRecoveryCustodyReceiptSignature, canonical)
		if err != nil {
			return err
		}
		receiptPublic, _ := decodeRawURL(custodian.ReceiptPublicKey, ed25519.PublicKeySize)
		signature, err = decodeRawURL(receipt.ReceiptSignature, ed25519.SignatureSize)
		if err != nil || !ed25519.Verify(receiptPublic, message, signature) {
			return errors.New("[恢复密钥保管] 保管人签名无效")
		}
		domains[custodian.FaultDomain] = true
	}
	root, err := recoveryCustodyReceiptRoot(binding.AvailabilityReceipts)
	if err != nil || root != binding.AvailabilityReceiptsRoot || int64(len(domains)) < artifact.RequiredFaultDomainCount {
		return errors.New("[恢复密钥保管] 回执树或独立故障域门槛不符")
	}
	return nil
}

func RecoveryPrivateCustodyRoot(bindings []RecoveryKeyCustodyBindingV1) (string, error) {
	if len(bindings) == 0 {
		return "", errors.New("[恢复密钥保管] 保管证明为空")
	}
	leaves := make([][]byte, len(bindings))
	for i := range bindings {
		binding := &bindings[i]
		if err := validateRecoveryCustodyBinding(binding); err != nil {
			return "", err
		}
		if i > 0 && bindings[i-1].Artifact.KeyID >= binding.Artifact.KeyID {
			return "", errors.New("[恢复密钥保管] bindings 必须按 key ID 唯一排序")
		}
		hash, err := HashObject(DomainRecoveryCustodyBinding, binding)
		if err != nil {
			return "", err
		}
		leaves[i], err = MarshalCanonical(RecoveryKeyCustodyLeafV1{1, binding.Artifact.KeyID, hash})
		if err != nil {
			return "", err
		}
	}
	return fmt.Sprintf("sha256:%x", MerkleRoot(leaves)), nil
}

// 结构、密码学与 root 验证适用于已提交历史；新提交另以实际提交时间验证新鲜度。
func ValidateRecoveryPrivateCustody(policy *RecoveryPolicyV1, object *RecoveryPrivateCustodyObjectV1) error {
	if err := ValidateRecoveryPolicy(policy); err != nil {
		return err
	}
	if object == nil || object.Schema != 1 || object.ClusterID != policy.ClusterID || object.PolicyID != policy.PolicyID ||
		object.PolicyGeneration != policy.Generation || len(object.Bindings) != len(policy.Keys) {
		return errors.New("[恢复密钥保管] 私有同行对象未覆盖 policy")
	}
	for i, binding := range object.Bindings {
		artifact, key := binding.Artifact, policy.Keys[i]
		if artifact.ClusterID != policy.ClusterID || artifact.PolicyID != policy.PolicyID || artifact.PolicyGeneration != policy.Generation ||
			artifact.KeyID != key.KeyID || artifact.PublicKey != key.PublicKey {
			return errors.New("[恢复密钥保管] 私有同行对象替换了 policy key")
		}
	}
	root, err := RecoveryPrivateCustodyRoot(object.Bindings)
	if err != nil {
		return err
	}
	if root != object.PrivateKeyCustodyRoot || root != policy.PrivateKeyCustodyRoot {
		return errors.New("[恢复密钥保管] 私有保管树与公开承诺不符")
	}
	return nil
}

func VerifyRecoveryPrivateCustody(policy *RecoveryPolicyV1, object *RecoveryPrivateCustodyObjectV1, candidateTime time.Time, maximumClockSkew time.Duration) error {
	if err := ValidateRecoveryPrivateCustody(policy, object); err != nil {
		return err
	}
	if candidateTime.IsZero() || maximumClockSkew < 0 {
		return errors.New("[恢复密钥保管] 缺实际候选提交时间")
	}
	for _, binding := range object.Bindings {
		for _, receipt := range binding.AvailabilityReceipts {
			at, err := ParseTimeZ(receipt.Body.ObservedAt)
			if err != nil || !receiptTimeValid(at, candidateTime, maximumClockSkew, binding.Artifact.MaxReceiptAgeSeconds) {
				return errors.New("[恢复密钥保管] 回执过期或来自未来")
			}
		}
	}
	return nil
}
