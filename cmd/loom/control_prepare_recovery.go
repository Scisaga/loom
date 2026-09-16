package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"loom/internal/enrollmentv2"
	"loom/internal/wire"
)

type controlRecoveryMaterialV1 struct {
	Schema  int                                 `json:"schema"`
	Policy  wire.RecoveryPolicyV1               `json:"policy"`
	Custody wire.RecoveryPrivateCustodyObjectV1 `json:"custody"`
	Proofs  []wire.RecoveryKeyPossessionProofV1 `json:"proofs"`
}

// 独立保管目录不归 daemon 管理；控制日志只取得公钥、密文引用和签名证明。
// 此命令不接触 control state，不生成或替换原网络 authority。
func cmdControlPrepareRecovery(args []string) error {
	flags := flag.NewFlagSet("control prepare-recovery", flag.ContinueOnError)
	dir := flags.String("custody-dir", "", "与 control state 分离的受保护恢复材料目录")
	cluster := flags.String("cluster-id", "", "原网络 cluster ID")
	policy := flags.String("policy-id", "", "固定的 recovery policy ID")
	custodian := flags.String("custodian-id", "", "本次独立保管人标识")
	request := flags.String("request-id", "", "固定的回执请求 ID；刷新须使用新 ID")
	out := flags.String("out", "", "不含解封私钥的迁移输入文件")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *dir == "" || *cluster == "" || *policy == "" || *custodian == "" || *request == "" || *out == "" {
		return errors.New("prepare-recovery 必须指定 custody-dir、cluster-id、policy-id、custodian-id、request-id 和 out")
	}
	parent, err := os.Lstat(filepath.Dir(*out))
	if err != nil || !parent.IsDir() || parent.Mode().Perm() != 0o700 || parent.Mode()&os.ModeSymlink != 0 {
		return errors.New("恢复公开材料输出须位于已有 0700 实体目录")
	}
	prepared, err := prepareControlRecovery(*dir, *cluster, *policy, *custodian, *request, time.Now().UTC().Truncate(time.Second))
	if err != nil {
		return err
	}
	var existing controlRecoveryMaterialV1
	if err := readCanonicalFile(*out, 8<<20, &existing); err == nil {
		if !wire.EqualCanonical(existing, prepared) {
			return errors.New("恢复材料输出已绑定不同回执，不允许覆盖")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	} else if err := writeCanonicalAtomic(*out, prepared, 0o600); err != nil {
		return err
	}
	fmt.Println("✓ 独立恢复密钥已耐久封装并完成解封签名；公开证明已生成，尚未激活")
	return nil
}

func prepareControlRecovery(dir, clusterID, policyID, custodianID, requestID string, at time.Time) (controlRecoveryMaterialV1, error) {
	var result controlRecoveryMaterialV1
	proposal, err := wire.RecoveryCustodyProposalID(clusterID, policyID, 1)
	if err != nil {
		return result, err
	}
	if requestID == "" || len(requestID) > 128 || at.IsZero() || at != at.UTC().Truncate(time.Second) {
		return result, errors.New("恢复材料缺固定请求 ID 或规范时间")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return result, err
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 || info.Mode()&os.ModeSymlink != 0 {
		return result, errors.New("恢复材料目录必须是 0700 实体目录")
	}
	unlock, err := lockControlState(dir)
	if err != nil {
		return result, err
	}
	defer unlock()
	// 存储格式可复用软件封装器，但使用独立目录、独立 wrapping/reporter/recovery 三把 key。
	path := filepath.Join(dir, "recovery-key-artifact.json")
	_, artifactErr := os.Lstat(path)
	if artifactErr != nil && !errors.Is(artifactErr, os.ErrNotExist) {
		return result, artifactErr
	}
	material, err := openControlSoftwareMaterial(dir, custodianID, errors.Is(artifactErr, os.ErrNotExist))
	if err != nil {
		return result, err
	}
	defer material.Close()
	recipient, err := material.recipient()
	if err != nil {
		return result, err
	}
	var evidence enrollmentv2.SealedMaterialEvidenceV1
	if err := readCanonicalFile(path, 4<<20, &evidence); errors.Is(err, os.ErrNotExist) {
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return result, err
		}
		defer clear(private)
		keyID, _ := wire.ControlKeyID(public)
		secret, err := x509.MarshalPKCS8PrivateKey(private)
		if err != nil {
			return result, err
		}
		defer clear(secret)
		sealing := wire.P256RootOnlySealingPolicyV1()
		recipients := []wire.SealedBlobRecipientKeyRefV1{recipient}
		context, err := wire.NewSealedSecretContext(clusterID, proposal, keyID, "recovery_private_key",
			wire.SecretArtifactOwnerV1{Kind: "recovery_policy", RecoveryPolicy: &wire.SecretArtifactRecoveryOwnerV1{PolicyID: policyID, PolicyGeneration: 1, KeyID: keyID}},
			1, &sealing, recipients)
		if err != nil {
			return result, err
		}
		availability, err := material.availabilityPolicy(clusterID)
		if err != nil {
			return result, err
		}
		evidence, err = enrollmentv2.CreateLocalSealedMaterial(material.store, context, sealing, recipients, secret, private, availability, custodianID, material.reporter, at, rand.Reader)
		if err != nil {
			return result, err
		}
		if err := writeCanonicalAtomic(path, evidence, 0o600); err != nil {
			return result, err
		}
	} else if err != nil {
		return result, err
	}
	// 所有后续操作从磁盘回读，不能用刚生成但没有耐久保存的 key 签可用性回执。
	if err := readCanonicalFile(path, 4<<20, &evidence); err != nil {
		return result, err
	}
	ref, owner := &evidence.Ref, evidence.Ref.Owner.RecoveryPolicy
	if ref.ClusterID != clusterID || ref.ProposalID != proposal || ref.Purpose != "recovery_private_key" ||
		owner == nil || owner.PolicyID != policyID || owner.PolicyGeneration != 1 || ref.SealedBlob == nil ||
		len(ref.SealedBlob.RecipientKeyVersions) != 1 || !wire.EqualCanonical(ref.SealedBlob.RecipientKeyVersions[0], recipient) || len(evidence.Receipts) != 1 {
		return result, errors.New("恢复材料目录已绑定不同网络、策略或保管人")
	}
	created, err := wire.ParseTimeZ(evidence.Receipts[0].Body.ObservedAt)
	if err != nil {
		return result, err
	}
	if err := wire.VerifySecretArtifactEvidence(ref, evidence.Proof, &evidence.Policy, evidence.Receipts, created, 0, ""); err != nil {
		return result, err
	}
	envelope, err := material.store.Get(ref.SealedBlob.CiphertextDigest)
	if err != nil {
		return result, err
	}
	if err := wire.VerifySealedSecretBinding(ref, &envelope); err != nil {
		return result, err
	}
	plaintext, err := wire.UnsealSecretP256(&envelope, recipient, material.wrapping)
	if err != nil {
		return result, err
	}
	defer clear(plaintext)
	parsed, err := x509.ParsePKCS8PrivateKey(plaintext)
	private, ok := parsed.(ed25519.PrivateKey)
	if err != nil || !ok {
		return result, errors.New("恢复介质解封后不是 Ed25519 私钥")
	}
	defer clear(private)
	key, err := enrollmentv2.MaterialAuthorityKey(private.Public())
	if err != nil || ref.PublicKey == nil || !wire.EqualCanonical(key, *ref.PublicKey) {
		return result, errors.New("恢复介质中的私钥与 exact SPKI 不同")
	}
	public := private.Public().(ed25519.PublicKey)
	keyID, _ := wire.ControlKeyID(public)
	if keyID != owner.KeyID || keyID != ref.SecretID {
		return result, errors.New("恢复介质没有保留同一 recovery key")
	}
	requestHash := wire.HashRaw("loom-recovery-custody-request-v1", []byte(requestID))
	requests := filepath.Join(dir, "receipts")
	if err := os.MkdirAll(requests, 0o700); err != nil {
		return result, err
	}
	requestPath := filepath.Join(requests, requestHash[len("sha256:"):]+".json")
	if err := readCanonicalFile(requestPath, 8<<20, &result); err == nil {
		if result.Schema != 1 || result.Policy.ClusterID != clusterID || result.Policy.PolicyID != policyID ||
			len(result.Policy.Keys) != 1 || result.Policy.Keys[0].KeyID != keyID || len(result.Custody.Bindings) != 1 ||
			!wire.EqualCanonical(result.Custody.Bindings[0].Artifact.KeyArtifactRef, *ref) {
			return result, errors.New("恢复回执请求已绑定不同材料")
		}
		if _, err := wire.RecoveryKeyPossessionRoot(&result.Policy, result.Proofs); err != nil {
			return result, err
		}
		// 同一请求只返回原回执，过期时调用者显式用新 request ID 刷新，密钥不改变。
		return result, wire.ValidateRecoveryPrivateCustody(&result.Policy, &result.Custody)
	} else if !errors.Is(err, os.ErrNotExist) {
		return result, err
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return result, err
	}
	receiptPublic := material.reporter.Public().(ed25519.PublicKey)
	if bytes.Equal(receiptPublic, public) {
		return result, errors.New("恢复密钥不能兼任保管回执密钥")
	}
	receiptKeyID, _ := wire.ControlKeyID(receiptPublic)
	artifact := wire.RecoveryKeyCustodyArtifactV1{Schema: 1, ClusterID: clusterID, PolicyID: policyID, PolicyGeneration: 1,
		KeyID: keyID, PublicKey: base64.RawURLEncoding.EncodeToString(public), HidingNonce: base64.RawURLEncoding.EncodeToString(nonce), KeyArtifactRef: *ref,
		Custodians: []wire.RecoveryCustodianRefV1{{CustodianID: custodianID, ReceiptKeyAlgorithm: "ed25519", ReceiptKeyID: receiptKeyID,
			ReceiptPublicKey: base64.RawURLEncoding.EncodeToString(receiptPublic), RecipientKey: &recipient, FaultDomain: custodianID}},
		RequiredReceiptCount: 1, RequiredFaultDomainCount: 1, MaxReceiptAgeSeconds: 900}
	receipt, err := wire.NewRecoveryCustodyReceipt(&artifact, custodianID, private, material.reporter, at)
	if err != nil {
		return result, err
	}
	binding, err := wire.NewRecoveryCustodyBinding(artifact, []wire.RecoveryKeyCustodyAvailabilityReceiptV1{receipt})
	if err != nil {
		return result, err
	}
	bindings := []wire.RecoveryKeyCustodyBindingV1{binding}
	root, err := wire.RecoveryPrivateCustodyRoot(bindings)
	if err != nil {
		return result, err
	}
	result = controlRecoveryMaterialV1{Schema: 1,
		Policy: wire.RecoveryPolicyV1{Schema: 1, ClusterID: clusterID, PolicyID: policyID, Generation: 1, Algorithm: "ed25519-multisig-v1",
			Keys: []wire.RecoveryPolicyKeyV1{{KeyID: keyID, Algorithm: "ed25519", PublicKey: artifact.PublicKey}}, Threshold: 1,
			PrivateKeyCustodyRoot: root, CeremonyProfile: "offline-independent-keys-v1"},
		Custody: wire.RecoveryPrivateCustodyObjectV1{Schema: 1, ClusterID: clusterID, PolicyID: policyID, PolicyGeneration: 1, Bindings: bindings, PrivateKeyCustodyRoot: root}}
	proof, err := wire.NewRecoveryKeyPossessionProof(wire.RecoveryKeyPossessionProofBodyV1{Schema: 1, ClusterID: clusterID,
		PolicyID: policyID, PolicyGeneration: 1, KeyID: keyID, PublicKey: artifact.PublicKey}, private)
	if err != nil {
		return result, err
	}
	result.Proofs = []wire.RecoveryKeyPossessionProofV1{proof}
	if err := wire.VerifyRecoveryPrivateCustody(&result.Policy, &result.Custody, at, 0); err != nil {
		return result, err
	}
	if err := writeCanonicalAtomic(requestPath, result, 0o600); err != nil {
		return result, err
	}
	return result, nil
}
