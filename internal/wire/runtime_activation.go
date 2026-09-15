package wire

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
)

const (
	DomainLegacyRuntimePolicy                = "loom-runtime-recovery-policy-v1"
	DomainRuntimeActivationStatement         = "loom-runtime-activation-statement-v1"
	DomainRuntimeActivationProof             = "loom-runtime-activation-proof-v1"
	DomainRuntimeActivationOwnerSignature    = "loom-runtime-activation-owner-signature-v1"
	DomainRuntimeActivationPlatformSignature = "loom-runtime-activation-platform-signature-v1"
)

// LegacyRuntimePolicyV1 是早期 N=1 daemon 已承诺的原始 preimage，不能冒充
// RecoveryPolicyV1，也不能由普通管理 operation 修改（D104、D119）。
type LegacyRuntimePolicyV1 struct {
	Schema    int    `json:"schema"`
	AdminRoot string `json:"admin_root"`
}

// RuntimeActivationRootsV1 承诺完成迁移后的实际状态；daemon 必须从保留的
// SSOT、Device 身份和新 profile preimage 独立重算，不能只接受这些哈希（D104）。
type RuntimeActivationRootsV1 struct {
	SnapshotHash                string `json:"snapshot_hash"`
	EffectiveSSOTHash           string `json:"effective_ssot_hash"`
	DeviceViewsRoot             string `json:"device_views_root"`
	AdminACLRoot                string `json:"admin_acl_root"`
	CAProfileRoot               string `json:"ca_profile_root"`
	BootstrapIssuerRegistryRoot string `json:"bootstrap_issuer_registry_root"`
	RenderContractVersion       int64  `json:"render_contract_version"`
}

type RuntimeActivationStatementV1 struct {
	Schema                   int                      `json:"schema"`
	ClusterID                string                   `json:"cluster_id"`
	OperationID              string                   `json:"operation_id"`
	ParentHeadHash           string                   `json:"parent_head_hash"`
	ParentQCHash             string                   `json:"parent_qc_hash"`
	LegacyRecoveryPolicyHash string                   `json:"legacy_recovery_policy_hash"`
	V1PlatformKeyID          string                   `json:"v1_platform_key_id"`
	V1PlatformPublicKey      string                   `json:"v1_platform_public_key"`
	V1PlatformKeyDigest      string                   `json:"v1_platform_key_digest"`
	NewRecoveryEpoch         int64                    `json:"new_recovery_epoch"`
	NewRecoveryPolicyHash    string                   `json:"new_recovery_policy_hash"`
	NewRecoveryKeyPoPRoot    string                   `json:"new_recovery_key_pop_root"`
	Roots                    RuntimeActivationRootsV1 `json:"roots"`
	IssuedAt                 string                   `json:"issued_at"`
	Reason                   string                   `json:"reason"`
}

type RuntimeActivationProofV1 struct {
	Schema            int                          `json:"schema"`
	Statement         RuntimeActivationStatementV1 `json:"statement"`
	LegacyPolicy      LegacyRuntimePolicyV1        `json:"legacy_policy"`
	OwnerSignature    string                       `json:"owner_signature"`
	PlatformSignature string                       `json:"platform_signature"`
}

type RuntimeActivationContextV1 struct {
	Schema        int    `json:"schema"`
	Kind          string `json:"kind"`
	StatementHash string `json:"statement_hash"`
}

// RuntimeActivationBundleV1 是一次性旧 daemon 迁移的公开证明。它沿用原
// ControlSet、日志和身份，追加 Head；绝不生成另一个 index=1 的 bootstrap。
// 其中只有公钥、状态承诺和 opaque operation leaves，没有 SSOT/Device/ACL preimage。
type RuntimeActivationBundleV1 struct {
	Schema                      int                            `json:"schema"`
	Proof                       RuntimeActivationProofV1       `json:"proof"`
	Parent                      HeadEntryV2                    `json:"parent"`
	ParentQC                    StableHeadReplicationQCV1      `json:"parent_qc"`
	ControlSet                  ControlSetV1                   `json:"control_set"`
	RecoveryPolicy              RecoveryPolicyV1               `json:"recovery_policy"`
	RecoveryKeyPossessionProofs []RecoveryKeyPossessionProofV1 `json:"recovery_key_possession_proofs"`
	PreviousOperationLeaves     []ControlOperationLeafV1       `json:"previous_operation_leaves"`
	Head                        HeadEntryV2                    `json:"head"`
	ConfigQC                    StableHeadReplicationQCV1      `json:"config_qc"`
}

func RuntimeActivationStatementHash(statement *RuntimeActivationStatementV1) (string, error) {
	if statement == nil || statement.Schema != 1 || !validIdentifier(statement.ClusterID, 128) ||
		!validIdentifier(statement.OperationID, 128) || !validIdentifier(statement.V1PlatformKeyID, 256) ||
		statement.NewRecoveryEpoch != 2 || statement.Roots.RenderContractVersion < 2 ||
		statement.Reason == "" || len(statement.Reason) > 512 {
		return "", errors.New("[D104 runtime activation] statement header 无效")
	}
	if _, err := ParseTimeZ(statement.IssuedAt); err != nil {
		return "", err
	}
	if err := requireCanonicalHashes(statement.ParentHeadHash, statement.ParentQCHash,
		statement.LegacyRecoveryPolicyHash, statement.V1PlatformKeyDigest, statement.NewRecoveryPolicyHash,
		statement.NewRecoveryKeyPoPRoot, statement.Roots.SnapshotHash, statement.Roots.EffectiveSSOTHash,
		statement.Roots.DeviceViewsRoot, statement.Roots.AdminACLRoot, statement.Roots.CAProfileRoot,
		statement.Roots.BootstrapIssuerRegistryRoot); err != nil {
		return "", err
	}
	public, err := decodeRawURL(statement.V1PlatformPublicKey, ed25519.PublicKeySize)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(public)
	if statement.V1PlatformKeyDigest != "sha256:"+hex.EncodeToString(digest[:]) {
		return "", errors.New("[D111 runtime activation] platform key digest 不一致")
	}
	return HashObject(DomainRuntimeActivationStatement, statement)
}

// SignRuntimeActivationProof 同时要求原始恢复根和既有 v1 平台私钥；当前 ping ACL
// 没有权限授予自己正式业务权限，不能只凭现任 control config key 签署迁移（D104）。
func SignRuntimeActivationProof(statement RuntimeActivationStatementV1, policy LegacyRuntimePolicyV1,
	ownerKey, platformKey ed25519.PrivateKey) (RuntimeActivationProofV1, error) {
	proof := RuntimeActivationProofV1{Schema: 1, Statement: statement, LegacyPolicy: policy}
	if len(ownerKey) != ed25519.PrivateKeySize || len(platformKey) != ed25519.PrivateKeySize {
		return RuntimeActivationProofV1{}, errors.New("[D104 runtime activation] signer key 无效")
	}
	if _, err := RuntimeActivationStatementHash(&statement); err != nil {
		return RuntimeActivationProofV1{}, err
	}
	canonical, _ := MarshalCanonical(statement)
	ownerMessage, _ := Frame(DomainRuntimeActivationOwnerSignature, canonical)
	platformMessage, _ := Frame(DomainRuntimeActivationPlatformSignature, canonical)
	proof.OwnerSignature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(ownerKey, ownerMessage))
	proof.PlatformSignature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(platformKey, platformMessage))
	if _, err := verifyRuntimeActivationProof(&proof); err != nil {
		return RuntimeActivationProofV1{}, err
	}
	return proof, nil
}

func verifyRuntimeActivationProof(proof *RuntimeActivationProofV1) (string, error) {
	if proof == nil || proof.Schema != 1 || proof.LegacyPolicy.Schema != 1 {
		return "", errors.New("[D104 runtime activation] proof header 无效")
	}
	if _, err := RuntimeActivationStatementHash(&proof.Statement); err != nil {
		return "", err
	}
	legacyHash, err := HashObject(DomainLegacyRuntimePolicy, proof.LegacyPolicy)
	if err != nil || legacyHash != proof.Statement.LegacyRecoveryPolicyHash {
		return "", errors.New("[D119 runtime activation] 原恢复根不匹配")
	}
	der, err := base64.RawURLEncoding.DecodeString(proof.LegacyPolicy.AdminRoot)
	if err != nil {
		return "", errors.New("[D119 runtime activation] 原恢复根编码无效")
	}
	root, err := x509.ParseCertificate(der)
	if err != nil || !root.IsCA || root.CheckSignatureFrom(root) != nil {
		return "", errors.New("[D119 runtime activation] 原恢复根证书无效")
	}
	owner, ok := root.PublicKey.(ed25519.PublicKey)
	if !ok {
		return "", errors.New("[D119 runtime activation] 不属于早期 Ed25519 恢复根")
	}
	platform, _ := decodeRawURL(proof.Statement.V1PlatformPublicKey, ed25519.PublicKeySize)
	canonical, _ := MarshalCanonical(proof.Statement)
	for _, signer := range []struct {
		domain, signature string
		public            ed25519.PublicKey
	}{
		{DomainRuntimeActivationOwnerSignature, proof.OwnerSignature, owner},
		{DomainRuntimeActivationPlatformSignature, proof.PlatformSignature, ed25519.PublicKey(platform)},
	} {
		message, _ := Frame(signer.domain, canonical)
		signature, err := decodeRawURL(signer.signature, ed25519.SignatureSize)
		if err != nil || !ed25519.Verify(signer.public, message, signature) {
			return "", errors.New("[D104 runtime activation] owner/platform signature 无效")
		}
	}
	return HashObject(DomainRuntimeActivationProof, proof)
}

// RuntimeActivationHeadBody 在原日志中构造唯一的 activation candidate。signature
// 绑定 parent 与状态，不绑定未提交的 Raft term；重启只可重定位同一未提交 candidate。
func RuntimeActivationHeadBody(bundle *RuntimeActivationBundleV1, raftTerm, raftIndex int64,
	previousLogHash, committedAt string) (HeadEntryBodyV2, error) {
	if bundle == nil || bundle.Schema != 1 || len(bundle.ControlSet.Members) != 1 {
		return HeadEntryBodyV2{}, errors.New("[D104 runtime activation] 仅支持原 N=1 迁移")
	}
	proofHash, err := verifyRuntimeActivationProof(&bundle.Proof)
	if err != nil {
		return HeadEntryBodyV2{}, err
	}
	statement, parent := &bundle.Proof.Statement, &bundle.Parent.Body.Payload
	if err := VerifyStableHeadQC(&bundle.Parent, &bundle.ControlSet, &bundle.ParentQC); err != nil {
		return HeadEntryBodyV2{}, err
	}
	qcRaw, _ := MarshalCanonical(bundle.ParentQC)
	qcHash, _ := ConfigQCHash(qcRaw)
	if parent.ClusterID != statement.ClusterID || bundle.Parent.HeadHash != statement.ParentHeadHash ||
		qcHash != statement.ParentQCHash || parent.RecoveryPolicyHash != statement.LegacyRecoveryPolicyHash ||
		parent.RecoveryEpoch != 1 || parent.ControlEpoch != 1 || parent.RenderContractVersion != 1 {
		return HeadEntryBodyV2{}, errors.New("[D104 runtime activation] 不是 exact 早期 authority")
	}
	policyHash, err := RecoveryPolicyHash(&bundle.RecoveryPolicy)
	if err != nil || bundle.RecoveryPolicy.ClusterID != parent.ClusterID || policyHash != statement.NewRecoveryPolicyHash {
		return HeadEntryBodyV2{}, errors.New("[D119 runtime activation] 正式 recovery policy 不一致")
	}
	popRoot, err := RecoveryKeyPossessionRoot(&bundle.RecoveryPolicy, bundle.RecoveryKeyPossessionProofs)
	if err != nil || popRoot != statement.NewRecoveryKeyPoPRoot {
		return HeadEntryBodyV2{}, errors.New("[D119 runtime activation] recovery key PoP 不一致")
	}
	if err := ValidateRecoveryControlKeySeparation(&bundle.RecoveryPolicy, &bundle.ControlSet); err != nil {
		return HeadEntryBodyV2{}, err
	}
	oldRoot, err := ControlOperationRoot(bundle.PreviousOperationLeaves)
	if err != nil || bundle.PreviousOperationLeaves == nil || oldRoot != parent.OperationRoot {
		return HeadEntryBodyV2{}, errors.New("[D104 runtime activation] 原 operation history 不一致")
	}
	statementHash, _ := RuntimeActivationStatementHash(statement)
	leaves := append(append([]ControlOperationLeafV1(nil), bundle.PreviousOperationLeaves...),
		ControlOperationLeafV1{Schema: 1, OperationID: statement.OperationID, ObjectID: statementHash})
	operationRoot, err := ControlOperationRoot(leaves)
	if err != nil {
		return HeadEntryBodyV2{}, err
	}
	issued, _ := ParseTimeZ(statement.IssuedAt)
	committed, err := ParseTimeZ(committedAt)
	parentTime, _ := ParseTimeZ(parent.CommittedLogicalTime)
	if err != nil || committed.Before(issued) || issued.Before(parentTime) ||
		raftTerm < parent.RaftTerm || raftIndex <= parent.RaftIndex {
		return HeadEntryBodyV2{}, errors.New("[D104 runtime activation] 时间或 Raft 坐标回退")
	}
	context, _ := MarshalCanonical(RuntimeActivationContextV1{Schema: 1, Kind: "legacy_runtime_activation", StatementHash: statementHash})
	body := bundle.Parent.Body
	p := &body.Payload
	p.HeadKind, p.RecoveryEpoch, p.ControlEpoch = "legacy_runtime_activation", statement.NewRecoveryEpoch, 0
	p.RecoveryStatementHash, p.RecoveryPolicyHash = statementHash, policyHash
	p.RaftTerm, p.RaftIndex, p.ControlRevision = raftTerm, raftIndex, raftIndex
	p.PreviousLogEntryHash, p.ParentHeadHash = previousLogHash, bundle.Parent.HeadHash
	p.OperationRoot, p.SnapshotHash = operationRoot, statement.Roots.SnapshotHash
	p.EffectiveSSOTHash, p.DeviceViewsRoot = statement.Roots.EffectiveSSOTHash, statement.Roots.DeviceViewsRoot
	p.AdminACLRoot, p.CAProfileRoot = statement.Roots.AdminACLRoot, statement.Roots.CAProfileRoot
	p.BootstrapIssuerRegistryRoot = statement.Roots.BootstrapIssuerRegistryRoot
	p.RenderContractVersion, p.CommittedLogicalTime, p.TransitionContext = statement.Roots.RenderContractVersion, committedAt, context
	body.TransitionProofHash = proofHash
	candidate, err := NewHeadEntry(body)
	if err != nil {
		return HeadEntryBodyV2{}, err
	}
	if err := ValidateHeadEntry(&candidate, &bundle.Parent); err != nil {
		return HeadEntryBodyV2{}, err
	}
	return body, nil
}

// VerifyRuntimeActivationBundle 验证公开迁移证明。调用者还必须提供既有 v1
// trust root、既有 certified parent，或用户交付的 exact 新 Head checkpoint 之一。
func VerifyRuntimeActivationBundle(bundle *RuntimeActivationBundleV1, trust InviteProofTrustV2,
	trustedParentHash, trustedCheckpointHash string) (string, error) {
	if bundle == nil {
		return "", errors.New("[D104 runtime activation] bundle 缺失")
	}
	statement := &bundle.Proof.Statement
	anchored := false
	if len(trust.V1PlatformKey) != 0 {
		if len(trust.V1PlatformKey) != ed25519.PublicKeySize ||
			base64.RawURLEncoding.EncodeToString(trust.V1PlatformKey) != statement.V1PlatformPublicKey ||
			trust.V1PlatformKeyID != statement.V1PlatformKeyID || trust.V1MigrationAnchorDigest != statement.V1PlatformKeyDigest {
			return "", errors.New("[D111 runtime activation] v1 trust root 不匹配")
		}
		anchored = true
	}
	if trustedParentHash != "" {
		if trustedParentHash != bundle.Parent.HeadHash {
			return "", errors.New("[D104 runtime activation] 已信任 parent 不匹配")
		}
		anchored = true
	}
	if trustedCheckpointHash != "" {
		if trustedCheckpointHash != bundle.Head.HeadHash {
			return "", errors.New("[D111 runtime activation] checkpoint 不匹配")
		}
		anchored = true
	}
	if !anchored {
		return "", errors.New("[D111 runtime activation] 缺外部 trust root")
	}
	p := &bundle.Head.Body.Payload
	expected, err := RuntimeActivationHeadBody(bundle, p.RaftTerm, p.RaftIndex, p.PreviousLogEntryHash, p.CommittedLogicalTime)
	if err != nil {
		return "", err
	}
	if !EqualCanonical(expected, bundle.Head.Body) {
		return "", errors.New("[D104 runtime activation] Head 未精确投影已签 statement")
	}
	if err := VerifyStableHeadQC(&bundle.Head, &bundle.ControlSet, &bundle.ConfigQC); err != nil {
		return "", err
	}
	return bundle.Head.Body.TransitionProofHash, nil
}
