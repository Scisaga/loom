package wire

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"unicode/utf8"
)

const (
	DomainRecoveryPolicy               = "loom-recovery-policy-v1"
	DomainRecoveryKeyPoP               = "loom-recovery-key-pop-v1"
	DomainRecoveryKeyPoPSignature      = "loom-recovery-key-pop-signature-v1"
	DomainRecoveryStatement            = "loom-recovery-statement-v1"
	DomainRecoveryEmergencySignature   = "loom-recovery-emergency-signature-v1"
	DomainRecoveryTransitionProof      = "loom-recovery-transition-proof-v1"
	DomainRecoveryGenesisPayload       = "loom-recovery-genesis-payload-v1"
	DomainInitialV2HeadPayload         = "loom-initial-v2-head-payload-v1"
	DomainBootstrapTransitionBody      = "loom-bootstrap-transition-body-v1-to-v2"
	DomainBootstrapTransitionProof     = "loom-bootstrap-transition-proof-v1-to-v2"
	DomainBootstrapTransitionSignature = "loom-bootstrap-transition-signature-v1-to-v2"
)

type RecoveryPolicyKeyV1 struct {
	KeyID     string `json:"key_id"`
	Algorithm string `json:"algorithm"`
	PublicKey string `json:"public_key"`
}

type RecoveryPolicyV1 struct {
	Schema                int                   `json:"schema"`
	ClusterID             string                `json:"cluster_id"`
	PolicyID              string                `json:"policy_id"`
	Generation            int64                 `json:"generation"`
	Algorithm             string                `json:"algorithm"`
	Keys                  []RecoveryPolicyKeyV1 `json:"keys"`
	Threshold             int64                 `json:"threshold"`
	PrivateKeyCustodyRoot string                `json:"private_key_custody_root"`
	CeremonyProfile       string                `json:"ceremony_profile"`
}

type RecoveryKeyPossessionProofBodyV1 struct {
	Schema           int    `json:"schema"`
	ClusterID        string `json:"cluster_id"`
	PolicyID         string `json:"policy_id"`
	PolicyGeneration int64  `json:"policy_generation"`
	KeyID            string `json:"key_id"`
	PublicKey        string `json:"public_key"`
}

type RecoveryKeyPossessionProofV1 struct {
	Body      RecoveryKeyPossessionProofBodyV1 `json:"body"`
	Signature string                           `json:"signature"`
}

type RecoveryKeyPossessionLeafV1 struct {
	Schema             int    `json:"schema"`
	KeyID              string `json:"key_id"`
	RecoveryKeyPoPHash string `json:"recovery_key_pop_hash"`
}

type RecoveryThresholdSignatureV1 struct {
	KeyID     string `json:"key_id"`
	Signature string `json:"signature"`
}

type RecoveryBootstrapStatementV1 struct {
	Schema                             int    `json:"schema"`
	StatementType                      string `json:"statement_type"`
	ClusterID                          string `json:"cluster_id"`
	RecoveryEpoch                      int64  `json:"recovery_epoch"`
	RecoveryPolicyHash                 string `json:"recovery_policy_hash"`
	InitialRecoveryKeyPoPRoot          string `json:"initial_recovery_key_pop_root"`
	InitialControlEpoch                int64  `json:"initial_control_epoch"`
	InitialControlSetHash              string `json:"initial_control_set_hash"`
	InitialControlPeerDirectoryHash    string `json:"initial_control_peer_directory_hash"`
	InitialControlKeyPoPRoot           string `json:"initial_control_key_pop_root"`
	InitialAdminACLHash                string `json:"initial_admin_acl_hash"`
	InternalCAProfileAndAnchorHash     string `json:"internal_ca_profile_and_anchor_hash"`
	InitialBootstrapIssuerRegistryRoot string `json:"initial_bootstrap_issuer_registry_root"`
}

type InitialV2HeadPayloadV1 struct {
	Schema                      int    `json:"schema"`
	ClusterID                   string `json:"cluster_id"`
	RecoveryEpoch               int64  `json:"recovery_epoch"`
	RecoveryStatementHash       string `json:"recovery_statement_hash"`
	RecoveryPolicyHash          string `json:"recovery_policy_hash"`
	ControlEpoch                int64  `json:"control_epoch"`
	ControlSetHash              string `json:"control_set_hash"`
	ControlPeerDirectoryHash    string `json:"control_peer_directory_hash"`
	ControlRevision             int64  `json:"control_revision"`
	SnapshotHash                string `json:"snapshot_hash"`
	OperationRoot               string `json:"operation_root"`
	EffectiveSSOTHash           string `json:"effective_ssot_hash"`
	DeviceViewsRoot             string `json:"device_views_root"`
	AdminACLRoot                string `json:"admin_acl_root"`
	CAProfileRoot               string `json:"ca_profile_root"`
	BootstrapIssuerRegistryRoot string `json:"bootstrap_issuer_registry_root"`
	RenderContractVersion       int64  `json:"render_contract_version"`
	MinReaderVersion            int64  `json:"min_reader_version"`
	MaxClockSkewSeconds         int64  `json:"max_clock_skew_seconds"`
}

type BootstrapTransitionBodyV1ToV2 struct {
	Schema                             int                          `json:"schema"`
	ClusterID                          string                       `json:"cluster_id"`
	V1PlatformKeyID                    string                       `json:"v1_platform_key_id"`
	V1PlatformKeyDigest                string                       `json:"v1_platform_key_digest"`
	V1DeviceFloorMerkleRoot            string                       `json:"v1_device_floor_merkle_root"`
	RecoveryBootstrapStatement         RecoveryBootstrapStatementV1 `json:"recovery_bootstrap_statement"`
	RecoveryStatementHash              string                       `json:"recovery_statement_hash"`
	InitialRecoveryKeyPoPRoot          string                       `json:"initial_recovery_key_pop_root"`
	InitialControlSetHash              string                       `json:"initial_control_set_hash"`
	InitialControlPeerDirectoryHash    string                       `json:"initial_control_peer_directory_hash"`
	InitialControlKeyPoPRoot           string                       `json:"initial_control_key_pop_root"`
	InitialAdminACLHash                string                       `json:"initial_admin_acl_hash"`
	InternalCAProfileAndAnchorHash     string                       `json:"internal_ca_profile_and_anchor_hash"`
	InitialBootstrapIssuerRegistryRoot string                       `json:"initial_bootstrap_issuer_registry_root"`
	InitialV2HeadPayloadHash           string                       `json:"initial_v2_head_payload_hash"`
	InitialV2RaftIndex                 int64                        `json:"initial_v2_raft_index"`
	MinimumReaderVersion               int64                        `json:"minimum_reader_version"`
}

type V1PlatformSignatureV1 struct {
	KeyID     string `json:"key_id"`
	Signature string `json:"signature"`
}

type BootstrapTransitionProofV1ToV2 struct {
	Body                BootstrapTransitionBodyV1ToV2 `json:"body"`
	BodyHash            string                        `json:"body_hash"`
	V1PlatformSignature V1PlatformSignatureV1         `json:"v1_platform_signature"`
}

type InitialV2HeadEntryV1 struct {
	Schema         int                       `json:"schema"`
	InitialPayload InitialV2HeadPayloadV1    `json:"initial_payload"`
	Head           HeadEntryV2               `json:"head"`
	ReplicationQC  StableHeadReplicationQCV1 `json:"replication_qc"`
}

type BootstrapTransitionBundleV1ToV2 struct {
	Schema                             int                            `json:"schema"`
	TransitionProof                    BootstrapTransitionProofV1ToV2 `json:"transition_proof"`
	InitialRecoveryPolicy              RecoveryPolicyV1               `json:"initial_recovery_policy"`
	InitialRecoveryKeyPossessionProofs []RecoveryKeyPossessionProofV1 `json:"initial_recovery_key_possession_proofs"`
	InitialControlSet                  ControlSetV1                   `json:"initial_control_set"`
	InitialControlKeyPossessionProofs  []ControlKeyPossessionProofV1  `json:"initial_control_key_possession_proofs"`
	InitialHeadEntry                   InitialV2HeadEntryV1           `json:"initial_head_entry"`
}

type BootstrapDeviceFloorLeafV1 struct {
	Schema              int    `json:"schema"`
	DeviceID            string `json:"device_id"`
	V1Generation        int64  `json:"v1_generation"`
	V1SignedCurrentHash string `json:"v1_signed_current_hash"`
	V1PayloadHash       string `json:"v1_payload_hash"`
}

type BootstrapDeviceFloorProofV1 struct {
	Schema    int                        `json:"schema"`
	Leaf      BootstrapDeviceFloorLeafV1 `json:"leaf"`
	LeafIndex int64                      `json:"leaf_index"`
	TreeSize  int64                      `json:"tree_size"`
	AuditPath []string                   `json:"audit_path"`
}

type BootstrapDeviceMigrationPackageV1ToV2 struct {
	Schema           int                             `json:"schema"`
	BootstrapBundle  BootstrapTransitionBundleV1ToV2 `json:"bootstrap_bundle"`
	DeviceFloorProof BootstrapDeviceFloorProofV1     `json:"device_floor_proof"`
}

type RecoveryTransitionBodyV1 struct {
	Schema                             int    `json:"schema"`
	StatementType                      string `json:"statement_type"`
	ClusterID                          string `json:"cluster_id"`
	PreviousRecoveryEpoch              int64  `json:"previous_recovery_epoch"`
	PreviousRecoveryStatementHash      string `json:"previous_recovery_statement_hash"`
	PreviousRecoveryPolicyHash         string `json:"previous_recovery_policy_hash"`
	PreviousTrustedHeadHash            string `json:"previous_trusted_head_hash"`
	NewRecoveryEpoch                   int64  `json:"new_recovery_epoch"`
	NewRecoveryPolicyHash              string `json:"new_recovery_policy_hash"`
	NewPolicyPoPRoot                   string `json:"new_policy_pop_root"`
	NewControlEpoch                    int64  `json:"new_control_epoch"`
	NewControlSetHash                  string `json:"new_control_set_hash"`
	NewControlPeerDirectoryHash        string `json:"new_control_peer_directory_hash"`
	NewControlKeyPoPRoot               string `json:"new_control_key_pop_root"`
	InitialAdminACLHash                string `json:"initial_admin_acl_hash"`
	InternalCAProfileAndAnchorHash     string `json:"internal_ca_profile_and_anchor_hash"`
	InitialBootstrapIssuerRegistryRoot string `json:"initial_bootstrap_issuer_registry_root"`
	NewLineageGenesisPayloadHash       string `json:"new_lineage_genesis_payload_hash"`
	Reason                             string `json:"reason"`
	IssuedAt                           string `json:"issued_at"`
}

type RecoveryTransitionProofV1 struct {
	Schema                       int                            `json:"schema"`
	Body                         RecoveryTransitionBodyV1       `json:"body"`
	RecoveryStatementHash        string                         `json:"recovery_statement_hash"`
	OldPolicyThresholdSignatures []RecoveryThresholdSignatureV1 `json:"old_policy_threshold_signatures"`
}

type RecoveryGenesisPayloadV1 struct {
	Schema                             int    `json:"schema"`
	ClusterID                          string `json:"cluster_id"`
	NewRecoveryEpoch                   int64  `json:"new_recovery_epoch"`
	NewRecoveryPolicyHash              string `json:"new_recovery_policy_hash"`
	NewPolicyPoPRoot                   string `json:"new_policy_pop_root"`
	NewControlEpoch                    int64  `json:"new_control_epoch"`
	NewControlSetHash                  string `json:"new_control_set_hash"`
	NewControlPeerDirectoryHash        string `json:"new_control_peer_directory_hash"`
	NewControlKeyPoPRoot               string `json:"new_control_key_pop_root"`
	ParentRecoveryHeadHash             string `json:"parent_recovery_head_hash"`
	InitialAdminACLHash                string `json:"initial_admin_acl_hash"`
	InternalCAProfileAndAnchorHash     string `json:"internal_ca_profile_and_anchor_hash"`
	InitialBootstrapIssuerRegistryRoot string `json:"initial_bootstrap_issuer_registry_root"`
	OperationRoot                      string `json:"operation_root"`
	SnapshotHash                       string `json:"snapshot_hash"`
	EffectiveSSOTHash                  string `json:"effective_ssot_hash"`
	DeviceViewsRoot                    string `json:"device_views_root"`
	RenderContractVersion              int64  `json:"render_contract_version"`
	MinReaderVersion                   int64  `json:"min_reader_version"`
	MaxClockSkewSeconds                int64  `json:"max_clock_skew_seconds"`
}

type RecoveryGenesisV1 struct {
	Schema             int                       `json:"schema"`
	GenesisPayload     RecoveryGenesisPayloadV1  `json:"genesis_payload"`
	GenesisPayloadHash string                    `json:"genesis_payload_hash"`
	Head               HeadEntryV2               `json:"head"`
	ReplicationQC      StableHeadReplicationQCV1 `json:"replication_qc"`
}

type EmergencyRecoveryBundleV1 struct {
	Schema                         int                            `json:"schema"`
	TransitionProof                RecoveryTransitionProofV1      `json:"transition_proof"`
	NewRecoveryPolicy              RecoveryPolicyV1               `json:"new_recovery_policy"`
	NewRecoveryKeyPossessionProofs []RecoveryKeyPossessionProofV1 `json:"new_recovery_key_possession_proofs"`
	NewControlSet                  ControlSetV1                   `json:"new_control_set"`
	NewControlKeyPossessionProofs  []ControlKeyPossessionProofV1  `json:"new_control_key_possession_proofs"`
	Genesis                        RecoveryGenesisV1              `json:"genesis"`
}

// VerifiedRecoveryTransitionV1 只能由完整 emergency bundle verifier 构造。
// 字段保持私有，防止调用方拿一个自报 hash 绕过 recovery floor（D119）。
type VerifiedRecoveryTransitionV1 struct {
	clusterID                     string
	previousRecoveryEpoch         int64
	previousRecoveryStatementHash string
	previousRecoveryPolicyHash    string
	previousTrustedHeadHash       string
	newRecoveryEpoch              int64
	newRecoveryStatementHash      string
	newRecoveryPolicyHash         string
	newControlEpoch               int64
	newControlSetHash             string
	newGenesisHeadHash            string
	newGenesisControlRevision     int64
	transitionProofHash           string
}

func (verified VerifiedRecoveryTransitionV1) TransitionProofHash() string {
	return verified.transitionProofHash
}

func (verified VerifiedRecoveryTransitionV1) RecoveryStatementHash() string {
	return verified.newRecoveryStatementHash
}

func ValidateRecoveryPolicy(policy *RecoveryPolicyV1) error {
	if policy == nil || policy.Schema != 1 || !validIdentifier(policy.ClusterID, 128) ||
		!validIdentifier(policy.PolicyID, 128) || policy.Generation < 1 || policy.Algorithm != "ed25519-multisig-v1" ||
		policy.CeremonyProfile != "offline-independent-keys-v1" || len(policy.Keys) == 0 ||
		policy.Threshold < 1 || policy.Threshold > int64(len(policy.Keys)) {
		return errors.New("[D119 recovery] policy header/threshold 无效")
	}
	if _, err := ParseHash(policy.PrivateKeyCustodyRoot); err != nil {
		return err
	}
	publicKeys := make(map[string]struct{}, len(policy.Keys))
	for i := range policy.Keys {
		key := &policy.Keys[i]
		public, err := decodeRawURL(key.PublicKey, ed25519.PublicKeySize)
		keyID, _ := ControlKeyID(public)
		if err != nil || key.Algorithm != "ed25519" || key.KeyID != keyID ||
			i > 0 && policy.Keys[i-1].KeyID >= key.KeyID {
			return errors.New("[D119 recovery] policy keys 无效/未排序")
		}
		if _, exists := publicKeys[key.PublicKey]; exists {
			return errors.New("[D119 recovery] policy public key 重复")
		}
		publicKeys[key.PublicKey] = struct{}{}
	}
	return nil
}

func RecoveryPolicyHash(policy *RecoveryPolicyV1) (string, error) {
	if err := ValidateRecoveryPolicy(policy); err != nil {
		return "", err
	}
	return HashObject(DomainRecoveryPolicy, policy)
}

func RecoveryKeyPossessionProofHash(proof *RecoveryKeyPossessionProofV1) (string, error) {
	if proof == nil {
		return "", errors.New("[D119 recovery] key PoP 缺失")
	}
	return HashObject(DomainRecoveryKeyPoP, proof)
}

func NewRecoveryKeyPossessionProof(body RecoveryKeyPossessionProofBodyV1, privateKey ed25519.PrivateKey) (RecoveryKeyPossessionProofV1, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return RecoveryKeyPossessionProofV1{}, errors.New("[D119 recovery] private key 无效")
	}
	public := privateKey.Public().(ed25519.PublicKey)
	keyID, _ := ControlKeyID(public)
	if body.Schema != 1 || body.KeyID != keyID || body.PublicKey != base64.RawURLEncoding.EncodeToString(public) {
		return RecoveryKeyPossessionProofV1{}, errors.New("[D119 recovery] key PoP body/private key 不匹配")
	}
	canonical, err := MarshalCanonical(body)
	if err != nil {
		return RecoveryKeyPossessionProofV1{}, err
	}
	message, _ := Frame(DomainRecoveryKeyPoPSignature, canonical)
	return RecoveryKeyPossessionProofV1{Body: body, Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, message))}, nil
}

func RecoveryKeyPossessionRoot(policy *RecoveryPolicyV1, proofs []RecoveryKeyPossessionProofV1) (string, error) {
	if err := ValidateRecoveryPolicy(policy); err != nil {
		return "", err
	}
	if len(proofs) != len(policy.Keys) {
		return "", errors.New("[D119 recovery] key PoP 必须恰好覆盖 policy keys")
	}
	leaves := make([][]byte, len(proofs))
	for i := range proofs {
		proof, key := &proofs[i], &policy.Keys[i]
		body := &proof.Body
		if body.Schema != 1 || body.ClusterID != policy.ClusterID || body.PolicyID != policy.PolicyID ||
			body.PolicyGeneration != policy.Generation || body.KeyID != key.KeyID || body.PublicKey != key.PublicKey ||
			i > 0 && proofs[i-1].Body.KeyID >= body.KeyID {
			return "", errors.New("[D119 recovery] key PoP 与 policy 不一一对应")
		}
		public, _ := decodeRawURL(body.PublicKey, ed25519.PublicKeySize)
		signature, err := decodeRawURL(proof.Signature, ed25519.SignatureSize)
		canonical, canonicalErr := MarshalCanonical(*body)
		message, frameErr := Frame(DomainRecoveryKeyPoPSignature, canonical)
		if err != nil || canonicalErr != nil || frameErr != nil || !ed25519.Verify(public, message, signature) {
			return "", errors.New("[D119 recovery] key PoP signature 无效")
		}
		hash, _ := RecoveryKeyPossessionProofHash(proof)
		leaf := RecoveryKeyPossessionLeafV1{Schema: 1, KeyID: body.KeyID, RecoveryKeyPoPHash: hash}
		leaves[i], _ = MarshalCanonical(leaf)
	}
	return "sha256:" + fmt.Sprintf("%x", MerkleRoot(leaves)), nil
}

func validateRecoveryBootstrapStatement(statement *RecoveryBootstrapStatementV1) error {
	if statement == nil || statement.Schema != 1 || statement.StatementType != "bootstrap" ||
		!validIdentifier(statement.ClusterID, 128) || statement.RecoveryEpoch != 0 || statement.InitialControlEpoch != 0 {
		return errors.New("[D111 bootstrap] recovery bootstrap statement header 无效")
	}
	return requireCanonicalHashes(statement.RecoveryPolicyHash, statement.InitialRecoveryKeyPoPRoot,
		statement.InitialControlSetHash, statement.InitialControlPeerDirectoryHash, statement.InitialControlKeyPoPRoot,
		statement.InitialAdminACLHash, statement.InternalCAProfileAndAnchorHash, statement.InitialBootstrapIssuerRegistryRoot)
}

func validateRecoveryTransitionBody(body *RecoveryTransitionBodyV1) error {
	if body == nil {
		return errors.New("[D119 recovery] transition body 缺失")
	}
	nextEpoch, addErr := CheckedAdd(body.PreviousRecoveryEpoch, 1)
	if body.Schema != 1 || body.StatementType != "emergency" || !validIdentifier(body.ClusterID, 128) ||
		body.PreviousRecoveryEpoch < 0 || addErr != nil || body.NewRecoveryEpoch != nextEpoch || body.NewControlEpoch != 0 ||
		!validRecoveryReason(body.Reason) {
		return errors.New("[D119 recovery] transition body header/epoch 无效")
	}
	if _, err := ParseTimeZ(body.IssuedAt); err != nil {
		return err
	}
	return requireCanonicalHashes(body.PreviousRecoveryStatementHash, body.PreviousRecoveryPolicyHash,
		body.PreviousTrustedHeadHash, body.NewRecoveryPolicyHash, body.NewPolicyPoPRoot, body.NewControlSetHash,
		body.NewControlPeerDirectoryHash, body.NewControlKeyPoPRoot, body.InitialAdminACLHash,
		body.InternalCAProfileAndAnchorHash, body.InitialBootstrapIssuerRegistryRoot, body.NewLineageGenesisPayloadHash)
}

func validRecoveryReason(value string) bool {
	if len(value) == 0 || len(value) > 2048 || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func RecoveryStatementHash(statement any) (string, error) {
	switch typed := statement.(type) {
	case RecoveryBootstrapStatementV1:
		return RecoveryStatementHash(&typed)
	case *RecoveryBootstrapStatementV1:
		if err := validateRecoveryBootstrapStatement(typed); err != nil {
			return "", err
		}
	case RecoveryTransitionBodyV1:
		return RecoveryStatementHash(&typed)
	case *RecoveryTransitionBodyV1:
		if err := validateRecoveryTransitionBody(typed); err != nil {
			return "", err
		}
	default:
		return "", errors.New("[D119 recovery] statement type 未获协议授权")
	}
	return HashObject(DomainRecoveryStatement, statement)
}

func InitialV2HeadPayloadHash(payload *InitialV2HeadPayloadV1) (string, error) {
	if err := validateInitialV2Payload(payload); err != nil {
		return "", err
	}
	return HashObject(DomainInitialV2HeadPayload, payload)
}

func validateInitialV2Payload(payload *InitialV2HeadPayloadV1) error {
	if payload == nil || payload.Schema != 1 || !validIdentifier(payload.ClusterID, 128) || payload.RecoveryEpoch != 0 ||
		payload.ControlEpoch != 0 || payload.ControlRevision != 1 || payload.RenderContractVersion < 1 ||
		payload.MinReaderVersion < 2 || payload.MaxClockSkewSeconds < 0 || payload.MaxClockSkewSeconds > 300 {
		return errors.New("[D111 bootstrap] initial payload 坐标/版本无效")
	}
	return requireCanonicalHashes(payload.RecoveryStatementHash, payload.RecoveryPolicyHash, payload.ControlSetHash,
		payload.ControlPeerDirectoryHash, payload.SnapshotHash, payload.OperationRoot, payload.EffectiveSSOTHash,
		payload.DeviceViewsRoot, payload.AdminACLRoot, payload.CAProfileRoot, payload.BootstrapIssuerRegistryRoot)
}

func BootstrapTransitionBodyHash(body *BootstrapTransitionBodyV1ToV2) (string, error) {
	if err := validateBootstrapTransitionBody(body); err != nil {
		return "", err
	}
	return HashObject(DomainBootstrapTransitionBody, body)
}

func validateBootstrapTransitionBody(body *BootstrapTransitionBodyV1ToV2) error {
	if body == nil || body.Schema != 1 || !validIdentifier(body.ClusterID, 128) || !validIdentifier(body.V1PlatformKeyID, 256) ||
		body.InitialV2RaftIndex != 1 || body.MinimumReaderVersion < 2 || body.RecoveryBootstrapStatement.ClusterID != body.ClusterID {
		return errors.New("[D111 bootstrap] transition body header 无效")
	}
	if err := validateRecoveryBootstrapStatement(&body.RecoveryBootstrapStatement); err != nil {
		return err
	}
	return requireCanonicalHashes(body.V1PlatformKeyDigest, body.V1DeviceFloorMerkleRoot, body.RecoveryStatementHash,
		body.InitialRecoveryKeyPoPRoot, body.InitialControlSetHash, body.InitialControlPeerDirectoryHash,
		body.InitialControlKeyPoPRoot, body.InitialAdminACLHash, body.InternalCAProfileAndAnchorHash,
		body.InitialBootstrapIssuerRegistryRoot, body.InitialV2HeadPayloadHash)
}

func BootstrapTransitionProofHash(proof *BootstrapTransitionProofV1ToV2) (string, error) {
	if proof == nil || proof.V1PlatformSignature.KeyID != proof.Body.V1PlatformKeyID {
		return "", errors.New("[D111 bootstrap] transition proof/key ID 无效")
	}
	bodyHash, err := BootstrapTransitionBodyHash(&proof.Body)
	if err != nil || proof.BodyHash != bodyHash {
		return "", errors.New("[D111 bootstrap] transition body hash 不匹配")
	}
	if _, err := decodeRawURL(proof.V1PlatformSignature.Signature, ed25519.SignatureSize); err != nil {
		return "", errors.New("[D111 bootstrap] v1 platform signature 编码无效")
	}
	return HashObject(DomainBootstrapTransitionProof, proof)
}

func VerifyBootstrapTransitionBundle(bundle *BootstrapTransitionBundleV1ToV2, platformKey ed25519.PublicKey, expectedPlatformKeyID, expectedMigrationAnchorDigest string) (string, error) {
	if bundle == nil || bundle.Schema != 1 || len(platformKey) != ed25519.PublicKeySize {
		return "", errors.New("[D111 bootstrap] transition bundle/platform key 无效")
	}
	return verifyBootstrapTransitionBundle(bundle, platformKey, expectedPlatformKeyID, expectedMigrationAnchorDigest, "")
}

// VerifyBootstrapTransitionBundleFromCheckpoint 供全新 v2 Device 使用二维码内的
// trusted checkpoint 建立初始信任；checkpoint 必须是 exact initial certified head hash（D111）。
func VerifyBootstrapTransitionBundleFromCheckpoint(bundle *BootstrapTransitionBundleV1ToV2, expectedInitialHeadHash string) (string, error) {
	if bundle == nil || bundle.Schema != 1 {
		return "", errors.New("[D111 bootstrap] transition bundle 无效")
	}
	if _, err := ParseHash(expectedInitialHeadHash); err != nil || bundle.InitialHeadEntry.Head.HeadHash != expectedInitialHeadHash {
		return "", errors.New("[D111 bootstrap] trusted checkpoint 未绑定 initial certified head")
	}
	return verifyBootstrapTransitionBundle(bundle, nil, "", "", expectedInitialHeadHash)
}

func verifyBootstrapTransitionBundle(bundle *BootstrapTransitionBundleV1ToV2, platformKey ed25519.PublicKey, expectedPlatformKeyID, expectedMigrationAnchorDigest, expectedInitialHeadHash string) (string, error) {
	proof, body := &bundle.TransitionProof, &bundle.TransitionProof.Body
	if len(platformKey) != 0 {
		publicDigestRaw := sha256.Sum256(platformKey)
		publicDigest := "sha256:" + fmt.Sprintf("%x", publicDigestRaw[:])
		if body.V1PlatformKeyID != expectedPlatformKeyID || body.V1PlatformKeyDigest != publicDigest ||
			body.V1PlatformKeyDigest != expectedMigrationAnchorDigest || proof.V1PlatformSignature.KeyID != expectedPlatformKeyID {
			return "", errors.New("[D111 bootstrap] platform key/migration anchor 不匹配")
		}
		canonicalBody, _ := MarshalCanonical(*body)
		message, _ := Frame(DomainBootstrapTransitionSignature, canonicalBody)
		signature, _ := decodeRawURL(proof.V1PlatformSignature.Signature, ed25519.SignatureSize)
		if !ed25519.Verify(platformKey, message, signature) {
			return "", errors.New("[D111 bootstrap] v1 platform transition signature 无效")
		}
	} else if expectedInitialHeadHash == "" {
		return "", errors.New("[D111 bootstrap] 缺 platform anchor 或 trusted checkpoint")
	}
	transitionHash, err := BootstrapTransitionProofHash(proof)
	if err != nil {
		return "", err
	}
	policyHash, err := RecoveryPolicyHash(&bundle.InitialRecoveryPolicy)
	if err != nil || policyHash != body.RecoveryBootstrapStatement.RecoveryPolicyHash || bundle.InitialRecoveryPolicy.ClusterID != body.ClusterID {
		return "", errors.New("[D111 bootstrap] initial recovery policy hash 不匹配")
	}
	recoveryPoPRoot, err := RecoveryKeyPossessionRoot(&bundle.InitialRecoveryPolicy, bundle.InitialRecoveryKeyPossessionProofs)
	if err != nil || recoveryPoPRoot != body.InitialRecoveryKeyPoPRoot {
		return "", errors.New("[D111 bootstrap] initial recovery key PoP root 不匹配")
	}
	setHash, err := ControlSetHash(&bundle.InitialControlSet)
	if err != nil || setHash != body.InitialControlSetHash || bundle.InitialControlSet.ClusterID != body.ClusterID {
		return "", errors.New("[D111 bootstrap] initial ControlSet hash 不匹配")
	}
	controlPoPRoot, err := ControlKeyPossessionRoot(&bundle.InitialControlSet, bundle.InitialControlKeyPossessionProofs)
	if err != nil || controlPoPRoot != body.InitialControlKeyPoPRoot {
		return "", errors.New("[D111 bootstrap] initial control key PoP root 不匹配")
	}
	if err := ValidateRecoveryControlKeySeparation(&bundle.InitialRecoveryPolicy, &bundle.InitialControlSet); err != nil {
		return "", err
	}
	statementHash, err := RecoveryStatementHash(&body.RecoveryBootstrapStatement)
	if err != nil || statementHash != body.RecoveryStatementHash || !bootstrapRepeatedCommitmentsMatch(body) {
		return "", errors.New("[D111 bootstrap] recovery statement/repeated commitments 不匹配")
	}
	initial := &bundle.InitialHeadEntry
	payloadHash, err := InitialV2HeadPayloadHash(&initial.InitialPayload)
	if err != nil || payloadHash != body.InitialV2HeadPayloadHash || !initialPayloadMatchesBootstrap(body, &initial.InitialPayload) {
		return "", errors.New("[D111 bootstrap] initial payload/transition 不匹配")
	}
	if initial.Schema != 1 || !headMatchesInitialPayload(&initial.Head, &initial.InitialPayload, transitionHash) {
		return "", errors.New("[D111 bootstrap] initial HeadEntry 与 payload/transition 不匹配")
	}
	if err := VerifyStableHeadQC(&initial.Head, &bundle.InitialControlSet, &initial.ReplicationQC); err != nil {
		return "", err
	}
	return transitionHash, nil
}

func bootstrapRepeatedCommitmentsMatch(body *BootstrapTransitionBodyV1ToV2) bool {
	statement := &body.RecoveryBootstrapStatement
	return body.RecoveryStatementHash != "" && body.InitialRecoveryKeyPoPRoot == statement.InitialRecoveryKeyPoPRoot &&
		body.InitialControlSetHash == statement.InitialControlSetHash &&
		body.InitialControlPeerDirectoryHash == statement.InitialControlPeerDirectoryHash &&
		body.InitialControlKeyPoPRoot == statement.InitialControlKeyPoPRoot && body.InitialAdminACLHash == statement.InitialAdminACLHash &&
		body.InternalCAProfileAndAnchorHash == statement.InternalCAProfileAndAnchorHash &&
		body.InitialBootstrapIssuerRegistryRoot == statement.InitialBootstrapIssuerRegistryRoot
}

func initialPayloadMatchesBootstrap(body *BootstrapTransitionBodyV1ToV2, payload *InitialV2HeadPayloadV1) bool {
	return payload.ClusterID == body.ClusterID && payload.RecoveryEpoch == 0 && payload.RecoveryStatementHash == body.RecoveryStatementHash &&
		payload.RecoveryPolicyHash == body.RecoveryBootstrapStatement.RecoveryPolicyHash && payload.ControlEpoch == 0 &&
		payload.ControlSetHash == body.InitialControlSetHash && payload.ControlPeerDirectoryHash == body.InitialControlPeerDirectoryHash &&
		payload.ControlRevision == 1 && payload.AdminACLRoot == body.InitialAdminACLHash &&
		payload.CAProfileRoot == body.InternalCAProfileAndAnchorHash && payload.BootstrapIssuerRegistryRoot == body.InitialBootstrapIssuerRegistryRoot &&
		payload.MinReaderVersion == body.MinimumReaderVersion
}

func headMatchesInitialPayload(head *HeadEntryV2, initial *InitialV2HeadPayloadV1, transitionHash string) bool {
	if head == nil || ValidateHeadEntry(head, nil) != nil || head.Body.TransitionProofHash != transitionHash {
		return false
	}
	payload := &head.Body.Payload
	var context BootstrapHeadContextV1
	if _, err := DecodeStrict(payload.TransitionContext, 4096, &context); err != nil {
		return false
	}
	initialHash, _ := InitialV2HeadPayloadHash(initial)
	return context.Schema == 1 && context.Kind == "bootstrap" && context.InitialV2HeadPayloadHash == initialHash &&
		payload.HeadKind == "bootstrap" && payload.ClusterID == initial.ClusterID && payload.RecoveryEpoch == initial.RecoveryEpoch &&
		payload.RecoveryStatementHash == initial.RecoveryStatementHash && payload.RecoveryPolicyHash == initial.RecoveryPolicyHash &&
		payload.ControlEpoch == initial.ControlEpoch && payload.ControlSetHash == initial.ControlSetHash &&
		payload.ControlPeerDirectoryHash == initial.ControlPeerDirectoryHash && payload.ControlRevision == initial.ControlRevision &&
		payload.SnapshotHash == initial.SnapshotHash && payload.OperationRoot == initial.OperationRoot &&
		payload.EffectiveSSOTHash == initial.EffectiveSSOTHash && payload.DeviceViewsRoot == initial.DeviceViewsRoot &&
		payload.AdminACLRoot == initial.AdminACLRoot && payload.CAProfileRoot == initial.CAProfileRoot &&
		payload.BootstrapIssuerRegistryRoot == initial.BootstrapIssuerRegistryRoot &&
		payload.RenderContractVersion == initial.RenderContractVersion && payload.MinReaderVersion == initial.MinReaderVersion &&
		payload.MaxClockSkewSeconds == initial.MaxClockSkewSeconds
}

func VerifyBootstrapDeviceFloor(proof *BootstrapDeviceFloorProofV1, expectedDeviceID string, minimumGeneration int64, expectedCurrentHash, expectedPayloadHash, rootHash string) error {
	if proof == nil || proof.Schema != 1 || proof.Leaf.Schema != 1 || proof.Leaf.DeviceID != expectedDeviceID ||
		proof.Leaf.V1Generation < minimumGeneration || proof.Leaf.V1SignedCurrentHash != expectedCurrentHash ||
		proof.Leaf.V1PayloadHash != expectedPayloadHash {
		return errors.New("[D111 bootstrap] v1 Device floor binding 无效")
	}
	if !validIdentifier(proof.Leaf.DeviceID, 128) {
		return errors.New("[D111 bootstrap] v1 Device ID 无效")
	}
	if err := requireCanonicalHashes(proof.Leaf.V1SignedCurrentHash, proof.Leaf.V1PayloadHash); err != nil {
		return err
	}
	root, err := ParseHash(rootHash)
	if err != nil {
		return err
	}
	path := make([][]byte, len(proof.AuditPath))
	for i := range proof.AuditPath {
		path[i], err = ParseHash(proof.AuditPath[i])
		if err != nil {
			return err
		}
	}
	leaf, _ := MarshalCanonical(proof.Leaf)
	return VerifyMerkleInclusion(leaf, proof.LeafIndex, proof.TreeSize, path, root)
}

func RecoveryTransitionProofHash(proof *RecoveryTransitionProofV1, previousPolicy *RecoveryPolicyV1) (string, error) {
	if proof == nil || proof.Schema != 1 {
		return "", errors.New("[D119 recovery] transition proof schema 无效")
	}
	statementHash, err := RecoveryStatementHash(&proof.Body)
	if err != nil || statementHash != proof.RecoveryStatementHash {
		return "", errors.New("[D119 recovery] transition statement hash 不匹配")
	}
	if err := VerifyRecoveryThresholdSignatures(previousPolicy, &proof.Body, DomainRecoveryEmergencySignature, proof.OldPolicyThresholdSignatures); err != nil {
		return "", err
	}
	return HashObject(DomainRecoveryTransitionProof, proof)
}

func VerifyRecoveryThresholdSignatures(policy *RecoveryPolicyV1, body any, domain string, signatures []RecoveryThresholdSignatureV1) error {
	if err := ValidateRecoveryPolicy(policy); err != nil {
		return err
	}
	if domain == "" || len(signatures) < int(policy.Threshold) || len(signatures) > len(policy.Keys) {
		return errors.New("[D119 recovery] threshold signatures 数量/domain 无效")
	}
	canonical, err := MarshalCanonical(body)
	if err != nil {
		return err
	}
	message, _ := Frame(domain, canonical)
	keys := make(map[string]string, len(policy.Keys))
	for _, key := range policy.Keys {
		keys[key.KeyID] = key.PublicKey
	}
	for i := range signatures {
		signature := &signatures[i]
		encoded, found := keys[signature.KeyID]
		if !found || i > 0 && signatures[i-1].KeyID >= signature.KeyID {
			return errors.New("[D119 recovery] threshold signer 未授权/未排序")
		}
		public, _ := decodeRawURL(encoded, ed25519.PublicKeySize)
		raw, err := decodeRawURL(signature.Signature, ed25519.SignatureSize)
		if err != nil || !ed25519.Verify(public, message, raw) {
			return errors.New("[D119 recovery] threshold signature 无效")
		}
	}
	return nil
}

func VerifyEmergencyRecoveryBundle(bundle *EmergencyRecoveryBundleV1, previousPolicy *RecoveryPolicyV1, previousHead *HeadEntryV2) (VerifiedRecoveryTransitionV1, error) {
	if bundle == nil || bundle.Schema != 1 || previousHead == nil || ValidateHeadEntry(previousHead, nil) != nil {
		return VerifiedRecoveryTransitionV1{}, errors.New("[D119 recovery] emergency bundle/previous head 无效")
	}
	body := &bundle.TransitionProof.Body
	oldPolicyHash, err := RecoveryPolicyHash(previousPolicy)
	if err != nil || oldPolicyHash != body.PreviousRecoveryPolicyHash || previousPolicy.ClusterID != body.ClusterID || previousHead.HeadHash != body.PreviousTrustedHeadHash ||
		previousHead.Body.Payload.ClusterID != body.ClusterID || previousHead.Body.Payload.RecoveryEpoch != body.PreviousRecoveryEpoch ||
		previousHead.Body.Payload.RecoveryStatementHash != body.PreviousRecoveryStatementHash ||
		previousHead.Body.Payload.RecoveryPolicyHash != body.PreviousRecoveryPolicyHash {
		return VerifiedRecoveryTransitionV1{}, errors.New("[D119 recovery] previous lineage/policy binding 不匹配")
	}
	transitionHash, err := RecoveryTransitionProofHash(&bundle.TransitionProof, previousPolicy)
	if err != nil {
		return VerifiedRecoveryTransitionV1{}, err
	}
	newPolicyHash, err := RecoveryPolicyHash(&bundle.NewRecoveryPolicy)
	if err != nil || newPolicyHash != body.NewRecoveryPolicyHash || bundle.NewRecoveryPolicy.ClusterID != body.ClusterID {
		return VerifiedRecoveryTransitionV1{}, errors.New("[D119 recovery] new recovery policy hash/cluster 不匹配")
	}
	newPolicyPoP, err := RecoveryKeyPossessionRoot(&bundle.NewRecoveryPolicy, bundle.NewRecoveryKeyPossessionProofs)
	if err != nil || newPolicyPoP != body.NewPolicyPoPRoot {
		return VerifiedRecoveryTransitionV1{}, errors.New("[D119 recovery] new recovery key PoP root 不匹配")
	}
	newSetHash, err := ControlSetHash(&bundle.NewControlSet)
	if err != nil || newSetHash != body.NewControlSetHash || bundle.NewControlSet.ClusterID != body.ClusterID {
		return VerifiedRecoveryTransitionV1{}, errors.New("[D119 recovery] new ControlSet hash/cluster 不匹配")
	}
	newControlPoP, err := ControlKeyPossessionRoot(&bundle.NewControlSet, bundle.NewControlKeyPossessionProofs)
	if err != nil || newControlPoP != body.NewControlKeyPoPRoot {
		return VerifiedRecoveryTransitionV1{}, errors.New("[D119 recovery] new control key PoP root 不匹配")
	}
	if err := ValidateRecoveryControlKeySeparation(&bundle.NewRecoveryPolicy, &bundle.NewControlSet); err != nil {
		return VerifiedRecoveryTransitionV1{}, err
	}
	genesis := &bundle.Genesis
	genesisHash, err := recoveryGenesisPayloadHash(&genesis.GenesisPayload)
	if err != nil || genesis.Schema != 1 || genesisHash != genesis.GenesisPayloadHash || genesisHash != body.NewLineageGenesisPayloadHash ||
		!genesisPayloadMatchesTransition(&genesis.GenesisPayload, body) || !headMatchesRecoveryGenesis(&genesis.Head, &genesis.GenesisPayload, &bundle.TransitionProof, transitionHash) {
		return VerifiedRecoveryTransitionV1{}, errors.New("[D119 recovery] Genesis payload/head/transition 不匹配")
	}
	if err := VerifyStableHeadQC(&genesis.Head, &bundle.NewControlSet, &genesis.ReplicationQC); err != nil {
		return VerifiedRecoveryTransitionV1{}, err
	}
	return VerifiedRecoveryTransitionV1{
		clusterID:                     bundle.NewControlSet.ClusterID,
		previousRecoveryEpoch:         body.PreviousRecoveryEpoch,
		previousRecoveryStatementHash: body.PreviousRecoveryStatementHash,
		previousRecoveryPolicyHash:    body.PreviousRecoveryPolicyHash,
		previousTrustedHeadHash:       body.PreviousTrustedHeadHash,
		newRecoveryEpoch:              body.NewRecoveryEpoch,
		newRecoveryStatementHash:      bundle.TransitionProof.RecoveryStatementHash,
		newRecoveryPolicyHash:         body.NewRecoveryPolicyHash,
		newControlEpoch:               body.NewControlEpoch,
		newControlSetHash:             body.NewControlSetHash,
		newGenesisHeadHash:            genesis.Head.HeadHash,
		newGenesisControlRevision:     genesis.Head.Body.Payload.ControlRevision,
		transitionProofHash:           transitionHash,
	}, nil
}

func recoveryGenesisPayloadHash(payload *RecoveryGenesisPayloadV1) (string, error) {
	if payload == nil || payload.Schema != 1 || !validIdentifier(payload.ClusterID, 128) || payload.NewRecoveryEpoch < 1 ||
		payload.NewControlEpoch != 0 || payload.RenderContractVersion < 1 || payload.MinReaderVersion < 2 ||
		payload.MaxClockSkewSeconds < 0 || payload.MaxClockSkewSeconds > 300 {
		return "", errors.New("[D119 recovery] genesis payload header 无效")
	}
	if err := requireCanonicalHashes(payload.NewRecoveryPolicyHash, payload.NewPolicyPoPRoot, payload.NewControlSetHash,
		payload.NewControlPeerDirectoryHash, payload.NewControlKeyPoPRoot, payload.ParentRecoveryHeadHash,
		payload.InitialAdminACLHash, payload.InternalCAProfileAndAnchorHash, payload.InitialBootstrapIssuerRegistryRoot,
		payload.OperationRoot, payload.SnapshotHash, payload.EffectiveSSOTHash, payload.DeviceViewsRoot); err != nil {
		return "", err
	}
	return HashObject(DomainRecoveryGenesisPayload, payload)
}

func genesisPayloadMatchesTransition(payload *RecoveryGenesisPayloadV1, body *RecoveryTransitionBodyV1) bool {
	return payload.ClusterID == body.ClusterID && payload.NewRecoveryEpoch == body.NewRecoveryEpoch &&
		payload.NewRecoveryPolicyHash == body.NewRecoveryPolicyHash && payload.NewPolicyPoPRoot == body.NewPolicyPoPRoot &&
		payload.NewControlEpoch == body.NewControlEpoch && payload.NewControlSetHash == body.NewControlSetHash &&
		payload.NewControlPeerDirectoryHash == body.NewControlPeerDirectoryHash && payload.NewControlKeyPoPRoot == body.NewControlKeyPoPRoot &&
		payload.ParentRecoveryHeadHash == body.PreviousTrustedHeadHash && payload.InitialAdminACLHash == body.InitialAdminACLHash &&
		payload.InternalCAProfileAndAnchorHash == body.InternalCAProfileAndAnchorHash &&
		payload.InitialBootstrapIssuerRegistryRoot == body.InitialBootstrapIssuerRegistryRoot
}

func headMatchesRecoveryGenesis(head *HeadEntryV2, genesis *RecoveryGenesisPayloadV1, proof *RecoveryTransitionProofV1, transitionHash string) bool {
	if head == nil || ValidateHeadEntry(head, nil) != nil || head.Body.TransitionProofHash != transitionHash {
		return false
	}
	payload := &head.Body.Payload
	var context RecoveryGenesisContextV1
	if _, err := DecodeStrict(payload.TransitionContext, 4096, &context); err != nil {
		return false
	}
	genesisHash, _ := recoveryGenesisPayloadHash(genesis)
	return context.Schema == 1 && context.Kind == "emergency_recovery" && context.GenesisPayloadHash == genesisHash &&
		payload.HeadKind == "emergency_recovery" && payload.ClusterID == genesis.ClusterID &&
		payload.RecoveryEpoch == genesis.NewRecoveryEpoch && payload.RecoveryStatementHash == proof.RecoveryStatementHash &&
		payload.RecoveryPolicyHash == genesis.NewRecoveryPolicyHash && payload.ControlEpoch == 0 &&
		payload.ControlSetHash == genesis.NewControlSetHash && payload.ControlPeerDirectoryHash == genesis.NewControlPeerDirectoryHash &&
		payload.RaftIndex == 1 && payload.ControlRevision == 1 && payload.PreviousLogEntryHash == EmptyHashV1 &&
		payload.ParentHeadHash == genesis.ParentRecoveryHeadHash && payload.OperationRoot == genesis.OperationRoot &&
		payload.SnapshotHash == genesis.SnapshotHash && payload.EffectiveSSOTHash == genesis.EffectiveSSOTHash &&
		payload.DeviceViewsRoot == genesis.DeviceViewsRoot && payload.AdminACLRoot == genesis.InitialAdminACLHash &&
		payload.CAProfileRoot == genesis.InternalCAProfileAndAnchorHash &&
		payload.BootstrapIssuerRegistryRoot == genesis.InitialBootstrapIssuerRegistryRoot &&
		payload.RenderContractVersion == genesis.RenderContractVersion && payload.MinReaderVersion == genesis.MinReaderVersion &&
		payload.MaxClockSkewSeconds == genesis.MaxClockSkewSeconds
}

// AdvanceFloorsWithRecovery 只接受完整 bundle verifier 产生的 opaque evidence；并把
// old floor 与 recovery Genesis 两端逐字段绑定（D119）。
func AdvanceFloorsWithRecovery(current, candidate ClientFloorsV2, verified VerifiedRecoveryTransitionV1) (ClientFloorsV2, error) {
	if verified.clusterID == "" || current.ClusterID != verified.clusterID || candidate.ClusterID != verified.clusterID ||
		current.AcceptedRecoveryEpoch != verified.previousRecoveryEpoch ||
		current.RecoveryStatementHash != verified.previousRecoveryStatementHash ||
		current.RecoveryPolicyHash != verified.previousRecoveryPolicyHash ||
		current.HeadHash != verified.previousTrustedHeadHash ||
		candidate.AcceptedRecoveryEpoch != verified.newRecoveryEpoch ||
		candidate.RecoveryStatementHash != verified.newRecoveryStatementHash ||
		candidate.RecoveryPolicyHash != verified.newRecoveryPolicyHash ||
		candidate.AcceptedControlEpoch != verified.newControlEpoch ||
		candidate.ControlSetHash != verified.newControlSetHash ||
		candidate.AcceptedControlRevision != verified.newGenesisControlRevision ||
		candidate.HeadHash != verified.newGenesisHeadHash {
		return current, errors.New("[D119 floor] recovery evidence 与 old floor/Genesis candidate 不匹配")
	}
	return advanceFloors(current, candidate, floorAdvanceAuthority{recovery: true})
}
