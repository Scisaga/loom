package wire

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"sort"
	"time"
)

const (
	DomainControlOperationSignature = "loom-control-operation-signature-v1"
	DomainControlOperation          = "loom-control-operation-v1"
)

// ControlOperationBodyV1 是管理员操作的唯一签名 preimage（D104 §7.1）。
type ControlOperationBodyV1 struct {
	Schema                    int    `json:"schema"`
	ClusterID                 string `json:"cluster_id"`
	OperationID               string `json:"operation_id"`
	AuthorID                  string `json:"author_id"`
	AdminCertDigest           string `json:"admin_cert_digest"`
	CreatedAt                 string `json:"created_at"`
	ExpiresAt                 string `json:"expires_at,omitempty"`
	BaseRecoveryEpoch         int64  `json:"base_recovery_epoch"`
	BaseRecoveryStatementHash string `json:"base_recovery_statement_hash"`
	BaseRecoveryPolicyHash    string `json:"base_recovery_policy_hash"`
	BaseControlEpoch          int64  `json:"base_control_epoch"`
	BaseControlSetHash        string `json:"base_control_set_hash"`
	BaseControlRevision       int64  `json:"base_control_revision"`
	ParentHeadHash            string `json:"parent_head_hash"`
	Kind                      string `json:"kind"`
	PayloadSchema             int64  `json:"payload_schema"`
	PayloadHash               string `json:"payload_hash"`
	Reason                    string `json:"reason"`
}

type AdminOperationSignatureV1 struct {
	Algorithm  string `json:"algorithm"`
	AdminKeyID string `json:"admin_key_id"`
	Signature  string `json:"signature"`
}

type ControlOperationV1 struct {
	Body            ControlOperationBodyV1    `json:"body"`
	AuthorSignature AdminOperationSignatureV1 `json:"author_signature"`
}

type ControlOperationLeafV1 struct {
	Schema      int    `json:"schema"`
	OperationID string `json:"operation_id"`
	ObjectID    string `json:"object_id"`
}

// OperationSchemaRegistry 由调用方从已认证的 reader contract 注入；未登记 kind 必须失败关闭。
type OperationSchemaRegistry map[string]int64

func ValidateControlOperationBody(body *ControlOperationBodyV1, schemas OperationSchemaRegistry) error {
	if body == nil || body.Schema != 1 || !validIdentifier(body.ClusterID, 128) ||
		!validIdentifier(body.OperationID, 128) || !validIdentifier(body.AuthorID, 128) ||
		body.BaseRecoveryEpoch < 0 || body.BaseControlEpoch < 0 || body.BaseControlRevision < 1 ||
		body.Kind == "" || body.PayloadSchema < 1 || body.Reason == "" {
		return errors.New("[D104 operation] body identity/base/schema/reason 无效")
	}
	expectedSchema, found := schemas[body.Kind]
	if !found || expectedSchema != body.PayloadSchema {
		return errors.New("[D104 operation] kind 或 payload schema 未获 reader contract 授权")
	}
	for _, hash := range []string{body.AdminCertDigest, body.BaseRecoveryStatementHash,
		body.BaseRecoveryPolicyHash, body.BaseControlSetHash, body.ParentHeadHash, body.PayloadHash} {
		if _, err := ParseHash(hash); err != nil {
			return err
		}
	}
	created, err := ParseTimeZ(body.CreatedAt)
	if err != nil {
		return err
	}
	if body.ExpiresAt != "" {
		expires, err := ParseTimeZ(body.ExpiresAt)
		if err != nil || !created.Before(expires) {
			return errors.New("[D104 operation] expires_at 必须晚于 created_at")
		}
	}
	return nil
}

// AdminKeyID 从完整 DER SPKI 计算普通 sha256 key ID；不与 control raw-key ID 混用。
func AdminKeyID(rawSPKI []byte) (string, error) {
	publicKey, err := x509.ParsePKIXPublicKey(rawSPKI)
	if err != nil {
		return "", errors.New("[D104 operation] admin SPKI DER 无效")
	}
	if _, ok := publicKey.(ed25519.PublicKey); !ok {
		return "", errors.New("[D104 operation] admin signing key 必须是 Ed25519")
	}
	digest := sha256.Sum256(rawSPKI)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func VerifyControlOperation(operation *ControlOperationV1, adminSPKI []byte, trustedTime time.Time, schemas OperationSchemaRegistry) error {
	if operation == nil {
		return errors.New("[D104 operation] operation 不能为空")
	}
	if err := ValidateControlOperationBody(&operation.Body, schemas); err != nil {
		return err
	}
	if trustedTime.IsZero() {
		return errors.New("[D104 operation] 可信时间不能为空")
	}
	created, _ := ParseTimeZ(operation.Body.CreatedAt)
	instant := trustedTime.UTC()
	if instant.Before(created) {
		return errors.New("[D104 operation] operation 尚未生效")
	}
	if operation.Body.ExpiresAt != "" {
		expires, _ := ParseTimeZ(operation.Body.ExpiresAt)
		if !instant.Before(expires) {
			return errors.New("[D104 operation] operation 已过期")
		}
	}
	public, err := x509.ParsePKIXPublicKey(adminSPKI)
	if err != nil {
		return errors.New("[D104 operation] admin SPKI DER 无效")
	}
	ed25519Public, ok := public.(ed25519.PublicKey)
	keyID, keyErr := AdminKeyID(adminSPKI)
	if !ok || keyErr != nil || operation.AuthorSignature.Algorithm != "ed25519" ||
		operation.AuthorSignature.AdminKeyID != keyID {
		return errors.New("[D104 operation] admin signature profile/key ID 无效")
	}
	signature, err := decodeRawURL(operation.AuthorSignature.Signature, ed25519.SignatureSize)
	if err != nil {
		return errors.New("[D104 operation] admin signature 必须是 raw64 base64url")
	}
	canonical, err := MarshalCanonical(operation.Body)
	if err != nil {
		return err
	}
	message, err := Frame(DomainControlOperationSignature, canonical)
	if err != nil || !ed25519.Verify(ed25519Public, message, signature) {
		return errors.New("[D104 operation] admin signature 无效")
	}
	return nil
}

func NewControlOperation(body ControlOperationBodyV1, privateKey ed25519.PrivateKey, schemas OperationSchemaRegistry) (ControlOperationV1, error) {
	if err := ValidateControlOperationBody(&body, schemas); err != nil {
		return ControlOperationV1{}, err
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	rawSPKI, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return ControlOperationV1{}, err
	}
	keyID, _ := AdminKeyID(rawSPKI)
	canonical, _ := MarshalCanonical(body)
	message, _ := Frame(DomainControlOperationSignature, canonical)
	return ControlOperationV1{
		Body: body,
		AuthorSignature: AdminOperationSignatureV1{
			Algorithm: "ed25519", AdminKeyID: keyID,
			Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, message)),
		},
	}, nil
}

func ControlOperationObjectID(operation *ControlOperationV1, adminSPKI []byte, trustedTime time.Time, schemas OperationSchemaRegistry) (string, error) {
	if err := VerifyControlOperation(operation, adminSPKI, trustedTime, schemas); err != nil {
		return "", err
	}
	return HashObject(DomainControlOperation, operation)
}

// ControlOperationRoot 对累计 operations 按 operation_id 排序，拒绝 ID 冲突并计算 RFC6962 root。
func ControlOperationRoot(leaves []ControlOperationLeafV1) (string, error) {
	ordered := append([]ControlOperationLeafV1(nil), leaves...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].OperationID < ordered[j].OperationID })
	canonicalLeaves := make([][]byte, len(ordered))
	for i := range ordered {
		leaf := &ordered[i]
		if leaf.Schema != 1 || !validIdentifier(leaf.OperationID, 128) {
			return "", errors.New("[D104 operation] operation leaf 无效")
		}
		if _, err := ParseHash(leaf.ObjectID); err != nil {
			return "", err
		}
		if i > 0 && ordered[i-1].OperationID == leaf.OperationID {
			return "", errors.New("[D104 operation] operation_id 冲突或重复")
		}
		canonicalLeaves[i], _ = MarshalCanonical(leaf)
	}
	return "sha256:" + hex.EncodeToString(MerkleRoot(canonicalLeaves)), nil
}

func VerifyControlOperationInclusion(leaf *ControlOperationLeafV1, index, treeSize int64, auditPath []string, head *HeadEntryV2) error {
	if leaf == nil || head == nil || leaf.Schema != 1 || !validIdentifier(leaf.OperationID, 128) {
		return errors.New("[D104 operation] inclusion leaf/head 无效")
	}
	if _, err := ParseHash(leaf.ObjectID); err != nil {
		return err
	}
	root, err := ParseHash(head.Body.Payload.OperationRoot)
	if err != nil {
		return err
	}
	path := make([][]byte, len(auditPath))
	for i, hash := range auditPath {
		path[i], err = ParseHash(hash)
		if err != nil {
			return err
		}
	}
	canonical, err := MarshalCanonical(leaf)
	if err != nil {
		return err
	}
	return VerifyMerkleInclusion(canonical, index, treeSize, path, root)
}
