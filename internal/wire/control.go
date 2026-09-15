package wire

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sort"
)

const (
	DomainControlSet                 = "loom-control-set-v1"
	DomainHeadEntry                  = "loom-raft-head-entry-v2"
	DomainControlHead                = "loom-control-head-v2"
	DomainHeadReplicationAttestation = "loom-head-replication-attestation-v1"
	DomainQuorumCertificate          = "loom-quorum-certificate-v1"
)

// ControlMemberV1 只携公开 opaque member/key，不泄露 Device 或 peer 拓扑（D124）。
type ControlMemberV1 struct {
	Schema                 int    `json:"schema"`
	ClusterID              string `json:"cluster_id"`
	MemberID               string `json:"member_id"`
	MembershipKeyID        string `json:"membership_key_id"`
	MembershipPublicKey    string `json:"membership_public_key"`
	ConfigKeyID            string `json:"config_key_id"`
	ConfigPublicKey        string `json:"config_public_key"`
	EnrollmentKeyID        string `json:"enrollment_key_id"`
	EnrollmentPublicKey    string `json:"enrollment_public_key"`
	MinimumControlProtocol int64  `json:"minimum_control_protocol"`
}

type ControlSetV1 struct {
	Schema    int               `json:"schema"`
	ClusterID string            `json:"cluster_id"`
	Members   []ControlMemberV1 `json:"members"`
}

type ControlConfigSignatureV1 struct {
	Algorithm   string `json:"algorithm"`
	MemberID    string `json:"member_id"`
	ConfigKeyID string `json:"config_key_id"`
	Signature   string `json:"signature"`
}

type ControlConfigSignerRefV1 struct {
	MemberID    string `json:"member_id"`
	ConfigKeyID string `json:"config_key_id"`
}

type OrdinaryHeadContextV1 struct {
	Schema int    `json:"schema"`
	Kind   string `json:"kind"`
}

type BootstrapHeadContextV1 struct {
	Schema                   int    `json:"schema"`
	Kind                     string `json:"kind"`
	InitialV2HeadPayloadHash string `json:"initial_v2_head_payload_hash"`
}

type FinalControlSetContextV1 struct {
	Schema                      int    `json:"schema"`
	Kind                        string `json:"kind"`
	TransitionID                string `json:"transition_id"`
	OldControlEpoch             int64  `json:"old_control_epoch"`
	OldControlSetHash           string `json:"old_control_set_hash"`
	OldControlPeerDirectoryHash string `json:"old_control_peer_directory_hash"`
	NewControlEpoch             int64  `json:"new_control_epoch"`
	NewControlSetHash           string `json:"new_control_set_hash"`
	NewControlPeerDirectoryHash string `json:"new_control_peer_directory_hash"`
	MembershipApprovalProofHash string `json:"membership_approval_proof_hash"`
	JointEntryHash              string `json:"joint_entry_hash"`
	JointProofHash              string `json:"joint_proof_hash"`
}

type RecoveryGenesisContextV1 struct {
	Schema             int    `json:"schema"`
	Kind               string `json:"kind"`
	GenesisPayloadHash string `json:"genesis_payload_hash"`
}

type RecoveryPolicyActivationContextV1 struct {
	Schema         int    `json:"schema"`
	Kind           string `json:"kind"`
	IntentHash     string `json:"intent_hash"`
	IntentHeadHash string `json:"intent_head_hash"`
	IntentQCHash   string `json:"intent_qc_hash"`
}

type HeadEntryPayloadV2 struct {
	Schema                      int             `json:"schema"`
	HeadKind                    string          `json:"head_kind"`
	ClusterID                   string          `json:"cluster_id"`
	RecoveryEpoch               int64           `json:"recovery_epoch"`
	RecoveryStatementHash       string          `json:"recovery_statement_hash"`
	RecoveryPolicyHash          string          `json:"recovery_policy_hash"`
	ControlEpoch                int64           `json:"control_epoch"`
	ControlSetHash              string          `json:"control_set_hash"`
	ControlPeerDirectoryHash    string          `json:"control_peer_directory_hash"`
	RaftTerm                    int64           `json:"raft_term"`
	RaftIndex                   int64           `json:"raft_index"`
	PreviousLogEntryHash        string          `json:"previous_log_entry_hash"`
	ControlRevision             int64           `json:"control_revision"`
	ParentHeadHash              string          `json:"parent_head_hash"`
	OperationRoot               string          `json:"operation_root"`
	SnapshotHash                string          `json:"snapshot_hash"`
	EffectiveSSOTHash           string          `json:"effective_ssot_hash"`
	DeviceViewsRoot             string          `json:"device_views_root"`
	AdminACLRoot                string          `json:"admin_acl_root"`
	CAProfileRoot               string          `json:"ca_profile_root"`
	BootstrapIssuerRegistryRoot string          `json:"bootstrap_issuer_registry_root"`
	RenderContractVersion       int64           `json:"render_contract_version"`
	MinReaderVersion            int64           `json:"min_reader_version"`
	CommittedLogicalTime        string          `json:"committed_logical_time"`
	MaxClockSkewSeconds         int64           `json:"max_clock_skew_seconds"`
	TransitionContext           json.RawMessage `json:"transition_context"`
}

type HeadEntryBodyV2 struct {
	Payload             HeadEntryPayloadV2 `json:"payload"`
	TransitionProofHash string             `json:"transition_proof_hash"`
}

type HeadEntryV2 struct {
	Body      HeadEntryBodyV2 `json:"body"`
	EntryHash string          `json:"entry_hash"`
	HeadHash  string          `json:"head_hash"`
}

type HeadReplicationAttestationBodyV1 struct {
	Schema                      int    `json:"schema"`
	AttestationType             string `json:"attestation_type"`
	ClusterID                   string `json:"cluster_id"`
	RecoveryEpoch               int64  `json:"recovery_epoch"`
	RecoveryStatementHash       string `json:"recovery_statement_hash"`
	RecoveryPolicyHash          string `json:"recovery_policy_hash"`
	ControlEpoch                int64  `json:"control_epoch"`
	ControlSetHash              string `json:"control_set_hash"`
	ControlPeerDirectoryHash    string `json:"control_peer_directory_hash"`
	RaftTerm                    int64  `json:"raft_term"`
	RaftIndex                   int64  `json:"raft_index"`
	PreviousLogEntryHash        string `json:"previous_log_entry_hash"`
	ControlRevision             int64  `json:"control_revision"`
	EntryHash                   string `json:"entry_hash"`
	HeadHash                    string `json:"head_hash"`
	ParentHeadHash              string `json:"parent_head_hash"`
	TransitionProofHash         string `json:"transition_proof_hash"`
	OperationRoot               string `json:"operation_root"`
	SnapshotHash                string `json:"snapshot_hash"`
	EffectiveSSOTHash           string `json:"effective_ssot_hash"`
	DeviceViewsRoot             string `json:"device_views_root"`
	AdminACLRoot                string `json:"admin_acl_root"`
	CAProfileRoot               string `json:"ca_profile_root"`
	BootstrapIssuerRegistryRoot string `json:"bootstrap_issuer_registry_root"`
	RenderContractVersion       int64  `json:"render_contract_version"`
	MinReaderVersion            int64  `json:"min_reader_version"`
	CommittedLogicalTime        string `json:"committed_logical_time"`
	MaxClockSkewSeconds         int64  `json:"max_clock_skew_seconds"`
}

// StableHeadReplicationQCV1 是稳定集合的提交后多数证明。
type StableHeadReplicationQCV1 struct {
	Schema      int                              `json:"schema"`
	QCType      string                           `json:"qc_type"`
	Attestation HeadReplicationAttestationBodyV1 `json:"attestation"`
	Signatures  []ControlConfigSignatureV1       `json:"signatures"`
	SignerRefs  []ControlConfigSignerRefV1       `json:"signer_refs"`
}

type JointHeadReplicationQCV1 struct {
	Schema        int                              `json:"schema"`
	QCType        string                           `json:"qc_type"`
	Attestation   HeadReplicationAttestationBodyV1 `json:"attestation"`
	Signatures    []ControlConfigSignatureV1       `json:"signatures"`
	OldSignerRefs []ControlConfigSignerRefV1       `json:"old_signer_refs"`
	NewSignerRefs []ControlConfigSignerRefV1       `json:"new_signer_refs"`
}

func Quorum(memberCount int) (int, error) {
	if memberCount < 1 {
		return 0, errors.New("[D100 ControlSet] ControlSet 必须至少有一个成员")
	}
	return memberCount/2 + 1, nil
}

func ControlKeyID(publicKey []byte) (string, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return "", errors.New("[D102 key] control public key 必须是 32-byte Ed25519 raw key")
	}
	sum := sha256.Sum256(publicKey)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func ValidateControlSet(set *ControlSetV1) error {
	if set == nil || set.Schema != 1 || !validIdentifier(set.ClusterID, 128) || len(set.Members) == 0 {
		return errors.New("[D100 ControlSet] schema/cluster/members 无效")
	}
	memberIDs := make(map[string]struct{}, len(set.Members))
	keyIDs := make(map[string]struct{}, len(set.Members)*3)
	publicKeys := make(map[string]struct{}, len(set.Members)*3)
	for i := range set.Members {
		member := &set.Members[i]
		if member.Schema != 1 || member.ClusterID != set.ClusterID || !ValidMemberID(member.MemberID) ||
			member.MinimumControlProtocol < 1 {
			return fmt.Errorf("[D112 ControlSet] member %d 字段无效", i)
		}
		if i > 0 && set.Members[i-1].MemberID >= member.MemberID {
			return errors.New("[D112 ControlSet] members 必须按 member_id 严格排序且不重复")
		}
		if _, found := memberIDs[member.MemberID]; found {
			return errors.New("[D112 ControlSet] member_id 重复")
		}
		memberIDs[member.MemberID] = struct{}{}
		pairs := []struct{ id, key, purpose string }{
			{member.MembershipKeyID, member.MembershipPublicKey, "membership"},
			{member.ConfigKeyID, member.ConfigPublicKey, "config"},
			{member.EnrollmentKeyID, member.EnrollmentPublicKey, "enrollment"},
		}
		for _, pair := range pairs {
			raw, err := decodeRawURL(pair.key, ed25519.PublicKeySize)
			if err != nil {
				return fmt.Errorf("[D102 key] member %s 的 %s key 无效: %w", member.MemberID, pair.purpose, err)
			}
			wantID, _ := ControlKeyID(raw)
			if pair.id != wantID {
				return fmt.Errorf("[D102 key] member %s 的 %s key_id 不匹配", member.MemberID, pair.purpose)
			}
			if _, found := keyIDs[pair.id]; found {
				return errors.New("[D102 key] ControlSet 内 key_id 跨成员/用途重复")
			}
			if _, found := publicKeys[pair.key]; found {
				return errors.New("[D102 key] ControlSet 内 public key 跨成员/用途复用")
			}
			keyIDs[pair.id], publicKeys[pair.key] = struct{}{}, struct{}{}
		}
	}
	return nil
}

func ControlSetHash(set *ControlSetV1) (string, error) {
	if err := ValidateControlSet(set); err != nil {
		return "", err
	}
	return HashObject(DomainControlSet, set)
}

// NewHeadEntry 只进行纯函数构造；term/index/time 都必须由调用方注入。
func NewHeadEntry(body HeadEntryBodyV2) (HeadEntryV2, error) {
	entryHash, err := HashObject(DomainHeadEntry, body)
	if err != nil {
		return HeadEntryV2{}, err
	}
	headHash, err := HashObject(DomainControlHead, body)
	if err != nil {
		return HeadEntryV2{}, err
	}
	entry := HeadEntryV2{Body: body, EntryHash: entryHash, HeadHash: headHash}
	if err := ValidateHeadEntry(&entry, nil); err != nil {
		return HeadEntryV2{}, err
	}
	return entry, nil
}

func ValidateHeadEntry(entry *HeadEntryV2, parent *HeadEntryV2) error {
	if entry == nil || entry.Body.Payload.Schema != 2 {
		return errors.New("[D104 Raft] HeadEntry schema 无效")
	}
	payload := &entry.Body.Payload
	if !validIdentifier(payload.ClusterID, 128) || payload.RecoveryEpoch < 0 || payload.ControlEpoch < 0 ||
		payload.RaftTerm < 1 || payload.RaftIndex < 1 || payload.ControlRevision != payload.RaftIndex ||
		payload.RenderContractVersion < 1 || payload.MinReaderVersion < 1 ||
		payload.MaxClockSkewSeconds < 0 || payload.MaxClockSkewSeconds > 300 {
		return errors.New("[D104 Raft] HeadEntry 坐标/版本/clock skew 无效")
	}
	if _, err := ParseTimeZ(payload.CommittedLogicalTime); err != nil {
		return err
	}
	hashes := []string{payload.RecoveryStatementHash, payload.RecoveryPolicyHash, payload.ControlSetHash,
		payload.ControlPeerDirectoryHash, payload.PreviousLogEntryHash, payload.ParentHeadHash,
		payload.OperationRoot, payload.SnapshotHash, payload.EffectiveSSOTHash, payload.DeviceViewsRoot,
		payload.AdminACLRoot, payload.CAProfileRoot, payload.BootstrapIssuerRegistryRoot,
		entry.Body.TransitionProofHash, entry.EntryHash, entry.HeadHash}
	for _, hash := range hashes {
		if _, err := ParseHash(hash); err != nil {
			return err
		}
	}
	if err := validateTransitionContext(payload.HeadKind, payload.TransitionContext); err != nil {
		return err
	}
	wantEntry, err := HashObject(DomainHeadEntry, entry.Body)
	if err != nil || wantEntry != entry.EntryHash {
		return errors.New("[D104 Raft] entry_hash 不匹配")
	}
	wantHead, err := HashObject(DomainControlHead, entry.Body)
	if err != nil || wantHead != entry.HeadHash {
		return errors.New("[D104 Raft] head_hash 不匹配")
	}
	if parent == nil {
		if payload.HeadKind == "bootstrap" {
			if payload.RaftIndex != 1 || payload.ControlRevision != 1 ||
				payload.PreviousLogEntryHash != EmptyHashV1 || payload.ParentHeadHash != EmptyHashV1 {
				return errors.New("[D111 bootstrap] 初始 head 前项/坐标无效")
			}
		}
		return nil
	}
	if err := ValidateHeadEntry(parent, nil); err != nil {
		return fmt.Errorf("[D104 Raft] parent 无效: %w", err)
	}
	if payload.ClusterID != parent.Body.Payload.ClusterID || payload.ParentHeadHash != parent.HeadHash ||
		payload.RaftIndex <= parent.Body.Payload.RaftIndex ||
		payload.ControlRevision != payload.RaftIndex ||
		payload.RaftTerm < parent.Body.Payload.RaftTerm {
		return errors.New("[D104 Raft] head/entry hash chain 或 term/index 不连续")
	}
	// parent 是前一份 certified Head，而 previous_log_entry_hash 指向真实 Raft
	// 直接前项；两份 Head 间允许存在 current-term barrier 等内部 entry（D104）。
	if payload.RaftIndex == parent.Body.Payload.RaftIndex+1 && payload.PreviousLogEntryHash != parent.EntryHash {
		return errors.New("[D104 Raft] 相邻 head 的 previous log hash 不匹配")
	}
	if payload.HeadKind == "ordinary" {
		previous := &parent.Body.Payload
		if payload.RecoveryEpoch != previous.RecoveryEpoch ||
			payload.RecoveryStatementHash != previous.RecoveryStatementHash ||
			payload.RecoveryPolicyHash != previous.RecoveryPolicyHash ||
			payload.ControlEpoch != previous.ControlEpoch || payload.ControlSetHash != previous.ControlSetHash ||
			payload.ControlPeerDirectoryHash != previous.ControlPeerDirectoryHash ||
			entry.Body.TransitionProofHash != parent.Body.TransitionProofHash {
			return errors.New("[D104 Raft] ordinary head 不能改变 authority/transition")
		}
	}
	return nil
}

func AttestationForHead(entry *HeadEntryV2) HeadReplicationAttestationBodyV1 {
	p := entry.Body.Payload
	return HeadReplicationAttestationBodyV1{
		Schema: 1, AttestationType: "head", ClusterID: p.ClusterID,
		RecoveryEpoch: p.RecoveryEpoch, RecoveryStatementHash: p.RecoveryStatementHash,
		RecoveryPolicyHash: p.RecoveryPolicyHash, ControlEpoch: p.ControlEpoch,
		ControlSetHash: p.ControlSetHash, ControlPeerDirectoryHash: p.ControlPeerDirectoryHash,
		RaftTerm: p.RaftTerm, RaftIndex: p.RaftIndex, PreviousLogEntryHash: p.PreviousLogEntryHash,
		ControlRevision: p.ControlRevision, EntryHash: entry.EntryHash, HeadHash: entry.HeadHash,
		ParentHeadHash: p.ParentHeadHash, TransitionProofHash: entry.Body.TransitionProofHash,
		OperationRoot: p.OperationRoot, SnapshotHash: p.SnapshotHash, EffectiveSSOTHash: p.EffectiveSSOTHash,
		DeviceViewsRoot: p.DeviceViewsRoot, AdminACLRoot: p.AdminACLRoot, CAProfileRoot: p.CAProfileRoot,
		BootstrapIssuerRegistryRoot: p.BootstrapIssuerRegistryRoot,
		RenderContractVersion:       p.RenderContractVersion, MinReaderVersion: p.MinReaderVersion,
		CommittedLogicalTime: p.CommittedLogicalTime, MaxClockSkewSeconds: p.MaxClockSkewSeconds,
	}
}

func SignHeadAttestation(attestation HeadReplicationAttestationBodyV1, member ControlMemberV1, key ed25519.PrivateKey) (ControlConfigSignatureV1, error) {
	if len(key) != ed25519.PrivateKeySize {
		return ControlConfigSignatureV1{}, errors.New("[D102 key] config private key 无效")
	}
	public := key.Public().(ed25519.PublicKey)
	encoded := base64.RawURLEncoding.EncodeToString(public)
	if encoded != member.ConfigPublicKey {
		return ControlConfigSignatureV1{}, errors.New("[D102 key] config private key 与 member 不匹配")
	}
	canonical, err := MarshalCanonical(attestation)
	if err != nil {
		return ControlConfigSignatureV1{}, err
	}
	message, err := Frame(DomainHeadReplicationAttestation, canonical)
	if err != nil {
		return ControlConfigSignatureV1{}, err
	}
	return ControlConfigSignatureV1{
		Algorithm: "ed25519", MemberID: member.MemberID, ConfigKeyID: member.ConfigKeyID,
		Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, message)),
	}, nil
}

func VerifyStableHeadQC(entry *HeadEntryV2, set *ControlSetV1, qc *StableHeadReplicationQCV1) error {
	if err := ValidateHeadEntry(entry, nil); err != nil {
		return err
	}
	if err := ValidateControlSet(set); err != nil {
		return err
	}
	setHash, _ := ControlSetHash(set)
	if entry.Body.Payload.ControlSetHash != setHash || qc == nil || qc.Schema != 1 || qc.QCType != "stable_head" {
		return errors.New("[D104 QC] stable QC/set/head 绑定无效")
	}
	wantAttestation := AttestationForHead(entry)
	wantCanonical, _ := MarshalCanonical(wantAttestation)
	gotCanonical, err := MarshalCanonical(qc.Attestation)
	if err != nil || !bytes.Equal(wantCanonical, gotCanonical) {
		return errors.New("[D104 QC] attestation 与 HeadEntry 不一致")
	}
	if len(qc.Signatures) != len(qc.SignerRefs) {
		return errors.New("[D104 QC] signature/ref 数量不一致")
	}
	threshold, _ := Quorum(len(set.Members))
	if len(qc.Signatures) < threshold {
		return errors.New("[D104 QC] 未达到 committed ControlSet quorum")
	}
	members := make(map[string]ControlMemberV1, len(set.Members))
	for _, member := range set.Members {
		members[member.MemberID] = member
	}
	message, _ := Frame(DomainHeadReplicationAttestation, wantCanonical)
	for i, signature := range qc.Signatures {
		if i > 0 && compareSigner(qc.Signatures[i-1].MemberID, qc.Signatures[i-1].ConfigKeyID, signature.MemberID, signature.ConfigKeyID) >= 0 {
			return errors.New("[D104 QC] signatures 必须严格排序且不重复")
		}
		ref := qc.SignerRefs[i]
		if ref.MemberID != signature.MemberID || ref.ConfigKeyID != signature.ConfigKeyID ||
			(i > 0 && compareSigner(qc.SignerRefs[i-1].MemberID, qc.SignerRefs[i-1].ConfigKeyID, ref.MemberID, ref.ConfigKeyID) >= 0) {
			return errors.New("[D104 QC] signer refs 必须与 signatures 同序同字段")
		}
		member, ok := members[signature.MemberID]
		if !ok || signature.Algorithm != "ed25519" || member.ConfigKeyID != signature.ConfigKeyID {
			return errors.New("[D102 key] QC signer/key purpose 无效")
		}
		public, err := decodeRawURL(member.ConfigPublicKey, ed25519.PublicKeySize)
		if err != nil {
			return err
		}
		rawSignature, err := decodeRawURL(signature.Signature, ed25519.SignatureSize)
		if err != nil || !ed25519.Verify(public, message, rawSignature) {
			return errors.New("[D104 QC] config attestation 签名无效")
		}
	}
	return nil
}

func VerifyHeadAttestationSignature(entry *HeadEntryV2, signature *ControlConfigSignatureV1,
	set *ControlSetV1) error {
	if entry == nil || signature == nil {
		return errors.New("[D104 QC] head/signature 不能为空")
	}
	if err := ValidateHeadEntry(entry, nil); err != nil {
		return err
	}
	if err := ValidateControlSet(set); err != nil {
		return err
	}
	setHash, _ := ControlSetHash(set)
	if entry.Body.Payload.ControlSetHash != setHash {
		return errors.New("[D104 QC] attestation signature 使用错误 ControlSet")
	}
	var member *ControlMemberV1
	for index := range set.Members {
		if set.Members[index].MemberID == signature.MemberID {
			member = &set.Members[index]
			break
		}
	}
	if member == nil || signature.Algorithm != "ed25519" || member.ConfigKeyID != signature.ConfigKeyID {
		return errors.New("[D102 key] attestation signer/key purpose 无效")
	}
	canonical, _ := MarshalCanonical(AttestationForHead(entry))
	message, _ := Frame(DomainHeadReplicationAttestation, canonical)
	public, err := decodeRawURL(member.ConfigPublicKey, ed25519.PublicKeySize)
	if err != nil {
		return err
	}
	rawSignature, err := decodeRawURL(signature.Signature, ed25519.SignatureSize)
	if err != nil || !ed25519.Verify(public, message, rawSignature) {
		return errors.New("[D104 QC] config attestation signature 无效")
	}
	return nil
}

func StableQC(entry *HeadEntryV2, signatures []ControlConfigSignatureV1) StableHeadReplicationQCV1 {
	sorted := append([]ControlConfigSignatureV1(nil), signatures...)
	sort.Slice(sorted, func(i, j int) bool {
		return compareSigner(sorted[i].MemberID, sorted[i].ConfigKeyID, sorted[j].MemberID, sorted[j].ConfigKeyID) < 0
	})
	refs := make([]ControlConfigSignerRefV1, len(sorted))
	for i := range sorted {
		refs[i] = ControlConfigSignerRefV1{MemberID: sorted[i].MemberID, ConfigKeyID: sorted[i].ConfigKeyID}
	}
	return StableHeadReplicationQCV1{Schema: 1, QCType: "stable_head", Attestation: AttestationForHead(entry), Signatures: sorted, SignerRefs: refs}
}

func QCStableHash(qc *StableHeadReplicationQCV1) (string, error) {
	return HashObject(DomainQuorumCertificate, qc)
}

func JointHeadQC(entry *HeadEntryV2, signatures []ControlConfigSignatureV1, oldSet, newSet *ControlSetV1) JointHeadReplicationQCV1 {
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
	return JointHeadReplicationQCV1{Schema: 1, QCType: "joint_head", Attestation: AttestationForHead(entry), Signatures: sorted, OldSignerRefs: refsFor(oldSet), NewSignerRefs: refsFor(newSet)}
}

func VerifyJointHeadQC(entry *HeadEntryV2, oldSet, newSet *ControlSetV1, qc *JointHeadReplicationQCV1) error {
	if err := ValidateHeadEntry(entry, nil); err != nil {
		return err
	}
	if err := ValidateControlSet(oldSet); err != nil {
		return err
	}
	if err := ValidateControlSet(newSet); err != nil {
		return err
	}
	newHash, _ := ControlSetHash(newSet)
	if oldSet.ClusterID != newSet.ClusterID || entry.Body.Payload.ClusterID != newSet.ClusterID || entry.Body.Payload.ControlSetHash != newHash || qc == nil || qc.Schema != 1 || qc.QCType != "joint_head" {
		return errors.New("[D112 joint QC] old/new set/head 绑定无效")
	}
	wantAttestation := AttestationForHead(entry)
	wantCanonical, _ := MarshalCanonical(wantAttestation)
	gotCanonical, err := MarshalCanonical(qc.Attestation)
	if err != nil || !bytes.Equal(wantCanonical, gotCanonical) {
		return errors.New("[D112 joint QC] attestation 与 HeadEntry 不一致")
	}
	union := make(map[string]ControlMemberV1, len(oldSet.Members)+len(newSet.Members))
	for _, set := range []*ControlSetV1{oldSet, newSet} {
		for _, member := range set.Members {
			union[member.MemberID+"\x00"+member.ConfigKeyID] = member
		}
	}
	message, _ := Frame(DomainHeadReplicationAttestation, wantCanonical)
	for i, signature := range qc.Signatures {
		if i > 0 && compareSigner(qc.Signatures[i-1].MemberID, qc.Signatures[i-1].ConfigKeyID, signature.MemberID, signature.ConfigKeyID) >= 0 {
			return errors.New("[D112 joint QC] signatures 必须严格排序且不重复")
		}
		member, ok := union[signature.MemberID+"\x00"+signature.ConfigKeyID]
		if !ok || signature.Algorithm != "ed25519" || signature.ConfigKeyID != member.ConfigKeyID {
			return errors.New("[D112 joint QC] signer/key 无效")
		}
		public, _ := decodeRawURL(member.ConfigPublicKey, ed25519.PublicKeySize)
		rawSignature, err := decodeRawURL(signature.Signature, ed25519.SignatureSize)
		if err != nil || !ed25519.Verify(public, message, rawSignature) {
			return errors.New("[D112 joint QC] signature 无效")
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

func verifyJointRefs(refs []ControlConfigSignerRefV1, signatures []ControlConfigSignatureV1, set *ControlSetV1) error {
	quorum, _ := Quorum(len(set.Members))
	if len(refs) < quorum {
		return errors.New("[D112 joint QC] 一侧 signer refs 未达到 committed set quorum")
	}
	members := make(map[string]string, len(set.Members))
	for _, member := range set.Members {
		members[member.MemberID] = member.ConfigKeyID
	}
	signed := make(map[string]struct{}, len(signatures))
	for _, signature := range signatures {
		signed[signature.MemberID+"\x00"+signature.ConfigKeyID] = struct{}{}
	}
	for i, ref := range refs {
		_, hasSignature := signed[ref.MemberID+"\x00"+ref.ConfigKeyID]
		if i > 0 && compareSigner(refs[i-1].MemberID, refs[i-1].ConfigKeyID, ref.MemberID, ref.ConfigKeyID) >= 0 || members[ref.MemberID] != ref.ConfigKeyID || !hasSignature {
			return errors.New("[D112 joint QC] signer refs 未排序、重复或未绑定 signature/set")
		}
	}
	return nil
}

func QCJointHeadHash(qc *JointHeadReplicationQCV1) (string, error) {
	return HashObject(DomainQuorumCertificate, qc)
}

func ValidMemberID(value string) bool {
	const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	if len(value) != 26 || value[0] < '0' || value[0] > '7' {
		return false
	}
	number := new(big.Int)
	for _, character := range value {
		index := bytes.IndexByte([]byte(alphabet), byte(character))
		if index < 0 {
			return false
		}
		number.Lsh(number, 5)
		number.Or(number, big.NewInt(int64(index)))
	}
	return len(number.Bytes()) <= 16
}

func decodeRawURL(value string, size int) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(raw) != size || base64.RawURLEncoding.EncodeToString(raw) != value {
		return nil, errors.New("必须是规范无 padding base64url")
	}
	return raw, nil
}

func validIdentifier(value string, maximum int) bool {
	if len(value) == 0 || len(value) > maximum {
		return false
	}
	for _, character := range value {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	return true
}

func validateTransitionContext(kind string, body []byte) error {
	if len(body) == 0 {
		return errors.New("[D104 Raft] transition_context 缺失")
	}
	switch kind {
	case "ordinary":
		var context OrdinaryHeadContextV1
		if _, err := DecodeStrict(body, 4096, &context); err != nil || context.Schema != 1 || context.Kind != "ordinary" {
			return errors.New("[D104 Raft] ordinary transition_context 无效")
		}
		return nil
	case "bootstrap":
		var context BootstrapHeadContextV1
		if _, err := DecodeStrict(body, 4096, &context); err != nil || context.Schema != 1 || context.Kind != kind || requireCanonicalHashes(context.InitialV2HeadPayloadHash) != nil {
			return errors.New("[D111 bootstrap] bootstrap transition_context 无效")
		}
		return nil
	case "control_set_final":
		var context FinalControlSetContextV1
		if _, err := DecodeStrict(body, 16<<10, &context); err != nil || context.Schema != 1 || context.Kind != kind ||
			!validIdentifier(context.TransitionID, 128) || context.OldControlEpoch < 0 || context.OldControlEpoch == int64(^uint64(0)>>1) || context.NewControlEpoch != context.OldControlEpoch+1 ||
			requireCanonicalHashes(context.OldControlSetHash, context.OldControlPeerDirectoryHash,
				context.NewControlSetHash, context.NewControlPeerDirectoryHash, context.MembershipApprovalProofHash,
				context.JointEntryHash, context.JointProofHash) != nil {
			return errors.New("[D112 joint] FinalControlSet transition_context 无效")
		}
		return nil
	case "emergency_recovery":
		var context RecoveryGenesisContextV1
		if _, err := DecodeStrict(body, 4096, &context); err != nil || context.Schema != 1 || context.Kind != kind || requireCanonicalHashes(context.GenesisPayloadHash) != nil {
			return errors.New("[D119 recovery] recovery genesis transition_context 无效")
		}
		return nil
	case "recovery_policy_activation":
		var context RecoveryPolicyActivationContextV1
		if _, err := DecodeStrict(body, 4096, &context); err != nil || context.Schema != 1 || context.Kind != kind ||
			requireCanonicalHashes(context.IntentHash, context.IntentHeadHash, context.IntentQCHash) != nil {
			return errors.New("[D116 recovery] recovery policy activation context 无效")
		}
		return nil
	case "legacy_runtime_activation":
		var context RuntimeActivationContextV1
		if _, err := DecodeStrict(body, 4096, &context); err != nil || context.Schema != 1 || context.Kind != kind ||
			requireCanonicalHashes(context.StatementHash) != nil {
			return errors.New("[D104 runtime activation] 旧 daemon 迁移 context 无效")
		}
		return nil
	default:
		return fmt.Errorf("[D104 Raft] 未知 head_kind %q", kind)
	}
}

func requireCanonicalHashes(values ...string) error {
	for _, value := range values {
		if _, err := ParseHash(value); err != nil {
			return err
		}
	}
	return nil
}

func compareSigner(leftMember, leftKey, rightMember, rightKey string) int {
	if leftMember < rightMember {
		return -1
	}
	if leftMember > rightMember {
		return 1
	}
	if leftKey < rightKey {
		return -1
	}
	if leftKey > rightKey {
		return 1
	}
	return 0
}
