package wire

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const (
	DomainDeviceConfigArtifact = "loom-device-config-artifact-bytes-v1"
	DomainDeviceEndpointBundle = "loom-device-endpoint-bundle-v1"
	DomainDeviceView           = "loom-device-view-v2"
)

type DeviceConfigArtifactRefV1 struct {
	ArtifactID       string `json:"artifact_id"`
	Generation       int64  `json:"generation"`
	Platform         string `json:"platform"`
	MediaType        string `json:"media_type"`
	RenderContractID string `json:"render_contract_id"`
	SizeBytes        int64  `json:"size_bytes"`
	ContentHash      string `json:"content_hash"`
}

type DeviceDataIngressBindingV1 struct {
	EndpointSetID   string                   `json:"endpoint_set_id"`
	EndpointSet     DataIngressEndpointSetV2 `json:"endpoint_set"`
	EndpointSetHash string                   `json:"endpoint_set_hash"`
}

type DeviceEndpointBundleV1 struct {
	Schema           int                          `json:"schema"`
	ClusterID        string                       `json:"cluster_id"`
	DeviceID         string                       `json:"device_id"`
	DeviceGeneration int64                        `json:"device_generation"`
	DataIngressSets  []DeviceDataIngressBindingV1 `json:"data_ingress_sets"`
}

type DeviceActiveViewV1 struct {
	IdentitySPKIHash       string                        `json:"identity_spki_hash"`
	Membership             EnrollmentMembershipV1        `json:"membership"`
	MembershipHash         string                        `json:"membership_hash"`
	Responsibilities       EnrollmentResponsibilitiesV1  `json:"responsibilities"`
	ResponsibilitiesHash   string                        `json:"responsibilities_hash"`
	Grants                 EnrollmentDestinationGrantsV1 `json:"grants"`
	GrantsHash             string                        `json:"grants_hash"`
	EndpointBundle         DeviceEndpointBundleV1        `json:"endpoint_bundle"`
	EndpointBundleHash     string                        `json:"endpoint_bundle_hash"`
	ConfigArtifactRefs     []DeviceConfigArtifactRefV1   `json:"config_artifact_refs"`
	SecretArtifactRefsRoot string                        `json:"secret_artifact_refs_root"`
}

type DeviceTombstoneViewV1 struct {
	Reason string `json:"reason"`
}

type DeviceViewPayloadV2 struct {
	Schema           int                    `json:"schema"`
	ClusterID        string                 `json:"cluster_id"`
	DeviceID         string                 `json:"device_id"`
	DeviceGeneration int64                  `json:"device_generation"`
	State            string                 `json:"state"`
	Active           *DeviceActiveViewV1    `json:"active,omitempty"`
	Tombstone        *DeviceTombstoneViewV1 `json:"tombstone,omitempty"`
}

type DeviceViewLeafV2 struct {
	Schema            int    `json:"schema"`
	ClusterID         string `json:"cluster_id"`
	ViewSchemaVersion int64  `json:"view_schema_version"`
	DeviceID          string `json:"device_id"`
	DeviceGeneration  int64  `json:"device_generation"`
	State             string `json:"state"`
	PayloadHash       string `json:"payload_hash"`
	PreviousViewHash  string `json:"previous_view_hash"`
	EndpointSetHash   string `json:"endpoint_set_hash"`
	MinReaderVersion  int64  `json:"min_reader_version"`
}

type SignedCurrentV2 struct {
	Schema            int             `json:"schema"`
	Head              HeadEntryV2     `json:"head"`
	QuorumCertificate json.RawMessage `json:"quorum_certificate"`
	PublishedAt       string          `json:"published_at"`
}

type DeviceViewEnvelopeV2 struct {
	Schema             int                 `json:"schema"`
	Payload            DeviceViewPayloadV2 `json:"payload"`
	Leaf               DeviceViewLeafV2    `json:"leaf"`
	LeafIndex          int64               `json:"leaf_index"`
	TreeSize           int64               `json:"tree_size"`
	AuditPath          []string            `json:"audit_path"`
	SignedCurrent      SignedCurrentV2     `json:"signed_current"`
	SecretArtifactRefs []json.RawMessage   `json:"secret_artifact_refs,omitempty"`
}

// MarshalJSON 保留 nil 与空数组的协议差异：active 的空 secret refs 必须编码为
// []，tombstone 的 nil 必须完全省略，不能被 omitempty 合并成同一 wire（D105）。
func (envelope DeviceViewEnvelopeV2) MarshalJSON() ([]byte, error) {
	type alias DeviceViewEnvelopeV2
	if envelope.SecretArtifactRefs == nil {
		return json.Marshal(alias(envelope))
	}
	return json.Marshal(struct {
		alias
		SecretArtifactRefs []json.RawMessage `json:"secret_artifact_refs"`
	}{alias: alias(envelope), SecretArtifactRefs: envelope.SecretArtifactRefs})
}

// UnmarshalJSON 同时拒绝 null 与未知字段，避免自定义 decoder 绕过 DecodeStrict
// 的 unknown-field 规则（D104、D105）。
func (envelope *DeviceViewEnvelopeV2) UnmarshalJSON(body []byte) error {
	if envelope == nil {
		return errors.New("[D105 Device view] envelope target 不能为空")
	}
	type alias DeviceViewEnvelopeV2
	decoded := struct {
		alias
		SecretArtifactRefs json.RawMessage `json:"secret_artifact_refs"`
	}{}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("[D105 Device view] envelope 含尾随 JSON")
	}
	*envelope = DeviceViewEnvelopeV2(decoded.alias)
	if len(decoded.SecretArtifactRefs) == 0 {
		envelope.SecretArtifactRefs = nil
		return nil
	}
	if bytes.Equal(decoded.SecretArtifactRefs, []byte("null")) {
		return errors.New("[D105 Device view] secret_artifact_refs 禁止 null")
	}
	var refs []json.RawMessage
	if err := json.Unmarshal(decoded.SecretArtifactRefs, &refs); err != nil || refs == nil {
		return errors.New("[D105 Device view] secret_artifact_refs 必须是数组")
	}
	envelope.SecretArtifactRefs = refs
	return nil
}

type ClientFloorsV2 struct {
	Schema                  int    `json:"schema"`
	ClusterID               string `json:"cluster_id"`
	AcceptedRecoveryEpoch   int64  `json:"accepted_recovery_epoch"`
	RecoveryStatementHash   string `json:"recovery_statement_hash"`
	RecoveryPolicyHash      string `json:"recovery_policy_hash"`
	AcceptedControlEpoch    int64  `json:"accepted_control_epoch"`
	ControlSetHash          string `json:"control_set_hash"`
	AcceptedControlRevision int64  `json:"accepted_control_revision"`
	HeadHash                string `json:"head_hash"`
	DeviceGeneration        int64  `json:"device_generation"`
	DeviceLeafHash          string `json:"device_leaf_hash"`
	DeviceViewHash          string `json:"device_view_hash"`
	BootstrapTransitionHash string `json:"bootstrap_transition_hash"`
	V2Latched               bool   `json:"v2_latched"`
}

func DeviceConfigArtifactContentHash(raw []byte) (string, error) {
	return HashCanonical(DomainDeviceConfigArtifact, raw)
}

func DeviceEndpointBundleHash(bundle *DeviceEndpointBundleV1) (string, error) {
	if err := ValidateDeviceEndpointBundle(bundle); err != nil {
		return "", err
	}
	return HashObject(DomainDeviceEndpointBundle, bundle)
}

func ValidateDeviceEndpointBundle(bundle *DeviceEndpointBundleV1) error {
	if bundle == nil || bundle.Schema != 1 || !validIdentifier(bundle.ClusterID, 128) ||
		!validIdentifier(bundle.DeviceID, 128) || bundle.DeviceGeneration < 1 {
		return errors.New("[D105 Device view] endpoint bundle header 无效")
	}
	for i := range bundle.DataIngressSets {
		binding := &bundle.DataIngressSets[i]
		if i > 0 && bundle.DataIngressSets[i-1].EndpointSetID >= binding.EndpointSetID {
			return errors.New("[D105 Device view] endpoint bindings 必须严格排序且不重复")
		}
		if binding.EndpointSetID != binding.EndpointSet.EndpointSetID || binding.EndpointSet.ClusterID != bundle.ClusterID {
			return errors.New("[D105 Device view] endpoint binding identity 不一致")
		}
		hash, err := DataIngressSetHash(&binding.EndpointSet)
		if err != nil || hash != binding.EndpointSetHash {
			return errors.New("[D105 Device view] endpoint set hash 不匹配")
		}
	}
	return nil
}

func DeviceViewHash(payload *DeviceViewPayloadV2) (string, error) {
	if err := ValidateDeviceViewPayload(payload); err != nil {
		return "", err
	}
	return HashObject(DomainDeviceView, payload)
}

func ValidateDeviceViewPayload(payload *DeviceViewPayloadV2) error {
	if payload == nil || payload.Schema != 2 || !validIdentifier(payload.ClusterID, 128) ||
		!validIdentifier(payload.DeviceID, 128) || payload.DeviceGeneration < 1 ||
		!oneOf(payload.State, "active", "revoked", "decommissioned") {
		return errors.New("[D105 Device view] payload header/state 无效")
	}
	if payload.State == "active" {
		if payload.Active == nil || payload.Tombstone != nil {
			return errors.New("[D105 Device view] active tagged union 无效")
		}
		active := payload.Active
		if active.EndpointBundle.ClusterID != payload.ClusterID || active.EndpointBundle.DeviceID != payload.DeviceID ||
			active.EndpointBundle.DeviceGeneration != payload.DeviceGeneration {
			return errors.New("[D105 Device view] active endpoint bundle identity 不一致")
		}
		if _, err := ParseHash(active.IdentitySPKIHash); err != nil {
			return err
		}
		if err := ValidateEnrollmentResponsibilities(&active.Responsibilities); err != nil {
			return err
		}
		if err := ValidateEnrollmentDestinationGrants(&active.Grants); err != nil {
			return err
		}
		membershipHash, err := HashObject("loom-enrollment-membership-v1", active.Membership)
		if err != nil || membershipHash != active.MembershipHash {
			return errors.New("[D105 Device view] membership hash 不匹配")
		}
		responsibilitiesHash, err := HashObject("loom-enrollment-responsibilities-v1", active.Responsibilities)
		if err != nil || responsibilitiesHash != active.ResponsibilitiesHash {
			return errors.New("[D105 Device view] responsibilities hash 不匹配")
		}
		grantsHash, err := HashObject("loom-enrollment-destination-grants-v1", active.Grants)
		if err != nil || grantsHash != active.GrantsHash {
			return errors.New("[D105 Device view] grants hash 不匹配")
		}
		bundleHash, err := DeviceEndpointBundleHash(&active.EndpointBundle)
		if err != nil || bundleHash != active.EndpointBundleHash {
			return errors.New("[D105 Device view] endpoint bundle hash 不匹配")
		}
		for i, ref := range active.ConfigArtifactRefs {
			if err := ValidateDeviceConfigArtifactRef(&ref); err != nil {
				return err
			}
			if i > 0 {
				previous := active.ConfigArtifactRefs[i-1]
				if previous.ArtifactID > ref.ArtifactID || previous.ArtifactID == ref.ArtifactID && previous.Generation >= ref.Generation {
					return errors.New("[D105 Device view] config refs 必须按 artifact/generation 严格排序")
				}
			}
			if _, err := ParseHash(ref.ContentHash); err != nil {
				return err
			}
		}
		if _, err := ParseHash(active.SecretArtifactRefsRoot); err != nil {
			return err
		}
		return nil
	}
	if payload.Active != nil || payload.Tombstone == nil ||
		(payload.State == "revoked" && payload.Tombstone.Reason != "revoked") ||
		(payload.State == "decommissioned" && payload.Tombstone.Reason != "decommissioned") {
		return errors.New("[D105 Device view] tombstone tagged union 无效")
	}
	return nil
}

// ValidateDeviceConfigArtifactRef 是 Device view 与客户端制品安装共用的
// 单项边界；顺序与去重仍由所属 Device view 检查（D105、D124）。
func ValidateDeviceConfigArtifactRef(ref *DeviceConfigArtifactRefV1) error {
	if ref == nil || ref.Generation < 1 || ref.SizeBytes < 1 ||
		!validIdentifier(ref.ArtifactID, 128) || !validIdentifier(ref.RenderContractID, 128) ||
		!oneOf(ref.Platform, "windows-desktop", "android", "linux-server") ||
		!oneOf(ref.MediaType, "application/vnd.loom.config+json", "application/vnd.loom.sing-box+json") {
		return errors.New("[D105 Device view] config artifact ref 无效")
	}
	if _, err := ParseHash(ref.ContentHash); err != nil {
		return err
	}
	return nil
}

func VerifyDeviceViewEnvelope(envelope *DeviceViewEnvelopeV2, set *ControlSetV1) (ClientFloorsV2, error) {
	return VerifyDeviceViewEnvelopeWithPrevious(envelope, set, nil)
}

// VerifyDeviceViewEnvelopeWithPrevious 接受 stable head 与精确 joint Final head。
// joint_head 必须显式提供 previousSet，不能从 DNS、在线 peer 或新集合推导（D112、D118）。
func VerifyDeviceViewEnvelopeWithPrevious(envelope *DeviceViewEnvelopeV2, set, previousSet *ControlSetV1) (ClientFloorsV2, error) {
	if envelope == nil || envelope.Schema != 2 || envelope.SignedCurrent.Schema != 2 {
		return ClientFloorsV2{}, errors.New("[D105 Device view] envelope/current schema 无效")
	}
	if _, err := ParseTimeZ(envelope.SignedCurrent.PublishedAt); err != nil {
		return ClientFloorsV2{}, err
	}
	var tag struct {
		QCType string `json:"qc_type"`
	}
	if _, err := CanonicalizeStrict(envelope.SignedCurrent.QuorumCertificate); err != nil {
		return ClientFloorsV2{}, err
	}
	if err := json.Unmarshal(envelope.SignedCurrent.QuorumCertificate, &tag); err != nil {
		return ClientFloorsV2{}, errors.New("[D105 Device view] head QC tag 无效")
	}
	switch tag.QCType {
	case "stable_head":
		var qc StableHeadReplicationQCV1
		if _, err := DecodeStrict(envelope.SignedCurrent.QuorumCertificate, 1<<20, &qc); err != nil {
			return ClientFloorsV2{}, err
		}
		if err := VerifyStableHeadQC(&envelope.SignedCurrent.Head, set, &qc); err != nil {
			return ClientFloorsV2{}, err
		}
	case "joint_head":
		if previousSet == nil {
			return ClientFloorsV2{}, errors.New("[D112 Device view] joint head 缺 previous exact ControlSet")
		}
		var qc JointHeadReplicationQCV1
		if _, err := DecodeStrict(envelope.SignedCurrent.QuorumCertificate, 1<<20, &qc); err != nil {
			return ClientFloorsV2{}, err
		}
		if err := VerifyJointHeadQC(&envelope.SignedCurrent.Head, previousSet, set, &qc); err != nil {
			return ClientFloorsV2{}, err
		}
	default:
		return ClientFloorsV2{}, errors.New("[D105 Device view] 未知 certified head QC type")
	}
	leaf := &envelope.Leaf
	payloadHash, err := VerifyDeviceViewProjection(&envelope.Payload, leaf, envelope.LeafIndex,
		envelope.TreeSize, envelope.AuditPath, envelope.SecretArtifactRefs,
		envelope.SignedCurrent.Head.Body.Payload.DeviceViewsRoot)
	if err != nil {
		return ClientFloorsV2{}, err
	}
	canonicalLeaf, _ := MarshalCanonical(leaf)
	leafRaw := MerkleLeafHash(canonicalLeaf)
	leafHash := "sha256:" + fmt.Sprintf("%x", leafRaw)
	head := envelope.SignedCurrent.Head
	return ClientFloorsV2{
		Schema: 2, ClusterID: leaf.ClusterID,
		AcceptedRecoveryEpoch: head.Body.Payload.RecoveryEpoch,
		RecoveryStatementHash: head.Body.Payload.RecoveryStatementHash,
		RecoveryPolicyHash:    head.Body.Payload.RecoveryPolicyHash,
		AcceptedControlEpoch:  head.Body.Payload.ControlEpoch, ControlSetHash: head.Body.Payload.ControlSetHash,
		AcceptedControlRevision: head.Body.Payload.ControlRevision, HeadHash: head.HeadHash,
		DeviceGeneration: leaf.DeviceGeneration, DeviceLeafHash: leafHash, DeviceViewHash: payloadHash,
		BootstrapTransitionHash: head.Body.TransitionProofHash, V2Latched: true,
	}, nil
}

// VerifyDeviceViewProjection 在 Head 获得 QC 前先验证 payload/leaf/root/secret refs
// 的完整投影；这样 proposer 不会先提交一份客户端永远无法接受的 Device root（D105）。
func VerifyDeviceViewProjection(payload *DeviceViewPayloadV2, leaf *DeviceViewLeafV2,
	leafIndex, treeSize int64, auditPath []string, secretArtifactRefs []json.RawMessage,
	deviceViewsRoot string) (string, error) {
	if payload == nil || leaf == nil {
		return "", errors.New("[D105 Device view] projection payload/leaf 不能为空")
	}
	payloadHash, err := DeviceViewHash(payload)
	if err != nil {
		return "", err
	}
	if leaf.Schema != 2 || leaf.ViewSchemaVersion != 2 || leaf.MinReaderVersion < 1 ||
		leaf.ClusterID != payload.ClusterID || leaf.DeviceID != payload.DeviceID ||
		leaf.DeviceGeneration != payload.DeviceGeneration || leaf.State != payload.State ||
		leaf.PayloadHash != payloadHash {
		return "", errors.New("[D105 Device view] payload/leaf 字段不一致")
	}
	if _, err := ParseHash(leaf.PreviousViewHash); err != nil {
		return "", err
	}
	if payload.State == "active" {
		if leaf.EndpointSetHash != payload.Active.EndpointBundleHash || secretArtifactRefs == nil {
			return "", errors.New("[D105 Device view] active endpoint/secret refs 不一致")
		}
		if err := VerifySecretArtifactRefsRoot(secretArtifactRefs,
			payload.Active.SecretArtifactRefsRoot); err != nil {
			return "", err
		}
	} else if leaf.EndpointSetHash != EmptyHashV1 || secretArtifactRefs != nil {
		return "", errors.New("[D105 Device view] tombstone 禁止 endpoint/secret refs")
	}
	canonicalLeaf, err := MarshalCanonical(leaf)
	if err != nil {
		return "", err
	}
	audit := make([][]byte, len(auditPath))
	for i, hash := range auditPath {
		audit[i], err = ParseHash(hash)
		if err != nil {
			return "", err
		}
	}
	root, err := ParseHash(deviceViewsRoot)
	if err != nil {
		return "", err
	}
	if err := VerifyMerkleInclusion(canonicalLeaf, leafIndex, treeSize, audit, root); err != nil {
		return "", err
	}
	return payloadHash, nil
}

// VerifyDeviceViewSuccessor 钉住 per-Device hash chain。离线客户端必须逐个重放
// generation，不能靠一个更大整数跳过撤权 tombstone，也不能从 tombstone 复活（D105、D106）。
func VerifyDeviceViewSuccessor(current, candidate *DeviceViewEnvelopeV2) error {
	if current == nil || candidate == nil || current.Payload.ClusterID != candidate.Payload.ClusterID ||
		current.Payload.DeviceID != candidate.Payload.DeviceID {
		return errors.New("[D105 Device view] successor Device/cluster binding 无效")
	}
	if candidate.Payload.DeviceGeneration < current.Payload.DeviceGeneration {
		return errors.New("[D106 Device view] Device generation 回退")
	}
	if candidate.Payload.DeviceGeneration == current.Payload.DeviceGeneration {
		currentHash, currentErr := DeviceViewHash(&current.Payload)
		candidateHash, candidateErr := DeviceViewHash(&candidate.Payload)
		if currentErr != nil || candidateErr != nil || currentHash != candidateHash ||
			candidate.Leaf.PreviousViewHash != current.Leaf.PreviousViewHash {
			return errors.New("[D106 Device view] 同 generation 出现 view 分叉")
		}
		return nil
	}
	next, err := CheckedAdd(current.Payload.DeviceGeneration, 1)
	currentHash, hashErr := DeviceViewHash(&current.Payload)
	if err != nil || hashErr != nil || candidate.Payload.DeviceGeneration != next ||
		candidate.Leaf.PreviousViewHash != currentHash {
		return errors.New("[D105 Device view] successor 必须逐代绑定 previous_view_hash")
	}
	if current.Payload.State != "active" {
		return errors.New("[D105 Device view] tombstone Device 禁止恢复为后继 view")
	}
	return nil
}

// AdvanceFloors 原子持久化前验证四组 floor；相同坐标不同 hash 一律视为 fork。
func AdvanceFloors(current, candidate ClientFloorsV2) (ClientFloorsV2, error) {
	return advanceFloors(current, candidate, floorAdvanceAuthority{})
}

type floorAdvanceAuthority struct {
	recovery bool
	control  bool
}

func advanceFloors(current, candidate ClientFloorsV2, authority floorAdvanceAuthority) (ClientFloorsV2, error) {
	if err := validateClientFloors(candidate); err != nil {
		return current, errors.New("[D106 floor] candidate floor 无效")
	}
	if current.Schema == 0 {
		return candidate, nil
	}
	if current.Schema != 2 || !current.V2Latched || current.ClusterID != candidate.ClusterID ||
		current.BootstrapTransitionHash != candidate.BootstrapTransitionHash {
		return current, errors.New("[D106 latch] v2 latch/cluster/bootstrap transition 不匹配")
	}
	if candidate.AcceptedRecoveryEpoch < current.AcceptedRecoveryEpoch {
		return current, errors.New("[D106 floor] recovery epoch 回退")
	}
	nextRecoveryEpoch, addErr := CheckedAdd(current.AcceptedRecoveryEpoch, 1)
	if addErr != nil || candidate.AcceptedRecoveryEpoch > nextRecoveryEpoch {
		return current, errors.New("[D119 floor] recovery epoch 必须逐次增加，禁止跳号")
	}
	if candidate.AcceptedRecoveryEpoch > current.AcceptedRecoveryEpoch && !authority.recovery {
		return current, errors.New("[D119 floor] recovery epoch 提升缺 transition proof")
	}
	if candidate.AcceptedRecoveryEpoch == current.AcceptedRecoveryEpoch {
		if candidate.RecoveryStatementHash != current.RecoveryStatementHash || candidate.RecoveryPolicyHash != current.RecoveryPolicyHash {
			return current, errors.New("[D106 floor] 相同 recovery epoch 出现分叉")
		}
		if candidate.AcceptedControlEpoch < current.AcceptedControlEpoch {
			return current, errors.New("[D106 floor] control epoch 回退")
		}
		nextControlEpoch, addErr := CheckedAdd(current.AcceptedControlEpoch, 1)
		if addErr != nil || candidate.AcceptedControlEpoch > nextControlEpoch {
			return current, errors.New("[D112 floor] control epoch 必须逐次增加，禁止跳号")
		}
		if candidate.AcceptedControlEpoch > current.AcceptedControlEpoch && !authority.control {
			return current, errors.New("[D112 floor] control epoch 提升缺 Joint→Final transition proof")
		}
		if candidate.AcceptedControlEpoch == current.AcceptedControlEpoch {
			if candidate.ControlSetHash != current.ControlSetHash {
				return current, errors.New("[D106 floor] 相同 control epoch 出现 ControlSet 分叉")
			}
			if candidate.AcceptedControlRevision < current.AcceptedControlRevision {
				return current, errors.New("[D106 floor] control revision 回退")
			}
			if candidate.AcceptedControlRevision == current.AcceptedControlRevision && candidate.HeadHash != current.HeadHash {
				return current, errors.New("[D106 floor] 相同 control revision 出现 head 分叉")
			}
		}
	}
	if candidate.DeviceGeneration < current.DeviceGeneration {
		return current, errors.New("[D106 floor] Device generation 回退")
	}
	if candidate.DeviceGeneration == current.DeviceGeneration &&
		(!bytes.Equal([]byte(candidate.DeviceLeafHash), []byte(current.DeviceLeafHash)) || candidate.DeviceViewHash != current.DeviceViewHash) {
		return current, errors.New("[D106 floor] 相同 Device generation 出现 view 分叉")
	}
	return candidate, nil
}

func validateClientFloors(floor ClientFloorsV2) error {
	if floor.Schema != 2 || !floor.V2Latched || !validIdentifier(floor.ClusterID, 128) ||
		floor.AcceptedRecoveryEpoch < 0 || floor.AcceptedControlEpoch < 0 || floor.AcceptedControlRevision < 1 || floor.DeviceGeneration < 1 {
		return errors.New("floor coordinates invalid")
	}
	for _, hash := range []string{floor.RecoveryStatementHash, floor.RecoveryPolicyHash, floor.ControlSetHash,
		floor.HeadHash, floor.DeviceLeafHash, floor.DeviceViewHash, floor.BootstrapTransitionHash} {
		if _, err := ParseHash(hash); err != nil {
			return err
		}
	}
	return nil
}
