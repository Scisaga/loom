package loomcore

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"loom/internal/wire"
)

type canonicalGolden struct {
	Schema  int `json:"schema"`
	Vectors []struct {
		Name      string `json:"name"`
		Input     string `json:"input"`
		Canonical string `json:"canonical"`
		Domain    string `json:"domain"`
		Hash      string `json:"hash"`
	} `json:"vectors"`
	Malicious []struct {
		Name  string `json:"name"`
		Input string `json:"input"`
	} `json:"malicious"`
}

type androidV2DeviceState struct {
	Schema             int                              `json:"schema"`
	Floors             wire.ClientFloorsV2              `json:"floors"`
	Envelope           wire.DeviceViewEnvelopeV2        `json:"envelope"`
	ControlSet         *wire.ControlSetV1               `json:"control_set,omitempty"`
	PreviousControlSet *wire.ControlSetV1               `json:"previous_control_set,omitempty"`
	Enrollment         *androidEnrollmentInstallationV1 `json:"enrollment,omitempty"`
}

// CanonicalizeV2/HashCanonicalV2 向 Kotlin 暴露同一 Go verifier，避免 Android
// 另写一套会产生细微分叉的 JSON/signature 语义。
func CanonicalizeV2(input []byte) ([]byte, error) {
	return wire.CanonicalizeStrict(input)
}

func HashCanonicalV2(domain string, canonical []byte) (string, error) {
	return wire.HashCanonical(domain, canonical)
}

// VerifyCanonicalGolden 让 Android instrumentation 使用交付 AAR 与仓库唯一
// golden 文件验证相同语义。
func VerifyCanonicalGolden(goldenJSON []byte) error {
	var golden canonicalGolden
	if _, err := wire.DecodeStrict(goldenJSON, 1<<20, &golden); err != nil || golden.Schema != 1 {
		return errors.New("[Android] shared golden schema 无效")
	}
	for _, vector := range golden.Vectors {
		canonical, err := wire.CanonicalizeStrict([]byte(vector.Input))
		if err != nil || !bytes.Equal(canonical, []byte(vector.Canonical)) {
			return errors.New("[Android] golden canonical bytes 不匹配: " + vector.Name)
		}
		hash, err := wire.HashCanonical(vector.Domain, canonical)
		if err != nil || hash != vector.Hash {
			return errors.New("[Android] golden hash 不匹配: " + vector.Name)
		}
	}
	for _, vector := range golden.Malicious {
		if _, err := wire.CanonicalizeStrict([]byte(vector.Input)); err == nil {
			return errors.New("[Android] malicious golden 被接受: " + vector.Name)
		}
	}
	return nil
}

// PrepareV2DeviceState 是 Android v2 的单一提交边界：strict wire、ControlSet
// QC、Merkle inclusion、本机 identity 与四组 floor 全部通过后才返回状态 bytes。
// binding 永远不接收 private key。
func PrepareV2DeviceState(envelopeJSON, controlSetJSON []byte, expectedDeviceID, expectedIdentitySPKIHash string, currentStateJSON []byte) ([]byte, error) {
	return PrepareV2DeviceStateWithPrevious(envelopeJSON, controlSetJSON, nil, expectedDeviceID, expectedIdentitySPKIHash, currentStateJSON)
}

func PrepareV2DeviceStateWithPrevious(envelopeJSON, controlSetJSON, previousControlSetJSON []byte, expectedDeviceID, expectedIdentitySPKIHash string, currentStateJSON []byte) ([]byte, error) {
	if expectedDeviceID == "" || expectedIdentitySPKIHash == "" {
		return nil, errors.New("[Android] local Device/identity binding 缺失")
	}
	if len(currentStateJSON) == 0 {
		return nil, errors.New("[Android] 首次 v2 latch 必须绑定 verified Invite proof")
	}
	var envelope wire.DeviceViewEnvelopeV2
	if err := decodeExactAndroidV2(envelopeJSON, 32<<20, &envelope, "Device view"); err != nil {
		return nil, err
	}
	var set wire.ControlSetV1
	if err := decodeExactAndroidV2(controlSetJSON, 1<<20, &set, "ControlSet"); err != nil {
		return nil, err
	}
	var previousSet *wire.ControlSetV1
	if len(previousControlSetJSON) > 0 {
		var decoded wire.ControlSetV1
		if err := decodeExactAndroidV2(previousControlSetJSON, 1<<20, &decoded, "previous ControlSet"); err != nil {
			return nil, err
		}
		previousSet = &decoded
	}
	floors, err := wire.VerifyDeviceViewEnvelopeWithPrevious(&envelope, &set, previousSet)
	if err != nil {
		return nil, err
	}
	if envelope.Payload.DeviceID != expectedDeviceID || envelope.Payload.State == "active" && envelope.Payload.Active.IdentitySPKIHash != expectedIdentitySPKIHash {
		return nil, errors.New("[Android] Device view 与本机 Keystore identity 不匹配")
	}
	current, err := decodeAndroidV2DeviceState(currentStateJSON)
	if err != nil {
		return nil, err
	}
	if current.Envelope.Payload.DeviceID != expectedDeviceID ||
		current.Envelope.Payload.State == "active" &&
			current.Envelope.Payload.Active.IdentitySPKIHash != expectedIdentitySPKIHash {
		return nil, errors.New("[Android] protected v2 state 与本机 Keystore identity 不匹配")
	}
	if err := wire.VerifyDeviceViewSuccessor(&current.Envelope, &envelope); err != nil {
		return nil, err
	}
	nextSetHash, _ := wire.ControlSetHash(&set)
	if current.ControlSet != nil && nextSetHash != current.Floors.ControlSetHash &&
		(previousSet == nil || !wire.EqualCanonical(*current.ControlSet, *previousSet)) {
		return nil, errors.New("[Android] ControlSet 过渡未延续 protected current set")
	}
	nextFloors, err := wire.AdvanceFloors(current.Floors, floors)
	if err != nil {
		return nil, err
	}
	setCopy := set
	var previousCopy *wire.ControlSetV1
	if previousSet != nil {
		copied := *previousSet
		previousCopy = &copied
	}
	return marshalAndroidV2DeviceState(androidV2DeviceState{
		Schema: 1, Floors: nextFloors, Envelope: envelope, ControlSet: &setCopy,
		PreviousControlSet: previousCopy, Enrollment: current.Enrollment,
	})
}

// PrepareAndroidV2PrivateDeviceViewUpdate 只接受当前 protected ControlSet 能独立
// 验证、且无需尚未获取 artifact 的 private Device view。配置/secret 变化必须走
// “先验证 refs、取回并原子安装”事务，不能先推进 floor。
func PrepareAndroidV2PrivateDeviceViewUpdate(currentStateJSON, envelopeJSON,
	identitySPKIDER []byte,
) ([]byte, error) {
	current, err := decodeAndroidV2DeviceState(currentStateJSON)
	if err != nil {
		return nil, err
	}
	if current.ControlSet == nil || current.Enrollment == nil {
		return nil, errors.New("[Android config] protected ControlSet/Enrollment 不完整")
	}
	identityHash, err := wire.HashBytes(wire.DomainEnrollmentIdentitySPKI, identitySPKIDER)
	if err != nil || identityHash != current.Enrollment.IdentityKeyHash {
		return nil, errors.New("[Android config] Keystore identity 与 protected state 不匹配")
	}
	var envelope wire.DeviceViewEnvelopeV2
	if err := decodeExactAndroidV2(envelopeJSON, 32<<20, &envelope, "private Device view"); err != nil {
		return nil, err
	}
	if envelope.Payload.State == "active" {
		if current.Envelope.Payload.Active == nil || envelope.Payload.Active == nil ||
			!wire.EqualCanonical(envelope.Payload.Active.ConfigArtifactRefs,
				current.Envelope.Payload.Active.ConfigArtifactRefs) ||
			!equalRawAndroidV2(envelope.SecretArtifactRefs, current.Envelope.SecretArtifactRefs) {
			return nil, errors.New("[Android config] Device view artifact refs 已变化，必须原子取回后安装")
		}
	}
	setJSON, err := wire.MarshalCanonical(current.ControlSet)
	if err != nil {
		return nil, err
	}
	var previousJSON []byte
	var qcTag struct {
		QCType string `json:"qc_type"`
	}
	if err := json.Unmarshal(envelope.SignedCurrent.QuorumCertificate, &qcTag); err != nil {
		return nil, errors.New("[Android config] Device view QC tag 无效")
	}
	if qcTag.QCType == "joint_head" && current.PreviousControlSet != nil {
		previousJSON, err = wire.MarshalCanonical(current.PreviousControlSet)
		if err != nil {
			return nil, err
		}
	}
	return PrepareV2DeviceStateWithPrevious(envelopeJSON, setJSON, previousJSON,
		current.Envelope.Payload.DeviceID, identityHash, currentStateJSON)
}

// PrepareAndroidV2PrivateDeviceConfigUpdate 从 protected exact Head 重放服务端
// 保留窗口，并一次性返回 final view/floors/ControlSet。artifact refs 变化仍须由
// 后续“取回全部 artifact 后一起提交”的事务处理。
func PrepareAndroidV2PrivateDeviceConfigUpdate(currentStateJSON, deliveryJSON,
	identitySPKIDER []byte,
) ([]byte, error) {
	current, _, verified, err := verifyAndroidV2PrivateDeviceConfigDelivery(
		currentStateJSON, deliveryJSON, identitySPKIDER)
	if err != nil {
		return nil, err
	}
	envelope := verified.Envelope()
	if envelope.Payload.State == "active" &&
		(current.Envelope.Payload.Active == nil || envelope.Payload.Active == nil ||
			!wire.EqualCanonical(envelope.Payload.Active.ConfigArtifactRefs,
				current.Envelope.Payload.Active.ConfigArtifactRefs) ||
			!equalRawAndroidV2(envelope.SecretArtifactRefs, current.Envelope.SecretArtifactRefs)) {
		return nil, errors.New("[Android config] Device view artifact refs 已变化，必须原子取回后安装")
	}
	if envelope.Payload.State != "active" && current.Enrollment != nil {
		current.Enrollment.Configs = nil
		current.Enrollment.Credentials = []androidInstalledSecretV1{}
		emptyRefs := []wire.SecretArtifactRefV2{}
		current.Enrollment.CurrentSecretArtifactRefs = &emptyRefs
	}
	set := verified.ControlSet()
	return marshalAndroidV2DeviceState(androidV2DeviceState{
		Schema: 1, Floors: verified.Floors(), Envelope: envelope, ControlSet: &set,
		PreviousControlSet: verified.PreviousControlSet(), Enrollment: current.Enrollment,
	})
}

// PrepareAndroidV2PrivateDeviceConfigUpdateWithConfigs 在全部新 config 已由 ref
// 重绑后，把 configs 与 final view/floors/ControlSet 放入同一个 EncryptedStore blob。
func PrepareAndroidV2PrivateDeviceConfigUpdateWithConfigs(currentStateJSON, deliveryJSON,
	installedConfigsJSON, identitySPKIDER []byte,
) ([]byte, error) {
	current, _, verified, err := verifyAndroidV2PrivateDeviceConfigDelivery(
		currentStateJSON, deliveryJSON, identitySPKIDER)
	if err != nil {
		return nil, err
	}
	if current.Enrollment == nil {
		return nil, errors.New("[Android config] enrollment installation 缺失")
	}
	envelope := verified.Envelope()
	var configs []androidInstalledConfigV1
	if envelope.Payload.State != "active" {
		if len(installedConfigsJSON) != 0 {
			return nil, errors.New("[Android config] tombstone 禁止新 artifact")
		}
		current.Enrollment.Credentials = []androidInstalledSecretV1{}
		emptyRefs := []wire.SecretArtifactRefV2{}
		current.Enrollment.CurrentSecretArtifactRefs = &emptyRefs
	} else {
		if err := decodeExactAndroidV2(installedConfigsJSON, androidMaximumConfigTotalBytes+(4<<20),
			&configs, "private installed configs"); err != nil || configs == nil {
			return nil, errors.New("[Android config] installed configs 不是 canonical array")
		}
		if !equalRawAndroidV2(envelope.SecretArtifactRefs, current.Envelope.SecretArtifactRefs) {
			return nil, errors.New("[Android config] secret refs 已变化，必须先取回并原子解封")
		}
	}
	current.Enrollment.Configs = configs
	set := verified.ControlSet()
	return marshalAndroidV2DeviceState(androidV2DeviceState{
		Schema: 1, Floors: verified.Floors(), Envelope: envelope, ControlSet: &set,
		PreviousControlSet: verified.PreviousControlSet(), Enrollment: current.Enrollment,
	})
}

// PrepareAndroidV2PrivateDeviceConfigUpdateWithArtifacts 是动态 artifact 轮换的
// 唯一提交边界：只有已重绑的 config/credential 全部到齐，才与 final
// view、floors 和 ControlSet 一起替换 protected blob。
func PrepareAndroidV2PrivateDeviceConfigUpdateWithArtifacts(currentStateJSON, deliveryJSON,
	installedConfigsJSON, installedSecretsJSON, identitySPKIDER []byte,
) ([]byte, error) {
	current, _, verified, err := verifyAndroidV2PrivateDeviceConfigDelivery(
		currentStateJSON, deliveryJSON, identitySPKIDER)
	if err != nil {
		return nil, err
	}
	if current.Enrollment == nil {
		return nil, errors.New("[Android config] enrollment installation 缺失")
	}
	envelope := verified.Envelope()
	if envelope.Payload.State != "active" {
		if len(installedConfigsJSON) != 0 || len(installedSecretsJSON) != 0 {
			return nil, errors.New("[Android config] tombstone 禁止新 artifact")
		}
		current.Enrollment.Configs = nil
		current.Enrollment.Credentials = []androidInstalledSecretV1{}
		emptyRefs := []wire.SecretArtifactRefV2{}
		current.Enrollment.CurrentSecretArtifactRefs = &emptyRefs
	} else {
		if envelope.Payload.Active == nil || current.Envelope.Payload.Active == nil {
			return nil, errors.New("[Android config] active Device view 缺失")
		}
		configChanged := !wire.EqualCanonical(envelope.Payload.Active.ConfigArtifactRefs,
			current.Envelope.Payload.Active.ConfigArtifactRefs)
		secretsChanged := !equalRawAndroidV2(envelope.SecretArtifactRefs,
			current.Envelope.SecretArtifactRefs)
		if configChanged {
			var configs []androidInstalledConfigV1
			if err := decodeExactAndroidV2(installedConfigsJSON,
				androidMaximumConfigTotalBytes+(4<<20), &configs,
				"private installed configs"); err != nil || configs == nil {
				return nil, errors.New("[Android config] 新 installed configs 不是 canonical array")
			}
			current.Enrollment.Configs = configs
		} else if len(installedConfigsJSON) != 0 {
			return nil, errors.New("[Android config] config refs 未变更却提交了 artifact")
		}
		if secretsChanged {
			var credentials []androidInstalledSecretV1
			if err := decodeExactAndroidV2(installedSecretsJSON, 16<<20, &credentials,
				"private installed credentials"); err != nil || credentials == nil {
				return nil, errors.New("[Android config] 新 installed credentials 不是 canonical array")
			}
			refs, err := decodeAndroidSecretArtifactRefs(envelope.SecretArtifactRefs)
			if err != nil {
				return nil, err
			}
			current.Enrollment.Credentials = credentials
			current.Enrollment.CurrentSecretArtifactRefs = cloneAndroidSecretArtifactRefs(refs)
		} else if len(installedSecretsJSON) != 0 {
			return nil, errors.New("[Android config] secret refs 未变更却提交了 credential")
		}
	}
	set := verified.ControlSet()
	return marshalAndroidV2DeviceState(androidV2DeviceState{
		Schema: 1, Floors: verified.Floors(), Envelope: envelope, ControlSet: &set,
		PreviousControlSet: verified.PreviousControlSet(), Enrollment: current.Enrollment,
	})
}

func decodeAndroidSecretArtifactRefs(raw []json.RawMessage) ([]wire.SecretArtifactRefV2, error) {
	refs := make([]wire.SecretArtifactRefV2, len(raw))
	for index := range raw {
		if err := decodeExactAndroidV2(raw[index], 4<<20, &refs[index],
			"private secret artifact ref"); err != nil {
			return nil, err
		}
	}
	return refs, nil
}

func verifyAndroidV2PrivateDeviceConfigDelivery(currentStateJSON, deliveryJSON,
	identitySPKIDER []byte,
) (androidV2DeviceState, wire.DeviceConfigDeliveryV1,
	wire.VerifiedDeviceConfigDeliveryV1, error,
) {
	current, err := decodeAndroidV2DeviceState(currentStateJSON)
	if err != nil {
		return androidV2DeviceState{}, wire.DeviceConfigDeliveryV1{},
			wire.VerifiedDeviceConfigDeliveryV1{}, err
	}
	if current.ControlSet == nil || current.Enrollment == nil {
		return androidV2DeviceState{}, wire.DeviceConfigDeliveryV1{},
			wire.VerifiedDeviceConfigDeliveryV1{},
			errors.New("[Android config] protected ControlSet/Enrollment 不完整")
	}
	identityHash, err := wire.HashBytes(wire.DomainEnrollmentIdentitySPKI, identitySPKIDER)
	if err != nil || identityHash != current.Enrollment.IdentityKeyHash {
		return androidV2DeviceState{}, wire.DeviceConfigDeliveryV1{},
			wire.VerifiedDeviceConfigDeliveryV1{},
			errors.New("[Android config] Keystore identity 与 protected state 不匹配")
	}
	var delivery wire.DeviceConfigDeliveryV1
	if err := decodeExactAndroidV2(deliveryJSON, 32<<20, &delivery, "private Device delivery"); err != nil {
		return androidV2DeviceState{}, wire.DeviceConfigDeliveryV1{},
			wire.VerifiedDeviceConfigDeliveryV1{}, err
	}
	verified, err := wire.VerifyDeviceConfigDeliveryFromProtected(&delivery, &current.Envelope,
		current.Floors, current.ControlSet, current.PreviousControlSet,
		current.Envelope.Payload.DeviceID, identityHash)
	if err != nil {
		return androidV2DeviceState{}, wire.DeviceConfigDeliveryV1{},
			wire.VerifiedDeviceConfigDeliveryV1{}, err
	}
	return current, delivery, verified, nil
}

func equalRawAndroidV2(left, right []json.RawMessage) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if !bytes.Equal(left[index], right[index]) {
			return false
		}
	}
	return true
}

// PrepareInitialV2DeviceStateFromInvite 是 fresh Android Enrollment 的唯一首次
// latch 入口。ControlSet 与 candidate floors 必须延续 exact public Invite proof
// 的已验证 authority，不能由 Activity 或响应字段自行指定。
func PrepareInitialV2DeviceStateFromInvite(envelopeJSON, controlSetJSON, descriptorJSON,
	proofBundleJSON []byte, expectedDeviceID, expectedIdentitySPKIHash, trustedTime string) ([]byte, error) {
	if expectedDeviceID == "" || expectedIdentitySPKIHash == "" {
		return nil, errors.New("[Android] initial Device/identity binding 缺失")
	}
	now, err := wire.ParseTimeZ(trustedTime)
	if err != nil {
		return nil, errors.New("[Android] Invite proof trusted time 无效")
	}
	var envelope wire.DeviceViewEnvelopeV2
	if err := decodeExactAndroidV2(envelopeJSON, 32<<20, &envelope, "initial Device view"); err != nil {
		return nil, err
	}
	var set wire.ControlSetV1
	if err := decodeExactAndroidV2(controlSetJSON, 1<<20, &set, "initial ControlSet"); err != nil {
		return nil, err
	}
	var descriptor wire.InviteBootstrapDescriptorV2
	if err := decodeExactAndroidV2(descriptorJSON, 8<<20, &descriptor, "Invite descriptor"); err != nil {
		return nil, err
	}
	var bundle wire.InviteProofBundleV2
	if err := decodeExactAndroidV2(proofBundleJSON, 32<<20, &bundle, "Invite proof bundle"); err != nil {
		return nil, err
	}
	verified, err := wire.VerifyInviteProofBundle(&bundle, &descriptor, now, wire.InviteProofTrustV2{})
	if err != nil {
		return nil, err
	}
	state, err := prepareInitialAndroidV2DeviceStateFromVerified(
		envelope, set, verified, expectedDeviceID, expectedIdentitySPKIHash,
	)
	if err != nil {
		return nil, err
	}
	return marshalAndroidV2DeviceState(state)
}

func prepareInitialAndroidV2DeviceStateFromVerified(envelope wire.DeviceViewEnvelopeV2,
	set wire.ControlSetV1, verified wire.VerifiedInviteProofV2,
	expectedDeviceID, expectedIdentitySPKIHash string,
) (androidV2DeviceState, error) {
	if expectedDeviceID == "" || expectedIdentitySPKIHash == "" {
		return androidV2DeviceState{}, errors.New("[Android] initial Device/identity binding 缺失")
	}
	proofSet, proofHead := verified.ControlSet(), verified.Head()
	if verified.CertifiedInviteRecordHash() == "" || !wire.EqualCanonical(proofSet, set) {
		return androidV2DeviceState{}, errors.New("[Android] initial ControlSet 未绑定 verified Invite proof")
	}
	floors, err := wire.VerifyDeviceViewEnvelope(&envelope, &set)
	if err != nil {
		return androidV2DeviceState{}, err
	}
	if envelope.Payload.DeviceID != expectedDeviceID || envelope.Payload.State != "active" ||
		envelope.Payload.DeviceGeneration != 1 || envelope.Payload.Active == nil ||
		envelope.Payload.Active.IdentitySPKIHash != expectedIdentitySPKIHash {
		return androidV2DeviceState{}, errors.New("[Android] initial Device view 与 Enrollment identity 不匹配")
	}
	if floors.ClusterID != proofHead.Body.Payload.ClusterID ||
		floors.AcceptedRecoveryEpoch != proofHead.Body.Payload.RecoveryEpoch ||
		floors.RecoveryStatementHash != proofHead.Body.Payload.RecoveryStatementHash ||
		floors.RecoveryPolicyHash != proofHead.Body.Payload.RecoveryPolicyHash ||
		floors.AcceptedControlEpoch != proofHead.Body.Payload.ControlEpoch ||
		floors.ControlSetHash != proofHead.Body.Payload.ControlSetHash ||
		floors.BootstrapTransitionHash != proofHead.Body.TransitionProofHash ||
		floors.AcceptedControlRevision < proofHead.Body.Payload.ControlRevision {
		return androidV2DeviceState{}, errors.New("[Android] initial Device view 未延续 verified Invite authority")
	}
	setCopy := set
	return androidV2DeviceState{Schema: 1, Floors: floors, Envelope: envelope,
		ControlSet: &setCopy}, nil
}

func V2DeviceStateFloors(stateJSON []byte) ([]byte, error) {
	state, err := decodeAndroidV2DeviceState(stateJSON)
	if err != nil {
		return nil, err
	}
	return wire.MarshalCanonical(state.Floors)
}

func marshalAndroidV2DeviceState(state androidV2DeviceState) ([]byte, error) {
	if err := validateAndroidV2DeviceState(&state); err != nil {
		return nil, err
	}
	return wire.MarshalCanonical(state)
}

func decodeAndroidV2DeviceState(body []byte) (androidV2DeviceState, error) {
	var state androidV2DeviceState
	if err := decodeExactAndroidV2(body, 64<<20, &state, "protected v2 state"); err != nil {
		return state, err
	}
	if err := validateAndroidV2DeviceState(&state); err != nil {
		return state, err
	}
	return state, nil
}

func validateAndroidV2DeviceState(state *androidV2DeviceState) error {
	if state == nil || state.Schema != 1 || !state.Floors.V2Latched {
		return errors.New("[Android] protected v2 state header 无效")
	}
	envelope := &state.Envelope
	head := &envelope.SignedCurrent.Head
	if _, err := wire.ParseTimeZ(envelope.SignedCurrent.PublishedAt); err != nil {
		return errors.New("[Android] protected SignedCurrent time 无效")
	}
	canonicalQC, err := wire.CanonicalizeStrict(envelope.SignedCurrent.QuorumCertificate)
	if err != nil || !bytes.Equal(canonicalQC, envelope.SignedCurrent.QuorumCertificate) {
		return errors.New("[Android] protected Head QC 不是 exact canonical wire")
	}
	rebuiltHead, err := wire.NewHeadEntry(head.Body)
	if err != nil || !wire.EqualCanonical(rebuiltHead, *head) {
		return errors.New("[Android] protected Head hash/entry hash 无效")
	}
	payloadHash, err := wire.VerifyDeviceViewProjection(&envelope.Payload, &envelope.Leaf,
		envelope.LeafIndex, envelope.TreeSize, envelope.AuditPath, envelope.SecretArtifactRefs,
		head.Body.Payload.DeviceViewsRoot)
	if err != nil {
		return err
	}
	leafBytes, err := wire.MarshalCanonical(envelope.Leaf)
	if err != nil {
		return err
	}
	leafHash := fmt.Sprintf("sha256:%x", wire.MerkleLeafHash(leafBytes))
	floors := state.Floors
	if floors.ClusterID != envelope.Payload.ClusterID ||
		floors.AcceptedRecoveryEpoch != head.Body.Payload.RecoveryEpoch ||
		floors.RecoveryStatementHash != head.Body.Payload.RecoveryStatementHash ||
		floors.RecoveryPolicyHash != head.Body.Payload.RecoveryPolicyHash ||
		floors.AcceptedControlEpoch != head.Body.Payload.ControlEpoch ||
		floors.ControlSetHash != head.Body.Payload.ControlSetHash ||
		floors.AcceptedControlRevision != head.Body.Payload.ControlRevision ||
		floors.HeadHash != head.HeadHash || floors.DeviceGeneration != envelope.Payload.DeviceGeneration ||
		floors.DeviceLeafHash != leafHash || floors.DeviceViewHash != payloadHash ||
		head.Body.Payload.HeadKind == "bootstrap" &&
			floors.BootstrapTransitionHash != head.Body.TransitionProofHash {
		return errors.New("[Android] protected floors 与同一 Device LKG 不一致")
	}
	if _, err := wire.AdvanceFloors(wire.ClientFloorsV2{}, floors); err != nil {
		return errors.New("[Android] protected floors wire 无效")
	}
	if state.ControlSet != nil {
		setHash, err := wire.ControlSetHash(state.ControlSet)
		if err != nil || setHash != floors.ControlSetHash ||
			state.ControlSet.ClusterID != floors.ClusterID {
			return errors.New("[Android] protected ControlSet 与 floors 不一致")
		}
		if state.PreviousControlSet != nil {
			if err := wire.ValidateControlSet(state.PreviousControlSet); err != nil ||
				state.PreviousControlSet.ClusterID != floors.ClusterID {
				return errors.New("[Android] protected previous ControlSet 无效")
			}
		}
		verifiedFloors, verifyErr := wire.VerifyDeviceViewEnvelopeWithPrevious(
			envelope, state.ControlSet, state.PreviousControlSet,
		)
		if verifyErr == nil && head.Body.Payload.HeadKind != "bootstrap" {
			verifiedFloors.BootstrapTransitionHash = floors.BootstrapTransitionHash
		}
		if verifyErr != nil || !wire.EqualCanonical(verifiedFloors, floors) {
			return errors.New("[Android] protected Device view/ControlSet/QC 不可重放")
		}
	}
	if state.Enrollment != nil {
		if err := validateAndroidEnrollmentInstallation(state.Enrollment, envelope); err != nil {
			return err
		}
	}
	return nil
}

func decodeExactAndroidV2(body []byte, maximum int, target any, name string) error {
	canonical, err := wire.DecodeStrict(body, maximum, target)
	if err != nil {
		return err
	}
	if !bytes.Equal(canonical, body) {
		return errors.New("[Android] " + name + " 不是 exact canonical wire")
	}
	return nil
}

// EnrollmentClaimCoreHashV2 让宿主只组装字段，所有 SPKI/CSR/profile exact
// binding 仍由共享 verifier 完成。
func EnrollmentClaimCoreHashV2(coreJSON []byte) (string, error) {
	var core wire.EnrollmentClaimCoreV2
	if err := decodeExactAndroidV2(coreJSON, 4<<20, &core, "Enrollment claim core"); err != nil {
		return "", err
	}
	return wire.EnrollmentClaimCoreHash(&core)
}

// EnrollmentPoPMessageV2 返回 Android Keystore identity key 应签的 exact
// framed bytes；私钥不会跨过 Kotlin callback 边界。
func EnrollmentPoPMessageV2(popBodyJSON []byte) ([]byte, error) {
	var body wire.EnrollmentPoPBodyV2
	if err := decodeExactAndroidV2(popBodyJSON, 1<<20, &body, "Enrollment PoP body"); err != nil {
		return nil, err
	}
	return wire.EnrollmentPoPMessage(&body)
}

// PrepareSealedSecretP256UnsealV2 先把授权 ref 与下载到的 immutable envelope
// 逐字段绑定，再向 Kotlin 投影硬件 ECDH 所需公开输入。
func PrepareSealedSecretP256UnsealV2(refJSON, envelopeJSON []byte, recipientID string, recipientGeneration int64, recipientSPKIDER []byte) ([]byte, error) {
	var ref wire.SecretArtifactRefV2
	if err := decodeExactAndroidV2(refJSON, 4<<20, &ref, "secret artifact ref"); err != nil {
		return nil, err
	}
	var envelope wire.SealedSecretEnvelopeV1
	if err := decodeExactAndroidV2(envelopeJSON, 32<<20, &envelope, "sealed secret envelope"); err != nil {
		return nil, err
	}
	if err := wire.VerifySealedSecretBinding(&ref, &envelope); err != nil {
		return nil, err
	}
	inputs, err := wire.PrepareP256UnsealInputs(&envelope, recipientID, recipientGeneration, recipientSPKIDER)
	if err != nil {
		return nil, err
	}
	return wire.MarshalCanonical(inputs)
}

// DeriveSealedSecretP256KEKV2 接收 Keystore ECDH 输出，私钥不跨 binding。
func DeriveSealedSecretP256KEKV2(sharedSecret, wrapContextJSON []byte) ([]byte, error) {
	var context wire.RecipientWrapContextV1
	if err := decodeExactAndroidV2(wrapContextJSON, 1<<20, &context, "recipient wrap context"); err != nil {
		return nil, err
	}
	return wire.DeriveSealedSecretP256KEK(sharedSecret, context)
}

// PrepareSealedSecretRSAUnsealV2 对 API 26–30 执行同一 ref/envelope binding，
// Kotlin 只把 exact OAEP ciphertext 交给 PURPOSE_DECRYPT alias。
func PrepareSealedSecretRSAUnsealV2(refJSON, envelopeJSON []byte, recipientID string, recipientGeneration int64, recipientSPKIDER []byte) ([]byte, error) {
	var ref wire.SecretArtifactRefV2
	if err := decodeExactAndroidV2(refJSON, 4<<20, &ref, "secret artifact ref"); err != nil {
		return nil, err
	}
	var envelope wire.SealedSecretEnvelopeV1
	if err := decodeExactAndroidV2(envelopeJSON, 32<<20, &envelope, "sealed secret envelope"); err != nil {
		return nil, err
	}
	if err := wire.VerifySealedSecretBinding(&ref, &envelope); err != nil {
		return nil, err
	}
	inputs, err := wire.PrepareRSAUnsealInputs(&envelope, recipientID, recipientGeneration, recipientSPKIDER)
	if err != nil {
		return nil, err
	}
	return wire.MarshalCanonical(inputs)
}

// FinishSealedSecretPlaintextV2 重新验证内嵌 context 后才返回 secret bytes。
func FinishSealedSecretPlaintextV2(plaintext, expectedContextJSON []byte) ([]byte, error) {
	var context wire.SealedSecretContextV1
	if err := decodeExactAndroidV2(expectedContextJSON, 1<<20, &context, "sealed secret context"); err != nil {
		return nil, err
	}
	return wire.FinishSealedSecretPlaintext(plaintext, context)
}
