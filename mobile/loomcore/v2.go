package loomcore

import (
	"bytes"
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
	Schema     int                              `json:"schema"`
	Floors     wire.ClientFloorsV2              `json:"floors"`
	Envelope   wire.DeviceViewEnvelopeV2        `json:"envelope"`
	Enrollment *androidEnrollmentInstallationV1 `json:"enrollment,omitempty"`
}

// CanonicalizeV2/HashCanonicalV2 向 Kotlin 暴露同一 Go verifier，避免 Android
// 另写一套会产生细微分叉的 JSON/signature 语义（D104）。
func CanonicalizeV2(input []byte) ([]byte, error) {
	return wire.CanonicalizeStrict(input)
}

func HashCanonicalV2(domain string, canonical []byte) (string, error) {
	return wire.HashCanonical(domain, canonical)
}

// VerifyCanonicalGolden 让 Android instrumentation 使用交付 AAR 与仓库唯一
// golden 文件验证相同语义（D104）。
func VerifyCanonicalGolden(goldenJSON []byte) error {
	var golden canonicalGolden
	if _, err := wire.DecodeStrict(goldenJSON, 1<<20, &golden); err != nil || golden.Schema != 1 {
		return errors.New("[D104 Android] shared golden schema 无效")
	}
	for _, vector := range golden.Vectors {
		canonical, err := wire.CanonicalizeStrict([]byte(vector.Input))
		if err != nil || !bytes.Equal(canonical, []byte(vector.Canonical)) {
			return errors.New("[D104 Android] golden canonical bytes 不匹配: " + vector.Name)
		}
		hash, err := wire.HashCanonical(vector.Domain, canonical)
		if err != nil || hash != vector.Hash {
			return errors.New("[D104 Android] golden hash 不匹配: " + vector.Name)
		}
	}
	for _, vector := range golden.Malicious {
		if _, err := wire.CanonicalizeStrict([]byte(vector.Input)); err == nil {
			return errors.New("[D104 Android] malicious golden 被接受: " + vector.Name)
		}
	}
	return nil
}

// PrepareV2DeviceState 是 Android v2 的单一提交边界：strict wire、ControlSet
// QC、Merkle inclusion、本机 identity 与四组 floor 全部通过后才返回状态 bytes。
// binding 永远不接收 private key（D105、D106）。
func PrepareV2DeviceState(envelopeJSON, controlSetJSON []byte, expectedDeviceID, expectedIdentitySPKIHash string, currentStateJSON []byte) ([]byte, error) {
	return PrepareV2DeviceStateWithPrevious(envelopeJSON, controlSetJSON, nil, expectedDeviceID, expectedIdentitySPKIHash, currentStateJSON)
}

func PrepareV2DeviceStateWithPrevious(envelopeJSON, controlSetJSON, previousControlSetJSON []byte, expectedDeviceID, expectedIdentitySPKIHash string, currentStateJSON []byte) ([]byte, error) {
	if expectedDeviceID == "" || expectedIdentitySPKIHash == "" {
		return nil, errors.New("[D105 Android] local Device/identity binding 缺失")
	}
	if len(currentStateJSON) == 0 {
		return nil, errors.New("[D106 Android] 首次 v2 latch 必须绑定 verified Invite proof")
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
		return nil, errors.New("[D105 Android] Device view 与本机 Keystore identity 不匹配")
	}
	current, err := decodeAndroidV2DeviceState(currentStateJSON)
	if err != nil {
		return nil, err
	}
	if current.Envelope.Payload.DeviceID != expectedDeviceID ||
		current.Envelope.Payload.State == "active" &&
			current.Envelope.Payload.Active.IdentitySPKIHash != expectedIdentitySPKIHash {
		return nil, errors.New("[D106 Android] protected v2 state 与本机 Keystore identity 不匹配")
	}
	nextFloors, err := wire.AdvanceFloors(current.Floors, floors)
	if err != nil {
		return nil, err
	}
	return marshalAndroidV2DeviceState(androidV2DeviceState{
		Schema: 1, Floors: nextFloors, Envelope: envelope, Enrollment: current.Enrollment,
	})
}

// PrepareInitialV2DeviceStateFromInvite 是 fresh Android Enrollment 的唯一首次
// latch 入口。ControlSet 与 candidate floors 必须延续 exact public Invite proof
// 的已验证 authority，不能由 Activity 或响应字段自行指定（D106、D115）。
func PrepareInitialV2DeviceStateFromInvite(envelopeJSON, controlSetJSON, descriptorJSON,
	proofBundleJSON []byte, expectedDeviceID, expectedIdentitySPKIHash, trustedTime string) ([]byte, error) {
	if expectedDeviceID == "" || expectedIdentitySPKIHash == "" {
		return nil, errors.New("[D105 Android] initial Device/identity binding 缺失")
	}
	now, err := wire.ParseTimeZ(trustedTime)
	if err != nil {
		return nil, errors.New("[D115 Android] Invite proof trusted time 无效")
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
		return androidV2DeviceState{}, errors.New("[D105 Android] initial Device/identity binding 缺失")
	}
	proofSet, proofHead := verified.ControlSet(), verified.Head()
	if verified.CertifiedInviteRecordHash() == "" || !wire.EqualCanonical(proofSet, set) {
		return androidV2DeviceState{}, errors.New("[D115 Android] initial ControlSet 未绑定 verified Invite proof")
	}
	floors, err := wire.VerifyDeviceViewEnvelope(&envelope, &set)
	if err != nil {
		return androidV2DeviceState{}, err
	}
	if envelope.Payload.DeviceID != expectedDeviceID || envelope.Payload.State != "active" ||
		envelope.Payload.DeviceGeneration != 1 || envelope.Payload.Active == nil ||
		envelope.Payload.Active.IdentitySPKIHash != expectedIdentitySPKIHash {
		return androidV2DeviceState{}, errors.New("[D105 Android] initial Device view 与 Enrollment identity 不匹配")
	}
	if floors.ClusterID != proofHead.Body.Payload.ClusterID ||
		floors.AcceptedRecoveryEpoch != proofHead.Body.Payload.RecoveryEpoch ||
		floors.RecoveryStatementHash != proofHead.Body.Payload.RecoveryStatementHash ||
		floors.RecoveryPolicyHash != proofHead.Body.Payload.RecoveryPolicyHash ||
		floors.AcceptedControlEpoch != proofHead.Body.Payload.ControlEpoch ||
		floors.ControlSetHash != proofHead.Body.Payload.ControlSetHash ||
		floors.BootstrapTransitionHash != proofHead.Body.TransitionProofHash ||
		floors.AcceptedControlRevision < proofHead.Body.Payload.ControlRevision {
		return androidV2DeviceState{}, errors.New("[D115 Android] initial Device view 未延续 verified Invite authority")
	}
	return androidV2DeviceState{Schema: 1, Floors: floors, Envelope: envelope}, nil
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
	if err := decodeExactAndroidV2(body, 32<<20, &state, "protected v2 state"); err != nil {
		return state, err
	}
	if err := validateAndroidV2DeviceState(&state); err != nil {
		return state, err
	}
	return state, nil
}

func validateAndroidV2DeviceState(state *androidV2DeviceState) error {
	if state == nil || state.Schema != 1 || !state.Floors.V2Latched {
		return errors.New("[D106 Android] protected v2 state header 无效")
	}
	envelope := &state.Envelope
	head := &envelope.SignedCurrent.Head
	if _, err := wire.ParseTimeZ(envelope.SignedCurrent.PublishedAt); err != nil {
		return errors.New("[D106 Android] protected SignedCurrent time 无效")
	}
	canonicalQC, err := wire.CanonicalizeStrict(envelope.SignedCurrent.QuorumCertificate)
	if err != nil || !bytes.Equal(canonicalQC, envelope.SignedCurrent.QuorumCertificate) {
		return errors.New("[D106 Android] protected Head QC 不是 exact canonical wire")
	}
	rebuiltHead, err := wire.NewHeadEntry(head.Body)
	if err != nil || !wire.EqualCanonical(rebuiltHead, *head) {
		return errors.New("[D106 Android] protected Head hash/entry hash 无效")
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
		floors.BootstrapTransitionHash != head.Body.TransitionProofHash {
		return errors.New("[D106 Android] protected floors 与同一 Device LKG 不一致")
	}
	if _, err := wire.AdvanceFloors(wire.ClientFloorsV2{}, floors); err != nil {
		return errors.New("[D106 Android] protected floors wire 无效")
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
		return errors.New("[D104 Android] " + name + " 不是 exact canonical wire")
	}
	return nil
}

// EnrollmentClaimCoreHashV2 让宿主只组装字段，所有 SPKI/CSR/profile exact
// binding 仍由共享 verifier 完成（D129）。
func EnrollmentClaimCoreHashV2(coreJSON []byte) (string, error) {
	var core wire.EnrollmentClaimCoreV2
	if err := decodeExactAndroidV2(coreJSON, 4<<20, &core, "Enrollment claim core"); err != nil {
		return "", err
	}
	return wire.EnrollmentClaimCoreHash(&core)
}

// EnrollmentPoPMessageV2 返回 Android Keystore identity key 应签的 exact
// framed bytes；私钥不会跨过 Kotlin callback 边界（D129）。
func EnrollmentPoPMessageV2(popBodyJSON []byte) ([]byte, error) {
	var body wire.EnrollmentPoPBodyV2
	if err := decodeExactAndroidV2(popBodyJSON, 1<<20, &body, "Enrollment PoP body"); err != nil {
		return nil, err
	}
	return wire.EnrollmentPoPMessage(&body)
}

// PrepareSealedSecretP256UnsealV2 先把授权 ref 与下载到的 immutable envelope
// 逐字段绑定，再向 Kotlin 投影硬件 ECDH 所需公开输入（D124）。
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

// DeriveSealedSecretP256KEKV2 接收 Keystore ECDH 输出，私钥不跨 binding（D124）。
func DeriveSealedSecretP256KEKV2(sharedSecret, wrapContextJSON []byte) ([]byte, error) {
	var context wire.RecipientWrapContextV1
	if err := decodeExactAndroidV2(wrapContextJSON, 1<<20, &context, "recipient wrap context"); err != nil {
		return nil, err
	}
	return wire.DeriveSealedSecretP256KEK(sharedSecret, context)
}

// PrepareSealedSecretRSAUnsealV2 对 API 26–30 执行同一 ref/envelope binding，
// Kotlin 只把 exact OAEP ciphertext 交给 PURPOSE_DECRYPT alias（D124）。
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

// FinishSealedSecretPlaintextV2 重新验证内嵌 context 后才返回 secret bytes（D124）。
func FinishSealedSecretPlaintextV2(plaintext, expectedContextJSON []byte) ([]byte, error) {
	var context wire.SealedSecretContextV1
	if err := decodeExactAndroidV2(expectedContextJSON, 1<<20, &context, "sealed secret context"); err != nil {
		return nil, err
	}
	return wire.FinishSealedSecretPlaintext(plaintext, context)
}
