package loomcore

import (
	"encoding/json"
	"errors"

	"loom/internal/wire"
)

type androidCompletionConfigFetchPlanV1 struct {
	Schema  int                              `json:"schema"`
	State   string                           `json:"state"`
	Mirrors []wire.DistributionMirrorRefV1   `json:"mirrors"`
	Refs    []wire.DeviceConfigArtifactRefV1 `json:"refs"`
}

type androidPrivateDeviceArtifactPlanV1 struct {
	Schema          int                              `json:"schema"`
	State           string                           `json:"state"`
	ConfigChanged   bool                             `json:"config_changed"`
	SecretsChanged  bool                             `json:"secrets_changed"`
	Mirrors         []wire.DistributionMirrorRefV1   `json:"mirrors"`
	Refs            []wire.DeviceConfigArtifactRefV1 `json:"refs"`
	SecretRefs      []json.RawMessage                `json:"secret_refs"`
	SecretEnvelopes []wire.SealedSecretEnvelopeV1    `json:"secret_envelopes"`
}

// PrepareAndroidV2PrivateDeviceConfigFetchPlan 先从 protected exact Head 验证
// delivery lineage，再只投影 final Device view 承诺的 Android refs 和 Enrollment
// 时钉住的 public mirrors。尚未下载制品时不会推进任何 floor（D106、D124）。
func PrepareAndroidV2PrivateDeviceConfigFetchPlan(stateJSON, deliveryJSON,
	identitySPKIDER []byte,
) ([]byte, error) {
	state, delivery, verified, err := verifyAndroidV2PrivateDeviceConfigDelivery(
		stateJSON, deliveryJSON, identitySPKIDER)
	if err != nil {
		return nil, err
	}
	envelope := verified.Envelope()
	if envelope.Payload.State != "active" {
		return wire.MarshalCanonical(androidPrivateDeviceArtifactPlanV1{
			Schema: 1, State: "tombstone", Mirrors: []wire.DistributionMirrorRefV1{},
			Refs: []wire.DeviceConfigArtifactRefV1{}, SecretRefs: []json.RawMessage{},
			SecretEnvelopes: []wire.SealedSecretEnvelopeV1{},
		})
	}
	if envelope.Payload.Active == nil || state.Envelope.Payload.Active == nil {
		return nil, errors.New("[D124 Android config] active Device view 缺失")
	}
	configChanged := !wire.EqualCanonical(envelope.Payload.Active.ConfigArtifactRefs,
		state.Envelope.Payload.Active.ConfigArtifactRefs)
	secretsChanged := !equalRawAndroidV2(envelope.SecretArtifactRefs,
		state.Envelope.SecretArtifactRefs)
	plan := androidPrivateDeviceArtifactPlanV1{
		Schema: 1, State: "unchanged", ConfigChanged: configChanged,
		SecretsChanged: secretsChanged, Mirrors: []wire.DistributionMirrorRefV1{},
		Refs: []wire.DeviceConfigArtifactRefV1{}, SecretRefs: []json.RawMessage{},
		SecretEnvelopes: []wire.SealedSecretEnvelopeV1{},
	}
	if !configChanged && !secretsChanged {
		return wire.MarshalCanonical(plan)
	}
	plan.State = "active"
	if configChanged && (state.Enrollment == nil || state.Enrollment.DistributionMirrors == nil) {
		return nil, errors.New("[D124 Android config] durable distribution mirrors 缺失")
	}
	if configChanged {
		plan.Mirrors = append([]wire.DistributionMirrorRefV1(nil),
			state.Enrollment.DistributionMirrors...)
		plan.Refs = append([]wire.DeviceConfigArtifactRefV1(nil),
			envelope.Payload.Active.ConfigArtifactRefs...)
	}
	if secretsChanged {
		if len(delivery.SecretEnvelopes) != len(envelope.SecretArtifactRefs) {
			return nil, errors.New("[D124 Android config] 轮换凭据未 exact 覆盖 final refs")
		}
		plan.SecretRefs = cloneAndroidRawMessages(envelope.SecretArtifactRefs)
		plan.SecretEnvelopes = append([]wire.SealedSecretEnvelopeV1(nil),
			delivery.SecretEnvelopes...)
	}
	return wire.MarshalCanonical(plan)
}

func cloneAndroidRawMessages(values []json.RawMessage) []json.RawMessage {
	cloned := make([]json.RawMessage, len(values))
	for index := range values {
		cloned[index] = append(json.RawMessage(nil), values[index]...)
	}
	return cloned
}

// CompletionConfigFetchPlan 只在同一 session 已验完整 completion receipt 后
// 才投影 certified Device view 中的 Android exact refs 与原 descriptor 的
// pinned public mirrors。公开请求不会携带 Invite token 或 Device 凭据（D115、D124）。
func (session *AndroidV2BootstrapSession) CompletionConfigFetchPlan() ([]byte, error) {
	session.flowMu.Lock()
	defer session.flowMu.Unlock()
	if session == nil || session.closed.Load() || len(session.completedResult) == 0 ||
		session.completedEvidence == nil || session.core == nil {
		return nil, errors.New("[D124 Android] config fetch 前尚无 verified completion")
	}
	var result wire.EnrollmentClaimResultV2
	if err := decodeExactAndroidV2(session.completedResult, 32<<20, &result,
		"verified config completion"); err != nil {
		return nil, err
	}
	var proof wire.VerifiedInviteProofV2
	var mirrors []wire.DistributionMirrorRefV1
	if session.resume != nil {
		proof = session.resume.verified
		mirrors = session.resume.descriptor.DistributionMirrors
	} else {
		proof = session.inputs.verified
		mirrors = session.inputs.descriptor.DistributionMirrors
	}
	if err := session.completedEvidence.VerifyInstallationContext(&result, session.core, proof); err != nil {
		return nil, err
	}
	return prepareAndroidCompletionConfigFetchPlan(
		session.completedEvidence.DeviceViewEnvelope(), mirrors,
	)
}

func prepareAndroidCompletionConfigFetchPlan(envelope wire.DeviceViewEnvelopeV2,
	mirrors []wire.DistributionMirrorRefV1,
) ([]byte, error) {
	if envelope.Payload.State != "active" || envelope.Payload.Active == nil {
		return nil, errors.New("[D124 Android] completion Device view 不是 active")
	}
	if err := wire.ValidateDistributionMirrorRefs(mirrors); err != nil {
		return nil, err
	}
	refs := envelope.Payload.Active.ConfigArtifactRefs
	if len(refs) == 0 || len(refs) > androidMaximumConfigArtifacts {
		return nil, errors.New("[D124 Android] completion Device view 未承诺 Android config")
	}
	totalBytes := int64(0)
	for index := range refs {
		ref := &refs[index]
		if err := wire.ValidateDeviceConfigArtifactRef(ref); err != nil {
			return nil, err
		}
		if ref.Platform != "android" || ref.SizeBytes > androidMaximumConfigArtifactBytes {
			return nil, errors.New("[D124 Android] completion 含非 Android 或超限 config ref")
		}
		totalBytes += ref.SizeBytes
		if totalBytes > androidMaximumConfigTotalBytes {
			return nil, errors.New("[D124 Android] completion configs 超过总预算")
		}
	}
	return wire.MarshalCanonical(androidCompletionConfigFetchPlanV1{
		Schema: 1, State: "active", Mirrors: append([]wire.DistributionMirrorRefV1(nil), mirrors...),
		Refs: append([]wire.DeviceConfigArtifactRefV1(nil), refs...),
	})
}
