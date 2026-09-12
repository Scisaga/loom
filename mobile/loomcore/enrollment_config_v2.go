package loomcore

import (
	"errors"

	"loom/internal/wire"
)

type androidCompletionConfigFetchPlanV1 struct {
	Schema  int                              `json:"schema"`
	Mirrors []wire.DistributionMirrorRefV1   `json:"mirrors"`
	Refs    []wire.DeviceConfigArtifactRefV1 `json:"refs"`
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
		Schema: 1, Mirrors: append([]wire.DistributionMirrorRefV1(nil), mirrors...),
		Refs: append([]wire.DeviceConfigArtifactRefV1(nil), refs...),
	})
}
