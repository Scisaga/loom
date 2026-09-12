package loomcore

import (
	"encoding/json"
	"errors"

	"loom/internal/enrollmentv2"
	"loom/internal/wire"
)

type androidVerifiedEnrollmentResultV2 struct {
	Schema             int                              `json:"schema"`
	Status             string                           `json:"status"`
	ResumeExpected     *wire.EnrollmentResumeExpectedV1 `json:"resume_expected,omitempty"`
	DeviceViewEnvelope *wire.DeviceViewEnvelopeV2       `json:"device_view_envelope,omitempty"`
	ControlSet         *wire.ControlSetV1               `json:"control_set,omitempty"`
	ResultArtifact     *wire.EnrollmentResultArtifactV1 `json:"result_artifact,omitempty"`
	ExactResult        json.RawMessage                  `json:"exact_result"`
}

// VerifyAndroidEnrollmentV2ClaimResult 在 Android 相信 pending/completed 状态前，
// 从 exact Invite Head 重放 progress 或 completion receipt。返回值只包含经过
// 不透明 verifier 绑定的安装/恢复投影（D115、D130）。
func VerifyAndroidEnrollmentV2ClaimResult(descriptorJSON, proofBundleJSON, preflightJSON,
	claimCoreJSON, resultJSON []byte, trustedTime string,
) ([]byte, error) {
	inputs, err := loadAndroidEnrollmentInputsV2(descriptorJSON, proofBundleJSON, trustedTime)
	if err != nil {
		return nil, err
	}
	preflight, err := verifyAndroidEnrollmentPreflightV2(inputs, preflightJSON)
	if err != nil {
		return nil, err
	}
	var core wire.EnrollmentClaimCoreV2
	if err := decodeExactAndroidV2(claimCoreJSON, 4<<20, &core, "Enrollment claim core"); err != nil {
		return nil, err
	}
	if err := validateAndroidEnrollmentClaimCoreV2(inputs, preflight, &core); err != nil {
		return nil, err
	}
	var result wire.EnrollmentClaimResultV2
	if err := decodeExactAndroidV2(resultJSON, 32<<20, &result, "Enrollment claim result"); err != nil {
		return nil, err
	}
	if err := wire.ValidateEnrollmentClaimResult(&result); err != nil {
		return nil, err
	}
	projection := androidVerifiedEnrollmentResultV2{
		Schema: 1, Status: result.Status, ExactResult: append(json.RawMessage(nil), resultJSON...),
	}
	expectedProgress := enrollmentv2.EnrollmentProgressExpectedV1{
		Record: inputs.bundle.CertifiedInviteRecord, Policy: inputs.bundle.InviteIssuancePolicy,
		Opening: preflight.DeviceEnrollmentIntentOpening, ClaimCore: core,
		BaseHead: inputs.head, BaseControlSet: inputs.set,
	}
	if result.Status != "completed" {
		verified, verifyErr := enrollmentv2.VerifyEnrollmentProgressReceipt(
			result.ProgressReceipt, &result, expectedProgress,
		)
		if verifyErr != nil {
			return nil, verifyErr
		}
		resume := verified.ResumeExpected()
		projection.ResumeExpected = &resume
		return wire.MarshalCanonical(projection)
	}
	now, _ := wire.ParseTimeZ(trustedTime)
	verified, err := enrollmentv2.VerifyEnrollmentCompletionReceipt(
		result.CompletionReceipt,
		&result,
		enrollmentv2.EnrollmentCompletionExpectedV1{
			Record: inputs.bundle.CertifiedInviteRecord, Policy: inputs.bundle.InviteIssuancePolicy,
			Opening: preflight.DeviceEnrollmentIntentOpening, ClaimCore: core,
			BaseHead: inputs.head, BaseControlSet: inputs.set, TrustedTime: now,
		},
	)
	if err != nil {
		return nil, err
	}
	if err := verified.VerifyInstallationContext(&result, &core, inputs.verified); err != nil {
		return nil, err
	}
	if result.ResultArtifact == nil {
		return nil, errors.New("[D130 Android] verified completion 缺 result artifact")
	}
	envelope, set := verified.DeviceViewEnvelope(), verified.ControlSet()
	artifact := *result.ResultArtifact
	projection.DeviceViewEnvelope = &envelope
	projection.ControlSet = &set
	projection.ResultArtifact = &artifact
	return wire.MarshalCanonical(projection)
}
