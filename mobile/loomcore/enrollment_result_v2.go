package loomcore

import (
	"encoding/json"
	"errors"
	"time"

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
	now, _ := wire.ParseTimeZ(trustedTime)
	projection, _, _, err := verifyAndroidEnrollmentV2ClaimResult(inputs, preflight, core, resultJSON, now)
	if err != nil {
		return nil, err
	}
	return wire.MarshalCanonical(projection)
}

// verifyAndroidEnrollmentV2ClaimResult 是 transport session 与公开 binding 共用的
// receipt 边界。这样 released artifact fetch 只能由同一个已验证 completed result
// 解锁，不能由 Kotlin 或任意 result 字段单独授权（D124、D130）。
func verifyAndroidEnrollmentV2ClaimResult(inputs androidEnrollmentInputsV2,
	preflight wire.EnrollmentIntentPreflightResponseV1, core wire.EnrollmentClaimCoreV2,
	resultJSON []byte, now time.Time,
) (androidVerifiedEnrollmentResultV2, wire.EnrollmentClaimResultV2,
	*enrollmentv2.VerifiedEnrollmentCompletionV1, error,
) {
	expected := enrollmentv2.EnrollmentProgressExpectedV1{
		Record: inputs.bundle.CertifiedInviteRecord, Policy: inputs.bundle.InviteIssuancePolicy,
		Opening: preflight.DeviceEnrollmentIntentOpening, ClaimCore: core,
		BaseHead: inputs.head, BaseControlSet: inputs.set,
	}
	return verifyAndroidEnrollmentResultExpected(expected, inputs.verified, resultJSON, now, nil)
}

func verifyAndroidEnrollmentResultExpected(expected enrollmentv2.EnrollmentProgressExpectedV1,
	proof wire.VerifiedInviteProofV2, resultJSON []byte, now time.Time, requiredTransactionHashes []string,
) (androidVerifiedEnrollmentResultV2, wire.EnrollmentClaimResultV2,
	*enrollmentv2.VerifiedEnrollmentCompletionV1, error,
) {
	var result wire.EnrollmentClaimResultV2
	if err := decodeExactAndroidV2(resultJSON, 32<<20, &result, "Enrollment claim result"); err != nil {
		return androidVerifiedEnrollmentResultV2{}, wire.EnrollmentClaimResultV2{}, nil, err
	}
	if err := wire.ValidateEnrollmentClaimResult(&result); err != nil {
		return androidVerifiedEnrollmentResultV2{}, wire.EnrollmentClaimResultV2{}, nil, err
	}
	projection := androidVerifiedEnrollmentResultV2{
		Schema: 1, Status: result.Status, ExactResult: append(json.RawMessage(nil), resultJSON...),
	}
	if result.Status != "completed" {
		verified, verifyErr := enrollmentv2.VerifyEnrollmentProgressReceipt(
			result.ProgressReceipt, &result, expected,
		)
		if verifyErr != nil {
			return androidVerifiedEnrollmentResultV2{}, wire.EnrollmentClaimResultV2{}, nil, verifyErr
		}
		for _, required := range requiredTransactionHashes {
			if required != "" && !verified.IncludesTransactionStateHash(required) {
				return androidVerifiedEnrollmentResultV2{}, wire.EnrollmentClaimResultV2{}, nil,
					errors.New("[D130 Android] progress receipt 不包含 resume transaction floor")
			}
		}
		resume := verified.ResumeExpected()
		projection.ResumeExpected = &resume
		return projection, result, nil, nil
	}
	verified, err := enrollmentv2.VerifyEnrollmentCompletionReceipt(
		result.CompletionReceipt,
		&result,
		enrollmentv2.EnrollmentCompletionExpectedV1{
			Record: expected.Record, Policy: expected.Policy, Opening: expected.Opening,
			ClaimCore: expected.ClaimCore, BaseHead: expected.BaseHead,
			BaseControlSet: expected.BaseControlSet, TrustedTime: now,
		},
	)
	if err != nil {
		return androidVerifiedEnrollmentResultV2{}, wire.EnrollmentClaimResultV2{}, nil, err
	}
	for _, required := range requiredTransactionHashes {
		if required != "" && !verified.IncludesTransactionStateHash(required) {
			return androidVerifiedEnrollmentResultV2{}, wire.EnrollmentClaimResultV2{}, nil,
				errors.New("[D130 Android] completion receipt 不包含 resume transaction floor")
		}
	}
	if err := verified.VerifyInstallationContext(&result, &expected.ClaimCore, proof); err != nil {
		return androidVerifiedEnrollmentResultV2{}, wire.EnrollmentClaimResultV2{}, nil, err
	}
	if result.ResultArtifact == nil {
		return androidVerifiedEnrollmentResultV2{}, wire.EnrollmentClaimResultV2{}, nil,
			errors.New("[D130 Android] verified completion 缺 result artifact")
	}
	envelope, set := verified.DeviceViewEnvelope(), verified.ControlSet()
	artifact := *result.ResultArtifact
	projection.DeviceViewEnvelope = &envelope
	projection.ControlSet = &set
	projection.ResultArtifact = &artifact
	return projection, result, &verified, nil
}
