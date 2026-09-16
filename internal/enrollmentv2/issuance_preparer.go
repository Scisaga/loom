package enrollmentv2

import (
	"crypto"
	"encoding/base64"
	"errors"
	"io"

	"loom/internal/wire"
)

// PrepareReservedDeviceIssuance 将 renderer/wrapping 的 exact 输出和真实 CA
// leaf 合成待提交的 provisional 操作。view 内容由上层认证投影器生成；这里禁止
// 替换已 admission 的身份、职责或 grants，不把生成制品当成完成入网（D124、D130）。
func PrepareReservedDeviceIssuance(input DeviceIssuanceContext, view wire.DeviceViewPayloadV2,
	secretRefs []wire.SecretArtifactRefV2, previousRegistry []wire.EnrollmentIssuanceRegistryLeafV1,
	issuerKey crypto.Signer, random io.Reader) (PreparedProvisionalV1, error) {
	if err := wire.ValidateDeviceViewPayload(&view); err != nil {
		return PreparedProvisionalV1{}, err
	}
	intent := input.Reservation.ClaimEvidence.Opening.DeviceEnrollmentIntent
	if view.State != "active" || view.Active == nil || view.DeviceGeneration != 1 ||
		view.ClusterID != intent.ClusterID || view.DeviceID != intent.DeviceID ||
		view.Active.IdentitySPKIHash != input.Reservation.State.IdentityKeyHash ||
		!wire.EqualCanonical(view.Active.Membership, intent.Membership) ||
		!wire.EqualCanonical(view.Active.Responsibilities, intent.Responsibilities) ||
		!wire.EqualCanonical(view.Active.Grants, intent.Grants) {
		return PreparedProvisionalV1{}, errors.New("[D130 Enrollment] renderer view 与 admitted intent/identity 不一致")
	}
	secretRoot, err := wire.SecretArtifactRefsRoot(secretRefs)
	if err != nil || secretRoot != view.Active.SecretArtifactRefsRoot {
		return PreparedProvisionalV1{}, errors.New("[D124 Enrollment] wrapping refs 与 view 不一致")
	}
	previousRoot, err := wire.EnrollmentIssuanceRegistryRoot(previousRegistry)
	if err != nil {
		return PreparedProvisionalV1{}, err
	}
	for _, leaf := range previousRegistry {
		if leaf.ClaimOperationHash == input.Reservation.State.ClaimOperationHash {
			return PreparedProvisionalV1{}, errors.New("[D130 Enrollment] 已有 issuance，必须恢复 first-result 而非重签")
		}
	}
	operationID, err := ProvisionalOperationID(&input.Reservation)
	if err != nil {
		return PreparedProvisionalV1{}, err
	}
	certificateDER, err := IssueReservedDeviceCertificate(input, issuerKey, random)
	if err != nil {
		return PreparedProvisionalV1{}, err
	}
	record := &input.Reservation
	result := wire.EnrollmentResultArtifactV1{Schema: 1, ClusterID: intent.ClusterID, InviteID: record.InviteID,
		RequestID: record.State.RequestID, DeviceCertificateDER: base64.RawURLEncoding.EncodeToString(certificateDER),
		InitialDeviceView: view, SecretArtifactRefs: secretRefs}
	resultHash, err := wire.EnrollmentResultArtifactHash(&result)
	if err != nil {
		return PreparedProvisionalV1{}, err
	}
	certificateHash, err := wire.DeviceCertificateHash(certificateDER)
	if err != nil {
		return PreparedProvisionalV1{}, err
	}
	viewHash, err := wire.DeviceViewHash(&view)
	if err != nil {
		return PreparedProvisionalV1{}, err
	}
	profileHash, err := wire.DeviceCertificateProfileStateHash(&input.Profile)
	if err != nil {
		return PreparedProvisionalV1{}, err
	}
	reservationQCHash, err := wire.ConfigQCHash(record.ReservationCertification.ConfigQC)
	if err != nil {
		return PreparedProvisionalV1{}, err
	}
	issuanceBody := wire.EnrollmentProvisionalIssuanceBodyV1{Schema: 1, ClusterID: intent.ClusterID,
		InviteID: record.InviteID, RequestID: record.State.RequestID, ClaimOperationHash: record.State.ClaimOperationHash,
		ReservationHeadHash: record.ReservationCertification.Head.HeadHash, ReservationHeadQCHash: reservationQCHash,
		DeviceCertificateHash: certificateHash, InitialDeviceViewHash: viewHash, SecretArtifactRefsRoot: secretRoot,
		ResultArtifactHash: resultHash, DeviceCertificateProfileStateHash: profileHash,
		IssuanceLogCoordinate: wire.IssuanceLogCoordinateV1{RecoveryEpoch: input.Coordinate.RecoveryEpoch, RaftIndex: input.Coordinate.RaftIndex}}
	issuance, err := wire.SignEnrollmentProvisionalIssuance(issuanceBody, &input.Profile, issuerKey)
	if err != nil {
		return PreparedProvisionalV1{}, err
	}
	issuanceHash, err := wire.EnrollmentProvisionalIssuanceHash(&issuance)
	if err != nil {
		return PreparedProvisionalV1{}, err
	}
	leaf := wire.EnrollmentIssuanceRegistryLeafV1{Schema: 1, ClaimOperationHash: record.State.ClaimOperationHash, ProvisionalIssuanceHash: issuanceHash}
	leaves := append(append([]wire.EnrollmentIssuanceRegistryLeafV1(nil), previousRegistry...), leaf)
	resultingRoot, err := wire.EnrollmentIssuanceRegistryRoot(leaves)
	if err != nil {
		return PreparedProvisionalV1{}, err
	}
	stateHash, err := TransactionHash(record.State)
	if err != nil {
		return PreparedProvisionalV1{}, err
	}
	prepared := PreparedProvisionalV1{Operation: ProvisionalIssuanceOperationV1{Schema: 1,
		ClusterID: intent.ClusterID, OperationID: operationID, InviteID: record.InviteID, RequestID: record.State.RequestID,
		ExpectedTransactionStateHash: stateHash, ClaimOperationHash: record.State.ClaimOperationHash,
		ProvisionalIssuanceHash: issuanceHash, IssuanceRegistryLeaf: leaf,
		PreviousIssuanceRegistryRoot: previousRoot, ResultingIssuanceRegistryRoot: resultingRoot,
		IssuedAt: input.Coordinate.CommittedLogicalTime}, Issuance: issuance, Profile: input.Profile, Result: result}
	if err := validatePreparedProvisional(&prepared, operationID, record, &input.Coordinate); err != nil {
		return PreparedProvisionalV1{}, err
	}
	return clonePreparedProvisional(prepared), nil
}
