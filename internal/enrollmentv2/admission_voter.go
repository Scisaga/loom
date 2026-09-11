package enrollmentv2

import (
	"context"
	"crypto/ed25519"
	"errors"
	"time"

	"loom/internal/wire"
)

type EnrollmentAdmissionVoteRequestV1 struct {
	Schema              int                                       `json:"schema"`
	EnrollmentServiceID string                                    `json:"enrollment_service_id"`
	Submission          wire.EnrollmentClaimSubmissionV2          `json:"submission"`
	Attestation         wire.EnrollmentAdmissionAttestationBodyV1 `json:"attestation"`
}

type EnrollmentAdmissionVoteResponseV1 struct {
	Schema    int                               `json:"schema"`
	Signature wire.ControlEnrollmentSignatureV1 `json:"signature"`
}

type AdmissionVotePeer interface {
	VoteAdmission(context.Context, EnrollmentAdmissionVoteRequestV1) (wire.ControlEnrollmentSignatureV1, error)
}

// AdmissionVoter 持有单个 control 的 enrollment-purpose key。它必须重新读取
// certified Invite 并独立验证秘密 submission，不能信任 ingress 的“已验证”标志。
type AdmissionVoter struct {
	member     wire.ControlMemberV1
	privateKey ed25519.PrivateKey
	now        func() time.Time
	readInvite InviteMaterialReader
}

func NewAdmissionVoter(memberID string, set wire.ControlSetV1, privateKey ed25519.PrivateKey,
	now func() time.Time, readInvite InviteMaterialReader) (*AdmissionVoter, error) {
	if memberID == "" || now == nil || readInvite == nil || len(privateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("[D129 Enrollment peer] voter identity/key/time/reader 配置不完整")
	}
	if err := wire.ValidateControlSet(&set); err != nil {
		return nil, err
	}
	var member *wire.ControlMemberV1
	for index := range set.Members {
		if set.Members[index].MemberID == memberID {
			member = &set.Members[index]
			break
		}
	}
	keyID, err := wire.ControlKeyID(privateKey.Public().(ed25519.PublicKey))
	if err != nil || member == nil || keyID != member.EnrollmentKeyID {
		return nil, errors.New("[D102 keys] voter enrollment key 不属于 committed ControlSet member")
	}
	return &AdmissionVoter{member: *member, privateKey: append(ed25519.PrivateKey(nil), privateKey...),
		now: now, readInvite: readInvite}, nil
}

func (voter *AdmissionVoter) VoteAdmission(ctx context.Context,
	request EnrollmentAdmissionVoteRequestV1) (wire.ControlEnrollmentSignatureV1, error) {
	if voter == nil || request.Schema != 1 || request.EnrollmentServiceID == "" {
		return wire.ControlEnrollmentSignatureV1{}, errors.New("[D129 Enrollment peer] admission vote request header 无效")
	}
	if err := ctx.Err(); err != nil {
		return wire.ControlEnrollmentSignatureV1{}, err
	}
	core := request.Submission.ClaimCore
	material, err := voter.readInvite(ctx, core.ClusterID, core.InviteID)
	if err != nil {
		return wire.ControlEnrollmentSignatureV1{}, errors.New("[D129 Enrollment peer] certified Invite material 不可用")
	}
	if err := VerifyPeerAdmissionAttempt(&material, &request.Submission, &request.Attestation,
		request.EnrollmentServiceID, voter.now().UTC()); err != nil {
		return wire.ControlEnrollmentSignatureV1{}, err
	}
	return wire.SignEnrollmentAdmission(request.Attestation, voter.member, voter.privateKey)
}
