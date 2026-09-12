package enrollmentv2

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"loom/internal/wire"
)

type workflowBackendFixture struct {
	t                *testing.T
	set              wire.ControlSetV1
	member           wire.ControlMemberV1
	enrollmentKey    ed25519.PrivateKey
	profile          wire.DeviceCertificateProfileStateV1
	issuerKey        ed25519.PrivateKey
	resultArtifact   wire.EnrollmentResultArtifactV1
	committedAt      string
	pendingProvision bool
	admissionCalls   int
	provisionCalls   int
	approvalCalls    int
	completionCalls  int
}

func TestCoordinatorResumesReservedTransactionAndFreezesCompletedResult(t *testing.T) {
	private := newPrivateServiceFixture(t)
	attempt := verifiedPrivateAttempt(t, private)
	set, member, enrollmentKey := controlSet(t)
	profile, issuerKey := private.deviceProfile, private.deviceIssuerKey
	resultArtifact := enrollmentResultArtifactFixture(t)
	bindResultArtifactToAttempt(t, &resultArtifact, attempt, profile, issuerKey, private.identity, private.now)
	path := filepath.Join(t.TempDir(), "workflow.json")
	store, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	firstBackend := &workflowBackendFixture{t: t, set: set, member: member, enrollmentKey: enrollmentKey,
		profile: profile, issuerKey: issuerKey, resultArtifact: resultArtifact, committedAt: private.now.Format("2006-01-02T15:04:05Z"),
		pendingProvision: true}
	coordinator, err := NewCoordinator(store, firstBackend)
	if err != nil {
		t.Fatal(err)
	}
	reserved, err := coordinator.ProcessClaim(context.Background(), attempt)
	if err != nil || reserved.Status != "reserved" || firstBackend.admissionCalls != 1 || firstBackend.provisionCalls != 1 {
		t.Fatalf("首次推进未稳定停在 reserved: result=%#v backend=%#v err=%v", reserved, firstBackend, err)
	}

	reopened, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	secondBackend := &workflowBackendFixture{t: t, set: set, member: member, enrollmentKey: enrollmentKey,
		profile: profile, issuerKey: issuerKey, resultArtifact: resultArtifact, committedAt: private.now.Format("2006-01-02T15:04:05Z")}
	recoveredCoordinator, _ := NewCoordinator(reopened, secondBackend)
	completed, err := recoveredCoordinator.ProcessClaim(context.Background(), attempt)
	if err != nil || completed.Status != "completed" || completed.ResultArtifactHash == "" ||
		completed.ResultArtifact == nil || len(completed.CompletionReceipt) == 0 {
		t.Fatalf("另一 coordinator 未从 reserved 恢复完成: result=%#v err=%v", completed, err)
	}
	submission := attempt.Submission()
	verifiedCompletion, err := VerifyEnrollmentCompletionReceipt(completed.CompletionReceipt, &completed,
		EnrollmentCompletionExpectedV1{
			Record: private.material.Record, Policy: private.material.Policy,
			Opening: private.material.Opening, ClaimCore: submission.ClaimCore,
			BaseHead: private.material.RecordHead, BaseControlSet: private.material.ControlSet,
			TrustedTime: private.now,
		})
	if err != nil || verifiedCompletion.TransactionStateHash() != completed.TransactionStateHash ||
		verifiedCompletion.DeviceViewEnvelope().Payload.DeviceID != resultArtifact.InitialDeviceView.DeviceID {
		t.Fatalf("客户端不能独立重放 completed receipt: evidence=%#v err=%v", verifiedCompletion, err)
	}
	for _, item := range []struct{ label, secret string }{
		{label: "token", secret: submission.Token},
		{label: "csr", secret: submission.ClaimCore.CSRDER},
		{label: "challenge", secret: submission.Challenge.ServerNonce},
		{label: "pop", secret: submission.ProofSignature},
	} {
		if bytes.Contains(completed.CompletionReceipt, []byte(item.secret)) {
			t.Fatalf("completion receipt 反射了 %s secret", item.label)
		}
	}
	var tamperedReceipt EnrollmentCompletionReceiptV1
	if _, err := wire.DecodeStrict(completed.CompletionReceipt, 32<<20, &tamperedReceipt); err != nil {
		t.Fatal(err)
	}
	tamperedReceipt.ClaimOperation.ClaimCoreHash = wire.EmptyHashV1
	tamperedRaw, err := wire.MarshalCanonical(tamperedReceipt)
	if err != nil {
		t.Fatal(err)
	}
	tamperedResult := completed
	tamperedResult.CompletionReceipt = tamperedRaw
	if _, err := VerifyEnrollmentCompletionReceipt(tamperedRaw, &tamperedResult,
		EnrollmentCompletionExpectedV1{
			Record: private.material.Record, Policy: private.material.Policy,
			Opening: private.material.Opening, ClaimCore: submission.ClaimCore,
			BaseHead: private.material.RecordHead, BaseControlSet: private.material.ControlSet,
			TrustedTime: private.now,
		}); err == nil {
		t.Fatal("客户端接受了改写 stable claim 的 completion receipt")
	}
	if secondBackend.admissionCalls != 0 || secondBackend.provisionCalls != 1 ||
		secondBackend.approvalCalls != 1 || secondBackend.completionCalls != 1 {
		t.Fatalf("恢复重跑了已 durable 的 admission: %#v", secondBackend)
	}

	frozenBackend := &workflowBackendFixture{t: t, set: set, member: member, enrollmentKey: enrollmentKey,
		profile: profile, issuerKey: issuerKey, resultArtifact: resultArtifact, committedAt: secondBackend.committedAt}
	frozenCoordinator, _ := NewCoordinator(reopened, frozenBackend)
	replayed, err := frozenCoordinator.ProcessClaim(context.Background(), attempt)
	if err != nil || !wire.EqualCanonical(replayed, completed) {
		t.Fatalf("completed replay 未返回同一结果: result=%#v err=%v", replayed, err)
	}
	if frozenBackend.admissionCalls+frozenBackend.provisionCalls+frozenBackend.approvalCalls+frozenBackend.completionCalls != 0 {
		t.Fatalf("completed replay 触发了外部副作用: %#v", frozenBackend)
	}
}

func TestCoordinatorRejectsBackendAdmissionForDifferentCore(t *testing.T) {
	private := newPrivateServiceFixture(t)
	attempt := verifiedPrivateAttempt(t, private)
	set, member, enrollmentKey := controlSet(t)
	profile, issuerKey := private.deviceProfile, private.deviceIssuerKey
	resultArtifact := enrollmentResultArtifactFixture(t)
	bindResultArtifactToAttempt(t, &resultArtifact, attempt, profile, issuerKey, private.identity, private.now)
	backend := &workflowBackendFixture{t: t, set: set, member: member, enrollmentKey: enrollmentKey,
		profile: profile, issuerKey: issuerKey, resultArtifact: resultArtifact, committedAt: private.now.Format("2006-01-02T15:04:05Z")}
	store, _ := OpenStore(filepath.Join(t.TempDir(), "workflow.json"))
	coordinator, _ := NewCoordinator(store, admissionTamperingBackend{WorkflowBackend: backend})
	if _, err := coordinator.ProcessClaim(context.Background(), attempt); err == nil {
		t.Fatal("接受了 backend 对不同 claim core 返回的 admission QC")
	}
}

type admissionTamperingBackend struct{ WorkflowBackend }

func (backend admissionTamperingBackend) CollectAdmission(ctx context.Context, attempt VerifiedClaimAttemptV2,
	body wire.EnrollmentAdmissionAttestationBodyV1) (wire.StableEnrollmentAdmissionQCV1, error) {
	body.ClaimCoreHash = wire.EmptyHashV1
	return backend.WorkflowBackend.CollectAdmission(ctx, attempt, body)
}

func (backend *workflowBackendFixture) CollectAdmission(_ context.Context, _ VerifiedClaimAttemptV2,
	body wire.EnrollmentAdmissionAttestationBodyV1) (wire.StableEnrollmentAdmissionQCV1, error) {
	backend.admissionCalls++
	signature, err := wire.SignEnrollmentAdmission(body, backend.member, backend.enrollmentKey)
	if err != nil {
		return wire.StableEnrollmentAdmissionQCV1{}, err
	}
	return wire.StableEnrollmentAdmissionQC(body, []wire.ControlEnrollmentSignatureV1{signature}), nil
}

func (backend *workflowBackendFixture) PlanReservation(_ context.Context, attempt VerifiedClaimAttemptV2,
	admission wire.StableEnrollmentAdmissionQCV1) (ReservationPlanV2, error) {
	baseHead := attempt.material.RecordHead
	plan := ReservationPlanV2{OperationID: "claim-operation", CommittedAt: backend.committedAt,
		BaseHead: baseHead}
	operation, err := claimOperationForAdmission(&admission, plan)
	if err != nil {
		return ReservationPlanV2{}, err
	}
	plan.Certification = certifiedOperationFixture(backend.t, backend.set, operation.OperationID,
		DomainClaimOperation, operation, operation.ReservedAt,
		baseHead.Body.Payload.RaftIndex+1, &baseHead)
	return plan, nil
}

func (backend *workflowBackendFixture) Provision(_ context.Context, _ VerifiedClaimAttemptV2,
	record DurableRecord) (ProvisionalPlanV1, error) {
	backend.provisionCalls++
	if backend.pendingProvision {
		return ProvisionalPlanV1{}, ErrEnrollmentProgressPending
	}
	profileHash, _ := wire.DeviceCertificateProfileStateHash(&backend.profile)
	certificateDER, err := wire.EnrollmentResultCertificateDER(&backend.resultArtifact)
	if err != nil {
		return ProvisionalPlanV1{}, err
	}
	certificateHash, _ := wire.DeviceCertificateHash(certificateDER)
	viewHash, _ := wire.DeviceViewHash(&backend.resultArtifact.InitialDeviceView)
	resultHash, _ := wire.EnrollmentResultArtifactHash(&backend.resultArtifact)
	reservationQCHash, err := wire.ConfigQCHash(record.ReservationCertification.ConfigQC)
	if err != nil {
		return ProvisionalPlanV1{}, err
	}
	issuanceIndex := record.ReservationCertification.Head.Body.Payload.RaftIndex + 1
	body := wire.EnrollmentProvisionalIssuanceBodyV1{
		Schema: 1, ClusterID: record.State.ClusterID, InviteID: record.State.InviteID,
		RequestID: record.State.RequestID, ClaimOperationHash: record.State.ClaimOperationHash,
		ReservationHeadHash:   record.ReservationCertification.Head.HeadHash,
		ReservationHeadQCHash: reservationQCHash, DeviceCertificateHash: certificateHash,
		InitialDeviceViewHash:             viewHash,
		SecretArtifactRefsRoot:            backend.resultArtifact.InitialDeviceView.Active.SecretArtifactRefsRoot,
		ResultArtifactHash:                resultHash,
		DeviceCertificateProfileStateHash: profileHash,
		IssuanceLogCoordinate:             wire.IssuanceLogCoordinateV1{RecoveryEpoch: 0, RaftIndex: issuanceIndex},
	}
	issuance, err := wire.SignEnrollmentProvisionalIssuance(body, &backend.profile, backend.issuerKey)
	if err != nil {
		return ProvisionalPlanV1{}, err
	}
	issuanceHash, _ := wire.EnrollmentProvisionalIssuanceHash(&issuance)
	leaf := wire.EnrollmentIssuanceRegistryLeafV1{Schema: 1,
		ClaimOperationHash: record.State.ClaimOperationHash, ProvisionalIssuanceHash: issuanceHash}
	previousRoot, _ := wire.EnrollmentIssuanceRegistryRoot(nil)
	resultingRoot, _ := wire.EnrollmentIssuanceRegistryRoot([]wire.EnrollmentIssuanceRegistryLeafV1{leaf})
	stateHash, _ := TransactionHash(record.State)
	operation := ProvisionalIssuanceOperationV1{
		Schema: 1, ClusterID: record.State.ClusterID, OperationID: "provisional-operation",
		InviteID: record.State.InviteID, RequestID: record.State.RequestID,
		ExpectedTransactionStateHash: stateHash, ClaimOperationHash: record.State.ClaimOperationHash,
		ProvisionalIssuanceHash: issuanceHash, IssuanceRegistryLeaf: leaf,
		PreviousIssuanceRegistryRoot: previousRoot, ResultingIssuanceRegistryRoot: resultingRoot,
		IssuedAt: backend.committedAt,
	}
	certification := certifiedOperationFixture(backend.t, backend.set, operation.OperationID,
		DomainProvisionalOperation, operation, operation.IssuedAt, issuanceIndex,
		&record.ReservationCertification.Head)
	return ProvisionalPlanV1{Operation: operation, Issuance: issuance, Profile: backend.profile,
		Result: backend.resultArtifact, Certification: certification}, nil
}

func (backend *workflowBackendFixture) CollectApproval(_ context.Context, _ VerifiedClaimAttemptV2,
	record DurableRecord) (wire.StableEnrollmentApprovalQCV2, wire.ControlSetV1, error) {
	backend.approvalCalls++
	if record.ProvisionalIssuance == nil || record.ProvisionalOperation == nil {
		return wire.StableEnrollmentApprovalQCV2{}, wire.ControlSetV1{}, errors.New("缺 provisional evidence")
	}
	body := record.ProvisionalIssuance.Body
	operationHash, _ := wire.HashObject(DomainProvisionalOperation, *record.ProvisionalOperation)
	issuanceHash, _ := wire.EnrollmentProvisionalIssuanceHash(record.ProvisionalIssuance)
	attestation := wire.EnrollmentApprovalAttestationBodyV2{
		Schema: 2, AttestationType: "enrollment_approval", ClusterID: body.ClusterID,
		InviteID: body.InviteID, RequestID: body.RequestID, ClaimOperationHash: body.ClaimOperationHash,
		ProvisionalIssuanceOperationHash: operationHash, ProvisionalIssuanceHash: issuanceHash,
		IssuanceHeadHash:              record.ProvisionalCertification.Head.HeadHash,
		IssuanceHeadQCHash:            mustConfigQCHash(backend.t, record.ProvisionalCertification.ConfigQC),
		ResultingIssuanceRegistryRoot: record.ProvisionalOperation.ResultingIssuanceRegistryRoot,
		DeviceCertificateHash:         body.DeviceCertificateHash, InitialDeviceViewHash: body.InitialDeviceViewHash,
		SecretArtifactRefsRoot: body.SecretArtifactRefsRoot, ResultArtifactHash: body.ResultArtifactHash,
	}
	signature, err := wire.SignEnrollmentApproval(attestation, backend.member, backend.enrollmentKey)
	if err != nil {
		return wire.StableEnrollmentApprovalQCV2{}, wire.ControlSetV1{}, err
	}
	return wire.StableEnrollmentApprovalQC(attestation, []wire.ControlEnrollmentSignatureV1{signature}), backend.set, nil
}

func (backend *workflowBackendFixture) CommitCompletion(_ context.Context, _ VerifiedClaimAttemptV2,
	record DurableRecord, _ wire.StableEnrollmentApprovalQCV2,
	operation CompletionOperationV2) (CompletionCertificationV1, error) {
	backend.completionCalls++
	return completionCertificationFixture(backend.t, backend.set, backend.member, operation,
		*record.ResultArtifact, &record.ProvisionalCertification.Head), nil
}

func verifiedPrivateAttempt(t *testing.T, fixture privateServiceFixture) VerifiedClaimAttemptV2 {
	t.Helper()
	challenge, err := fixture.service.Challenge(context.Background(), fixture.capability, &fixture.core)
	if err != nil {
		t.Fatal(err)
	}
	submission := signedPrivateSubmission(t, fixture, challenge)
	verified, err := wire.VerifyEnrollmentClaimSubmission(&submission, &fixture.material.Record,
		&fixture.material.Policy, &fixture.material.Opening, "enrollment-service", fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	return VerifiedClaimAttemptV2{capability: fixture.capability, claim: verified,
		submission: submission, material: fixture.material}
}

func bindResultArtifactToAttempt(t *testing.T, result *wire.EnrollmentResultArtifactV1,
	attempt VerifiedClaimAttemptV2, profile wire.DeviceCertificateProfileStateV1,
	issuerKey ed25519.PrivateKey, identity *ecdsa.PrivateKey, issuedAt time.Time) {
	t.Helper()
	deviceID := attempt.material.Opening.DeviceEnrollmentIntent.DeviceID
	result.DeviceCertificateDER = base64.RawURLEncoding.EncodeToString(
		approvalDeviceCertificate(t, profile, issuerKey, identity, deviceID, issuedAt))
	result.InitialDeviceView.DeviceID = deviceID
	result.InitialDeviceView.Active.IdentitySPKIHash = attempt.Claim().IdentityKeyHash()
	result.InitialDeviceView.Active.EndpointBundle.DeviceID = deviceID
	result.InitialDeviceView.Active.EndpointBundleHash, _ = wire.DeviceEndpointBundleHash(
		&result.InitialDeviceView.Active.EndpointBundle)
}
