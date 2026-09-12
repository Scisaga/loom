package enrollmentv2

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"loom/internal/wire"
)

type admissionQuorumFunc func(context.Context, VerifiedClaimAttemptV2,
	wire.EnrollmentAdmissionAttestationBodyV1) (wire.StableEnrollmentAdmissionQCV1, error)

func (function admissionQuorumFunc) CollectAdmission(ctx context.Context, attempt VerifiedClaimAttemptV2,
	attestation wire.EnrollmentAdmissionAttestationBodyV1) (wire.StableEnrollmentAdmissionQCV1, error) {
	return function(ctx, attempt, attestation)
}

type operationSequencerFunc func(context.Context, string, *wire.HeadEntryV2,
	EnrollmentOperationBuilder) (EnrollmentOperationCommitResultV1, error)

func (function operationSequencerFunc) CommitEnrollmentOperation(ctx context.Context, operationID string,
	lineageFrom *wire.HeadEntryV2, build EnrollmentOperationBuilder) (EnrollmentOperationCommitResultV1, error) {
	return function(ctx, operationID, lineageFrom, build)
}

type provisionalPreparerFunc func(context.Context, string, VerifiedClaimAttemptV2, DurableRecord,
	EnrollmentCommitCoordinateV1) (PreparedProvisionalV1, error)

func (function provisionalPreparerFunc) PrepareProvisional(ctx context.Context, operationID string,
	attempt VerifiedClaimAttemptV2, record DurableRecord,
	coordinate EnrollmentCommitCoordinateV1) (PreparedProvisionalV1, error) {
	return function(ctx, operationID, attempt, record, coordinate)
}

type approvalQuorumFunc func(context.Context,
	wire.EnrollmentApprovalAttestationBodyV2) (wire.StableEnrollmentApprovalQCV2, error)

func (function approvalQuorumFunc) CollectApproval(ctx context.Context,
	attestation wire.EnrollmentApprovalAttestationBodyV2) (wire.StableEnrollmentApprovalQCV2, error) {
	return function(ctx, attestation)
}

func TestDistributedBackendCommitsDeterministicCertifiedReservation(t *testing.T) {
	private := newPrivateServiceFixture(t)
	attempt := verifiedPrivateAttempt(t, private)
	set, member, enrollmentKey := controlSet(t)
	var collectedAdmission wire.StableEnrollmentAdmissionQCV1
	admission := admissionQuorumFunc(func(_ context.Context, _ VerifiedClaimAttemptV2,
		attestation wire.EnrollmentAdmissionAttestationBodyV1) (wire.StableEnrollmentAdmissionQCV1, error) {
		signature, err := wire.SignEnrollmentAdmission(attestation, member, enrollmentKey)
		if err != nil {
			return wire.StableEnrollmentAdmissionQCV1{}, err
		}
		return wire.StableEnrollmentAdmissionQC(attestation,
			[]wire.ControlEnrollmentSignatureV1{signature}), nil
	})
	sequencer := operationSequencerFunc(func(_ context.Context, operationID string, lineageFrom *wire.HeadEntryV2,
		build EnrollmentOperationBuilder) (EnrollmentOperationCommitResultV1, error) {
		if lineageFrom != nil {
			return EnrollmentOperationCommitResultV1{}, errors.New("reservation 不应伪造前序 stage")
		}
		coordinate := EnrollmentCommitCoordinateV1{Schema: 1, ClusterID: set.ClusterID,
			RecoveryEpoch: 0, RaftTerm: 1, RaftIndex: 2, PreviousLogEntryHash: hash,
			ParentHeadHash: hash, CommittedLogicalTime: private.now.Format(time.RFC3339)}
		mutation, err := build(coordinate)
		if err != nil {
			return EnrollmentOperationCommitResultV1{}, err
		}
		if mutation.OperationLeaf.OperationID != operationID || mutation.InitialDeviceView != nil {
			return EnrollmentOperationCommitResultV1{}, errors.New("reservation mutation 无效")
		}
		plan := ReservationPlanV2{OperationID: operationID, CommittedAt: coordinate.CommittedLogicalTime}
		operation, err := claimOperationForAdmission(&collectedAdmission, plan)
		if err != nil {
			return EnrollmentOperationCommitResultV1{}, err
		}
		certification := certifiedOperationFixture(t, set, operationID, DomainClaimOperation,
			operation, coordinate.CommittedLogicalTime, coordinate.RaftIndex, nil)
		return EnrollmentOperationCommitResultV1{Certification: certification}, nil
	})
	backend := mustDistributedBackend(t, admission, sequencer,
		provisionalPreparerFunc(rejectProvisional), rejectApprovalEvidence,
		approvalQuorumFunc(rejectApproval), func() time.Time { return private.now })
	attestation, err := attempt.AdmissionAttestation()
	if err != nil {
		t.Fatal(err)
	}
	qc, err := backend.CollectAdmission(context.Background(), attempt, attestation)
	if err != nil {
		t.Fatal(err)
	}
	collectedAdmission = qc
	plan, err := backend.PlanReservation(context.Background(), attempt, qc)
	if err != nil {
		t.Fatal(err)
	}
	wantID, _ := ClaimOperationID(&qc)
	if plan.OperationID != wantID {
		t.Fatalf("reservation operation ID 非确定性派生: got=%q want=%q", plan.OperationID, wantID)
	}
	operation, _ := claimOperationForAdmission(&qc, plan)
	store, _ := OpenStore(filepath.Join(t.TempDir(), "transactions.json"))
	if _, err := store.Reserve(attempt.InviteContext(), attempt.PrivateClaimEvidence(), operation,
		&qc, &set, plan.Certification); err != nil {
		t.Fatalf("distributed reservation 不能由 durable reducer 重验: %v", err)
	}
}

func TestDistributedBackendProvisionsAgainstExactReservationCoordinate(t *testing.T) {
	fixture := newApprovalEvidenceFixture(t)
	evidence := fixture.evidence
	reserved, err := Reserve(evidence.Invite, evidence.ClaimOperation, &evidence.AdmissionQC,
		&evidence.AdmissionControlSet, evidence.ClaimOperation.ReservedAt)
	if err != nil {
		t.Fatal(err)
	}
	record := DurableRecord{InviteID: evidence.Invite.InviteID,
		TokenCommitment: evidence.Invite.TokenCommitment, Invite: evidence.Invite,
		ClaimEvidence: evidence.ClaimEvidence, ClaimOperation: evidence.ClaimOperation,
		AdmissionQC: evidence.AdmissionQC, AdmissionControlSet: evidence.AdmissionControlSet,
		ReservationCertification: evidence.Reservation, State: reserved}
	operationID, _ := ProvisionalOperationID(&record)
	prepared := PreparedProvisionalV1{Operation: evidence.ProvisionalOperation,
		Issuance: evidence.ProvisionalIssuance, Profile: evidence.DeviceCertificateProfile,
		Result: evidence.ResultArtifact}
	prepared.Operation.OperationID = operationID
	preparer := provisionalPreparerFunc(func(_ context.Context, gotID string, _ VerifiedClaimAttemptV2,
		_ DurableRecord, coordinate EnrollmentCommitCoordinateV1) (PreparedProvisionalV1, error) {
		if gotID != operationID || coordinate.RaftIndex != evidence.Issuance.Head.Body.Payload.RaftIndex {
			return PreparedProvisionalV1{}, errors.New("preparer 收到错误 operation/coordinate")
		}
		return prepared, nil
	})
	sequencer := operationSequencerFunc(func(_ context.Context, gotID string, lineageFrom *wire.HeadEntryV2,
		build EnrollmentOperationBuilder) (EnrollmentOperationCommitResultV1, error) {
		if gotID != operationID || lineageFrom == nil ||
			!wire.EqualCanonical(*lineageFrom, evidence.Reservation.Head) {
			return EnrollmentOperationCommitResultV1{}, errors.New("issuance lineage 起点错误")
		}
		coordinate := coordinateForCertifiedHead(&evidence.Issuance.Head)
		mutation, err := build(coordinate)
		if err != nil {
			return EnrollmentOperationCommitResultV1{}, err
		}
		certification := certifiedOperationFixture(t, fixture.set, gotID, DomainProvisionalOperation,
			prepared.Operation, prepared.Operation.IssuedAt, coordinate.RaftIndex, lineageFrom)
		if mutation.OperationLeaf.ObjectID != certification.OperationLeaf.ObjectID {
			return EnrollmentOperationCommitResultV1{}, errors.New("issuance leaf 未绑定 prepared bytes")
		}
		return EnrollmentOperationCommitResultV1{Certification: certification}, nil
	})
	backend := mustDistributedBackend(t, admissionQuorumFunc(rejectAdmission), sequencer, preparer,
		rejectApprovalEvidence, approvalQuorumFunc(rejectApproval), func() time.Time { return fixture.trustedTime })
	plan, err := backend.Provision(context.Background(), VerifiedClaimAttemptV2{}, record)
	if err != nil {
		t.Fatal(err)
	}
	store, _ := OpenStore(filepath.Join(t.TempDir(), "transactions.json"))
	if _, err := store.Reserve(record.Invite, record.ClaimEvidence, record.ClaimOperation,
		&record.AdmissionQC, &record.AdmissionControlSet, record.ReservationCertification); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RecordProvisional(plan.Operation, plan.Issuance, plan.Profile, plan.Result,
		plan.Certification, plan.IntermediateHeads); err != nil {
		t.Fatalf("distributed issuance 不能由 durable reducer 重验: %v", err)
	}
}

func TestDistributedBackendRecomputesApprovalAndCommitsAtomicCompletion(t *testing.T) {
	fixture := newApprovalEvidenceFixture(t)
	record := durableRecordForApprovalFixture(t, fixture)
	var collectedApproval wire.StableEnrollmentApprovalQCV2
	reader := func(_ context.Context, _, _, _ string) (EnrollmentApprovalEvidenceV1, error) {
		return fixture.evidence, nil
	}
	approval := approvalQuorumFunc(func(_ context.Context,
		attestation wire.EnrollmentApprovalAttestationBodyV2) (wire.StableEnrollmentApprovalQCV2, error) {
		if !wire.EqualCanonical(attestation, fixture.attestation) {
			return wire.StableEnrollmentApprovalQCV2{}, errors.New("backend 未从本地完整 evidence 重算 attestation")
		}
		signature, err := wire.SignEnrollmentApproval(attestation, fixture.member, fixture.enrollmentKey)
		if err != nil {
			return wire.StableEnrollmentApprovalQCV2{}, err
		}
		return wire.StableEnrollmentApprovalQC(attestation,
			[]wire.ControlEnrollmentSignatureV1{signature}), nil
	})
	sequencer := operationSequencerFunc(func(_ context.Context, operationID string, lineageFrom *wire.HeadEntryV2,
		build EnrollmentOperationBuilder) (EnrollmentOperationCommitResultV1, error) {
		operationQC := collectedApproval
		operation, err := completionOperationForRecord(record, &operationQC)
		if err != nil {
			return EnrollmentOperationCommitResultV1{}, err
		}
		certification := completionCertificationFixture(t, fixture.set, fixture.member, operation,
			*record.ResultArtifact, lineageFrom)
		coordinate := coordinateForCertifiedHead(&certification.Operation.Head)
		mutation, err := build(coordinate)
		if err != nil {
			return EnrollmentOperationCommitResultV1{}, err
		}
		if operationID != operation.OperationID || mutation.InitialDeviceView == nil ||
			!wire.EqualCanonical(*mutation.InitialDeviceView, record.ResultArtifact.InitialDeviceView) {
			return EnrollmentOperationCommitResultV1{}, errors.New("completion mutation 未携 exact initial view")
		}
		envelope := certification.DeviceViewEnvelope
		return EnrollmentOperationCommitResultV1{Certification: certification.Operation,
			DeviceViewEnvelope: &envelope}, nil
	})
	backend := mustDistributedBackend(t, admissionQuorumFunc(rejectAdmission), sequencer,
		provisionalPreparerFunc(rejectProvisional), reader, approval, func() time.Time { return fixture.trustedTime })
	qc, set, err := backend.CollectApproval(context.Background(), VerifiedClaimAttemptV2{}, record)
	if err != nil || !wire.EqualCanonical(set, fixture.set) {
		t.Fatalf("approval collection failed: set=%#v err=%v", set, err)
	}
	collectedApproval = qc
	operation, err := completionOperationForRecord(record, &qc)
	if err != nil {
		t.Fatal(err)
	}
	certification, err := backend.CommitCompletion(context.Background(), VerifiedClaimAttemptV2{},
		record, qc, operation)
	if err != nil {
		t.Fatal(err)
	}
	completed, _ := Complete(record.State, operation, &qc, &set)
	if _, err := validateCompletionCertification(&record, &operation, &set,
		&certification, &completed); err != nil {
		t.Fatalf("distributed completion 不能由原子 reducer 重验: %v", err)
	}
}

func durableRecordForApprovalFixture(t *testing.T, fixture approvalEvidenceFixture) DurableRecord {
	t.Helper()
	evidence := fixture.evidence
	reserved, err := Reserve(evidence.Invite, evidence.ClaimOperation, &evidence.AdmissionQC,
		&evidence.AdmissionControlSet, evidence.ClaimOperation.ReservedAt)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := RecordProvisional(reserved, evidence.ProvisionalOperation)
	if err != nil {
		t.Fatal(err)
	}
	provisional := evidence.ProvisionalOperation
	issuance := evidence.ProvisionalIssuance
	profile := evidence.DeviceCertificateProfile
	result := evidence.ResultArtifact
	certification := evidence.Issuance
	return DurableRecord{InviteID: evidence.Invite.InviteID, TokenCommitment: evidence.Invite.TokenCommitment,
		Invite: evidence.Invite, ClaimEvidence: evidence.ClaimEvidence, ClaimOperation: evidence.ClaimOperation,
		AdmissionQC: evidence.AdmissionQC, AdmissionControlSet: evidence.AdmissionControlSet,
		ReservationCertification: evidence.Reservation, ProvisionalOperation: &provisional,
		ProvisionalIssuance: &issuance, DeviceCertificateProfile: &profile, ResultArtifact: &result,
		ProvisionalCertification:   &certification,
		ReservationToIssuanceHeads: append([]wire.HeadEntryV2(nil), evidence.IntermediateHeads...), State: issued}
}

func mustDistributedBackend(t *testing.T, admission EnrollmentAdmissionQuorum,
	sequencer EnrollmentOperationSequencer, provision DurableProvisionalPreparer,
	read ApprovalEvidenceReader, approval EnrollmentApprovalQuorum,
	now func() time.Time) *DistributedWorkflowBackend {
	t.Helper()
	backend, err := NewDistributedWorkflowBackend(admission, sequencer, provision, read, approval, now)
	if err != nil {
		t.Fatal(err)
	}
	return backend
}

func rejectAdmission(context.Context, VerifiedClaimAttemptV2,
	wire.EnrollmentAdmissionAttestationBodyV1) (wire.StableEnrollmentAdmissionQCV1, error) {
	return wire.StableEnrollmentAdmissionQCV1{}, errors.New("unexpected admission")
}

func rejectProvisional(context.Context, string, VerifiedClaimAttemptV2, DurableRecord,
	EnrollmentCommitCoordinateV1) (PreparedProvisionalV1, error) {
	return PreparedProvisionalV1{}, errors.New("unexpected provisional")
}

func rejectApprovalEvidence(context.Context, string, string, string) (EnrollmentApprovalEvidenceV1, error) {
	return EnrollmentApprovalEvidenceV1{}, errors.New("unexpected approval evidence")
}

func rejectApproval(context.Context,
	wire.EnrollmentApprovalAttestationBodyV2) (wire.StableEnrollmentApprovalQCV2, error) {
	return wire.StableEnrollmentApprovalQCV2{}, errors.New("unexpected approval")
}
