package enrollmentv2

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"loom/internal/wire"
)

func TestDurableProvisionalServiceFreezesFirstResultAcrossRestart(t *testing.T) {
	fixture := newApprovalEvidenceFixture(t)
	record := durableRecordForApprovalFixture(t, fixture)
	record.State, _ = Reserve(record.Invite, record.ClaimOperation, &record.AdmissionQC,
		&record.AdmissionControlSet, record.ClaimOperation.ReservedAt)
	record.ProvisionalOperation = nil
	record.ProvisionalIssuance = nil
	record.DeviceCertificateProfile = nil
	record.ResultArtifact = nil
	record.ProvisionalCertification = nil
	record.ReservationToIssuanceHeads = nil
	operationID, err := ProvisionalOperationID(&record)
	if err != nil {
		t.Fatal(err)
	}
	prepared := PreparedProvisionalV1{Operation: fixture.evidence.ProvisionalOperation,
		Issuance: fixture.evidence.ProvisionalIssuance,
		Profile:  fixture.evidence.DeviceCertificateProfile,
		Result:   fixture.evidence.ResultArtifact}
	prepared.Operation.OperationID = operationID
	coordinate := coordinateForCertifiedHead(&fixture.evidence.Issuance.Head)
	calls := 0
	path := filepath.Join(t.TempDir(), "provisional-first-results.json")
	service, err := OpenDurableProvisionalService(path,
		func(_ context.Context, gotID string, _ VerifiedClaimAttemptV2, gotRecord DurableRecord,
			gotCoordinate EnrollmentCommitCoordinateV1) (PreparedProvisionalV1, error) {
			calls++
			if gotID != operationID || !wire.EqualCanonical(gotRecord, record) ||
				!wire.EqualCanonical(gotCoordinate, coordinate) {
				return PreparedProvisionalV1{}, errors.New("generator request changed")
			}
			return prepared, nil
		})
	if err != nil {
		t.Fatal(err)
	}
	first, err := service.PrepareProvisional(context.Background(), operationID,
		VerifiedClaimAttemptV2{}, record, coordinate)
	if err != nil {
		t.Fatal(err)
	}
	first.Operation.OperationID = "caller-mutated"
	second, err := service.PrepareProvisional(context.Background(), operationID,
		VerifiedClaimAttemptV2{}, record, coordinate)
	if err != nil || calls != 1 || !wire.EqualCanonical(second, prepared) {
		t.Fatalf("same-process first-result replay failed: calls=%d value=%#v err=%v", calls, second, err)
	}
	reopened, err := OpenDurableProvisionalService(path,
		func(context.Context, string, VerifiedClaimAttemptV2, DurableRecord,
			EnrollmentCommitCoordinateV1) (PreparedProvisionalV1, error) {
			t.Fatal("reopened first-result 不应再次调用 CA generator")
			return PreparedProvisionalV1{}, nil
		})
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := reopened.PrepareProvisional(context.Background(), operationID,
		VerifiedClaimAttemptV2{}, record, coordinate)
	if err != nil || !wire.EqualCanonical(replayed, prepared) {
		t.Fatalf("restart first-result replay failed: value=%#v err=%v", replayed, err)
	}
	tampered := cloneDurableRecord(record)
	tampered.ClaimEvidence.WrappingKeyProfile = "different-profile"
	if _, err := reopened.PrepareProvisional(context.Background(), operationID,
		VerifiedClaimAttemptV2{}, tampered, coordinate); err == nil {
		t.Fatal("相同 operation ID 接受了不同 durable reservation request")
	}
}

func TestDurableProvisionalServiceRejectsInvalidGeneratorResultWithoutPersisting(t *testing.T) {
	fixture := newApprovalEvidenceFixture(t)
	record := durableRecordForApprovalFixture(t, fixture)
	record.State, _ = Reserve(record.Invite, record.ClaimOperation, &record.AdmissionQC,
		&record.AdmissionControlSet, record.ClaimOperation.ReservedAt)
	record.ProvisionalOperation = nil
	record.ProvisionalIssuance = nil
	record.DeviceCertificateProfile = nil
	record.ResultArtifact = nil
	record.ProvisionalCertification = nil
	record.ReservationToIssuanceHeads = nil
	operationID, _ := ProvisionalOperationID(&record)
	coordinate := coordinateForCertifiedHead(&fixture.evidence.Issuance.Head)
	prepared := PreparedProvisionalV1{Operation: fixture.evidence.ProvisionalOperation,
		Issuance: fixture.evidence.ProvisionalIssuance,
		Profile:  fixture.evidence.DeviceCertificateProfile,
		Result:   fixture.evidence.ResultArtifact}
	prepared.Operation.OperationID = operationID
	prepared.Issuance.Body.ReservationHeadHash = wire.EmptyHashV1
	path := filepath.Join(t.TempDir(), "provisional-first-results.json")
	service, err := OpenDurableProvisionalService(path,
		func(context.Context, string, VerifiedClaimAttemptV2, DurableRecord,
			EnrollmentCommitCoordinateV1) (PreparedProvisionalV1, error) {
			return prepared, nil
		})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.PrepareProvisional(context.Background(), operationID,
		VerifiedClaimAttemptV2{}, record, coordinate); err == nil {
		t.Fatal("invalid CA first-result was persisted")
	}
	if _, err := OpenDurableProvisionalService(path,
		func(context.Context, string, VerifiedClaimAttemptV2, DurableRecord,
			EnrollmentCommitCoordinateV1) (PreparedProvisionalV1, error) {
			return PreparedProvisionalV1{}, errors.New("unused")
		}); err != nil {
		t.Fatalf("invalid generator result left a corrupt store: %v", err)
	}
}
