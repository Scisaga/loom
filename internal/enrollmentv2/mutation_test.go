package enrollmentv2

import (
	"testing"
	"time"

	"loom/internal/wire"
)

func TestEnrollmentMutationReservationRecomputesAdmissionAndRejectsSecondCAS(t *testing.T) {
	fixture := newPrivateServiceFixture(t)
	attempt := verifiedPrivateAttempt(t, fixture)
	_, member, key := controlSet(t)
	attestation, err := attempt.AdmissionAttestation()
	if err != nil {
		t.Fatal(err)
	}
	signature, err := wire.SignEnrollmentAdmission(attestation, member, key)
	if err != nil {
		t.Fatal(err)
	}
	qc := wire.StableEnrollmentAdmissionQC(attestation, []wire.ControlEnrollmentSignatureV1{signature})
	id, _ := ClaimOperationID(&qc)
	coordinate := EnrollmentCommitCoordinateV1{Schema: 1, ClusterID: attestation.ClusterID,
		RecoveryEpoch: attestation.BaseRecoveryEpoch, RaftTerm: 1,
		RaftIndex:            attempt.material.RecordHead.Body.Payload.RaftIndex + 1,
		PreviousLogEntryHash: attempt.material.RecordHead.EntryHash,
		ParentHeadHash:       attempt.material.RecordHead.HeadHash, CommittedLogicalTime: fixture.now.Format(time.RFC3339)}
	operation, err := claimOperationForAdmission(&qc, ReservationPlanV2{OperationID: id, CommittedAt: coordinate.CommittedLogicalTime})
	if err != nil {
		t.Fatal(err)
	}
	objectID, _ := wire.HashObject(DomainClaimOperation, operation)
	mutation := EnrollmentHeadMutationV1{OperationLeaf: wire.ControlOperationLeafV1{Schema: 1, OperationID: id, ObjectID: objectID},
		Preimage: &EnrollmentMutationPreimageV1{Schema: 1, Kind: "reservation", Reservation: &EnrollmentReservationPreimageV1{
			Material: attempt.material, Evidence: attempt.PrivateClaimEvidence(), Operation: operation, Admission: qc}}}
	state, err := ReduceEnrollmentMutation(mutation, nil, coordinate)
	if err != nil || state.Status != "reserved" {
		t.Fatalf("certified admission 无法形成 reservation candidate: %v", err)
	}
	if _, err := ReduceEnrollmentMutation(mutation, &state, coordinate); err == nil {
		t.Fatal("全局已存在 reservation 时仍允许第二次消费 token")
	}
	for name, mutate := range map[string]func(*EnrollmentHeadMutationV1){
		"missing-private-preimage": func(m *EnrollmentHeadMutationV1) { m.Preimage = nil },
		"multiple-branches":        func(m *EnrollmentHeadMutationV1) { m.Preimage.Completion = &EnrollmentCompletionPreimageV1{} },
		"forged-operation-hash":    func(m *EnrollmentHeadMutationV1) { m.OperationLeaf.ObjectID = wire.EmptyHashV1 },
		"forged-voter-qc": func(m *EnrollmentHeadMutationV1) {
			m.Preimage.Reservation.Admission.Attestation.IdentityKeyHash = wire.EmptyHashV1
		},
		"grant-before-completion": func(m *EnrollmentHeadMutationV1) { m.InitialDeviceView = &wire.DeviceViewPayloadV2{} },
		"changed-opening": func(m *EnrollmentHeadMutationV1) {
			m.Preimage.Reservation.Evidence.Opening.InviteID = "demo-other-invite"
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := clonePrivateValue(mutation)
			mutate(&changed)
			if _, err := ReduceEnrollmentMutation(changed, nil, coordinate); err == nil {
				t.Fatal("无效私有 mutation 可以进入全局 Raft candidate")
			}
		})
	}
}

func TestEnrollmentMutationProvisionalRequiresExactDurableReservationAndCAResult(t *testing.T) {
	input, key := deviceIssuerFixture(t)
	prepared, err := PrepareReservedDeviceIssuance(input, issuerInitialView(t, input), []wire.SecretArtifactRefV2{}, nil, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	hash, _ := wire.HashObject(DomainProvisionalOperation, prepared.Operation)
	mutation := EnrollmentHeadMutationV1{OperationLeaf: wire.ControlOperationLeafV1{Schema: 1,
		OperationID: prepared.Operation.OperationID, ObjectID: hash},
		Preimage: &EnrollmentMutationPreimageV1{Schema: 1, Kind: "provisional",
			Provisional: &EnrollmentProvisionalPreimageV1{Record: input.Reservation, Prepared: prepared}}}
	state, err := ReduceEnrollmentMutation(mutation, &input.Reservation.State, input.Coordinate)
	if err != nil || state.Status != "issued_provisional" {
		t.Fatalf("真实 CA result 无法形成 provisional candidate: %v", err)
	}
	for name, mutate := range map[string]func(*EnrollmentHeadMutationV1){
		"replace-certificate": func(m *EnrollmentHeadMutationV1) {
			m.Preimage.Provisional.Prepared.Issuance.Body.DeviceCertificateHash = wire.EmptyHashV1
		},
		"replace-reservation": func(m *EnrollmentHeadMutationV1) {
			m.Preimage.Provisional.Record.State.IdentityKeyHash = wire.EmptyHashV1
		},
		"replace-issuance-coordinate": func(m *EnrollmentHeadMutationV1) {
			m.Preimage.Provisional.Prepared.Issuance.Body.IssuanceLogCoordinate.RaftIndex++
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := clonePrivateValue(mutation)
			mutate(&changed)
			if _, err := ReduceEnrollmentMutation(changed, &input.Reservation.State, input.Coordinate); err == nil {
				t.Fatal("改变已绑定制品仍可进入 Raft")
			}
		})
	}
}
