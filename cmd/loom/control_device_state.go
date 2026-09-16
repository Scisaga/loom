package main

import (
	"context"
	"encoding/base64"
	"errors"
	"path/filepath"

	"loom/internal/controlplane"
	"loom/internal/enrollmentv2"
	"loom/internal/wire"
)

// 所有业务 reader 共用 daemon 的写锁、已认证日志与 projection，不从独立可写的
// registry 或测试 fixture 推断身份。返回前复制，避免调用方修改共识 preimage。
func (runtime *controlRuntime) readApprovalEvidence(ctx context.Context, clusterID, inviteID, requestID string) (enrollmentv2.EnrollmentApprovalEvidenceV1, error) {
	if err := ctx.Err(); err != nil {
		return enrollmentv2.EnrollmentApprovalEvidenceV1{}, err
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	if _, err := runtime.certifiedApplicationLocked(); err != nil {
		return enrollmentv2.EnrollmentApprovalEvidenceV1{}, err
	}
	record, found := runtime.enrollmentStore.SnapshotRecord(inviteID)
	if !found || record.State.ClusterID != clusterID || record.State.RequestID != requestID ||
		record.ProvisionalOperation == nil || record.ProvisionalIssuance == nil ||
		record.ProvisionalCertification == nil || record.DeviceCertificateProfile == nil || record.ResultArtifact == nil {
		return enrollmentv2.EnrollmentApprovalEvidenceV1{}, errors.New("[D130 daemon] 缺该事务已认证的首次签发")
	}
	reservationIndex, issuanceIndex := -1, -1
	for index, operation := range runtime.journal.Records {
		if operation.Result == nil {
			continue
		}
		if operation.Result.Head.HeadHash == record.ReservationCertification.Head.HeadHash {
			reservationIndex = index
		}
		if operation.Result.Head.HeadHash == record.ProvisionalCertification.Head.HeadHash {
			issuanceIndex = index
		}
	}
	if reservationIndex < 0 || issuanceIndex <= reservationIndex {
		return enrollmentv2.EnrollmentApprovalEvidenceV1{}, errors.New("[D130 daemon] reservation/issuance 不在本机认证日志")
	}
	reservation, err := runtime.applicationBefore(reservationIndex + 1)
	if err != nil {
		return enrollmentv2.EnrollmentApprovalEvidenceV1{}, err
	}
	beforeIssuance, err := runtime.applicationBefore(issuanceIndex)
	if err != nil {
		return enrollmentv2.EnrollmentApprovalEvidenceV1{}, err
	}
	issued, err := runtime.applicationBefore(issuanceIndex + 1)
	if err != nil {
		return enrollmentv2.EnrollmentApprovalEvidenceV1{}, err
	}
	evidence := enrollmentv2.EnrollmentApprovalEvidenceV1{Schema: 1,
		Invite: record.Invite, ClaimEvidence: record.ClaimEvidence, ClaimOperation: record.ClaimOperation,
		AdmissionQC: record.AdmissionQC, AdmissionControlSet: record.AdmissionControlSet,
		ReservationBaseHead: record.ReservationBaseHead, BaseToReservationHeads: record.BaseToReservationHeads,
		BaseToReservationTransitions: record.BaseToReservationTransitions,
		Reservation:                  record.ReservationCertification, ReservationCARegistry: reservation.CARegistry,
		ProvisionalOperation: *record.ProvisionalOperation, ProvisionalIssuance: *record.ProvisionalIssuance,
		DeviceCertificateProfile: *record.DeviceCertificateProfile, PreviousIssuanceRegistryLeaves: beforeIssuance.IssuanceRegistry,
		IntermediateHeads: record.ReservationToIssuanceHeads, ControlSetTransitions: record.ReservationToIssuanceTransitions,
		Issuance: *record.ProvisionalCertification, IssuanceCARegistry: issued.CARegistry, ResultArtifact: *record.ResultArtifact,
	}
	if _, _, err := enrollmentv2.ApprovalAttestationForEvidence(&evidence, runtime.now().UTC()); err != nil {
		return enrollmentv2.EnrollmentApprovalEvidenceV1{}, err
	}
	return controlClone(evidence), nil
}

func (runtime *controlRuntime) certifiedApplicationLocked() (*controlApplicationV1, error) {
	state, raft := runtime.store.Snapshot(), runtime.storage.SnapshotRaft()
	if state.CertifiedHead == nil || state.CertifiedQC == nil || state.Active != nil ||
		raft.LastApplied != raft.CommitIndex || int64(len(raft.Log)) != raft.CommitIndex {
		return nil, errors.New("[D104 daemon] certified application 暂不可读")
	}
	for _, record := range runtime.journal.Records {
		if record.Result == nil {
			return nil, errors.New("[D104 daemon] 有未恢复的私有事务")
		}
	}
	application, err := runtime.applicationBefore(len(runtime.journal.Records))
	if err != nil {
		return nil, err
	}
	if application == nil {
		return nil, errors.New("[D131 daemon] 私有业务状态尚未激活")
	}
	return application, nil
}

func (runtime *controlRuntime) readDeviceIdentity(ctx context.Context, certificateHash string) (controlplane.DeviceIdentityAuthorityV1, error) {
	if err := ctx.Err(); err != nil {
		return controlplane.DeviceIdentityAuthorityV1{}, err
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	return runtime.readDeviceIdentityLocked(certificateHash)
}

func (runtime *controlRuntime) readDeviceIdentityLocked(certificateHash string) (controlplane.DeviceIdentityAuthorityV1, error) {
	if _, err := wire.ParseHash(certificateHash); err != nil {
		return controlplane.DeviceIdentityAuthorityV1{}, err
	}
	application, err := runtime.certifiedApplicationLocked()
	if err != nil {
		return controlplane.DeviceIdentityAuthorityV1{}, err
	}
	var record enrollmentv2.DurableRecord
	found := false
	for _, device := range application.Devices {
		candidate, exists := runtime.enrollmentStore.SnapshotRecord(device.EnrollmentInviteID)
		if !exists || candidate.State.Status != "completed" || candidate.CompletionProjection == nil ||
			candidate.ResultArtifact == nil || candidate.ProvisionalIssuance == nil || candidate.DeviceCertificateProfile == nil {
			continue
		}
		certificate, err := base64.RawURLEncoding.DecodeString(candidate.ResultArtifact.DeviceCertificateDER)
		hash, hashErr := wire.DeviceCertificateHash(certificate)
		if err == nil && hashErr == nil && hash == certificateHash {
			if found {
				return controlplane.DeviceIdentityAuthorityV1{}, errors.New("[D102 daemon] 同证书存在多个 identity")
			}
			record, found = candidate, true
		}
	}
	migrated, migrationFound, err := runtime.readMigratedDeviceIdentityLocked(application, certificateHash)
	if err != nil {
		return controlplane.DeviceIdentityAuthorityV1{}, err
	}
	if migrationFound {
		if found {
			return controlplane.DeviceIdentityAuthorityV1{}, errors.New("[设备迁移] 同一证书同时绑定迁移与新入网")
		}
		return migrated, nil
	}
	if !found || record.CompletionOperation == nil || record.CompletionCertification == nil {
		return controlplane.DeviceIdentityAuthorityV1{}, errors.New("[D102 daemon] 证书没有已完成的入网事务")
	}
	intent := record.ClaimEvidence.Opening.DeviceEnrollmentIntent
	state := runtime.store.Snapshot()
	qc, err := wire.MarshalCanonical(state.CertifiedQC)
	if err != nil {
		return controlplane.DeviceIdentityAuthorityV1{}, err
	}
	envelope, err := application.deviceEnvelope(intent.DeviceID, *state.CertifiedHead, qc)
	if err != nil {
		return controlplane.DeviceIdentityAuthorityV1{}, err
	}
	profile := *record.DeviceCertificateProfile
	for _, current := range application.CARegistry.DeviceProfiles {
		if current.ProfileID == profile.ProfileID && current.Generation == profile.Generation {
			profile = current
			break
		}
	}
	status := "active"
	if envelope.Payload.State != "active" {
		status = "revocation_pending"
	}
	authority := controlplane.DeviceIdentityAuthorityV1{
		Record: controlplane.DeviceIdentityRecordV1{Schema: 1, CertificateHash: certificateHash, DeviceID: intent.DeviceID,
			IdentitySPKIHash: record.State.IdentityKeyHash, Platform: intent.Platform, Responsibilities: intent.Responsibilities.Values,
			ProfileRef: intent.DeviceCertificateProfileRef, ProfileState: profile, Issuance: record.ProvisionalIssuance.Body.IssuanceLogCoordinate,
			ApprovedAt: record.CompletionCertification.Operation.Head.Body.Payload.CommittedLogicalTime, IdentityStatus: status},
		Head: *state.CertifiedHead, ConfigQC: qc, ControlSet: state.ControlSet,
		AdminCertificateProfiles: application.CARegistry.AdminProfiles, DeviceCertificateProfiles: application.CARegistry.DeviceProfiles,
		CurrentDeviceView: envelope, RecoveryPolicy: &application.RecoveryPolicy,
	}
	return runtime.completeDeviceAuthorityLocked(authority, record.CompletionCertification.Operation.Head.HeadHash)
}

// 迁移身份直接来自原 owner/platform 双签的不可变承诺，不伪造 Enrollment completion。
func (runtime *controlRuntime) readMigratedDeviceIdentityLocked(application *controlApplicationV1,
	certificateHash string) (controlplane.DeviceIdentityAuthorityV1, bool, error) {
	var empty controlplane.DeviceIdentityAuthorityV1
	var migration *wire.RuntimeDeviceMigrationLeafV1
	for i := range application.DeviceMigrations {
		candidate := &application.DeviceMigrations[i]
		if candidate.DeviceCertificateHash != certificateHash {
			continue
		}
		if migration != nil {
			return empty, false, errors.New("[设备迁移] 多个身份复用同一证书")
		}
		migration = candidate
	}
	if migration == nil {
		return empty, false, nil
	}
	var activation *controlOperationRecordV1
	for i := range runtime.journal.Records {
		if runtime.journal.Records[i].Activation != nil {
			activation = &runtime.journal.Records[i]
			break
		}
	}
	if activation == nil || activation.Result == nil {
		return empty, false, errors.New("[设备迁移] 原迁移尚未取得认证回执")
	}
	var original *wire.DeviceCertificateProfileStateV1
	for _, profile := range activation.Activation.Application.CARegistry.DeviceProfiles {
		hash, err := wire.DeviceCertificateProfileStateHash(&profile)
		if err == nil && hash == migration.DeviceCertificateProfileHash {
			copy := profile
			original = &copy
			break
		}
	}
	if original == nil {
		return empty, false, errors.New("[设备迁移] 原认证 CA profile 不存在")
	}
	profile := original
	for _, current := range application.CARegistry.DeviceProfiles {
		if current.ProfileID == original.ProfileID {
			copy := current
			profile = &copy
			break
		}
	}
	state := runtime.store.Snapshot()
	qc, err := wire.MarshalCanonical(state.CertifiedQC)
	if err != nil {
		return empty, false, err
	}
	envelope, err := application.deviceEnvelope(migration.DeviceID, *state.CertifiedHead, qc)
	if err != nil {
		return empty, false, err
	}
	initial, err := activation.Activation.Application.deviceEnvelope(migration.DeviceID, activation.Result.Head, activation.Result.ConfigQC)
	if err != nil || initial.Payload.Active == nil {
		return empty, false, errors.New("[设备迁移] 原身份缺完整迁移 View")
	}
	responsibilities := initial.Payload.Active.Responsibilities.Values
	status := "revocation_pending"
	if envelope.Payload.Active != nil {
		responsibilities, status = envelope.Payload.Active.Responsibilities.Values, "active"
	}
	profileHash, err := wire.DeviceCertificateProfileStateHash(profile)
	if err != nil {
		return empty, false, err
	}
	ref := wire.DeviceCertificateProfileRefV1{ProfileID: profile.ProfileID, Generation: profile.Generation,
		DeviceCertificateProfileIntentHash: profile.DeviceCertificateProfileIntentHash,
		DeviceCertificateProfileStateHash:  profileHash}
	authority := controlplane.DeviceIdentityAuthorityV1{
		Record: controlplane.DeviceIdentityRecordV1{Schema: 1, CertificateHash: certificateHash,
			DeviceID: migration.DeviceID, IdentitySPKIHash: migration.IdentitySPKIHash,
			Platform: migration.Platform, Responsibilities: responsibilities, ProfileRef: ref, ProfileState: *profile,
			Issuance: migration.Issuance, ApprovedAt: activation.Result.Head.Body.Payload.CommittedLogicalTime, IdentityStatus: status},
		Head: *state.CertifiedHead, ConfigQC: qc, ControlSet: state.ControlSet,
		AdminCertificateProfiles: application.CARegistry.AdminProfiles, DeviceCertificateProfiles: application.CARegistry.DeviceProfiles,
		CurrentDeviceView: envelope, RecoveryPolicy: &application.RecoveryPolicy,
	}
	result, err := runtime.completeDeviceAuthorityLocked(authority, activation.Result.Head.HeadHash)
	return result, err == nil, err
}

func (runtime *controlRuntime) completeDeviceAuthorityLocked(authority controlplane.DeviceIdentityAuthorityV1,
	initialHead string) (controlplane.DeviceIdentityAuthorityV1, error) {
	state := runtime.store.Snapshot()
	started := false
	_, err := runtime.walkApplications(len(runtime.journal.Records), func(i int, atHead *controlApplicationV1) error {
		operation := runtime.journal.Records[i]
		if operation.Result == nil {
			return errors.New("[D104 daemon] Device config lineage 未认证")
		}
		if operation.Result.Head.HeadHash == initialHead {
			started = true
		}
		if !started {
			return nil
		}
		view, err := atHead.deviceEnvelope(authority.Record.DeviceID, operation.Result.Head, operation.Result.ConfigQC)
		if err != nil {
			return err
		}
		authority.DeviceConfigUpdates = append(authority.DeviceConfigUpdates, wire.DeviceConfigUpdateV1{Schema: 1,
			Envelope: view, ControlSet: state.ControlSet, RecoveryPolicy: &atHead.RecoveryPolicy})
		return nil
	})
	if err != nil {
		return controlplane.DeviceIdentityAuthorityV1{}, err
	}
	if !started {
		return controlplane.DeviceIdentityAuthorityV1{}, errors.New("[Device identity] 身份起点不在本机认证日志")
	}
	if len(authority.CurrentDeviceView.SecretArtifactRefs) > 0 {
		artifacts, err := enrollmentv2.OpenSealedArtifactStore(filepath.Join(runtime.dir, "sealed-artifacts"))
		if err != nil {
			return controlplane.DeviceIdentityAuthorityV1{}, err
		}
		for _, encoded := range authority.CurrentDeviceView.SecretArtifactRefs {
			var ref wire.SecretArtifactRefV2
			if _, err := wire.DecodeStrict(encoded, 4<<20, &ref); err != nil || ref.SealedBlob == nil ||
				ref.Owner.Device == nil || ref.Owner.Device.DeviceID != authority.Record.DeviceID {
				return controlplane.DeviceIdentityAuthorityV1{}, errors.New("[device_config] sealed ref 不属于当前 Device")
			}
			envelope, err := artifacts.Get(ref.SealedBlob.CiphertextDigest)
			if err != nil {
				return controlplane.DeviceIdentityAuthorityV1{}, err
			}
			if err := wire.VerifySealedSecretBinding(&ref, &envelope); err != nil {
				return controlplane.DeviceIdentityAuthorityV1{}, err
			}
			authority.DeviceSecretEnvelopes = append(authority.DeviceSecretEnvelopes, envelope)
		}
	}
	return controlClone(authority), nil
}
