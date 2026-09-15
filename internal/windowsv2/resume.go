package windowsv2

import (
	"context"
	"errors"
	"time"

	"loom/internal/clientsecret"
	"loom/internal/enrollmentv2"
	"loom/internal/wire"
)

type PrivateEnrollmentResumeAPI interface {
	Preflight(context.Context, wire.EnrollmentIntentPreflightRequestV1, string) (wire.EnrollmentIntentPreflightResponseV1, error)
	Challenge(context.Context, wire.EnrollmentClaimCoreV2) (wire.EnrollmentPoPChallengeV1, error)
	SubmitResume(context.Context, wire.EnrollmentResumeSubmissionV1) (wire.EnrollmentClaimResultV2, error)
}

type ResumeAttempt struct {
	Descriptor     *wire.EnrollmentResumeDescriptorV1
	ProofBundle    *wire.InviteProofBundleV2
	Catalog        *wire.BootstrapEndpointCatalogV1
	Trust          wire.InviteProofTrustV2
	API            PrivateEnrollmentResumeAPI
	IdentityPath   string
	JournalPath    string
	Protector      clientsecret.Protector
	ClientProtocol int64
	Now            func() time.Time
}

// RunResumeAttempt 只恢复 DPAPI journal 中已 certified 的 committed transaction。
// descriptor 在第一个私网请求前 durable 绑定；整条路径不读取也不发送 Invite token。
func RunResumeAttempt(ctx context.Context, attempt ResumeAttempt) (EnrollmentAttemptResult, error) {
	if ctx == nil || attempt.Descriptor == nil || attempt.ProofBundle == nil ||
		attempt.Catalog == nil || attempt.API == nil || attempt.Protector == nil ||
		attempt.IdentityPath == "" || attempt.JournalPath == "" ||
		attempt.ClientProtocol < 1 || attempt.Now == nil {
		return EnrollmentAttemptResult{}, errors.New("[Windows resume] attempt 输入不完整")
	}
	now := attempt.Now().UTC()
	if now.IsZero() {
		return EnrollmentAttemptResult{}, errors.New("[Windows resume] 可信时间无效")
	}
	descriptor, bundle := attempt.Descriptor, attempt.ProofBundle
	verifiedProof, err := wire.VerifyResumeInviteProofBundle(bundle, descriptor, now, attempt.Trust)
	if err != nil {
		return EnrollmentAttemptResult{}, err
	}
	recordHash, err := wire.CertifiedInviteRecordHash(&bundle.CertifiedInviteRecord,
		&bundle.InviteIssuancePolicy)
	if err != nil || recordHash != verifiedProof.CertifiedInviteRecordHash() ||
		descriptor.ClusterID != bundle.ClusterID || descriptor.InviteID != bundle.InviteID {
		return EnrollmentAttemptResult{}, errors.New("[Windows resume] proof evidence/descriptor 不匹配")
	}
	verifiedHead, verifiedSet := verifiedProof.Head(), verifiedProof.ControlSet()
	setHash, err := wire.ControlSetHash(&verifiedSet)
	if err != nil || !wire.EqualCanonical(verifiedHead, bundle.RecordHead) ||
		verifiedHead.Body.Payload.ControlSetHash != setHash {
		return EnrollmentAttemptResult{}, errors.New("[Windows resume] proof evidence Head/ControlSet 不匹配")
	}
	catalogHash, err := wire.BootstrapEndpointCatalogHash(attempt.Catalog)
	if err != nil || catalogHash != descriptor.BootstrapCatalogHash ||
		wire.ValidateBootstrapEndpointCatalogAt(attempt.Catalog, now, attempt.ClientProtocol) != nil ||
		attempt.Catalog.BootstrapIngressSetHash != descriptor.ResumeTunnelCapability.Body.AllowedIngressSetHash {
		return EnrollmentAttemptResult{}, errors.New("[Windows resume] catalog/hash/ingress binding 无效")
	}
	catalogHead, catalogSet, previousSet, ok := verifiedProof.AuthorityForHead(attempt.Catalog.ParentHeadHash)
	if !ok || wire.VerifyConfigQCAuthority(attempt.Catalog.ParentHeadHash,
		attempt.Catalog.BootstrapIngressSet.ConfigQC, &catalogHead, &catalogSet, previousSet) != nil {
		return EnrollmentAttemptResult{}, errors.New("[Windows resume] catalog QC authority 未通过 Invite lineage")
	}

	identity, err := LoadIdentity(attempt.IdentityPath, attempt.Protector)
	if err != nil {
		return EnrollmentAttemptResult{}, err
	}
	defer identity.Close()
	store, err := newJournalStore(attempt.JournalPath, attempt.Protector)
	if err != nil {
		return EnrollmentAttemptResult{}, err
	}
	journal, err := store.load(identity)
	if err != nil {
		return EnrollmentAttemptResult{}, err
	}
	if journal.Progress == nil {
		return EnrollmentAttemptResult{}, errors.New("[Windows resume] 本机没有可恢复的 committed transaction")
	}
	core := journal.ClaimCore
	if core.ClusterID != descriptor.ClusterID || core.InviteID != descriptor.InviteID ||
		core.RequestID != descriptor.RequestID || journal.ClaimCoreHash != descriptor.ClaimCoreHash ||
		core.CertifiedInviteRecordHash != recordHash ||
		core.DeviceEnrollmentIntentCommitmentHash != bundle.CertifiedInviteRecord.DeviceEnrollmentIntentCommitmentHash ||
		core.BaseHeadHash != verifiedHead.HeadHash ||
		core.BaseRecoveryEpoch != verifiedHead.Body.Payload.RecoveryEpoch ||
		core.BaseControlEpoch != verifiedHead.Body.Payload.ControlEpoch || core.BaseControlSetHash != setHash {
		return EnrollmentAttemptResult{}, errors.New("[Windows resume] protected core 未绑定 exact Invite authority")
	}
	if err := wire.VerifyEnrollmentResumeDescriptorBindings(descriptor, journal.Progress.Expected,
		attempt.Catalog, &bundle.BootstrapIssuerAuthorizationProof,
		&bundle.InviteIssuancePolicy, now, attempt.ClientProtocol); err != nil {
		return EnrollmentAttemptResult{}, err
	}
	if err := bindResumeDescriptor(store, journal, identity, descriptor); err != nil {
		return EnrollmentAttemptResult{}, err
	}

	inputs := verifiedEnrollmentInputs{
		descriptor: cloneValue(journal.Descriptor), bundle: cloneValue(*bundle),
		record: cloneValue(bundle.CertifiedInviteRecord), policy: cloneValue(bundle.InviteIssuancePolicy),
		commitment: cloneValue(bundle.DeviceEnrollmentIntentCommitment), head: verifiedHead, set: verifiedSet,
	}
	identityHash, err := identity.IdentitySPKIHash()
	if err != nil {
		return EnrollmentAttemptResult{}, err
	}
	if journal.Result != nil && journal.Result.Status == "completed" {
		completion, err := verifyCompletedResult(*journal.Result, journal, inputs, now)
		if err != nil {
			return EnrollmentAttemptResult{}, err
		}
		if err := requireResumeTransactionFloors(completion.IncludesTransactionStateHash,
			journal.Progress.Expected.EnrollmentTransactionStateHash,
			descriptor.EnrollmentTransactionStateHash); err != nil {
			return EnrollmentAttemptResult{}, err
		}
		return EnrollmentAttemptResult{ClaimCoreHash: journal.ClaimCoreHash,
			IdentityHash: identityHash, Result: *journal.Result, Completion: completion}, nil
	}

	preflightRequest := wire.EnrollmentIntentPreflightRequestV1{
		Schema: 1, ClusterID: core.ClusterID, InviteID: core.InviteID,
		CertifiedInviteRecordHash: recordHash,
		CapabilityID:              descriptor.ResumeTunnelCapability.CapabilityID,
	}
	preflight, err := attempt.API.Preflight(ctx, preflightRequest,
		bundle.CertifiedInviteRecord.DeviceEnrollmentIntentCommitmentHash)
	if err != nil {
		return EnrollmentAttemptResult{}, err
	}
	if err := wire.VerifyEnrollmentIntentPreflight(&preflight, &preflightRequest,
		bundle.CertifiedInviteRecord.DeviceEnrollmentIntentCommitmentHash); err != nil {
		return EnrollmentAttemptResult{}, err
	}
	opening := preflight.DeviceEnrollmentIntentOpening
	openingHash, err := wire.IntentOpeningHash(&opening)
	intentHash, intentErr := wire.EnrollmentIntentHash(&opening.DeviceEnrollmentIntent)
	if err != nil || intentErr != nil || opening.DeviceEnrollmentIntent.Platform != "windows-desktop" ||
		openingHash != core.DeviceEnrollmentIntentOpeningHash ||
		intentHash != core.AcceptedDeviceEnrollmentIntentHash ||
		!wire.EqualCanonical(preflight.DeviceEnrollmentIntentCommitment,
			bundle.DeviceEnrollmentIntentCommitment) ||
		!wire.EqualCanonical(opening, journal.Preflight.DeviceEnrollmentIntentOpening) {
		return EnrollmentAttemptResult{}, errors.New("[Windows resume] preflight 未恢复 exact committed opening")
	}
	challenge, err := attempt.API.Challenge(ctx, core)
	if err != nil {
		return EnrollmentAttemptResult{}, err
	}
	challengeNow := attempt.Now().UTC()
	if challengeNow.IsZero() {
		return EnrollmentAttemptResult{}, errors.New("[Windows resume] challenge 可信时间无效")
	}
	if err := wire.VerifyEnrollmentResumeDescriptorBindings(descriptor, journal.Progress.Expected,
		attempt.Catalog, &bundle.BootstrapIssuerAuthorizationProof,
		&bundle.InviteIssuancePolicy, challengeNow, attempt.ClientProtocol); err != nil {
		return EnrollmentAttemptResult{}, err
	}
	challengeHash, err := wire.EnrollmentChallengeHash(&challenge, journal.ClaimCoreHash, challengeNow)
	if err != nil {
		return EnrollmentAttemptResult{}, err
	}
	pop := wire.EnrollmentPoPBodyV2{
		Schema: 2, ClusterID: core.ClusterID, InviteID: core.InviteID,
		RequestID: core.RequestID, ClaimCoreHash: journal.ClaimCoreHash,
		TokenCommitment: bundle.CertifiedInviteRecord.TokenCommitment,
		ChallengeHash:   challengeHash,
	}
	signature, err := identity.SignEnrollmentPoP(&pop)
	if err != nil {
		return EnrollmentAttemptResult{}, err
	}
	submission := wire.EnrollmentResumeSubmissionV1{
		Schema: 1, ClaimCore: core, Challenge: challenge,
		PoPBody: pop, ProofSignature: signature,
	}
	if _, err := wire.VerifyEnrollmentResumeSubmission(&submission,
		descriptor.ResumeTunnelCapability.Body.ResumeBinding, &bundle.CertifiedInviteRecord,
		&bundle.InviteIssuancePolicy, &opening,
		descriptor.EnrollmentServiceRef.ServiceID, challengeNow); err != nil {
		return EnrollmentAttemptResult{}, err
	}
	result, err := attempt.API.SubmitResume(ctx, submission)
	if err != nil {
		return EnrollmentAttemptResult{}, err
	}
	if err := wire.ValidateEnrollmentClaimResult(&result); err != nil {
		return EnrollmentAttemptResult{}, err
	}
	resultNow := attempt.Now().UTC()
	if resultNow.IsZero() {
		return EnrollmentAttemptResult{}, errors.New("[Windows resume] result 可信时间无效")
	}
	output := EnrollmentAttemptResult{ClaimCoreHash: journal.ClaimCoreHash,
		IdentityHash: identityHash, Result: result}
	proofExpected := enrollmentv2.EnrollmentProgressExpectedV1{
		Record: bundle.CertifiedInviteRecord, Policy: bundle.InviteIssuancePolicy,
		Opening: opening, ClaimCore: core, BaseHead: verifiedHead, BaseControlSet: verifiedSet,
	}
	if result.Status == "completed" {
		output.Completion, err = enrollmentv2.VerifyEnrollmentCompletionReceipt(result.CompletionReceipt,
			&result, enrollmentv2.EnrollmentCompletionExpectedV1{
				Record: proofExpected.Record, Policy: proofExpected.Policy, Opening: proofExpected.Opening,
				ClaimCore: proofExpected.ClaimCore, BaseHead: proofExpected.BaseHead,
				BaseControlSet: proofExpected.BaseControlSet, TrustedTime: resultNow,
			})
		if err == nil {
			err = requireResumeTransactionFloors(output.Completion.IncludesTransactionStateHash,
				journal.Progress.Expected.EnrollmentTransactionStateHash,
				descriptor.EnrollmentTransactionStateHash)
		}
	} else if len(result.ProgressReceipt) != 0 {
		output.Progress, err = enrollmentv2.VerifyEnrollmentProgressReceipt(result.ProgressReceipt,
			&result, proofExpected)
		if err == nil {
			err = requireResumeTransactionFloors(output.Progress.IncludesTransactionStateHash,
				journal.Progress.Expected.EnrollmentTransactionStateHash,
				descriptor.EnrollmentTransactionStateHash)
		}
		if err == nil {
			err = recordJournalProgress(journal, output.Progress)
		}
	} else {
		err = errors.New("[Windows resume] pending 响应缺 progress receipt")
	}
	if err != nil {
		return EnrollmentAttemptResult{}, err
	}
	resultCopy := cloneValue(result)
	journal.Result = &resultCopy
	if err := store.write(journal, identity); err != nil {
		return EnrollmentAttemptResult{}, err
	}
	return output, nil
}

func bindResumeDescriptor(store *journalStore, journal *EnrollmentJournalV1,
	identity *Identity, descriptor *wire.EnrollmentResumeDescriptorV1) error {
	if journal.ResumeDescriptor != nil {
		if !wire.EqualCanonical(*journal.ResumeDescriptor, *descriptor) {
			return errors.New("[Windows resume] 已绑定另一份 resume descriptor")
		}
		return nil
	}
	copy := cloneValue(*descriptor)
	hash, err := wire.HashObject(wire.DomainEnrollmentResumeDescriptor, &copy)
	if err != nil {
		return err
	}
	journal.ResumeDescriptor, journal.ResumeDescriptorHash = &copy, hash
	return store.write(journal, identity)
}

func requireResumeTransactionFloors(includes func(string) bool, hashes ...string) error {
	if includes == nil {
		return errors.New("[Windows resume] receipt floor verifier 缺失")
	}
	for _, hash := range hashes {
		if !includes(hash) {
			return errors.New("[Windows resume] receipt 不包含本机与 descriptor transaction floor")
		}
	}
	return nil
}
