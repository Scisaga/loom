//go:build linux

package clientv2

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"loom/internal/wire"
)

type fakePrivateEnrollmentAPI struct {
	t              *testing.T
	now            time.Time
	opening        wire.DeviceEnrollmentIntentOpeningV1
	commitmentHash string
	record         wire.CertifiedInviteRecordV2
	policy         wire.InviteIssuancePolicyV2
	serviceID      string
	identityPath   string
	failPreflight  bool
	preflightCalls int
	challengeByte  byte
	coreHashes     []string
}

func (fake *fakePrivateEnrollmentAPI) Preflight(_ context.Context, request wire.EnrollmentIntentPreflightRequestV1,
	expectedCommitmentHash string) (wire.EnrollmentIntentPreflightResponseV1, error) {
	if fake.preflightCalls == 0 {
		if _, err := os.Stat(fake.identityPath); !errors.Is(err, os.ErrNotExist) {
			fake.t.Fatal("identity key 在首次 token-free preflight 完成前已生成")
		}
	}
	fake.preflightCalls++
	if fake.failPreflight {
		return wire.EnrollmentIntentPreflightResponseV1{}, errors.New("preflight failed")
	}
	if expectedCommitmentHash != fake.commitmentHash {
		fake.t.Fatal("preflight 未使用 certified commitment")
	}
	requestHash, _ := wire.EnrollmentIntentPreflightRequestHash(&request)
	commitment, _, _ := wire.IntentCommitment(&fake.opening)
	return wire.EnrollmentIntentPreflightResponseV1{
		Schema: 1, ClusterID: request.ClusterID, InviteID: request.InviteID, RequestHash: requestHash,
		DeviceEnrollmentIntentCommitment: commitment, DeviceEnrollmentIntentOpening: fake.opening,
	}, nil
}

func (fake *fakePrivateEnrollmentAPI) Challenge(_ context.Context,
	core wire.EnrollmentClaimCoreV2) (wire.EnrollmentPoPChallengeV1, error) {
	coreHash, err := wire.EnrollmentClaimCoreHash(&core)
	if err != nil {
		return wire.EnrollmentPoPChallengeV1{}, err
	}
	fake.challengeByte++
	return wire.EnrollmentPoPChallengeV1{
		Schema: 1, ClusterID: core.ClusterID, InviteID: core.InviteID, RequestID: core.RequestID,
		EnrollmentServiceID: fake.serviceID, ClaimCoreHash: coreHash,
		ServerNonce: base64.RawURLEncoding.EncodeToString(bytesFilled(32, fake.challengeByte)),
		IssuedAt:    fake.now.Format(time.RFC3339), ExpiresAt: fake.now.Add(time.Minute).Format(time.RFC3339),
	}, nil
}

func (fake *fakePrivateEnrollmentAPI) SubmitClaim(_ context.Context,
	submission wire.EnrollmentClaimSubmissionV2) (wire.EnrollmentClaimResultV2, error) {
	verified, err := wire.VerifyEnrollmentClaimSubmission(&submission, &fake.record, &fake.policy,
		&fake.opening, fake.serviceID, fake.now)
	if err != nil {
		return wire.EnrollmentClaimResultV2{}, err
	}
	fake.coreHashes = append(fake.coreHashes, verified.ClaimCoreHash())
	return wire.EnrollmentClaimResultV2{
		Schema: 2, Status: "reserved", TransactionStateHash: wire.HashRaw("linux-enrollment-test", []byte("transaction")),
	}, nil
}

func TestLinuxEnrollmentOrdersPreflightBeforeKeysAndReusesStableCore(t *testing.T) {
	attempt, inputs, fake := linuxEnrollmentAttemptFixture(t)
	first, err := runLinuxEnrollmentAttempt(context.Background(), attempt, inputs)
	if err != nil {
		t.Fatal(err)
	}
	second, err := runLinuxEnrollmentAttempt(context.Background(), attempt, inputs)
	if err != nil {
		t.Fatal(err)
	}
	if first.ClaimCoreHash == "" || first.ClaimCoreHash != second.ClaimCoreHash || len(fake.coreHashes) != 2 ||
		fake.coreHashes[0] != fake.coreHashes[1] {
		t.Fatalf("跨 challenge retry 改变 stable claim core: first=%s second=%s seen=%v",
			first.ClaimCoreHash, second.ClaimCoreHash, fake.coreHashes)
	}
	identityInfo, err := os.Stat(attempt.IdentityPath)
	if err != nil {
		t.Fatal(err)
	}
	if identityInfo.Mode().Perm() != 0o600 {
		t.Fatalf("identity state 未按 0600 持久化: %#o", identityInfo.Mode().Perm())
	}
	identity, err := LoadEnrollmentIdentityForResume(attempt.IdentityPath)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := LoadPendingClaimForEnrollmentRetry(attempt.PendingPath, identity)
	if err != nil || retry.ClaimCore.RequestID != attempt.RequestID || retry.Progress != nil {
		t.Fatalf("首次 progress 前的 Enrollment retry state 不可复用: pending=%#v err=%v", retry, err)
	}
	if _, err := LoadPendingClaimForResume(attempt.PendingPath, identity); err == nil {
		t.Fatal("尚无 verified progress 的 pending claim 被用于 resume")
	}
}

func TestLinuxEnrollmentPreflightFailureCreatesNoIdentity(t *testing.T) {
	attempt, inputs, fake := linuxEnrollmentAttemptFixture(t)
	fake.failPreflight = true
	if _, err := runLinuxEnrollmentAttempt(context.Background(), attempt, inputs); err == nil {
		t.Fatal("preflight failure 被接受")
	}
	if _, err := os.Stat(attempt.IdentityPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("preflight 失败后遗留 identity state: %v", err)
	}
}

func TestLinuxPendingProgressPersistsResumeBindingAndRejectsRollback(t *testing.T) {
	attempt, inputs, fake := linuxEnrollmentAttemptFixture(t)
	if _, err := runLinuxEnrollmentAttempt(context.Background(), attempt, inputs); err != nil {
		t.Fatal(err)
	}
	identity, err := OpenOrCreateEnrollmentIdentity(attempt.IdentityPath)
	if err != nil {
		t.Fatal(err)
	}
	recordHash, _ := wire.CertifiedInviteRecordHash(&inputs.record, &inputs.policy)
	openingHash, _ := wire.IntentOpeningHash(&fake.opening)
	intentHash, _ := wire.EnrollmentIntentHash(&fake.opening.DeviceEnrollmentIntent)
	setHash, _ := wire.ControlSetHash(&inputs.set)
	input := ClaimCoreInputV2{
		ClusterID: inputs.record.ClusterID, InviteID: inputs.record.InviteID, RequestID: attempt.RequestID,
		CertifiedInviteRecordHash:            recordHash,
		DeviceEnrollmentIntentCommitmentHash: inputs.record.DeviceEnrollmentIntentCommitmentHash,
		DeviceEnrollmentIntentOpeningHash:    openingHash, AcceptedDeviceEnrollmentIntentHash: intentHash,
		BaseRecoveryEpoch:  inputs.head.Body.Payload.RecoveryEpoch,
		BaseControlEpoch:   inputs.head.Body.Payload.ControlEpoch,
		BaseControlSetHash: setHash, BaseHeadHash: inputs.head.HeadHash,
	}
	pending, err := loadPendingClaim(attempt.PendingPath, identity, input)
	if err != nil {
		t.Fatal(err)
	}
	identityHash, wrappingHash, csrHash, err := wire.EnrollmentClaimBinaryHashes(&pending.ClaimCore)
	if err != nil {
		t.Fatal(err)
	}
	expected := wire.EnrollmentResumeExpectedV1{
		ClusterID: pending.ClaimCore.ClusterID, InviteID: pending.ClaimCore.InviteID,
		RequestID: pending.ClaimCore.RequestID, ClaimCoreHash: pending.ClaimCoreHash,
		ClaimOperationHash: wire.HashRaw("linux-progress-test", []byte("claim")),
		AdmissionQCHash:    wire.HashRaw("linux-progress-test", []byte("admission")),
		CSRHash:            csrHash, IdentityKeyHash: identityHash, WrappingKeyHash: wrappingHash,
		EnrollmentTransactionStateHash: wire.HashRaw("linux-progress-test", []byte("reserved")),
		RetryNotAfter:                  fake.now.Add(30 * time.Minute).Format(time.RFC3339),
	}
	recorded, err := recordPendingProgress(attempt.PendingPath, identity, input, "reserved", expected)
	if err != nil || recorded.Progress == nil || !wire.EqualCanonical(recorded.Progress.Expected, expected) {
		t.Fatalf("reserved progress 未耐久化: progress=%#v err=%v", recorded.Progress, err)
	}
	if _, err := recordPendingProgress(attempt.PendingPath, identity, input, "reserved", expected); err != nil {
		t.Fatalf("exact progress replay 非幂等: %v", err)
	}
	issued := expected
	issued.EnrollmentTransactionStateHash = wire.HashRaw("linux-progress-test", []byte("issued"))
	if _, err := recordPendingProgress(attempt.PendingPath, identity, input, "issued_provisional", issued); err != nil {
		t.Fatalf("reserved→issued progress 被拒绝: %v", err)
	}
	resumable, err := LoadPendingClaimForResume(attempt.PendingPath, identity)
	if err != nil || resumable.Progress == nil || resumable.Progress.Status != "issued_provisional" {
		t.Fatalf("已固化 progress 的 pending claim 不可恢复: pending=%#v err=%v", resumable, err)
	}
	if _, err := recordPendingProgress(attempt.PendingPath, identity, input, "reserved", expected); err == nil {
		t.Fatal("较旧 reserved progress 覆盖了 issued floor")
	}
	fork := issued
	fork.EnrollmentTransactionStateHash = wire.HashRaw("linux-progress-test", []byte("fork"))
	if _, err := recordPendingProgress(attempt.PendingPath, identity, input, "issued_provisional", fork); err == nil {
		t.Fatal("同一 issued stage 的不同 transaction hash 被接受")
	}
}

func linuxEnrollmentAttemptFixture(t *testing.T) (LinuxEnrollmentAttemptV2, verifiedEnrollmentInputs, *fakePrivateEnrollmentAPI) {
	t.Helper()
	now := time.Date(2026, 9, 11, 11, 5, 0, 0, time.UTC)
	opening := privateClientOpening(t)
	commitment, commitmentHash, _ := wire.IntentCommitment(&opening)
	policy := wire.InviteIssuancePolicyV2{
		Schema: 2, ClusterID: "cluster", PolicyID: "policy", Generation: 1,
		MinimumTTLSeconds: 300, MaximumTTLSeconds: 1800, MaximumDescriptorBytes: 65536,
		MaximumIntentOpeningBytes: 65536, MinimumDistributionMirrors: 2, MaximumDistributionMirrors: 3,
		AllowedBootstrapTransports:         []string{"hysteria2", "trojan_tls"},
		MaximumInitialCapabilityTTLSeconds: 900, MaximumResumeCapabilityTTLSeconds: 900,
		MaximumReservationRetrySeconds: 1800, BootstrapSessionSeconds: 180,
		BootstrapTotalBytes: 8 << 20, BootstrapConnectionAttempts: 3, BootstrapMaxConcurrentSessions: 1,
	}
	policyHash, _ := wire.InviteIssuancePolicyHash(&policy)
	token := base64.RawURLEncoding.EncodeToString(bytesFilled(32, 0x71))
	tokenCommitment, _ := wire.TokenCommitment("cluster", "invite", token)
	record := wire.CertifiedInviteRecordV2{
		Schema: 2, ClusterID: "cluster", InviteID: "invite", Generation: 1,
		IssuedAt: "2026-09-11T11:00:00Z", ExpiresAt: "2026-09-11T11:15:00Z",
		DeviceEnrollmentIntentCommitmentHash: commitmentHash, TokenCommitment: tokenCommitment,
		TokenArtifactBindingHash: wire.HashRaw("linux-enrollment-test", []byte("token-artifact")),
		InviteIssuancePolicyHash: policyHash, BootstrapIssuerAuthorizationHash: wire.HashRaw("linux-enrollment-test", []byte("issuer")),
		BootstrapIssuerRegistryRoot: wire.HashRaw("linux-enrollment-test", []byte("issuer-root")),
		BootstrapCatalogHash:        wire.HashRaw("linux-enrollment-test", []byte("catalog")),
		EnrollmentServiceRefHash:    wire.HashRaw("linux-enrollment-test", []byte("service")),
		OperationID:                 "invite-operation", ParentHeadHash: wire.HashRaw("linux-enrollment-test", []byte("parent")),
	}
	set, _ := clientControlSet(t)
	set.ClusterID = "cluster"
	for i := range set.Members {
		set.Members[i].ClusterID = "cluster"
	}
	setHash, _ := wire.ControlSetHash(&set)
	head := wire.HeadEntryV2{HeadHash: wire.HashRaw("linux-enrollment-test", []byte("head")),
		Body: wire.HeadEntryBodyV2{Payload: wire.HeadEntryPayloadV2{
			ClusterID: "cluster", RecoveryEpoch: 0, ControlEpoch: 0, ControlSetHash: setHash,
		}}}
	descriptor := wire.InviteBootstrapDescriptorV2{
		Schema: 2, ClusterID: "cluster", InviteID: "invite", Token: token, TokenCommitment: tokenCommitment,
		BootstrapTunnelCapability: wire.BootstrapTunnelCapabilityV1{CapabilityID: wire.HashRaw("linux-enrollment-test", []byte("capability"))},
		EnrollmentServiceRef:      wire.PrivateEnrollmentServiceRefV1{ServiceID: "enrollment-service"},
	}
	directory := filepath.Join(t.TempDir(), "private")
	attempt := LinuxEnrollmentAttemptV2{
		API: nil, IdentityPath: filepath.Join(directory, "identity.json"), PendingPath: filepath.Join(directory, "pending.json"),
		RequestID: "request", Now: func() time.Time { return now },
	}
	fake := &fakePrivateEnrollmentAPI{t: t, now: now, opening: opening, commitmentHash: commitmentHash,
		record: record, policy: policy, serviceID: "enrollment-service", identityPath: attempt.IdentityPath}
	attempt.API = fake
	inputs := verifiedEnrollmentInputs{descriptor: descriptor, record: record, policy: policy, commitment: commitment, head: head, set: set}
	return attempt, inputs, fake
}

func bytesFilled(size int, value byte) []byte {
	result := make([]byte, size)
	for i := range result {
		result[i] = value
	}
	return result
}
