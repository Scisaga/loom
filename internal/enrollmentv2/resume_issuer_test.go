package enrollmentv2

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"loom/internal/wire"
)

func TestDurableResumeIssuerFreezesExactTokenFreeFirstResult(t *testing.T) {
	fixture, request, material := resumeIssuerFixture(t)
	path := filepath.Join(t.TempDir(), "resume-first-results.json")
	readCalls, signCalls := 0, 0
	issuer, err := OpenDurableResumeIssuer(path,
		func(_ context.Context, clusterID, inviteID, requestID string) (ResumeIssuanceMaterialV1, error) {
			readCalls++
			if clusterID != request.ClusterID || inviteID != request.InviteID || requestID != request.RequestID {
				t.Fatal("resume reader 收到错误 transaction identity")
			}
			return material, nil
		},
		func(_ context.Context, body wire.BootstrapTunnelCapabilityBodyV1) (wire.BootstrapTunnelCapabilityV1, error) {
			signCalls++
			return wire.SignBootstrapCapability(body, fixture.issuerPrivate)
		}, func() time.Time { return fixture.now })
	if err != nil {
		t.Fatal(err)
	}
	first, err := issuer.Issue(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := issuer.Issue(context.Background(), request)
	if err != nil || !wire.EqualCanonical(first, replayed) || readCalls != 1 || signCalls != 1 {
		t.Fatalf("同进程 replay 未返回 exact first-result: reads=%d signs=%d err=%v", readCalls, signCalls, err)
	}
	if first.ResumeTunnelCapability.Body.Mode != "resume_committed_claim" ||
		first.ResumeTunnelCapability.Body.ResumeBinding == nil ||
		first.ResumeTunnelCapability.Body.ResumeBinding.EnrollmentTransactionStateHash != request.ExpectedTransactionStateHash {
		t.Fatal("resume capability 未绑定 exact committed transaction")
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("resume journal 权限不是 0600: %v %v", info, err)
	}

	reopened, err := OpenDurableResumeIssuer(path,
		func(context.Context, string, string, string) (ResumeIssuanceMaterialV1, error) {
			t.Fatal("重启 replay 不应重新读取 transaction")
			return ResumeIssuanceMaterialV1{}, context.Canceled
		},
		func(context.Context, wire.BootstrapTunnelCapabilityBodyV1) (wire.BootstrapTunnelCapabilityV1, error) {
			t.Fatal("重启 replay 不应重新签名")
			return wire.BootstrapTunnelCapabilityV1{}, context.Canceled
		}, func() time.Time { return fixture.now.Add(time.Hour) })
	if err != nil {
		t.Fatal(err)
	}
	afterRestart, err := reopened.Issue(context.Background(), request)
	if err != nil || !wire.EqualCanonical(first, afterRestart) {
		t.Fatalf("重启 replay 未返回逐字节同一 descriptor: %v", err)
	}

	conflict := request
	conflict.ExpiresAt = fixture.now.Add(8 * time.Minute).Format(time.RFC3339)
	if _, err := reopened.Issue(context.Background(), conflict); err == nil {
		t.Fatal("同一 certified operation ID 接受了不同 resume request")
	}
}

func TestDurableResumeIssuerRejectsStaleOrOverlongAuthority(t *testing.T) {
	fixture, request, material := resumeIssuerFixture(t)
	tests := []struct {
		name   string
		mutate func(*ResumeIssueRequestV1, *ResumeIssuanceMaterialV1)
	}{
		{name: "stale transaction", mutate: func(request *ResumeIssueRequestV1, _ *ResumeIssuanceMaterialV1) {
			request.ExpectedTransactionStateHash = wire.HashRaw("resume-issuer-test", []byte("stale-transaction"))
		}},
		{name: "past retry deadline", mutate: func(request *ResumeIssueRequestV1, _ *ResumeIssuanceMaterialV1) {
			request.ExpiresAt = "2026-09-11T11:46:00Z"
		}},
		{name: "past issuer ttl", mutate: func(request *ResumeIssueRequestV1, _ *ResumeIssuanceMaterialV1) {
			request.ExpiresAt = "2026-09-11T11:21:00Z"
		}},
		{name: "substituted catalog", mutate: func(_ *ResumeIssueRequestV1, material *ResumeIssuanceMaterialV1) {
			material.BootstrapCatalog.CatalogGeneration++
		}},
		{name: "substituted service", mutate: func(_ *ResumeIssueRequestV1, material *ResumeIssuanceMaterialV1) {
			material.Invite.EnrollmentServiceRef.TCPPort++
		}},
		{name: "uncertified mirror", mutate: func(_ *ResumeIssueRequestV1, material *ResumeIssuanceMaterialV1) {
			material.DistributionMirrors[0].BaseURL = "https://evil.example.test:443/distribution/sha256/"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidateRequest := request
			candidateMaterial := clonePrivateValue(material)
			test.mutate(&candidateRequest, &candidateMaterial)
			signCalls := 0
			issuer, err := OpenDurableResumeIssuer(filepath.Join(t.TempDir(), "resume.json"),
				func(context.Context, string, string, string) (ResumeIssuanceMaterialV1, error) {
					return candidateMaterial, nil
				}, func(_ context.Context, body wire.BootstrapTunnelCapabilityBodyV1) (wire.BootstrapTunnelCapabilityV1, error) {
					signCalls++
					return wire.SignBootstrapCapability(body, fixture.issuerPrivate)
				}, func() time.Time { return fixture.now })
			if err != nil {
				t.Fatal(err)
			}
			if _, err := issuer.Issue(context.Background(), candidateRequest); err == nil || signCalls != 0 {
				t.Fatalf("无效 authority 到达 signer: signs=%d err=%v", signCalls, err)
			}
		})
	}
}

func TestDurableResumeIssuerRejectsSignerSubstitutionAndCorruptJournal(t *testing.T) {
	fixture, request, material := resumeIssuerFixture(t)
	path := filepath.Join(t.TempDir(), "resume.json")
	bad, err := OpenDurableResumeIssuer(path,
		func(context.Context, string, string, string) (ResumeIssuanceMaterialV1, error) { return material, nil },
		func(_ context.Context, body wire.BootstrapTunnelCapabilityBodyV1) (wire.BootstrapTunnelCapabilityV1, error) {
			body.ResumeBinding.RequestID = "different-request"
			return wire.SignBootstrapCapability(body, fixture.issuerPrivate)
		}, func() time.Time { return fixture.now })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bad.Issue(context.Background(), request); err == nil {
		t.Fatal("issuer 接受了 signer 替换后的 capability body")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("无效 signer result 被部分持久化")
	}

	good, err := OpenDurableResumeIssuer(path,
		func(context.Context, string, string, string) (ResumeIssuanceMaterialV1, error) { return material, nil },
		func(_ context.Context, body wire.BootstrapTunnelCapabilityBodyV1) (wire.BootstrapTunnelCapabilityV1, error) {
			return wire.SignBootstrapCapability(body, fixture.issuerPrivate)
		}, func() time.Time { return fixture.now })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := good.Issue(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var state resumeFirstResultStateV1
	if _, err := wire.DecodeStrict(body, 16<<20, &state); err != nil {
		t.Fatal(err)
	}
	state.Records[0].Descriptor.ProofBundleHash = wire.HashRaw("resume-issuer-test", []byte("tampered-proof"))
	body, err = wire.MarshalCanonical(state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenDurableResumeIssuer(path,
		func(context.Context, string, string, string) (ResumeIssuanceMaterialV1, error) { return material, nil },
		func(context.Context, wire.BootstrapTunnelCapabilityBodyV1) (wire.BootstrapTunnelCapabilityV1, error) {
			return wire.BootstrapTunnelCapabilityV1{}, context.Canceled
		}, func() time.Time { return fixture.now }); err == nil {
		t.Fatal("损坏的 resume first-result journal 被接受")
	}
}

func resumeIssuerFixture(t *testing.T) (privateServiceFixture, ResumeIssueRequestV1, ResumeIssuanceMaterialV1) {
	t.Helper()
	fixture := newPrivateServiceFixture(t)
	attempt := verifiedPrivateAttempt(t, fixture)
	set, member, enrollmentKey := controlSet(t)
	attestation, err := attempt.AdmissionAttestation()
	if err != nil {
		t.Fatal(err)
	}
	signature, err := wire.SignEnrollmentAdmission(attestation, member, enrollmentKey)
	if err != nil {
		t.Fatal(err)
	}
	admission := wire.StableEnrollmentAdmissionQC(attestation, []wire.ControlEnrollmentSignatureV1{signature})
	admissionHash, err := wire.EnrollmentAdmissionQCHash(&admission)
	if err != nil {
		t.Fatal(err)
	}
	claim := ClaimOperationV2{
		Schema: 2, ClusterID: fixture.core.ClusterID, OperationID: "claim-operation-resume",
		InviteID: fixture.core.InviteID, RequestID: fixture.core.RequestID,
		CertifiedInviteRecordHash:            fixture.core.CertifiedInviteRecordHash,
		DeviceEnrollmentIntentCommitmentHash: fixture.core.DeviceEnrollmentIntentCommitmentHash,
		DeviceEnrollmentIntentOpeningHash:    fixture.core.DeviceEnrollmentIntentOpeningHash,
		TokenCommitment:                      fixture.material.Record.TokenCommitment, ClaimCoreHash: attempt.Claim().ClaimCoreHash(),
		AdmissionQCHash: admissionHash, IdentityKeyHash: attempt.Claim().IdentityKeyHash(),
		WrappingKeyHash: attempt.Claim().WrappingKeyHash(), CSRHash: attempt.Claim().CSRHash(),
		ReservedAt: "2026-09-11T11:06:00Z", RetryNotAfter: "2026-09-11T11:45:00Z",
	}
	certification := certifiedOperationFixture(t, set, claim.OperationID, DomainClaimOperation,
		claim, claim.ReservedAt, 4, &fixture.material.RecordHead)
	state, err := Reserve(attempt.InviteContext(), claim, &admission, &set, claim.ReservedAt)
	if err != nil {
		t.Fatal(err)
	}
	record := DurableRecord{
		InviteID: claim.InviteID, TokenCommitment: claim.TokenCommitment, Invite: attempt.InviteContext(),
		ClaimEvidence: attempt.PrivateClaimEvidence(), ClaimOperation: claim, AdmissionQC: admission,
		AdmissionControlSet: set, ReservationBaseHead: fixture.material.RecordHead,
		ReservationCertification: certification, State: state,
	}
	if err := validateDurableRecord(&record); err != nil {
		t.Fatal(err)
	}
	stateHash, err := TransactionHash(state)
	if err != nil {
		t.Fatal(err)
	}
	invite := cloneInviteMaterial(fixture.material)
	invite.Status = state.Status
	mirrors, endpointSets := resumeDistributionFixture(t, fixture.bootstrapCatalogHead,
		fixture.bootstrapCatalog.BootstrapIngressSet.ConfigQC)
	material := ResumeIssuanceMaterialV1{
		Transaction: record, Invite: invite, BootstrapCatalog: fixture.bootstrapCatalog,
		CatalogHead: fixture.bootstrapCatalogHead, CatalogControlSet: set,
		IssuerAuthorizationProof: fixture.issuerProof,
		ProofBundleHash:          wire.HashRaw("resume-issuer-test", []byte("proof-bundle")),
		DistributionMirrors:      mirrors, DistributionEndpointSets: endpointSets,
	}
	request := ResumeIssueRequestV1{
		Schema: 1, OperationID: "issue-resume-operation", ClusterID: state.ClusterID,
		InviteID: state.InviteID, RequestID: state.RequestID, DeviceID: "linux-device",
		ExpectedTransactionStateHash: stateHash,
		IssuedAt:                     fixture.now.Format(time.RFC3339), ExpiresAt: fixture.now.Add(9 * time.Minute).Format(time.RFC3339),
	}
	return fixture, request, material
}

func resumeDistributionFixture(t *testing.T, head wire.HeadEntryV2,
	configQC []byte) ([]wire.DistributionMirrorRefV1, map[string]wire.DistributionEndpointSetV1) {
	t.Helper()
	mirrors := make([]wire.DistributionMirrorRefV1, 0, 2)
	sets := make(map[string]wire.DistributionEndpointSetV1, 2)
	for index, marker := range []string{"a", "b"} {
		pin := wire.HashRaw("resume-issuer-test", []byte(marker+"-pin"))
		serverName := marker + ".example.test"
		port := int64(443 + index)
		listener := wire.ListenerGenerationV2{
			Schema: 2, ListenerGeneration: 1, PublishedState: "preferred", DialTargetFQDN: serverName,
			PublicPort: port, AddressFamilies: []string{"ipv4"}, TransportIdentityRefs: []string{pin, "webpki-v1"},
			CredentialGeneration: 1, CertificateIntentHash: wire.HashRaw("resume-issuer-test", []byte(marker+"-certificate")),
			PublicProfileGeneration: 1, IntroducedRevision: 1, ValidFrom: "2026-09-11T11:00:00Z",
			ValidUntil: "2026-09-12T11:00:00Z", RotationOperationHash: wire.HashRaw("resume-issuer-test", []byte(marker+"-rotation")),
		}
		endpointID := "mirror-" + marker
		set := wire.DistributionEndpointSetV1{
			Schema: 1, ClusterID: "cluster", EndpointSetID: "distribution-" + marker, Generation: 1,
			ValidFrom: "2026-09-11T11:00:00Z", ValidUntil: "2026-09-12T11:00:00Z",
			Endpoints: []wire.DistributionEndpointV1{{EndpointID: endpointID, LogicalServerID: "server-" + marker,
				Transport: "https", DistributionPathPrefix: "/distribution/sha256/",
				ListenerGenerations: []wire.ListenerGenerationV2{listener}, ListenerTombstones: []wire.ListenerGenerationTombstoneV1{}}},
			ParentHeadHash: head.HeadHash, ConfigQC: append([]byte(nil), configQC...),
		}
		setHash, err := wire.DistributionEndpointSetHash(&set)
		if err != nil {
			t.Fatal(err)
		}
		sets[setHash] = set
		mirrors = append(mirrors, wire.DistributionMirrorRefV1{
			Schema: 1, EndpointID: endpointID, DistributionEndpointSetHash: setHash, ListenerGeneration: 1,
			BaseURL:    "https://" + serverName + ":" + strconv.FormatInt(port, 10) + "/distribution/sha256/",
			ServerName: serverName, WebPKIProfileRef: "webpki-v1", SPKIPins: []string{pin}, HintRank: int64(index),
		})
	}
	return mirrors, sets
}
