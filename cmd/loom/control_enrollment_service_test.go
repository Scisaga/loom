package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"loom/internal/clientv2"
	"loom/internal/enrollmentv2"
	"loom/internal/model"
	"loom/internal/render"
	"loom/internal/ssotedit"
	"loom/internal/wire"
)

func TestControlEnrollmentRecoversFirstCertificateBeforeJournalWrite(t *testing.T) {
	runtime, adminDir := controlInviteRuntime(t)
	endpoint, client, _ := progressTestServer(t, runtime, adminDir)
	ctx := context.Background()
	var options controlInviteContextV1
	if err := fetchControlInviteJSON(ctx, endpoint, client, privateControlInviteContextPath, &options); err != nil {
		t.Fatal(err)
	}
	application, err := runtime.applicationBefore(len(runtime.journal.Records))
	if err != nil {
		t.Fatal(err)
	}
	ssot, err := model.Load([]byte(application.LegacySSOT))
	if err != nil {
		t.Fatal(err)
	}
	var grant wire.EnrollmentDestinationGrantV1
	for _, option := range options.Grants {
		for _, declaration := range ssot.Declarations {
			if option.Grant.Kind == "egress" && declaration.EgressAxis == "pinned:"+option.Grant.TargetID {
				grant = option.Grant
				break
			}
		}
		if grant.TargetID != "" {
			break
		}
	}
	if grant.TargetID == "" {
		t.Fatal("fixture 缺 pinned egress grant")
	}
	output := filepath.Join(t.TempDir(), "invitation")
	if err := createControlInvite(ctx, adminDir, endpoint, client, controlCreateInviteInputV1{
		Name: "demo-enrollment", Platform: "linux-server", Responsibilities: []string{"use_loom"},
		Grants: []string{grant.Kind + ":" + grant.TargetID}, TTLSeconds: 900}, output, runtime.now); err != nil {
		t.Fatal(err)
	}
	var descriptor wire.InviteBootstrapDescriptorV2
	var proof wire.InviteProofBundleV2
	if err := readCanonicalFile(filepath.Join(output, "invite.loom-invite"), 8<<20, &descriptor); err != nil {
		t.Fatal(err)
	}
	if err := readCanonicalFile(filepath.Join(output, "proof.json"), 8<<20, &proof); err != nil {
		t.Fatal(err)
	}
	capability, err := wire.VerifyCapabilityAuthorizationEvidence(&descriptor.BootstrapTunnelCapability,
		&proof.BootstrapIssuerAuthorizationProof, &proof.InviteIssuancePolicy, runtime.now())
	if err != nil {
		t.Fatal(err)
	}
	artifacts, err := enrollmentv2.OpenSealedArtifactStore(filepath.Join(runtime.dir, "sealed-artifacts"))
	if err != nil {
		t.Fatal(err)
	}
	journalPath := filepath.Join(runtime.dir, controlJournalName)
	retainedJournal := journalPath + ".before-issuance"
	signingCalls := 0
	var first enrollmentv2.PreparedProvisionalV1
	var coordinate enrollmentv2.EnrollmentCommitCoordinateV1
	provision, err := enrollmentv2.OpenDurableProvisionalService(filepath.Join(runtime.dir, controlProvisionalResultsName),
		func(_ context.Context, _ string, attempt enrollmentv2.VerifiedClaimAttemptV2, record enrollmentv2.DurableRecord,
			at enrollmentv2.EnrollmentCommitCoordinateV1) (enrollmentv2.PreparedProvisionalV1, error) {
			signingCalls++
			application, err := runtime.applicationBefore(len(runtime.journal.Records))
			if err != nil {
				return enrollmentv2.PreparedProvisionalV1{}, err
			}
			state := runtime.store.Snapshot()
			qc, _ := wire.MarshalCanonical(state.CertifiedQC)
			spki, err := base64.RawURLEncoding.DecodeString(attempt.Submission().ClaimCore.DeviceIdentityPublicKey)
			if err != nil {
				return enrollmentv2.PreparedProvisionalV1{}, err
			}
			keyBytes, err := os.ReadFile(filepath.Join(runtime.dir, "demo-device-ca.key"))
			if err != nil {
				return enrollmentv2.PreparedProvisionalV1{}, err
			}
			key, err := parsePrivateKeyPKCS8PEM(keyBytes)
			if err != nil {
				return enrollmentv2.PreparedProvisionalV1{}, err
			}
			input := enrollmentv2.DeviceIssuanceContext{Reservation: record, Head: *state.CertifiedHead, ConfigQC: qc,
				ControlSet: state.ControlSet, CARegistry: application.CARegistry, Profile: application.CARegistry.DeviceProfiles[0],
				Coordinate: at, IdentitySPKIDER: spki}
			first, err = enrollmentv2.PrepareReservedDeviceIssuance(input, controlCARecoveryView(t, application, record),
				[]wire.SecretArtifactRefV2{}, application.IssuanceRegistry, key, nil)
			if err != nil {
				return enrollmentv2.PreparedProvisionalV1{}, err
			}
			coordinate = at
			// 让实际 journal 原子 rename 失败：first-result 仍先正常 fsync。
			// 原日志字节原样保留，恢复时不手工构造 Head、QC 或签发坐标。
			if err := os.Rename(journalPath, retainedJournal); err != nil {
				return enrollmentv2.PreparedProvisionalV1{}, err
			}
			if err := os.Mkdir(journalPath, 0o700); err != nil {
				return enrollmentv2.PreparedProvisionalV1{}, err
			}
			return first, nil
		})
	if err != nil {
		t.Fatal(err)
	}
	workflow, err := runtime.newEnrollmentWorkflow(provision, artifacts)
	if err != nil {
		t.Fatal(err)
	}
	material, err := runtime.readInviteMaterial(ctx, descriptor.ClusterID, descriptor.InviteID)
	if err != nil {
		t.Fatal(err)
	}
	identityDir := filepath.Join(t.TempDir(), "private")
	identity, err := clientv2.OpenOrCreateEnrollmentIdentity(filepath.Join(identityDir, "identity.json"))
	if err != nil {
		t.Fatal(err)
	}
	openingHash, _ := wire.IntentOpeningHash(&material.Opening)
	intentHash, _ := wire.EnrollmentIntentHash(&material.Opening.DeviceEnrollmentIntent)
	setHash, _ := wire.ControlSetHash(&material.ControlSet)
	core, _, err := identity.PrepareClaimCore(clientv2.ClaimCoreInputV2{ClusterID: descriptor.ClusterID, InviteID: descriptor.InviteID,
		RequestID: "demo-recover-issued", CertifiedInviteRecordHash: capability.Body().CommittedInviteRecordHash,
		DeviceEnrollmentIntentCommitmentHash: material.Record.DeviceEnrollmentIntentCommitmentHash,
		DeviceEnrollmentIntentOpeningHash:    openingHash, AcceptedDeviceEnrollmentIntentHash: intentHash,
		BaseRecoveryEpoch: material.RecordHead.Body.Payload.RecoveryEpoch, BaseControlEpoch: material.RecordHead.Body.Payload.ControlEpoch,
		BaseControlSetHash: setHash, BaseHeadHash: material.RecordHead.HeadHash, ClientNonce: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x27}, 32))})
	if err != nil {
		t.Fatal(err)
	}
	submit := func(service *enrollmentv2.PrivateService) (wire.EnrollmentClaimResultV2, error) {
		challenge, err := service.Challenge(ctx, capability, &core)
		if err != nil {
			return wire.EnrollmentClaimResultV2{}, err
		}
		coreHash, _ := wire.EnrollmentClaimCoreHash(&core)
		challengeHash, err := wire.EnrollmentChallengeHash(&challenge, coreHash, runtime.now())
		if err != nil {
			return wire.EnrollmentClaimResultV2{}, err
		}
		pop := wire.EnrollmentPoPBodyV2{Schema: 2, ClusterID: core.ClusterID, InviteID: core.InviteID, RequestID: core.RequestID,
			ClaimCoreHash: coreHash, TokenCommitment: descriptor.TokenCommitment, ChallengeHash: challengeHash}
		signature, err := identity.SignPoP(&pop)
		if err != nil {
			return wire.EnrollmentClaimResultV2{}, err
		}
		return service.SubmitClaim(ctx, capability, &wire.EnrollmentClaimSubmissionV2{Schema: 2, Token: descriptor.Token,
			ClaimCore: core, Challenge: challenge, PoPBody: pop, ProofSignature: signature})
	}
	_, submitError := submit(workflow.Service)
	if submitError == nil {
		t.Fatal("journal 写失败仍报告入网成功")
	}
	if signingCalls != 1 {
		t.Fatalf("未到达真实首次签发: calls=%d", signingCalls)
	}
	stored, err := enrollmentv2.ReadDurableProvisionalResults(filepath.Join(runtime.dir, controlProvisionalResultsName))
	if err != nil || len(stored) != 1 || !wire.EqualCanonical(stored[0].Prepared, first) {
		t.Fatalf("first-result 未耐久保存: read=%v submit=%v", err, submitError)
	}
	if err := os.Remove(journalPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(retainedJournal, journalPath); err != nil {
		t.Fatal(err)
	}
	runtime, err = openControlRuntime(runtime.dir, runtime.now)
	if err != nil {
		t.Fatal(err)
	}
	recovered, found := runtime.enrollmentStore.SnapshotRecord(descriptor.InviteID)
	if !found || recovered.State.Status != "issued_provisional" || recovered.ResultArtifact == nil ||
		!wire.EqualCanonical(*recovered.ResultArtifact, first.Result) || recovered.ProvisionalCertification.Head.Body.Payload.RaftIndex != coordinate.RaftIndex {
		t.Fatal("新任期占用了首次签发坐标或改变了证书结果")
	}
	provision, err = enrollmentv2.OpenDurableProvisionalService(filepath.Join(runtime.dir, controlProvisionalResultsName),
		func(context.Context, string, enrollmentv2.VerifiedClaimAttemptV2, enrollmentv2.DurableRecord, enrollmentv2.EnrollmentCommitCoordinateV1) (enrollmentv2.PreparedProvisionalV1, error) {
			t.Error("恢复继续流程重复签发了证书")
			return enrollmentv2.PreparedProvisionalV1{}, errors.New("demo-unexpected-signing")
		})
	if err != nil {
		t.Fatal(err)
	}
	workflow, err = runtime.newEnrollmentWorkflow(provision, artifacts)
	if err != nil {
		t.Fatal(err)
	}
	completed, err := submit(workflow.Service)
	if err != nil || completed.Status != "completed" {
		t.Fatalf("恢复后的 approval/completion 失败: %v", err)
	}
	repeated, err := submit(workflow.Service)
	if err != nil || !wire.EqualCanonical(completed, repeated) {
		t.Fatalf("completion 后重试丢失原结果: %v", err)
	}
	certificate, _ := wire.EnrollmentResultCertificateDER(&first.Result)
	certificateHash, _ := wire.DeviceCertificateHash(certificate)
	authority, err := runtime.readDeviceIdentity(ctx, certificateHash)
	if err != nil || authority.Record.DeviceID != material.Opening.DeviceEnrollmentIntent.DeviceID ||
		wire.VerifyConfigQCAuthority(authority.Head.HeadHash, authority.ConfigQC, &authority.Head, &authority.ControlSet, nil) != nil {
		t.Fatalf("完成后 Device reader 未读取同一已认证身份: %v", err)
	}
	journalCount := len(runtime.journal.Records)
	runtime, err = openControlRuntime(runtime.dir, runtime.now)
	if err != nil {
		t.Fatal(err)
	}
	workflow, err = runtime.newEnrollmentWorkflow(provision, artifacts)
	if err != nil {
		t.Fatal(err)
	}
	repeated, err = submit(workflow.Service)
	if err != nil || !wire.EqualCanonical(completed, repeated) || len(runtime.journal.Records) != journalCount {
		t.Fatalf("完成后再次重启不能返回原认证结果: %v", err)
	}
}

// CA 故障测试使用真实 renderer 的非空输出绑定 result；此 fixture 的 render contract
// 仅用于签发/日志恢复测试，不作为 Linux 生产配置激活或永久控制链路的验收。
func controlCARecoveryView(t *testing.T, application *controlApplicationV1, record enrollmentv2.DurableRecord) wire.DeviceViewPayloadV2 {
	t.Helper()
	intent := record.ClaimEvidence.Opening.DeviceEnrollmentIntent
	ssot, err := model.Load([]byte(application.LegacySSOT))
	if err != nil {
		t.Fatal(err)
	}
	declarationID := ""
	for _, declaration := range ssot.Declarations {
		if declaration.EgressAxis == "pinned:"+intent.Grants.Values[0].TargetID {
			declarationID = declaration.ID
			break
		}
	}
	if declarationID == "" {
		t.Fatal("fixture grant 未找到")
	}
	plan, err := ssotedit.AddAccessClient([]byte(application.LegacySSOT), ssotedit.ClientInput{ID: intent.DeviceID, Name: "demo-recovery",
		Platform: model.LinuxServer, DestinationGrants: []string{declarationID}})
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := model.Load(plan.Content)
	if err != nil {
		t.Fatal(err)
	}
	rendered, err := render.Render(candidate)
	if err != nil {
		t.Fatal(err)
	}
	var raw []byte
	for _, bundle := range rendered.Bundles {
		if bundle.Owner == intent.DeviceID {
			raw, err = wire.MarshalCanonical(bundle)
		}
	}
	if err != nil || len(raw) < 1 {
		t.Fatal("fixture renderer 未产出配置")
	}
	contentHash, _ := wire.DeviceConfigArtifactContentHash(raw)
	membershipHash, _ := wire.HashObject("loom-enrollment-membership-v1", intent.Membership)
	roleHash, _ := wire.HashObject("loom-enrollment-responsibilities-v1", intent.Responsibilities)
	grantHash, _ := wire.HashObject("loom-enrollment-destination-grants-v1", intent.Grants)
	endpoints := wire.DeviceEndpointBundleV1{Schema: 1, ClusterID: intent.ClusterID, DeviceID: intent.DeviceID, DeviceGeneration: 1, DataIngressSets: []wire.DeviceDataIngressBindingV1{}}
	endpointHash, _ := wire.DeviceEndpointBundleHash(&endpoints)
	secretRoot, _ := wire.SecretArtifactRefsRoot([]wire.SecretArtifactRefV2{})
	return wire.DeviceViewPayloadV2{Schema: 2, ClusterID: intent.ClusterID, DeviceID: intent.DeviceID, DeviceGeneration: 1, State: "active",
		Active: &wire.DeviceActiveViewV1{IdentitySPKIHash: record.State.IdentityKeyHash, Membership: intent.Membership, MembershipHash: membershipHash,
			Responsibilities: intent.Responsibilities, ResponsibilitiesHash: roleHash, Grants: intent.Grants, GrantsHash: grantHash,
			EndpointBundle: endpoints, EndpointBundleHash: endpointHash, SecretArtifactRefsRoot: secretRoot,
			ConfigArtifactRefs: []wire.DeviceConfigArtifactRefV1{{ArtifactID: "demo-rendered", Generation: 1, Platform: "linux-server",
				MediaType: "application/vnd.loom.config+json", RenderContractID: "demo-render-v1", SizeBytes: int64(len(raw)), ContentHash: contentHash}}}}
}
