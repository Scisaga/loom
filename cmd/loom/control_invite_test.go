package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"loom/internal/controlplane"
	"loom/internal/enrollmentv2"
	"loom/internal/wire"
)

func TestControlInviteUsesDaemonAuthorityAndSurvivesRestart(t *testing.T) {
	runtime, adminDir := controlInviteRuntime(t)
	endpoint, client, address := progressTestServer(t, runtime, adminDir)
	before, err := fetchControlStatus(context.Background(), endpoint, client)
	if err != nil {
		t.Fatal(err)
	}
	request, payload := controlInviteRequest(t, runtime, adminDir, "demo-first")
	result, err := submitControlOperation(context.Background(), adminDir, endpoint, client, before, request)
	if err != nil {
		t.Fatal(err)
	}
	if result.Head.Body.Payload.SnapshotHash == before.Head.Body.Payload.SnapshotHash ||
		result.Head.Body.Payload.EffectiveSSOTHash != before.Head.Body.Payload.EffectiveSSOTHash ||
		result.Head.Body.Payload.DeviceViewsRoot != before.Head.Body.Payload.DeviceViewsRoot || result.OperationTreeSize != 3 {
		t.Fatal("创建邀请没有改变 private snapshot 或在 completion 前授予业务访问")
	}
	material, err := runtime.readInviteMaterial(context.Background(), runtime.config.ClusterID, payload.Invite.Record.InviteID)
	if err != nil {
		t.Fatal(err)
	}
	if material.Status != "available" || material.RecordHead.HeadHash != result.Head.HeadHash || material.InviteTreeSize != 3 ||
		!wire.EqualCanonical(material.Opening, payload.Invite.Opening) {
		t.Fatal("private Enrollment 没有读到同一认证邀请")
	}
	if err := wire.VerifyConfigQCAuthority(material.RecordHead.HeadHash, material.RecordHeadQC, &material.RecordHead, &material.ControlSet, nil); err != nil {
		t.Fatal(err)
	}
	if err := wire.VerifyControlOperationInclusion(&material.InviteOperationLeaf, material.InviteLeafIndex, material.InviteTreeSize,
		material.InviteAuditPath, &material.RecordHead); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{controlJournalName, controlRaftName, controlStateName} {
		contents, err := os.ReadFile(filepath.Join(runtime.dir, name))
		if err != nil || bytes.Contains(contents, []byte(payload.Token.Token)) {
			t.Fatalf("token 泄漏到 %s 或缺持久状态: %v", name, err)
		}
	}
	progress := fetchOperationProgress(t, client, address, controlplane.PrivateControlOperationPath+"/"+request.RequestID)
	if len(progress.Operations) != 1 || progress.Operations[0].Kind != controlCreateInviteKind || progress.Operations[0].Phase != controlplane.PhaseApplied {
		t.Fatal("管理操作进度没有关联真实创建邀请请求")
	}
	reopened, err := openControlRuntime(runtime.dir, runtime.now)
	if err != nil {
		t.Fatal(err)
	}
	after, err := reopened.readInviteMaterial(context.Background(), runtime.config.ClusterID, payload.Invite.Record.InviteID)
	if err != nil || !wire.EqualCanonical(material, after) {
		t.Fatalf("重启改变已认证邀请/证明: %v", err)
	}
	// 后续 ping 和第二个邀请必须保留原邀请的额外 opaque leaf。
	endpoint, client, address = progressTestServer(t, reopened, adminDir)
	repeatedResult, err := submitControlOperation(context.Background(), adminDir, endpoint, client, before, request)
	if err != nil || !wire.EqualCanonical(result, repeatedResult) || len(reopened.journal.Records) != 2 {
		t.Fatalf("丢失成功响应后的重试没有返回第一次结果: %v", err)
	}
	status, _ := fetchControlStatus(context.Background(), endpoint, client)
	ping, err := newControlPingRequest(adminDir, endpoint, status, "demo-following-ping", runtime.now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := submitControlOperation(context.Background(), adminDir, endpoint, client, status, ping); err != nil {
		t.Fatal(err)
	}
	status, _ = fetchControlStatus(context.Background(), endpoint, client)
	second, _ := controlInviteRequest(t, reopened, adminDir, "demo-second")
	secondResult, err := submitControlOperation(context.Background(), adminDir, endpoint, client, status, second)
	if err != nil || secondResult.OperationTreeSize != 6 {
		t.Fatalf("第二次创建邀请丢失累计 operation tree: %v", err)
	}
	secondPayload := controlCreateInvitePayloadV1{}
	if _, err := wire.DecodeStrict(second.Payload, 2<<20, &secondPayload); err != nil {
		t.Fatal(err)
	}
	response, err := client.Get("https://" + address + privateControlInvitePrefix + secondPayload.Invite.Record.InviteID + "/delivery")
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil || response.StatusCode != http.StatusOK || response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("Referrer-Policy") != "no-referrer" {
		t.Fatalf("私有邀请交付失败: status=%d body=%s err=%v", response.StatusCode, data, err)
	}
	var delivery controlInviteDeliveryV1
	if _, err := wire.DecodeStrict(data, 8<<20, &delivery); err != nil {
		t.Fatal(err)
	}
	verified, err := wire.VerifyInviteProofBundle(&delivery.Proof, &delivery.Descriptor, reopened.now(), wire.InviteProofTrustV2{})
	if err != nil || verified.Head().HeadHash != secondResult.Head.HeadHash || len(delivery.Proof.AuthorityTransitions) != 2 {
		t.Fatalf("实际交付没有完整普通 Head lineage: %v", err)
	}
	catalogHead, catalogSet, previousSet, found := verified.AuthorityForHead(delivery.Catalog.ParentHeadHash)
	if !found || wire.VerifyConfigQCAuthority(catalogHead.HeadHash, delivery.Catalog.BootstrapIngressSet.ConfigQC, &catalogHead, &catalogSet, previousSet) != nil {
		t.Fatal("客户端不能从已验迁移历史验证 bootstrap catalog")
	}
	for _, public := range []any{delivery.Proof, delivery.Catalog} {
		raw, err := wire.MarshalCanonical(public)
		if err != nil || bytes.Contains(raw, []byte(secondPayload.Token.Token)) || bytes.Contains(raw, []byte(secondPayload.Invite.Opening.HidingNonce)) ||
			bytes.Contains(raw, []byte(secondPayload.Invite.Opening.DeviceEnrollmentIntent.DeviceID)) {
			t.Fatal("public proof/catalog 泄漏私有邀请内容")
		}
	}
	for name, change := range map[string]func(*wire.InviteProofBundleV2){
		"missing-prefix": func(proof *wire.InviteProofBundleV2) { proof.AuthorityTransitions = proof.AuthorityTransitions[1:] },
		"missing-prefix-qc": func(proof *wire.InviteProofBundleV2) {
			var head wire.CertifiedHeadV1
			_, _ = wire.DecodeStrict(proof.AuthorityTransitions[0], 4<<20, &head)
			head.QC = json.RawMessage(`{}`)
			proof.AuthorityTransitions[0], _ = wire.MarshalCanonical(head)
		},
	} {
		t.Run(name, func(t *testing.T) {
			proof := controlClone(delivery.Proof)
			change(&proof)
			descriptor := controlClone(delivery.Descriptor)
			descriptor.ProofBundleHash, _ = wire.InviteProofBundleHash(&proof)
			if _, err := wire.VerifyInviteProofBundle(&proof, &descriptor, reopened.now(), wire.InviteProofTrustV2{}); err == nil {
				t.Fatal("客户端接受不完整或未认证的历史")
			}
		})
	}
	reopened.mu.Lock()
	clock := reopened.now
	later := clock().Add(30 * time.Second)
	reopened.now = func() time.Time { return later }
	repeated, repeatErr := reopened.inviteDeliveryLocked(secondPayload.Invite.Record.InviteID)
	reopened.now = clock
	reopened.mu.Unlock()
	if repeatErr != nil || !wire.EqualCanonical(delivery, repeated) {
		t.Fatalf("再次交付刷新 capability 或修改邀请: %v", repeatErr)
	}
}

func TestControlAdminRotationAfterInvitePreservesBusinessProjection(t *testing.T) {
	runtime, adminDir := controlInviteRuntime(t)
	request, payload := controlInviteRequest(t, runtime, adminDir, "demo-before-rotation")
	peer := readAdminTestCertificate(t, filepath.Join(adminDir, controlAdminCertName))
	serveRuntimeOperation(t, runtime, peer, request, http.StatusOK)
	before, err := runtime.applicationBefore(len(runtime.journal.Records))
	if err != nil {
		t.Fatal(err)
	}
	nextDir := filepath.Join(t.TempDir(), "admin")
	if err := runtime.rotateAdminCertificate(adminDir, nextDir, "demo-admin-rotation"); err != nil {
		t.Fatal(err)
	}
	reopened, err := openControlRuntime(runtime.dir, runtime.now)
	if err != nil {
		t.Fatal(err)
	}
	after, err := reopened.applicationBefore(len(reopened.journal.Records))
	if err != nil || !wire.EqualCanonical(before.CARegistry.DeviceProfiles, after.CARegistry.DeviceProfiles) ||
		!wire.EqualCanonical(before.Invites, after.Invites) || before.LegacySSOT != after.LegacySSOT {
		t.Fatalf("管理员换证改变了已有 Device CA、邀请或配置: %v", err)
	}
	material, err := reopened.readInviteMaterial(context.Background(), reopened.config.ClusterID, payload.Invite.Record.InviteID)
	if err != nil || material.InviteTreeSize != 3 {
		t.Fatalf("换证后丢失邀请证明: %v", err)
	}
	newRequest, _ := controlInviteRequest(t, reopened, nextDir, "demo-after-rotation")
	newPeer := readAdminTestCertificate(t, filepath.Join(nextDir, controlAdminCertName))
	serveRuntimeOperation(t, reopened, newPeer, newRequest, http.StatusOK)
}

func TestControlInviteRejectsTamperingAndMissingGrantWithoutStateChange(t *testing.T) {
	runtime, adminDir := controlInviteRuntime(t)
	_, client, address := progressTestServer(t, runtime, adminDir)
	original, payload := controlInviteRequest(t, runtime, adminDir, "demo-rejected")
	before := runtime.store.Snapshot().CertifiedHead.HeadHash
	for name, change := range map[string]func(*controlCreateInvitePayloadV1){
		"token": func(p *controlCreateInvitePayloadV1) {
			p.Token.Token = base64.RawURLEncoding.EncodeToString(make([]byte, 32))
		},
		"name": func(p *controlCreateInvitePayloadV1) { p.Invite.DisplayName = "demo-altered-name" },
		"opening": func(p *controlCreateInvitePayloadV1) {
			p.Invite.Opening.DeviceEnrollmentIntent.DeviceID = "demo-other-device"
		},
	} {
		t.Run(name, func(t *testing.T) {
			changed := controlClone(payload)
			change(&changed)
			request := controlClone(original)
			request.Payload, _ = wire.MarshalCanonical(changed)
			raw, _ := wire.MarshalCanonical(request)
			response, err := client.Post("https://"+address+controlplane.PrivateControlOperationPath, "application/json", bytes.NewReader(raw))
			if err != nil {
				t.Fatal(err)
			}
			_, _ = io.Copy(io.Discard, response.Body)
			_ = response.Body.Close()
			if response.StatusCode != http.StatusBadRequest || runtime.store.Snapshot().CertifiedHead.HeadHash != before || len(runtime.journal.Records) != 1 {
				t.Fatal("被替换的 payload/token 改变了认证状态")
			}
		})
	}
	// 有效签名也不能批准不存在的资源；必须由真实 reducer 根据当前 SSOT 拒绝。
	payload.Invite.Opening.DeviceEnrollmentIntent.Grants.Values = []wire.EnrollmentDestinationGrantV1{{Kind: "service", TargetID: "demo-missing-service"}}
	payload.Invite.Opening.DeviceEnrollmentIntentHash, _ = wire.EnrollmentIntentHash(&payload.Invite.Opening.DeviceEnrollmentIntent)
	payload.Invite.Commitment, payload.Invite.Record.DeviceEnrollmentIntentCommitmentHash, _ = wire.IntentCommitment(&payload.Invite.Opening)
	request := controlSignInviteRequest(t, adminDir, original, payload)
	peer := readAdminTestCertificate(t, filepath.Join(adminDir, controlAdminCertName))
	serveRuntimeOperation(t, runtime, peer, request, http.StatusServiceUnavailable)
	if runtime.store.Snapshot().CertifiedHead.HeadHash != before || len(runtime.journal.Records) != 1 {
		t.Fatal("管理员签名绕过资源投影验证")
	}
}

func TestControlInviteRecoversEveryDurablePhase(t *testing.T) {
	for _, phase := range controlOperationPhases {
		t.Run(string(phase), func(t *testing.T) {
			runtime, adminDir := controlInviteRuntime(t)
			request, payload := controlInviteRequest(t, runtime, adminDir, "demo-recovery")
			runtime.checkpoint = func(reached controlplane.Phase) error {
				if reached == phase {
					return errors.New("demo-crash-after-durable-stage")
				}
				return nil
			}
			peer := readAdminTestCertificate(t, filepath.Join(adminDir, controlAdminCertName))
			serveRuntimeOperation(t, runtime, peer, request, http.StatusServiceUnavailable)
			reopened, err := openControlRuntime(runtime.dir, runtime.now)
			if err != nil {
				t.Fatal(err)
			}
			material, err := reopened.readInviteMaterial(context.Background(), reopened.config.ClusterID, payload.Invite.Record.InviteID)
			if err != nil || len(reopened.journal.Records) != 2 || material.InviteTreeSize != 3 ||
				!wire.EqualCanonical(material.Record, payload.Invite.Record) {
				t.Fatalf("重启没有恢复唯一邀请: %v", err)
			}
		})
	}
}

func controlInviteRequest(t *testing.T, runtime *controlRuntime, adminDir, id string) (controlOperationRequestV1, controlCreateInvitePayloadV1) {
	t.Helper()
	peer := readAdminTestCertificate(t, filepath.Join(adminDir, controlAdminCertName))
	status := serveRuntimeStatus(t, runtime, peer)
	var endpoint controlAdminEndpointV1
	if err := readCanonicalFile(filepath.Join(adminDir, controlEndpointName), 4<<20, &endpoint); err != nil {
		t.Fatal(err)
	}
	request, err := newControlPingRequest(adminDir, endpoint, status, "demo-create-invite", runtime.now())
	if err != nil {
		t.Fatal(err)
	}
	application, err := runtime.applicationBefore(len(runtime.journal.Records))
	if err != nil {
		t.Fatal(err)
	}
	profile := application.CARegistry.DeviceProfiles[0]
	profileHash, _ := wire.DeviceCertificateProfileStateHash(&profile)
	intent := wire.DeviceEnrollmentIntentV1{Schema: 1, ClusterID: application.ClusterID, InviteID: id, DeviceID: id + "-device", Platform: "linux-server",
		DeviceCertificateProfileRef: wire.DeviceCertificateProfileRefV1{ProfileID: profile.ProfileID, Generation: profile.Generation,
			DeviceCertificateProfileIntentHash: profile.DeviceCertificateProfileIntentHash, DeviceCertificateProfileStateHash: profileHash},
		WrappingKeyProfiles: []string{"p256-root-only-pkcs8-ecdh-v1"}, Membership: wire.EnrollmentMembershipV1{Schema: 1, DesiredState: "active_on_completion"},
		Responsibilities: wire.EnrollmentResponsibilitiesV1{Schema: 1, Values: []string{"use_loom"}},
		Grants:           wire.EnrollmentDestinationGrantsV1{Schema: 1, Values: []wire.EnrollmentDestinationGrantV1{}}}
	intentHash, _ := wire.EnrollmentIntentHash(&intent)
	nonce, tokenBytes := make([]byte, 32), make([]byte, 32)
	_, _ = rand.Read(nonce)
	_, _ = rand.Read(tokenBytes)
	opening := wire.DeviceEnrollmentIntentOpeningV1{Schema: 1, ClusterID: application.ClusterID, InviteID: id, DeviceEnrollmentIntent: intent,
		DeviceEnrollmentIntentHash: intentHash, HidingNonce: base64.RawURLEncoding.EncodeToString(nonce)}
	commitment, commitmentHash, _ := wire.IntentCommitment(&opening)
	token := wire.InviteTokenCommitmentInputV2{Schema: 2, ClusterID: application.ClusterID, InviteID: id, Token: base64.RawURLEncoding.EncodeToString(tokenBytes)}
	tokenCommitment, _ := wire.TokenCommitment(application.ClusterID, id, token.Token)
	tokenArtifact, _ := wire.HashObject(controlInviteTokenDomain, token)
	policyHash, _ := wire.InviteIssuancePolicyHash(&application.InvitePolicy)
	catalogHash, _ := wire.BootstrapEndpointCatalogHash(&application.BootstrapCatalog)
	serviceHash, _ := wire.PrivateEnrollmentServiceRefHash(&application.EnrollmentService)
	issuerHash, _ := wire.BootstrapIssuerAuthorizationHash(&application.BootstrapIssuers[0])
	operationID, _ := controlInviteRecordOperationID(application.ClusterID, request.RequestID)
	record := wire.CertifiedInviteRecordV2{Schema: 2, ClusterID: application.ClusterID, InviteID: id, Generation: 1,
		IssuedAt: runtime.now().UTC().Format(time.RFC3339), ExpiresAt: runtime.now().Add(15 * time.Minute).UTC().Format(time.RFC3339),
		DeviceEnrollmentIntentCommitmentHash: commitmentHash, TokenCommitment: tokenCommitment, TokenArtifactBindingHash: tokenArtifact,
		InviteIssuancePolicyHash: policyHash, BootstrapIssuerAuthorizationHash: issuerHash, BootstrapIssuerRegistryRoot: status.Head.Body.Payload.BootstrapIssuerRegistryRoot,
		BootstrapCatalogHash: catalogHash, EnrollmentServiceRefHash: serviceHash, OperationID: operationID, ParentHeadHash: status.Head.HeadHash}
	payload := controlCreateInvitePayloadV1{Schema: 1, Invite: controlInviteStateV1{Status: "available", DisplayName: "demo-device", Record: record,
		Commitment: commitment, Opening: opening}, Token: token}
	raw, err := wire.MarshalCanonical(payload)
	if err != nil {
		t.Fatal(err)
	}
	request, err = newControlInviteRequest(adminDir, endpoint, status, request.RequestID, raw, "demo-create-invite")
	if err != nil {
		t.Fatal(err)
	}
	return request, payload
}

func controlSignInviteRequest(t *testing.T, adminDir string, request controlOperationRequestV1, payload controlCreateInvitePayloadV1) controlOperationRequestV1 {
	t.Helper()
	keyPEM, err := os.ReadFile(filepath.Join(adminDir, controlAdminKeyName))
	if err != nil {
		t.Fatal(err)
	}
	key, err := parseAdminPrivateKey(keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	body := request.Operation.Body
	body.Kind = controlCreateInviteKind
	body.PayloadHash, err = controlInvitePayloadHash(payload.Invite)
	if err != nil {
		t.Fatal(err)
	}
	request.Operation, err = wire.NewControlOperation(body, key, controlOperationSchemas)
	if err != nil {
		t.Fatal(err)
	}
	request.Payload, err = wire.MarshalCanonical(payload)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func controlInviteRuntime(t *testing.T) (*controlRuntime, string) {
	t.Helper()
	dir, adminDir := newAdminRotationFixture(t, true)
	now := time.Now().UTC().Truncate(time.Second)
	runtime, err := openControlRuntime(dir, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	application, recoveryProofs := controlInviteApplication(t, runtime)
	state := runtime.store.Snapshot()
	parent := *state.CertifiedHead
	qcRaw, _ := wire.MarshalCanonical(state.CertifiedQC)
	qcHash, _ := wire.ConfigQCHash(qcRaw)
	policyHash, _ := wire.RecoveryPolicyHash(&application.RecoveryPolicy)
	popRoot, _ := wire.RecoveryKeyPossessionRoot(&application.RecoveryPolicy, recoveryProofs)
	owner := readAdminTestCertificate(t, filepath.Join(adminDir, controlAdminRootName))
	var secrets controlDiskSecretsV1
	if err := readCanonicalFile(filepath.Join(dir, controlSecretsName), 8<<20, &secrets); err != nil {
		t.Fatal(err)
	}
	ownerKey, err := parseAdminPrivateKey([]byte(secrets.AdminCAPrivateKeyPKCS8PEM))
	if err != nil {
		t.Fatal(err)
	}
	platformPublic, platformKey, _ := ed25519.GenerateKey(rand.Reader)
	platformID, _ := wire.ControlKeyID(platformPublic)
	platformDigest := sha256.Sum256(platformPublic)
	roots, err := application.roots()
	if err != nil {
		t.Fatal(err)
	}
	migrationRoot, _ := wire.RuntimeDeviceMigrationRoot(nil)
	statement := wire.RuntimeActivationStatementV1{DeviceMigrationRoot: migrationRoot, Schema: 1, ClusterID: application.ClusterID, OperationID: "demo-runtime-activation",
		ParentHeadHash: parent.HeadHash, ParentQCHash: qcHash, LegacyRecoveryPolicyHash: parent.Body.Payload.RecoveryPolicyHash,
		V1PlatformKeyID: platformID, V1PlatformPublicKey: base64.RawURLEncoding.EncodeToString(platformPublic), V1PlatformKeyDigest: fmt.Sprintf("sha256:%x", platformDigest),
		NewRecoveryEpoch: 2, NewRecoveryPolicyHash: policyHash, NewRecoveryKeyPoPRoot: popRoot, Roots: roots,
		IssuedAt: now.Format(time.RFC3339), Reason: "demo-real-runtime-test"}
	proof, err := wire.SignRuntimeActivationProof(statement, wire.LegacyRuntimePolicyV1{Schema: 1, AdminRoot: base64.RawURLEncoding.EncodeToString(owner.Raw)}, ownerKey.(ed25519.PrivateKey), platformKey)
	if err != nil {
		t.Fatal(err)
	}
	activation := controlRuntimeActivationV1{Bundle: wire.RuntimeActivationBundleV1{Schema: 1, Proof: proof, Parent: parent, ParentQC: *state.CertifiedQC,
		ControlSet: runtime.config.ControlSet, RecoveryPolicy: application.RecoveryPolicy, RecoveryKeyPossessionProofs: recoveryProofs,
		PreviousOperationLeaves: runtime.operationLeaves(len(runtime.journal.Records))}, Application: application,
		PreviousAuthorization: runtime.config.Authorizations[0]}
	activation.PreviousProfile = runtime.config.AdminProfiles[activation.PreviousAuthorization.CertificateProfileRef.ProfileID]
	var endpoint controlAdminEndpointV1
	_ = readCanonicalFile(filepath.Join(adminDir, controlEndpointName), 4<<20, &endpoint)
	request, err := newControlPingRequest(adminDir, endpoint, serveRuntimeStatus(t, runtime, readAdminTestCertificate(t, filepath.Join(adminDir, controlAdminCertName))), "demo-activation", now)
	if err != nil {
		t.Fatal(err)
	}
	body := request.Operation.Body
	body.Kind, body.OperationID = controlActivationKind, statement.OperationID
	body.PayloadHash, _ = wire.RuntimeActivationStatementHash(&statement)
	keyRaw, _ := os.ReadFile(filepath.Join(adminDir, controlAdminKeyName))
	key, _ := parseAdminPrivateKey(keyRaw)
	operation, err := wire.NewControlOperation(body, key, controlActivationSchemas)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.activateRuntime(activation, operation); err != nil {
		t.Fatal(err)
	}
	return runtime, adminDir
}

func controlInviteApplication(t *testing.T, runtime *controlRuntime) (controlApplicationV1, []wire.RecoveryKeyPossessionProofV1) {
	t.Helper()
	now := runtime.now()
	from, until := now.Add(-time.Minute).Format(time.RFC3339), now.Add(time.Hour).Format(time.RFC3339)
	hash := func(value string) string { return wire.HashRaw("demo-runtime-fixture-v1", []byte(value)) }
	ssot, err := os.ReadFile(filepath.Join("..", "..", "testdata", "matrix", "ssot.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	recovery, err := prepareControlRecovery(filepath.Join(t.TempDir(), "custody"), runtime.config.ClusterID, "demo-recovery", "demo-custodian", "demo-prepare", now.UTC().Truncate(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	previous := runtime.config.Authorizations[0]
	profile := runtime.config.AdminProfiles[previous.CertificateProfileRef.ProfileID]
	next := controlClone(previous)
	next.Generation++
	next.PreviousAuthorizationHash, _ = wire.AdminAuthorizationHash(&previous, &profile)
	next.AllowedOperationKinds = []string{controlPingKind, controlCreateInviteKind}
	policy := wire.InviteIssuancePolicyV2{Schema: 2, ClusterID: runtime.config.ClusterID, PolicyID: "demo-invite-policy", Generation: 1,
		MinimumTTLSeconds: 300, MaximumTTLSeconds: 1800, MaximumDescriptorBytes: 65536, MaximumIntentOpeningBytes: 65536,
		MinimumDistributionMirrors: 2, MaximumDistributionMirrors: 3, AllowedBootstrapTransports: []string{"hysteria2", "trojan_tls"},
		MaximumInitialCapabilityTTLSeconds: 900, MaximumResumeCapabilityTTLSeconds: 900, MaximumReservationRetrySeconds: 1800,
		BootstrapSessionSeconds: 180, BootstrapTotalBytes: 8 << 20, BootstrapConnectionAttempts: 3, BootstrapMaxConcurrentSessions: 1}
	policyHash, _ := wire.InviteIssuancePolicyHash(&policy)
	services := []wire.PrivateControlServiceV1{runtime.config.ControlService}
	for index, role := range []string{"enroll", "device_config", "device_report"} {
		service := controlClone(runtime.config.ControlService)
		service.ServiceID, service.Role, service.Port = "demo-"+role, role, service.Port+int64(index)+10
		service.CertificateProfileRef, service.SPKIPins = "demo-"+role+"-profile", []string{hash(role + "-pin")}
		service.AuthorizedSubjectProfiles = []string{"demo-device-profile"}
		services = append(services, service)
	}
	enroll := wire.PrivateEnrollmentServiceRefV1{Schema: 1, ServiceID: services[1].ServiceID, OverlayIP: services[1].OverlayIP,
		TCPPort: services[1].Port, InternalCAProfileRef: services[1].CertificateProfileRef, ServerIdentitySPKIPins: services[1].SPKIPins, ServiceGeneration: 1}
	state := runtime.store.Snapshot()
	qc, _ := wire.MarshalCanonical(state.CertifiedQC)
	qcHash, _ := wire.ConfigQCHash(qc)
	listener := wire.ListenerGenerationV2{Schema: 2, ListenerGeneration: 1, PublishedState: "preferred", DialTargetFQDN: "demo-edge.example.test", PublicPort: 8443,
		AddressFamilies: []string{"ipv4"}, TransportIdentityRefs: []string{"profile:webpki-v1", hash("listener-pin")}, CredentialGeneration: 1,
		CertificateIdentityProjectionHash: hash("certificate-projection"), PublicProfileGeneration: 1, IntroducedRevision: 1,
		ValidFrom: from, ValidUntil: until, RotationOperationHash: hash("listener-operation")}
	ingress := wire.BootstrapIngressEndpointSetV1{Schema: 1, ClusterID: runtime.config.ClusterID, EndpointSetID: "demo-ingress-set", Generation: 1,
		ValidFrom: from, ValidUntil: until, ParentHeadHash: state.CertifiedHead.HeadHash, ConfigQC: qc,
		Endpoints: []wire.BootstrapIngressEndpointV1{{EndpointID: "demo-bootstrap-edge", LogicalServerID: "demo-edge", Transport: "hysteria2",
			ListenerGenerations: []wire.ListenerGenerationV2{listener}, ListenerTombstones: []wire.ListenerGenerationTombstoneV1{}}}}
	ingressHash, err := wire.BootstrapIngressSetHash(&ingress)
	if err != nil {
		t.Fatal(err)
	}
	catalog := wire.BootstrapEndpointCatalogV1{Schema: 1, ClusterID: runtime.config.ClusterID, CatalogGeneration: 1, ValidFrom: from, ValidUntil: until,
		BootstrapIngressSet: ingress, BootstrapIngressSetHash: ingressHash, RequiredClientProtocol: 2, ParentHeadHash: state.CertifiedHead.HeadHash, ConfigQCHash: qcHash}
	issuerPublic, issuerKey, _ := ed25519.GenerateKey(rand.Reader)
	issuerKeyID, _ := wire.ControlKeyID(issuerPublic)
	issuerDir := filepath.Join(runtime.dir, "bootstrap-issuers")
	if err := os.MkdirAll(issuerDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeCanonicalAtomic(filepath.Join(issuerDir, strings.TrimPrefix(issuerKeyID, "sha256:")+".json"),
		controlBootstrapIssuerKeyV1{Schema: 1, KeyID: issuerKeyID, PrivateKey: base64.RawURLEncoding.EncodeToString(issuerKey)}, 0o600); err != nil {
		t.Fatal(err)
	}
	issuer := wire.BootstrapIssuerAuthorizationV1{Schema: 1, ClusterID: runtime.config.ClusterID, AuthorizationID: "demo-bootstrap-issuer", Generation: 1,
		Status: "active", ParentHeadHash: state.CertifiedHead.HeadHash, Active: &wire.BootstrapIssuerAuthorizationActiveV1{IssuerEpoch: 1,
			IssuerKeyID: issuerKeyID, IssuerPublicKey: base64.RawURLEncoding.EncodeToString(issuerPublic), InviteIssuancePolicyHash: policyHash,
			ValidFrom: from, ValidUntil: until, MaximumCapabilityTTLSeconds: 900, MaximumConnectionAttempts: 3, MaximumConcurrentSessions: 1,
			MaximumSessionSeconds: 180, MaximumTotalBytes: 8 << 20, PermittedIngressSetHashes: []string{ingressHash}, PermittedServiceIDs: []string{enroll.ServiceID},
			PermittedModes: []string{"initial_claim", "resume_committed_claim"}}}
	application := controlApplicationV1{Schema: 1, ClusterID: runtime.config.ClusterID, LegacySSOT: string(ssot), LegacyRegistryHash: hash("legacy-registry"),
		RecoveryPolicy: recovery.Policy, RecoveryCustody: recovery.Custody, Authorizations: []wire.AdminAuthorizationV1{next}, CARegistry: enrollmentv2.CARegistryPreimageV1{
			AdminProfiles: []wire.AdminCertificateProfileV1{profile}, DeviceProfiles: []wire.DeviceCertificateProfileStateV1{controlInviteDeviceProfile(t, runtime)}},
		Services: services, EnrollmentService: enroll, InvitePolicy: policy, BootstrapIssuers: []wire.BootstrapIssuerAuthorizationV1{issuer}, BootstrapCatalog: catalog,
		Mirrors: []wire.DistributionMirrorRefV1{}, Invites: []controlInviteStateV1{}, Transactions: []enrollmentv2.TransactionStateV2{},
		IssuanceRegistry: []wire.EnrollmentIssuanceRegistryLeafV1{}, Devices: []controlDeviceStateV1{}}
	for _, id := range []string{"a", "b"} {
		application.Mirrors = append(application.Mirrors, wire.DistributionMirrorRefV1{Schema: 1, EndpointID: "demo-mirror-" + id,
			DistributionEndpointSetHash: hash("mirror-" + id), ListenerGeneration: 1, BaseURL: "https://demo-mirror-" + id + ".example.test:8443/distribution/sha256/",
			ServerName: "demo-mirror-" + id + ".example.test", WebPKIProfileRef: "webpki-v1", SPKIPins: []string{hash("mirror-pin-" + id)}})
	}
	return application, recovery.Proofs
}

func controlInviteDeviceProfile(t *testing.T, runtime *controlRuntime) wire.DeviceCertificateProfileStateV1 {
	t.Helper()
	now := runtime.now()
	_, issuer, issuerKey, err := makeCertificateAuthority("demo-device-ca", now.Add(-time.Hour), now.Add(48*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	issuerPKCS8, err := x509.MarshalPKCS8PrivateKey(issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(runtime.dir, "demo-device-ca.key"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: issuerPKCS8}), 0o600); err != nil {
		t.Fatal(err)
	}
	chain := []string{base64.RawURLEncoding.EncodeToString(issuer.Raw)}
	issuerHash, _ := wire.HashBytes(wire.DomainDeviceIssuerCertificateDER, issuer.Raw)
	chainHash, _ := wire.HashObject(wire.DomainDeviceIssuerChain, struct {
		Schema         int      `json:"schema"`
		IssuerChainDER []string `json:"issuer_chain_der"`
	}{1, chain})
	intent := wire.DeviceCertificateProfileIntentV1{Schema: 1, ClusterID: runtime.config.ClusterID, ProfileID: "demo-device-profile", Generation: 1,
		TargetStatus: "active", IssuerID: "demo-device-ca", IssuerGeneration: 1, IssuerFencingEpoch: 1,
		IssuanceNotBefore: now.Add(-time.Minute).Format(time.RFC3339), IssuanceNotAfter: now.Add(time.Hour).Format(time.RFC3339),
		ProfileKind: "loom-device-x509-v1", IssuerCertificateDER: chain[0], IssuerCertificateHash: issuerHash, IssuerChainDER: chain, IssuerChainHash: chainHash,
		IssuerKeyArtifactHash: wire.HashRaw("demo-secret-v1", []byte("device-ca")), AllowedPlatforms: []string{"windows-desktop", "android", "linux-server"}, AllowedResponsibilities: []string{"use_loom"},
		ValiditySeconds: 3600, AllowedSubjectKeyAlgorithm: "p256", SignatureAlgorithm: "ed25519", SubjectMode: "empty", SANURIPrefix: "spiffe://demo-cluster.example/device/",
		KeyUsageBits: []string{"digital_signature"}, RequiredEKUOIDs: []string{"1.3.6.1.5.5.7.3.2"}, RequiredPolicyOIDs: []string{"1.3.6.1.4.1.55555.2"},
		ExtensionOrderOIDs: []string{"2.5.29.15", "2.5.29.37", "2.5.29.19", "2.5.29.35", "2.5.29.17", "2.5.29.32"}}
	hash, err := wire.DeviceCertificateProfileIntentHash(&intent)
	if err != nil {
		t.Fatal(err)
	}
	return wire.DeviceCertificateProfileStateV1{Schema: 1, ClusterID: runtime.config.ClusterID, ProfileID: intent.ProfileID, Generation: 1,
		ProfileIntent: intent, DeviceCertificateProfileIntentHash: hash, Status: "active", StatusChangedAt: now.Format(time.RFC3339)}
}
