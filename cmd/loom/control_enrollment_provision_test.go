package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
	"loom/internal/clientv2"
	"loom/internal/controlplane"
	"loom/internal/enrollmentv2"
	"loom/internal/model"
	"loom/internal/render"
	"loom/internal/wire"
)

// 旧设备的材料在认证迁移前构造；新设备始终经过正式 Invite、CA generator、
// reservation/provisional/completion 与重启恢复，不注入固定签发结果。
func productionEnrollmentFixture(t *testing.T) (*controlRuntime, string) {
	t.Helper()
	return controlInviteRuntime(t, func(application *controlApplicationV1, runtime *controlRuntime) {
		now := runtime.now().UTC().Truncate(time.Second)
		material, err := openControlSoftwareMaterial(runtime.dir, runtime.config.DeviceID, true)
		if err != nil {
			t.Fatal(err)
		}
		defer material.Close()
		profile, err := material.prepareDeviceCA(application.ClusterID, "demo-existing-network", now)
		if err != nil {
			t.Fatal(err)
		}
		application.CARegistry.DeviceProfiles = []wire.DeviceCertificateProfileStateV1{profile}
		policy, err := material.availabilityPolicy(application.ClusterID)
		if err != nil {
			t.Fatal(err)
		}
		application.ArtifactPolicies = []wire.ArtifactAvailabilityPolicyV1{policy}
		application.ObservationCAPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: runtime.controlTLS.Certificate[1]}))
		prepared, err := runtime.preparePrivateServiceMaterials("demo-existing-network", profile.ProfileID, map[string]int64{"enroll": 18443, "device_config": 18444, "device_report": 18445}, now)
		if err != nil {
			t.Fatal(err)
		}
		application.Services = []wire.PrivateControlServiceV1{runtime.config.ControlService}
		for _, entry := range prepared.Services {
			application.Services = append(application.Services, entry.Service)
			if entry.Service.Role == "enroll" {
				application.EnrollmentService = wire.PrivateEnrollmentServiceRefV1{Schema: 1, ServiceID: entry.Service.ServiceID, OverlayIP: entry.Service.OverlayIP, TCPPort: entry.Service.Port,
					InternalCAProfileRef: entry.Service.CertificateProfileRef, ServerIdentitySPKIPins: entry.Service.SPKIPins, ServiceGeneration: 1}
				application.BootstrapIssuers[0].Active.PermittedServiceIDs = []string{entry.Service.ServiceID}
			}
		}
		source, err := model.Load([]byte(application.LegacySSOT))
		if err != nil {
			t.Fatal(err)
		}
		for _, node := range source.Nodes {
			if node.Server != nil {
				clone := controlClone(node)
				clone.ID = runtime.config.DeviceID
				clone.Name = "Demo control"
				clone.PublicEndpoint = "203.0.113.79"
				clone.Server.Direction = model.Bidirectional
				source.Nodes = append(source.Nodes, clone)
				break
			}
		}
		raw, err := yaml.Marshal(source)
		if err != nil {
			t.Fatal(err)
		}
		application.LegacySSOT = string(raw)
		recipients := map[string]wire.SealedBlobRecipientKeyRefV1{}
		views := map[string]wire.DeviceViewPayloadV2{}
		for _, node := range source.Nodes {
			platform, roles, grants, err := migrationDeviceAuthorization(source, &node)
			if err != nil {
				t.Fatal(err)
			}
			identityHash := wire.HashRaw("demo-existing-identity", []byte(node.ID))
			record := enrollmentv2.DurableRecord{ClaimEvidence: enrollmentv2.ClaimPrivateEvidenceV1{Opening: wire.DeviceEnrollmentIntentOpeningV1{DeviceEnrollmentIntent: wire.DeviceEnrollmentIntentV1{
				ClusterID: application.ClusterID, DeviceID: node.ID, Membership: wire.EnrollmentMembershipV1{Schema: 1, DesiredState: "active_on_completion"}, Responsibilities: roles, Grants: grants}}},
				State: enrollmentv2.TransactionStateV2{IdentityKeyHash: identityHash}}
			view, err := enrollmentInitialView(record, []controlPublishedConfigV1{}, []wire.SecretArtifactRefV2{})
			if err != nil {
				t.Fatal(err)
			}
			application.Devices = append(application.Devices, controlDeviceStateV1{View: view, PreviousViewHash: wire.EmptyHashV1, SecretArtifactRefs: []wire.SecretArtifactRefV2{}})
			views[node.ID] = view
			wrapping, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			public, err := enrollmentv2.MaterialAuthorityKey(wrapping.Public())
			if err != nil {
				t.Fatal(err)
			}
			profileName := wire.P256RootOnlySealingPolicyV1().RecipientKeyProfile
			if platform != "linux-server" {
				profileName = wire.P256SealingPolicyV1().RecipientKeyProfile
			}
			recipients[node.ID] = wire.SealedBlobRecipientKeyRefV1{RecipientID: node.ID, RecipientKeyID: public.KeyID, RecipientKeyGeneration: 1, RecipientKeyProfile: profileName, RecipientPublicKey: public}
			spki, _ := x509.MarshalPKIXPublicKey(wrapping.Public())
			wrapHash, _ := wire.HashBytes(wire.DomainEnrollmentWrappingSPKI, spki)
			profileHash, _ := wire.DeviceCertificateProfileStateHash(&profile)
			application.DeviceMigrations = append(application.DeviceMigrations, wire.RuntimeDeviceMigrationLeafV1{Schema: 1, ClusterID: application.ClusterID, DeviceID: node.ID, Platform: platform,
				IdentitySPKIHash: identityHash, WrappingKeyHash: wrapHash, DeviceCertificateHash: wire.HashRaw("demo-certificate", []byte(node.ID)), DeviceCertificateProfileHash: profileHash,
				Issuance:    wire.IssuanceLogCoordinateV1{RecoveryEpoch: 2, RaftIndex: runtime.storage.SnapshotRaft().CommitIndex + 1},
				LegacyFloor: wire.BootstrapDeviceFloorLeafV1{Schema: 1, DeviceID: node.ID, V1Generation: 1, V1SignedCurrentHash: wire.EmptyHashV1, V1PayloadHash: wire.EmptyHashV1}})
		}
		sort.Slice(application.Devices, func(i, j int) bool {
			return application.Devices[i].View.DeviceID < application.Devices[j].View.DeviceID
		})
		sort.Slice(application.DeviceMigrations, func(i, j int) bool {
			return application.DeviceMigrations[i].DeviceID < application.DeviceMigrations[j].DeviceID
		})
		clientID := ""
		for _, node := range source.Nodes {
			if node.Access != nil && node.Server == nil {
				clientID = node.ID
				break
			}
		}
		wg, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		link := wire.DeviceControlLinkV1{Resource: wire.LinuxWireGuardResourceV1{ResourceID: "device-control-demo-existing", LinkID: "device-control-demo-existing", ListenerDeviceID: runtime.config.DeviceID, DialerDeviceID: clientID,
			ListenerGeneration: 1, EndpointAddress: runtime.config.OverlayIP, EndpointPort: 51998, ListenerPublicKey: source.NodeByID()[runtime.config.DeviceID].Server.WGPublicKey,
			DialerPublicKey: base64.StdEncoding.EncodeToString(wg.PublicKey().Bytes()), ListenerTunnelPrefix: "10.250.0.1/32", DialerTunnelPrefix: "10.250.0.2/32"}}
		for _, service := range application.Services {
			if service.Role == "device_config" || service.Role == "device_report" {
				link.Services = append(link.Services, service)
			}
		}
		sort.Slice(link.Services, func(i, j int) bool { return link.Services[i].ServiceID < link.Services[j].ServiceID })
		application.DeviceControlLinks = []wire.DeviceControlLinkV1{link}
		state := runtime.store.Snapshot()
		qc, _ := wire.MarshalCanonical(state.CertifiedQC)
		for i := range application.Devices {
			device := &application.Devices[i]
			if source.NodeByID()[device.View.DeviceID].Server == nil {
				continue
			}
			rendered, err := render.RenderLinuxRuntimeV2(render.LinuxRuntimeV2Input{SSOT: source, Views: views, Authority: wire.CertifiedHeadV1{Head: *state.CertifiedHead, QC: qc}, DeviceID: device.View.DeviceID,
				DeviceGeneration: 2, ArtifactGeneration: 1, DeviceControlLinks: application.deviceControlLinksFor(device.View.DeviceID)})
			if err != nil {
				t.Fatal(err)
			}
			ids := append(rendered.Runtime.CredentialRefs, wire.DevicePrivateControlCredentialSecretIDV1, wire.DeviceObservationCASecretIDV1)
			values := map[string]string{}
			for _, id := range ids {
				values[id] = "demo-existing-secret"
			}
			sealed, err := sealEnrollmentCredentials(material, policy, "demo-existing-network", recipients[device.View.DeviceID], ids, values, nil, now.Format(time.RFC3339))
			if err != nil {
				t.Fatal(err)
			}
			for _, evidence := range sealed {
				device.SecretArtifactRefs = append(device.SecretArtifactRefs, evidence.Ref)
			}
			device.View.Active.SecretArtifactRefsRoot, _ = wire.SecretArtifactRefsRoot(device.SecretArtifactRefs)
		}
	})
}

func TestProductionEnrollmentPublishesBothSidesAndRetainsFirstResult(t *testing.T) {
	tests := []struct {
		name             string
		platform         string
		responsibilities []string
		useGrant         bool
		expiryCase       bool
	}{
		{name: "linux-use", platform: "linux-server", responsibilities: []string{"use_loom"}, useGrant: true},
		{name: "windows-use", platform: "windows-desktop", responsibilities: []string{"use_loom"}, useGrant: true},
		{name: "android-use", platform: "android", responsibilities: []string{"use_loom"}, useGrant: true},
		{name: "linux-forward-preparing", platform: "linux-server", responsibilities: []string{"forward"}},
		{name: "linux-use-forward-egress-preparing", platform: "linux-server", responsibilities: []string{"use_loom", "forward", "internet_egress"}, useGrant: true},
		{name: "expired-issuance", platform: "linux-server", responsibilities: []string{"use_loom"}, useGrant: true, expiryCase: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			platform, expiryCase := test.platform, test.expiryCase
			runtime, admin := productionEnrollmentFixture(t)
			endpoint, client, _ := progressTestServer(t, runtime, admin)
			var options controlInviteContextV1
			if err := fetchControlInviteJSON(context.Background(), endpoint, client, privateControlInviteContextPath, &options); err != nil {
				t.Fatal(err)
			}
			grants := []string{}
			if test.useGrant {
				grant := options.Grants[0].Grant
				grants = append(grants, grant.Kind+":"+grant.TargetID)
			}
			out := filepath.Join(t.TempDir(), "invite")
			if err := createControlInvite(context.Background(), admin, endpoint, client, controlCreateInviteInputV1{Name: "Demo new device", Platform: platform, Responsibilities: test.responsibilities, Grants: grants, TTLSeconds: 900}, out, runtime.now); err != nil {
				t.Fatal(err)
			}
			var descriptor wire.InviteBootstrapDescriptorV2
			var proof wire.InviteProofBundleV2
			if err := readCanonicalFile(filepath.Join(out, "invite.loom-invite"), 8<<20, &descriptor); err != nil {
				t.Fatal(err)
			}
			if err := readCanonicalFile(filepath.Join(out, "proof.json"), 8<<20, &proof); err != nil {
				t.Fatal(err)
			}
			capability, err := wire.VerifyCapabilityAuthorizationEvidence(&descriptor.BootstrapTunnelCapability, &proof.BootstrapIssuerAuthorizationProof, &proof.InviteIssuancePolicy, runtime.now())
			if err != nil {
				t.Fatal(err)
			}
			workflow, err := runtime.productionEnrollmentWorkflow()
			if err != nil {
				t.Fatal(err)
			}
			material, err := runtime.readInviteMaterial(context.Background(), descriptor.ClusterID, descriptor.InviteID)
			if err != nil {
				t.Fatal(err)
			}
			identity, err := clientv2.OpenOrCreateEnrollmentIdentity(filepath.Join(t.TempDir(), "private", "identity.json"))
			if err != nil {
				t.Fatal(err)
			}
			openingHash, _ := wire.IntentOpeningHash(&material.Opening)
			intentHash, _ := wire.EnrollmentIntentHash(&material.Opening.DeviceEnrollmentIntent)
			setHash, _ := wire.ControlSetHash(&material.ControlSet)
			core, _, err := identity.PrepareClaimCore(clientv2.ClaimCoreInputV2{ClusterID: descriptor.ClusterID, InviteID: descriptor.InviteID, RequestID: "demo-normal-claim", CertifiedInviteRecordHash: capability.Body().CommittedInviteRecordHash,
				DeviceEnrollmentIntentCommitmentHash: material.Record.DeviceEnrollmentIntentCommitmentHash, DeviceEnrollmentIntentOpeningHash: openingHash, AcceptedDeviceEnrollmentIntentHash: intentHash,
				BaseRecoveryEpoch: material.RecordHead.Body.Payload.RecoveryEpoch, BaseControlEpoch: material.RecordHead.Body.Payload.ControlEpoch, BaseControlSetHash: setHash, BaseHeadHash: material.RecordHead.HeadHash,
				ClientNonce: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x29}, 32))})
			if err != nil {
				t.Fatal(err)
			}
			// 测试协议消费，不把 Linux 上的 P-256 测试 key 当作 CNG/Keystore 实测。
			if platform != "linux-server" {
				core.WrappingKeyProfile = "p256-keystore-ecdh-v1"
				core.ClientPlatform = platform
				core.DeviceIdentityKeyProfile = "p256-sha256-v1"
				if platform == "android" {
					core.DeviceIdentityKeyProfile = "p256-android-keystore-sha256-v1"
				}
			}
			submit := func() wire.EnrollmentClaimResultV2 {
				challenge, err := workflow.Service.Challenge(context.Background(), capability, &core)
				if err != nil {
					t.Fatal(err)
				}
				coreHash, _ := wire.EnrollmentClaimCoreHash(&core)
				challengeHash, err := wire.EnrollmentChallengeHash(&challenge, coreHash, runtime.now())
				if err != nil {
					t.Fatal(err)
				}
				pop := wire.EnrollmentPoPBodyV2{Schema: 2, ClusterID: core.ClusterID, InviteID: core.InviteID, RequestID: core.RequestID, ClaimCoreHash: coreHash, TokenCommitment: descriptor.TokenCommitment, ChallengeHash: challengeHash}
				signature, err := identity.SignPoP(&pop)
				if err != nil {
					t.Fatal(err)
				}
				result, err := workflow.Service.SubmitClaim(context.Background(), capability, &wire.EnrollmentClaimSubmissionV2{Schema: 2, Token: descriptor.Token, ClaimCore: core, Challenge: challenge, PoPBody: pop, ProofSignature: signature})
				if err != nil {
					if expiryCase && strings.Contains(err.Error(), "demo-interrupted-after-first-result") {
						return wire.EnrollmentClaimResultV2{}
					}
					t.Fatal(err)
				}
				return result
			}
			if expiryCase {
				runtime.checkpoint = func(phase controlplane.Phase) error {
					last := runtime.journal.Records[len(runtime.journal.Records)-1]
					if last.Enrollment != nil && last.Enrollment.Mutation.Preimage.Provisional != nil {
						return errors.New("demo-interrupted-after-first-result")
					}
					return nil
				}
			}
			result := submit()
			if expiryCase {
				runtime, err = openControlRuntime(runtime.dir, runtime.now)
				if err != nil {
					t.Fatal(err)
				}
				record, found := runtime.enrollmentStore.SnapshotRecord(descriptor.InviteID)
				if !found || record.State.Status != "issued_provisional" {
					t.Fatal("未保留真实签发结果")
				}
				if err := runtime.expireEnrollmentTransactions(context.Background()); err != nil {
					t.Fatal(err)
				}
				before, _ := runtime.enrollmentStore.SnapshotRecord(descriptor.InviteID)
				if before.State.Status != "issued_provisional" {
					t.Fatal("提前终止了有效 reservation")
				}
				deadline, _ := wire.ParseTimeZ(record.ClaimOperation.RetryNotAfter)
				runtime.now = func() time.Time { return deadline }
				if err := runtime.expireEnrollmentTransactions(context.Background()); err != nil {
					t.Fatal(err)
				}
				application, err := runtime.certifiedApplicationLocked()
				if err != nil {
					t.Fatal(err)
				}
				if len(application.EnrollmentPlans) != 0 || len(application.IssuanceRegistry) != 1 {
					t.Fatal("终止没有释放配置计划或删除了签发记录")
				}
				for _, device := range application.Devices {
					if device.View.DeviceID == material.Opening.DeviceEnrollmentIntent.DeviceID || device.View.DeviceGeneration != 1 {
						t.Fatal("终止意外激活设备或服务器配置")
					}
				}
				count := len(runtime.journal.Records)
				runtime, err = openControlRuntime(runtime.dir, runtime.now)
				if err != nil {
					t.Fatal(err)
				}
				if err := runtime.expireEnrollmentTransactions(context.Background()); err != nil {
					t.Fatal(err)
				}
				after, _ := runtime.enrollmentStore.SnapshotRecord(descriptor.InviteID)
				if after.State.Status != "aborted" || after.Expiry == nil || len(runtime.journal.Records) != count || !wire.EqualCanonical(after.ResultArtifact, record.ResultArtifact) {
					t.Fatal("终止重启没有保留首份结果或产生重复操作")
				}
				return
			}
			if result.Status != "completed" {
				t.Fatalf("normal Enrollment status=%s", result.Status)
			}
			application, err := runtime.certifiedApplicationLocked()
			if err != nil {
				t.Fatal(err)
			}
			if len(application.EnrollmentPlans) != 0 {
				t.Fatal("completion left an unconsumed network plan")
			}
			targetID := material.Opening.DeviceEnrollmentIntent.DeviceID
			targetIndex := -1
			for index, device := range application.Devices {
				if device.View.DeviceID == targetID {
					targetIndex = index
					if device.View.DeviceGeneration != 1 || device.View.Active == nil ||
						!wire.EqualCanonical(device.View.Active.Responsibilities.Values, test.responsibilities) ||
						len(device.View.Active.EndpointBundle.DataIngressSets) != 0 {
						t.Fatal("new Device did not retain its exact preparing identity and responsibilities")
					}
					continue
				}
				if device.View.Active != nil && containsControlValue(device.View.Active.Responsibilities.Values, "forward") && device.View.DeviceGeneration != 2 {
					t.Fatal("server side was not activated atomically")
				}
			}
			if targetIndex < 0 {
				t.Fatal("completion omitted the new Device")
			}
			if containsControlValue(test.responsibilities, "forward") {
				network, err := model.Load([]byte(application.LegacySSOT))
				if err != nil {
					t.Fatal(err)
				}
				node := network.NodeByID()[targetID]
				if test.useGrant {
					if node == nil || node.Access == nil || node.Server != nil {
						t.Fatal("combined Device was not kept access-only while public access is preparing")
					}
				} else if node != nil {
					t.Fatal("forward-only Enrollment invented a strict-v1 server declaration")
				}
				public, err := application.deviceControlDialerPublicKey(controlClientConfigInputV1{DeviceID: targetID,
					ControlTunnel: render.ClientControlTunnelV2{PrivateKeyRef: render.LocalWireGuardSecretIDV2}})
				links := application.deviceControlLinksFor(targetID)
				if err != nil || len(links) != 1 || public != links[0].Resource.DialerPublicKey {
					t.Fatal("fresh forward did not retain its claimed WireGuard identity")
				}
				views := make(map[string]wire.DeviceViewPayloadV2, len(application.Devices))
				for _, device := range application.Devices {
					views[device.View.DeviceID] = device.View
				}
				state := runtime.store.Snapshot()
				qc, _ := wire.MarshalCanonical(state.CertifiedQC)
				rendered, err := render.RenderLinuxRuntimeV2(render.LinuxRuntimeV2Input{SSOT: network, Views: views,
					Authority: wire.CertifiedHeadV1{Head: *state.CertifiedHead, QC: qc}, DeviceID: targetID,
					DeviceGeneration: application.Devices[targetIndex].View.DeviceGeneration + 1, ArtifactGeneration: 2,
					DeviceControlLinks: links})
				if err != nil || len(rendered.Links.Content) == 0 || len(rendered.Runtime.Content) == 0 {
					t.Fatalf("fresh forward cannot consume its next certified control-only config: %v", err)
				}
			}
			if platform == "linux-server" {
				for index, entry := range runtime.journal.Records {
					if entry.Enrollment == nil || entry.Enrollment.Mutation.Preimage.Provisional == nil {
						continue
					}
					original, err := runtime.applicationBefore(index)
					if err != nil {
						t.Fatal(err)
					}
					provisional := entry.Enrollment.Mutation.Preimage.Provisional
					plan, err := decodeEnrollmentRuntimePlan(provisional.Prepared.RuntimePlan)
					if err != nil {
						t.Fatal(err)
					}
					for _, test := range []struct {
						name   string
						change func(*controlEnrollmentRuntimePlanV1)
					}{
						{"network", func(p *controlEnrollmentRuntimePlanV1) { p.Network += "\n# unexpected replacement\n" }},
						{"admitted public key", func(p *controlEnrollmentRuntimePlanV1) {
							key, err := ecdh.X25519().GenerateKey(rand.Reader)
							if err != nil {
								t.Fatal(err)
							}
							p.ControlLink.Resource.DialerPublicKey = base64.StdEncoding.EncodeToString(key.PublicKey().Bytes())
						}},
						{"client config", func(p *controlEnrollmentRuntimePlanV1) { p.ClientConfigs[0].Content = []byte(`{}`) }},
						{"server missing", func(p *controlEnrollmentRuntimePlanV1) { p.Servers = p.Servers[:len(p.Servers)-1] }},
						{"private key", func(p *controlEnrollmentRuntimePlanV1) {
							p.ClientSecrets[0].Ref.SecretID = wire.LocalWireGuardKeySecretID
						}},
						{"recipient", func(p *controlEnrollmentRuntimePlanV1) {
							p.ClientSecrets[0].Ref.SealedBlob.RecipientKeyVersions[0].RecipientID = "demo-other"
						}},
						{"address", func(p *controlEnrollmentRuntimePlanV1) {
							p.ControlLink.Resource.DialerTunnelPrefix = original.DeviceControlLinks[0].Resource.DialerTunnelPrefix
						}},
					} {
						altered := controlClone(plan)
						test.change(&altered)
						if _, err := original.applyEnrollmentRuntimePlan(altered, provisional.Record, provisional.Prepared.Result.InitialDeviceView, plan.PreparedAt); err == nil {
							t.Fatalf("accepted tampered %s", test.name)
						}
					}
					for _, secret := range plan.ClientSecrets {
						if secret.Ref.SecretID == wire.LocalWireGuardKeySecretID {
							t.Fatal("server produced a client private key")
						}
					}
				}
				private, closeKeys, err := runtime.newDeviceRuntime()
				if err != nil {
					t.Fatal(err)
				}
				closeKeys()
				if private == nil || runtime.enrollmentPeers == nil {
					t.Fatal("daemon omitted the private Enrollment service or quorum peers")
				}
			}
			count := len(runtime.journal.Records)
			runtime, err = openControlRuntime(runtime.dir, runtime.now)
			if err != nil {
				t.Fatal(err)
			}
			workflow, err = runtime.productionEnrollmentWorkflow()
			if err != nil {
				t.Fatal(err)
			}
			if again := submit(); !wire.EqualCanonical(result, again) || len(runtime.journal.Records) != count {
				t.Fatal("restart changed first result or duplicated the transaction")
			}
		})
	}
}
