package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"loom/internal/clientruntime"
	"loom/internal/enrollmentv2"
	"loom/internal/model"
	"loom/internal/render"
	"loom/internal/secret"
	"loom/internal/ssotedit"
	"loom/internal/wire"
	loomcore "loom/mobile/loomcore"
)

func controlRenderedClientFixture(t *testing.T, platform model.Platform) (*controlRuntime, string, wire.RuntimeDeviceMigrationLeafV1, controlClientConfigInputV1, *ecdsa.PrivateKey) {
	t.Helper()
	wrapping, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrapSPKI, _ := x509.MarshalPKIXPublicKey(wrapping.Public())
	wrapHash, _ := wire.HashBytes(wire.DomainEnrollmentWrappingSPKI, wrapSPKI)
	runtime, admin, migration, _ := controlMigratedDeviceRuntime(t, func(application *controlApplicationV1, runtime *controlRuntime) {
		material, err := openControlSoftwareMaterial(runtime.dir, runtime.config.DeviceID, true)
		if err != nil {
			t.Fatal(err)
		}
		defer material.Close()
		policy, err := material.availabilityPolicy(application.ClusterID)
		if err != nil {
			t.Fatal(err)
		}
		application.ArtifactPolicies = []wire.ArtifactAvailabilityPolicyV1{policy}
		application.DeviceMigrations[0].WrappingKeyHash = wrapHash
		application.DeviceMigrations[0].Platform = string(platform)
		application.Authorizations[0].AllowedOperationKinds = append(application.Authorizations[0].AllowedOperationKinds, controlPublishDeviceKind)
		sort.Strings(application.Authorizations[0].AllowedOperationKinds)
		for i := range application.Services {
			if application.Services[i].Role == "device_config" || application.Services[i].Role == "device_report" {
				application.Services[i].OverlayIP = "10.250.0.1"
			}
		}
		source, err := model.Load([]byte(application.LegacySSOT))
		if err != nil {
			t.Fatal(err)
		}
		var declarations []string
		for _, declaration := range source.Declarations {
			if declaration.AddressFromRequest() {
				declarations = append(declarations, declaration.ID)
			}
		}
		plan, err := ssotedit.AddAccessClient([]byte(application.LegacySSOT), ssotedit.ClientInput{ID: application.Devices[0].View.DeviceID,
			Name: "demo migrated client", Platform: platform, DestinationGrants: declarations})
		if err != nil {
			t.Fatal(err)
		}
		application.LegacySSOT = string(plan.Content)
		effective, err := model.Load(plan.Content)
		if err != nil {
			t.Fatal(err)
		}
		_, roles, grants, err := migrationDeviceAuthorization(effective, effective.NodeByID()[application.Devices[0].View.DeviceID])
		if err != nil {
			t.Fatal(err)
		}
		application.Devices[0].View.Active.Responsibilities, application.Devices[0].View.Active.Grants = roles, grants
		application.Devices[0].View.Active.ResponsibilitiesHash, _ = wire.HashObject("loom-enrollment-responsibilities-v1", roles)
		application.Devices[0].View.Active.GrantsHash, _ = wire.HashObject("loom-enrollment-destination-grants-v1", grants)
		{
			for _, node := range effective.Nodes {
				if node.Server == nil {
					continue
				}
				state := controlClone(application.Devices[0])
				state.View.DeviceID = node.ID
				state.View.Active.IdentitySPKIHash = wire.HashRaw("demo-server-identity", []byte(node.ID))
				state.View.Active.EndpointBundle.DeviceID = node.ID
				state.View.Active.EndpointBundleHash, _ = wire.DeviceEndpointBundleHash(&state.View.Active.EndpointBundle)
				_, roles, grants, err := migrationDeviceAuthorization(effective, &node)
				if err != nil {
					t.Fatal(err)
				}
				state.View.Active.Responsibilities, state.View.Active.Grants = roles, grants
				state.View.Active.ResponsibilitiesHash, _ = wire.HashObject("loom-enrollment-responsibilities-v1", roles)
				state.View.Active.GrantsHash, _ = wire.HashObject("loom-enrollment-destination-grants-v1", grants)
				application.Devices = append(application.Devices, state)
			}
			sort.Slice(application.Devices, func(i, j int) bool {
				return application.Devices[i].View.DeviceID < application.Devices[j].View.DeviceID
			})
		}
	})
	key, err := enrollmentv2.MaterialAuthorityKey(wrapping.Public())
	if err != nil {
		t.Fatal(err)
	}
	input := controlClientConfigInputV1{Schema: 1, DeviceID: migration.DeviceID,
		Recipient: wire.SealedBlobRecipientKeyRefV1{RecipientID: migration.DeviceID, RecipientKeyGeneration: 1,
			RecipientKeyID: key.KeyID, RecipientKeyProfile: wire.P256SealingPolicyV1().RecipientKeyProfile, RecipientPublicKey: key},
		ControlTunnel: render.ClientControlTunnelV2{Address: []string{"10.250.0.2/32"}, PrivateKeyRef: "private-control-wg-key",
			PeerAddress: "10.250.0.1", PeerTunnelPrefix: "10.250.0.3/32", PeerPort: 51998, MTU: 1280},
		SingBoxVersion: "1.11.4", ObservationCA: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: runtime.controlTLS.Certificate[1]})),
		Credentials: map[string]string{}}
	application, err := runtime.certifiedApplicationLocked()
	if err != nil {
		t.Fatal(err)
	}
	ssot, err := model.Load([]byte(application.LegacySSOT))
	if err != nil {
		t.Fatal(err)
	}
	for _, node := range ssot.Nodes {
		if node.Server != nil {
			input.ControlTunnel.PeerDeviceID, input.ControlTunnel.PeerPublicKey = node.ID, node.Server.WGPublicKey
			break
		}
	}
	tunnel := input.ControlTunnel
	tunnel.AllowedIPs = []string{"10.250.0.1/32"}
	if platform == model.LinuxServer {
		input.ControlTunnel = render.ClientControlTunnelV2{}
		input.Recipient.RecipientKeyProfile = wire.P256RootOnlySealingPolicyV1().RecipientKeyProfile
		views := map[string]wire.DeviceViewPayloadV2{}
		for _, device := range application.Devices {
			views[device.View.DeviceID] = device.View
		}
		state := runtime.store.Snapshot()
		qc, _ := wire.MarshalCanonical(state.CertifiedQC)
		rendered, err := render.RenderLinuxRuntimeV2(render.LinuxRuntimeV2Input{SSOT: ssot, Views: views,
			Authority: wire.CertifiedHeadV1{Head: *state.CertifiedHead, QC: qc}, DeviceID: input.DeviceID, DeviceGeneration: 2, ArtifactGeneration: 1})
		if err != nil {
			t.Fatal(err)
		}
		for _, ref := range rendered.Runtime.CredentialRefs {
			input.Credentials[ref] = "demo-sealed-client-credential"
		}
		return runtime, admin, migration, input, wrapping
	}
	var clientGrants wire.EnrollmentDestinationGrantsV1
	for _, device := range application.Devices {
		if device.View.DeviceID == input.DeviceID {
			clientGrants = device.View.Active.Grants
		}
	}
	rendered, err := render.RenderClientRuntimeV2(render.ClientRuntimeV2Input{SSOT: ssot, Grants: &clientGrants, ClusterID: application.ClusterID,
		DeviceID: input.DeviceID, DeviceGeneration: 2, ArtifactGeneration: 1, SingBoxVersion: input.SingBoxVersion,
		ObservationCA: input.ObservationCA, ControlTunnel: tunnel})
	if err != nil {
		t.Fatal(err)
	}
	for _, ref := range rendered.CredentialRefs {
		input.Credentials[ref] = "demo-sealed-client-credential"
	}
	input.Credentials[tunnel.PrivateKeyRef] = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{17}, 32))
	return runtime, admin, migration, input, wrapping
}

func TestLinuxControlAllocationUsesOriginalNodeKeysAndDedicatedCarrier(t *testing.T) {
	runtime, _, _, _, _ := controlRenderedClientFixture(t, model.LinuxServer)
	application, err := runtime.certifiedApplicationLocked()
	if err != nil {
		t.Fatal(err)
	}
	source, err := model.Load([]byte(application.LegacySSOT))
	if err != nil {
		t.Fatal(err)
	}
	var servers []*model.Node
	for i := range source.Nodes {
		if source.Nodes[i].Server != nil {
			servers = append(servers, &source.Nodes[i])
		}
	}
	if len(servers) < 2 {
		t.Fatal("fixture 缺服务器")
	}
	listener, client := servers[0], servers[1]
	// 此纯分配测试沿用 fixture 中两个服务器的认证平台投影。
	for _, server := range []*model.Node{listener, client} {
		migration := controlClone(application.DeviceMigrations[0])
		migration.DeviceID, migration.Platform = server.ID, "linux-server"
		application.DeviceMigrations = append(application.DeviceMigrations, migration)
	}
	input := controlClientConfigInputV1{Schema: 1, DeviceID: client.ID,
		ControlTunnel: render.ClientControlTunnelV2{PeerDeviceID: listener.ID, PeerAddress: "10.250.0.1", PeerPort: 51998,
			PeerPublicKey: listener.Server.WGPublicKey, PrivateKeyRef: render.LocalWireGuardSecretIDV2,
			PeerTunnelPrefix: "10.250.0.3/32", Address: []string{"10.250.0.2/32"}, MTU: 1280}}
	link, err := application.prepareDeviceControlLink(input, 2)
	if err != nil {
		t.Fatal(err)
	}
	if link.Resource.DialerPublicKey != client.Server.WGPublicKey || link.Carrier == nil ||
		link.Carrier.Address != listener.PublicEndpoint || link.Carrier.CredentialRef != wire.DeviceControlCarrierCredentialRef(link) {
		t.Fatal("分配未保留原节点公钥或未使用设备专用承载")
	}
	if err := application.replaceDeviceControlLink(link); err != nil {
		t.Fatal(err)
	}
	if len(application.deviceControlLinksFor(listener.ID)) != 1 || len(application.deviceControlLinksFor(client.ID)) != 1 {
		t.Fatal("认证分配未交付两端")
	}
	changed := controlClone(link)
	changed.Carrier.Address = "203.0.113.222"
	if err := application.validateDeviceControlLink(changed); err == nil {
		t.Fatal("允许把承载改指另一主机")
	}
	changed = controlClone(link)
	changed.Resource.DialerPublicKey = listener.Server.WGPublicKey
	if err := application.validateDeviceControlLink(changed); err == nil {
		t.Fatal("允许替换原节点 WireGuard 公钥")
	}
	input.ControlTunnel.PrivateKeyRef = "demo-copied-other-key"
	if _, err := application.prepareDeviceControlLink(input, 3); err == nil {
		t.Fatal("允许将远端凭据替代本机原密钥")
	}
}

func TestControlClientConfigRendersSealsPublishesAndReplays(t *testing.T) {
	for _, platform := range []model.Platform{model.Android, model.WindowsDesktop, model.LinuxServer} {
		t.Run(string(platform), func(t *testing.T) {
			runtime, admin, migration, input, wrapping := controlRenderedClientFixture(t, platform)
			endpoint, client, _ := progressTestServer(t, runtime, admin)
			status, err := fetchControlStatus(context.Background(), endpoint, client)
			if err != nil {
				t.Fatal(err)
			}
			prepare := controlPrepareClientRequestV1{Schema: 1, RequestID: "demo-rendered-publication", ExpectedHead: status.Head.HeadHash, Input: input}
			payload, err := prepareControlClientConfig(context.Background(), endpoint, client, prepare)
			if err != nil {
				_, reason := runtime.prepareClientConfigLocked(prepare)
				t.Fatal(err, reason)
			}
			repeated, err := prepareControlClientConfig(context.Background(), endpoint, client, prepare)
			if err != nil || !wire.EqualCanonical(payload, repeated) || len(runtime.journal.Records) != 1 {
				t.Fatal("准备重试改变密文或提前提交了 Device", err)
			}
			values := map[string]string{}
			for i, envelope := range payload.Envelopes {
				plaintext, err := wire.UnsealSecretP256(&envelope, input.Recipient, wrapping)
				if err != nil {
					t.Fatal(err)
				}
				values[payload.Publication.Secrets[i].Ref.SecretID] = string(plaintext)
				clear(plaintext)
			}
			var private wire.DevicePrivateControlCredentialV1
			if _, err := wire.DecodeStrict([]byte(values[wire.DevicePrivateControlCredentialSecretIDV1]), 4<<20, &private); err != nil ||
				wire.ValidateDevicePrivateControlCredential(&private) != nil || private.ParentHead.HeadHash != status.Head.HeadHash {
				t.Fatal("未交付当前认证的真实私有控制目录", err)
			}
			if platform == model.Android {
				var env strings.Builder
				for key, value := range input.Credentials {
					env.WriteString(key + "=" + value + "\n")
				}
				prepared, err := loomcore.PrepareAndroidRuntime(payload.Publication.Configs[0].Content, []byte(env.String()))
				var runtime struct {
					Config string `json:"sing_box_config"`
				}
				if err != nil || json.Unmarshal(prepared, &runtime) != nil || loomcore.ValidateAndroidV2RuntimeHost([]byte(runtime.Config)) != nil {
					t.Fatal("Android 无法消费正常发布的配置", err)
				}
			} else if platform == model.LinuxServer {
				if len(payload.Publication.Configs) != 2 {
					t.Fatal("Linux 发布必须同时交付 LinkIntent 与 runtime")
				}
				var links wire.LinuxLinkIntentArtifactV1
				var artifact wire.LinuxRuntimeArtifactV1
				if _, err := wire.DecodeStrict(payload.Publication.Configs[0].Content, 4<<20, &links); err != nil {
					t.Fatal(err)
				}
				if _, err := wire.DecodeStrict(payload.Publication.Configs[1].Content, 4<<20, &artifact); err != nil {
					t.Fatal(err)
				}
				if err := wire.ValidateLinuxRuntimeRedaction(&artifact, &links); err != nil {
					t.Fatal(err)
				}
				if links.LocalRuntime.AccessMode != "mixed" {
					t.Fatal("Linux 默认代理模式改变")
				}
				for _, file := range artifact.Files {
					if _, missing := secret.Hydrate(file.Content, values); len(missing) != 0 {
						t.Fatal("Linux 缺原 key 解封的凭据", missing)
					}
				}
			} else {
				var artifact wire.WindowsRuntimeArtifactV1
				if _, err := wire.DecodeStrict(payload.Publication.Configs[0].Content, 4<<20, &artifact); err != nil {
					t.Fatal(err)
				}
				for _, file := range artifact.Files {
					if file.Path != "sing-box/config.json" {
						continue
					}
					hydrated, missing := secret.Hydrate(file.Content, values)
					if len(missing) != 0 {
						t.Fatal("缺原 key 解封的数据面凭据")
					}
					for _, profile := range []clientruntime.WindowsRuntimeProfile{clientruntime.WindowsInstalledProfile, clientruntime.WindowsPortableMixedProfile, clientruntime.WindowsPortableTUNProfile} {
						if _, err := clientruntime.DeriveWindowsRuntimeConfig([]byte(hydrated), profile, clientruntime.WindowsInstalledCAPath); err != nil {
							t.Fatal(err)
						}
					}
				}
			}
			request, err := newControlDevicePublicationRequest(admin, endpoint, status, prepare.RequestID, payload, runtime.now())
			if err != nil {
				t.Fatal(err)
			}
			result, err := submitControlOperation(context.Background(), admin, endpoint, client, status, request)
			if err != nil {
				t.Fatal(err)
			}
			reopened, err := openControlRuntime(runtime.dir, runtime.now)
			if err != nil {
				t.Fatal(err)
			}
			endpoint, client, _ = progressTestServer(t, reopened, admin)
			again, err := submitControlOperation(context.Background(), admin, endpoint, client, status, request)
			if err != nil || !wire.EqualCanonical(result, again) || len(reopened.journal.Records) != 2 {
				t.Fatal("发布重试未复用原认证结果", err)
			}
			authority, err := reopened.readDeviceIdentityLocked(migration.DeviceCertificateHash)
			if err != nil || authority.Record.IdentitySPKIHash != migration.IdentitySPKIHash || authority.CurrentDeviceView.Payload.DeviceGeneration != 2 ||
				len(authority.DeviceSecretEnvelopes) != len(payload.Envelopes) || len(authority.DeviceConfigUpdates) != 2 ||
				len(authority.CurrentDeviceView.Payload.Active.ConfigArtifactRefs) != len(payload.Publication.Configs) {
				t.Fatal("真实身份读取链缺生成后的配置与材料", err)
			}
			if platform != model.LinuxServer {
				application, err := reopened.certifiedApplicationLocked()
				if err != nil {
					t.Fatal(err)
				}
				links := application.deviceControlLinksFor(input.ControlTunnel.PeerDeviceID)
				if len(links) != 1 || !wire.EqualCanonical(links[0], *payload.Publication.ControlLink) {
					t.Fatal("承载分配未随同一认证操作持久恢复")
				}
				source, err := model.Load([]byte(application.LegacySSOT))
				if err != nil {
					t.Fatal(err)
				}
				views := map[string]wire.DeviceViewPayloadV2{}
				for _, device := range application.Devices {
					views[device.View.DeviceID] = device.View
				}
				current := reopened.store.Snapshot()
				qc, _ := wire.MarshalCanonical(current.CertifiedQC)
				rendered, err := render.RenderLinuxRuntimeV2(render.LinuxRuntimeV2Input{SSOT: source, Views: views, Authority: wire.CertifiedHeadV1{Head: *current.CertifiedHead, QC: qc}, DeviceID: input.ControlTunnel.PeerDeviceID, DeviceGeneration: 2, ArtifactGeneration: 1, DeviceControlLinks: links})
				if err != nil {
					t.Fatal("认证分配无法生成实际承载配置", err)
				}
				var serverLinks wire.LinuxLinkIntentArtifactV1
				if json.Unmarshal(rendered.Links.Content, &serverLinks) != nil || !wire.EqualCanonical(serverLinks.LocalRuntime.DeviceControlLinks, links) {
					t.Fatal("承载生成器丢失已认证两端绑定")
				}
			}
			repeated, err = prepareControlClientConfig(context.Background(), endpoint, client, prepare)
			if err != nil || !wire.EqualCanonical(payload, repeated) {
				t.Fatal("重启改变第一次生成的密文", err)
			}
			for _, name := range []string{controlJournalName, controlRaftName, controlStateName} {
				raw, err := os.ReadFile(filepath.Join(runtime.dir, name))
				if err != nil || bytes.Contains(raw, []byte("demo-sealed-client-credential")) {
					t.Fatal("明文进入控制日志", err)
				}
			}
		})
	}
}

func TestControlClientConfigRejectsChangedAuthorityAndRecipient(t *testing.T) {
	runtime, admin, _, input, _ := controlRenderedClientFixture(t, model.WindowsDesktop)
	endpoint, client, _ := progressTestServer(t, runtime, admin)
	status, err := fetchControlStatus(context.Background(), endpoint, client)
	if err != nil {
		t.Fatal(err)
	}
	prepare := controlPrepareClientRequestV1{Schema: 1, RequestID: "demo-rendered-publication", ExpectedHead: status.Head.HeadHash, Input: input}
	for _, test := range []struct {
		name   string
		change func(*controlPrepareClientRequestV1)
	}{
		{"stale-head", func(p *controlPrepareClientRequestV1) { p.ExpectedHead = wire.EmptyHashV1 }},
		{"different-device", func(p *controlPrepareClientRequestV1) { p.Input.DeviceID = "demo-other" }},
		{"different-recipient", func(p *controlPrepareClientRequestV1) { p.Input.Recipient.RecipientID = "demo-other" }},
		{"expanded-private-route", func(p *controlPrepareClientRequestV1) { p.Input.ControlTunnel.AllowedIPs = []string{"10.0.0.0/8"} }},
		{"extra-credential", func(p *controlPrepareClientRequestV1) { p.Input.Credentials["demo-extra"] = "demo-secret" }},
		{"missing-credential", func(p *controlPrepareClientRequestV1) {
			delete(p.Input.Credentials, p.Input.ControlTunnel.PrivateKeyRef)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := controlClone(prepare)
			test.change(&changed)
			if _, err := prepareControlClientConfig(context.Background(), endpoint, client, changed); err == nil {
				t.Fatal("接受未绑定或扩大授权的输入")
			}
		})
	}
	if _, err := prepareControlClientConfig(context.Background(), endpoint, client, prepare); err != nil {
		t.Fatal(err)
	}
	prepare.Input.Credentials[prepare.Input.ControlTunnel.PrivateKeyRef] = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{23}, 32))
	if _, err := prepareControlClientConfig(context.Background(), endpoint, client, prepare); err == nil {
		t.Fatal("允许同 request ID 重新生成不同材料")
	}
}
