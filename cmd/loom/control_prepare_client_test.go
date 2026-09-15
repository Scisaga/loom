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
	})
	key, err := enrollmentv2.MaterialAuthorityKey(wrapping.Public())
	if err != nil {
		t.Fatal(err)
	}
	input := controlClientConfigInputV1{Schema: 1, DeviceID: migration.DeviceID,
		Recipient: wire.SealedBlobRecipientKeyRefV1{RecipientID: migration.DeviceID, RecipientKeyGeneration: 1,
			RecipientKeyID: key.KeyID, RecipientKeyProfile: wire.P256SealingPolicyV1().RecipientKeyProfile, RecipientPublicKey: key},
		ControlTunnel: render.ClientControlTunnelV2{Address: []string{"10.250.0.2/32"}, PrivateKeyRef: "private-control-wg-key",
			PeerAddress: "192.0.2.34", PeerPort: 51820, PeerPublicKey: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{19}, 32)), MTU: 1280},
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
	tunnel := input.ControlTunnel
	tunnel.AllowedIPs = []string{"10.250.0.1/32"}
	rendered, err := render.RenderClientRuntimeV2(render.ClientRuntimeV2Input{SSOT: ssot, ClusterID: application.ClusterID,
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

func TestControlClientConfigRendersSealsPublishesAndReplays(t *testing.T) {
	for _, platform := range []model.Platform{model.Android, model.WindowsDesktop} {
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
				len(authority.DeviceSecretEnvelopes) != len(payload.Envelopes) || len(authority.DeviceConfigUpdates) != 2 {
				t.Fatal("真实身份读取链缺生成后的配置与材料", err)
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
