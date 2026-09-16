//go:build linux

package clientv2

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"loom/internal/model"
	"loom/internal/render"
	"loom/internal/wire"
)

func TestOriginalLinuxWireGuardProjectsAndBindsBothCertifiedPeers(t *testing.T) {
	for _, mode := range []string{"dial", "listen"} {
		t.Run(mode, func(t *testing.T) {
			set, authorityKey := clientControlSet(t)
			envelope := clientEnvelope(t, &set, authorityKey)
			envelope.Payload.DeviceID = "demo-node"
			envelope.Leaf.DeviceID = "demo-node"
			envelope.Payload.Active.EndpointBundle.DeviceID = "demo-node"
			envelope.Payload.Active.EndpointBundleHash, _ = wire.DeviceEndpointBundleHash(&envelope.Payload.Active.EndpointBundle)
			envelope.Payload.Active.Responsibilities = wire.EnrollmentResponsibilitiesV1{Schema: 1, Values: []string{"forward"}}
			envelope.Payload.Active.ResponsibilitiesHash, _ = wire.HashObject("loom-enrollment-responsibilities-v1", envelope.Payload.Active.Responsibilities)
			local, err := ecdh.X25519().GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			remote, err := ecdh.X25519().GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			private := base64.StdEncoding.EncodeToString(local.Bytes())
			public := base64.StdEncoding.EncodeToString(local.PublicKey().Bytes())
			localDirection, remoteDirection := model.ReverseOnly, model.Bidirectional
			if mode == "listen" {
				localDirection, remoteDirection = remoteDirection, localDirection
			}
			source := &model.SSOT{Nodes: []model.Node{
				{ID: envelope.Payload.DeviceID, PublicEndpoint: "203.0.113.10", Server: &model.ServerRole{Direction: localDirection, WGPublicKey: public}},
				{ID: "demo-peer", PublicEndpoint: "203.0.113.11", Server: &model.ServerRole{Direction: remoteDirection, WGPublicKey: base64.StdEncoding.EncodeToString(remote.PublicKey().Bytes())}}},
				Tunnels: []model.Tunnel{{From: envelope.Payload.DeviceID, To: "demo-peer", Protocol: model.WG, ListenPort: 51820, FromAddr: "10.20.0.1/32", ToAddr: "10.20.0.2/32"}}}
			projection, err := render.ProjectExistingLinuxWireGuardV2(source, set.ClusterID, envelope.Payload.DeviceID, envelope.SignedCurrent.Head.HeadHash)
			if err != nil {
				t.Fatal(err)
			}
			opposite, err := render.ProjectExistingLinuxWireGuardV2(source, set.ClusterID, "demo-peer", envelope.SignedCurrent.Head.HeadHash)
			if err != nil || !wire.EqualCanonical(projection.Resources, opposite.Resources) || !wire.EqualCanonical(projection.LinkIntents, opposite.LinkIntents) {
				t.Fatal("同一原隧道的两端未得到同一认证资源/intent", err)
			}
			if projection.Bindings[0].Mode != mode || opposite.Bindings[0].Mode == mode {
				t.Fatal("旧方向未固化为相反的 dial/listen")
			}
			if projection.Files[0].Path != "wireguard/wg-demo-peer.conf" || opposite.Files[0].Path != "wireguard/wg-demo-node.conf" {
				t.Fatal("原接口身份改变，会使流量签名与历史断开")
			}
			artifact := wire.LinuxLinkIntentArtifactV1{Schema: 1, ClusterID: set.ClusterID, DeviceID: envelope.Payload.DeviceID,
				DeviceGeneration: envelope.Payload.DeviceGeneration, Generation: 1, RenderContractID: wire.LinuxLinkIntentRenderContract,
				LinkIntents: projection.LinkIntents, WireGuardResources: projection.Resources, LocalWireGuardKey: projection.LocalKey}
			raw := bindRuntimeArtifactToEnvelope(t, &envelope, &set, authorityKey, artifact)
			if err := json.Unmarshal(raw, &artifact); err != nil {
				t.Fatal(err)
			}
			for name, mutate := range map[string]func(*wire.LinuxLinkIntentArtifactV1){
				"direction":             func(a *wire.LinuxLinkIntentArtifactV1) { a.LinkIntents[0].Initiator = "to" },
				"foreign-peer":          func(a *wire.LinuxLinkIntentArtifactV1) { a.WireGuardResources[0].DialerDeviceID = "demo-unrelated" },
				"expanded-prefix":       func(a *wire.LinuxLinkIntentArtifactV1) { a.WireGuardResources[0].DialerTunnelPrefix = "10.0.0.0/8" },
				"unreferenced-resource": func(a *wire.LinuxLinkIntentArtifactV1) { a.WireGuardResources[0].ResourceID = "demo-unrelated" },
				"local-key":             func(a *wire.LinuxLinkIntentArtifactV1) { a.LocalWireGuardKey.PublicKey = opposite.LocalKey.PublicKey },
			} {
				var changed wire.LinuxLinkIntentArtifactV1
				if err := json.Unmarshal(raw, &changed); err != nil {
					t.Fatal(err)
				}
				mutate(&changed)
				if err := wire.ValidateLinuxLinkIntentArtifact(&changed); err == nil {
					t.Fatal("接受了不匹配的 peer 资源", name)
				}
			}
			plan, err := BuildLinuxLinkRuntimePlan(&envelope, &set, nil, nil, raw, nil, time.Date(2026, 9, 12, 0, 0, 0, 0, time.UTC), nil)
			if err != nil || len(plan.Actions) != 1 || plan.Actions[0].WireGuardPeer == nil {
				t.Fatal("私有 peer 资源未进入正式 reader", err)
			}
			if _, err := BuildLinuxLinkRuntimePlan(&envelope, &set, nil, nil, raw, nil, time.Now(), map[string]int64{projection.Resources[0].ResourceID: 2}); err == nil {
				t.Fatal("peer listener generation 回退")
			}
			contentHash, _ := wire.DeviceConfigArtifactContentHash(raw)
			runtime := wire.LinuxRuntimeArtifactV1{Schema: 1, ClusterID: set.ClusterID, DeviceID: envelope.Payload.DeviceID, DeviceGeneration: envelope.Payload.DeviceGeneration,
				Generation: 1, LinkIntentGeneration: 1, LinkIntentContentHash: contentHash, Files: projection.Files, Bindings: projection.Bindings}
			if err := wire.ValidateLinuxRuntimeRedaction(&runtime, &artifact); err != nil {
				t.Fatal(err)
			}
			if err := validateLinuxRuntimeBindings(&plan, &runtime); err != nil {
				t.Fatal(err)
			}
			file := projection.Files[0]
			hydrated := strings.ReplaceAll(file.Content, "${secret:"+projection.LocalKey.SecretID+"}", private)
			if err := validateLinuxRuntimeConfigSemantics(&plan, &runtime, map[string]string{file.Path: hydrated}); err != nil {
				t.Fatal(err)
			}
			for name, body := range map[string]string{
				"expanded-route": strings.ReplaceAll(hydrated, "AllowedIPs = 10.20.0.2/32", "AllowedIPs = 0.0.0.0/0"),
				"replaced-key":   strings.ReplaceAll(hydrated, private, base64.StdEncoding.EncodeToString(remote.Bytes())),
				"hook":           hydrated + "PostUp = false\n",
				"extra-peer":     hydrated + "\n[Peer]\nPublicKey = " + public + "\nAllowedIPs = 10.20.0.3/32\n",
			} {
				if body == hydrated {
					t.Fatal("错误的负向样例", name)
				}
				if err := validateLinuxRuntimeConfigSemantics(&plan, &runtime, map[string]string{file.Path: body}); err == nil {
					t.Fatal("接受了扩大或替换的 peer 配置", name)
				}
			}
			path := filepath.Join(t.TempDir(), "node.key")
			if err := os.WriteFile(path, []byte(private+"\n"), 0600); err != nil {
				t.Fatal(err)
			}
			if value, err := loadLinuxLocalWireGuardKey(path, public); err != nil || value != private {
				t.Fatal("原本地密钥未被保留", err)
			}
			if _, err := loadLinuxLocalWireGuardKey(path, opposite.LocalKey.PublicKey); err == nil {
				t.Fatal("本机 key 与认证公钥不符仍被接受")
			}
			if err := os.Chmod(path, 0644); err != nil {
				t.Fatal(err)
			}
			if _, err := loadLinuxLocalWireGuardKey(path, public); err == nil {
				t.Fatal("接受了可被其他用户读取的私钥")
			}
		})
	}
}
