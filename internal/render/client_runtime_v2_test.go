package render

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"sort"
	"strings"
	"testing"
	"time"

	"loom/internal/clientruntime"
	"loom/internal/model"
	"loom/internal/secret"
	"loom/internal/wire"
	loomcore "loom/mobile/loomcore"
)

func TestRenderV2ClientsDeliverConsumablePrivateRuntime(t *testing.T) {
	ssot := load(t)
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), NotAfter: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, public, key)
	if err != nil {
		t.Fatal(err)
	}
	platforms := map[model.Platform]int{}
	for _, node := range ssot.Nodes {
		if !node.IsAccess() || node.Server != nil || node.Access.Platform != model.Android && node.Access.Platform != model.WindowsDesktop {
			continue
		}
		platforms[node.Access.Platform]++
		t.Run(string(node.Access.Platform), func(t *testing.T) {
			source, _, err := renderSingBox(ssot, &node)
			if err != nil {
				t.Fatal(err)
			}
			var parsed struct {
				Outbounds []sbOutbound `json:"outbounds"`
			}
			if err := json.Unmarshal([]byte(source.Content), &parsed); err != nil {
				t.Fatal(err)
			}
			detour := ""
			for _, outbound := range parsed.Outbounds {
				if outbound.Type == "hysteria2" && outbound.Detour == "" {
					detour = outbound.Tag
					break
				}
			}
			if detour == "" {
				t.Fatal("fixture 缺实际代理入口")
			}
			input := ClientRuntimeV2Input{SSOT: ssot, Grants: allClientRuntimeGrants(ssot), ClusterID: "demo-network", DeviceID: node.ID, DeviceGeneration: 2,
				ArtifactGeneration: 3, SingBoxVersion: "1.11.4", ObservationCA: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
				ControlTunnel: ClientControlTunnelV2{Address: []string{"10.250.0.2/32"}, PrivateKeyRef: "private-control-wg-key",
					PeerAddress: "192.0.2.34", PeerPort: 51820, PeerPublicKey: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{19}, 32)),
					AllowedIPs: []string{"10.250.0.1/32"}, Detour: detour, MTU: 1280}}
			sourceDNS, _ := json.Marshal(ssot.DNSFor(&node))
			result, err := RenderClientRuntimeV2(input)
			if err != nil {
				t.Fatal(err)
			}
			repeated, err := RenderClientRuntimeV2(input)
			if err != nil || !bytes.Equal(repeated.Content, result.Content) {
				t.Fatal("v2 renderer 非纯函数", err)
			}
			afterDNS, _ := json.Marshal(ssot.DNSFor(&node))
			if !bytes.Equal(sourceDNS, afterDNS) {
				t.Fatal("移动平台解析器投影修改了认证源网络")
			}
			if hash, _ := wire.DeviceConfigArtifactContentHash(result.Content); hash != result.Ref.ContentHash {
				t.Fatal("制品摘要不匹配")
			}
			credentials := map[string]string{}
			var env strings.Builder
			for _, ref := range result.CredentialRefs {
				value := "demo-runtime-value"
				if ref == input.ControlTunnel.PrivateKeyRef {
					value = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{17}, 32))
				}
				credentials[ref] = value
				env.WriteString(ref + "=" + value + "\n")
			}
			if node.Access.Platform == model.Android {
				prepared, err := loomcore.PrepareAndroidRuntime(result.Content, []byte(env.String()))
				if err != nil {
					t.Fatal(err)
				}
				var runtime struct {
					SingBoxConfig string `json:"sing_box_config"`
				}
				if err := json.Unmarshal(prepared, &runtime); err != nil {
					t.Fatal(err)
				}
				if err := loomcore.ValidateAndroidV2RuntimeHost([]byte(runtime.SingBoxConfig)); err != nil {
					t.Fatal(err)
				}
				var config sbConfig
				if err := json.Unmarshal([]byte(runtime.SingBoxConfig), &config); err != nil {
					t.Fatal(err)
				}
				if len(config.DNS.Servers) != 2 || config.DNS.Servers[0].Address != "local" ||
					config.DNS.Rules[0].Server != androidFakeIPDNSTag || !config.DNS.IndependentCache || !config.DNS.DisableCache {
					t.Fatal("v2 Android 必须分开底层 Network 解析与最终出口 FakeIP 域名恢复")
				}
			} else {
				var artifact wire.WindowsRuntimeArtifactV1
				if _, err := wire.DecodeStrict(result.Content, 4<<20, &artifact); err != nil {
					t.Fatal(err)
				}
				hydrated, missing := secret.Hydrate(artifact.Files[1].Content, credentials)
				if len(missing) != 0 {
					t.Fatal("配置缺秘密")
				}
				for _, profile := range []clientruntime.WindowsRuntimeProfile{clientruntime.WindowsInstalledProfile, clientruntime.WindowsPortableMixedProfile, clientruntime.WindowsPortableTUNProfile} {
					if _, err := clientruntime.DeriveWindowsRuntimeConfig([]byte(hydrated), profile, clientruntime.WindowsInstalledCAPath); err != nil {
						t.Fatal(profile, err)
					}
				}
			}
			input.ControlTunnel.Detour = "demo-unapproved-proxy"
			if _, err := RenderClientRuntimeV2(input); err == nil {
				t.Fatal("未授权 detour 被加入运行面")
			}
		})
	}
	if platforms[model.Android] == 0 || platforms[model.WindowsDesktop] == 0 {
		t.Fatal("缺客户端平台消费验证")
	}
}

func allClientRuntimeGrants(ssot *model.SSOT) *wire.EnrollmentDestinationGrantsV1 {
	grants := &wire.EnrollmentDestinationGrantsV1{Schema: 1, Values: []wire.EnrollmentDestinationGrantV1{}}
	for _, node := range ssot.Nodes {
		if node.Server != nil && node.Server.EgressCapable && !node.Decommission {
			grants.Values = append(grants.Values, wire.EnrollmentDestinationGrantV1{Kind: "egress", TargetID: node.ID})
		}
	}
	for _, service := range ssot.Services {
		grants.Values = append(grants.Values, wire.EnrollmentDestinationGrantV1{Kind: "service", TargetID: service.ID})
	}
	sort.Slice(grants.Values, func(i, j int) bool {
		return grants.Values[i].Kind+":"+grants.Values[i].TargetID < grants.Values[j].Kind+":"+grants.Values[j].TargetID
	})
	return grants
}
