//go:build linux

package clientv2

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"sort"
	"strings"
	"testing"
	"time"

	"loom/internal/model"
	"loom/internal/render"
	"loom/internal/secret"
	"loom/internal/wire"
)

func TestLinuxProducerFeedsCertifiedReaderWithoutOldControlPaths(t *testing.T) {
	for _, hybrid := range []bool{false, true} {
		name := "separate"
		if hybrid {
			name = "combined"
		}
		t.Run(name, func(t *testing.T) { testLinuxProducerRuntime(t, hybrid, false) })
	}
	t.Run("private-control-carrier", func(t *testing.T) { testLinuxProducerRuntime(t, false, true) })
}

func testLinuxProducerRuntime(t *testing.T, hybrid, carrier bool) {
	source, err := model.LoadFile("../../testdata/matrix/ssot.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if hybrid {
		for i := range source.Nodes {
			node := &source.Nodes[i]
			if node.Access != nil && node.Access.Platform == model.LinuxServer {
				node.PublicEndpoint = "203.0.113.99"
				node.Server = &model.ServerRole{Direction: model.Bidirectional, InboundPort: 443, EgressCapable: true}
			}
		}
	}
	set, key := clientControlSet(t)
	base := clientEnvelope(t, &set, key)
	views := map[string]wire.DeviceViewPayloadV2{}
	privateKeys := map[string]string{}
	grants := wire.EnrollmentDestinationGrantsV1{Schema: 1, Values: []wire.EnrollmentDestinationGrantV1{}}
	for i := range source.Nodes {
		node := &source.Nodes[i]
		if node.Server != nil {
			private, err := ecdh.X25519().GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			node.Server.WGPublicKey = base64.StdEncoding.EncodeToString(private.PublicKey().Bytes())
			privateKeys[node.ID] = base64.StdEncoding.EncodeToString(private.Bytes())
			if node.Server.EgressCapable {
				grants.Values = append(grants.Values, wire.EnrollmentDestinationGrantV1{Kind: "egress", TargetID: node.ID})
			}
		}
	}
	for _, service := range source.Services {
		grants.Values = append(grants.Values, wire.EnrollmentDestinationGrantV1{Kind: "service", TargetID: service.ID})
	}
	sort.Slice(grants.Values, func(i, j int) bool {
		a, b := grants.Values[i], grants.Values[j]
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		return a.TargetID < b.TargetID
	})
	for _, node := range source.Nodes {
		roles := []string{}
		if node.Access != nil {
			roles = append(roles, "use_loom")
		}
		if node.Server != nil {
			roles = append(roles, "forward")
			if node.Server.EgressCapable {
				roles = append(roles, "internet_egress")
			}
		}
		view := base.Payload
		active := *base.Payload.Active
		view.DeviceID, view.Active = node.ID, &active
		active.Responsibilities = wire.EnrollmentResponsibilitiesV1{Schema: 1, Values: roles}
		active.ResponsibilitiesHash, _ = wire.HashObject("loom-enrollment-responsibilities-v1", active.Responsibilities)
		active.Grants = grants
		active.GrantsHash, _ = wire.HashObject("loom-enrollment-destination-grants-v1", grants)
		active.EndpointBundle.DeviceID = node.ID
		active.EndpointBundleHash, _ = wire.DeviceEndpointBundleHash(&active.EndpointBundle)
		views[node.ID] = view
	}
	for _, node := range source.Nodes {
		if node.Access != nil && node.Access.Platform != model.LinuxServer {
			continue
		}
		t.Run(node.ID, func(t *testing.T) {
			before, _ := json.Marshal(source)
			input := render.LinuxRuntimeV2Input{SSOT: source, Views: views,
				Authority: wire.CertifiedHeadV1{Head: base.SignedCurrent.Head, QC: base.SignedCurrent.QuorumCertificate},
				DeviceID:  node.ID, DeviceGeneration: 2, ArtifactGeneration: 1}
			if node.Server != nil {
				for _, client := range source.Nodes {
					if client.Access != nil && client.Access.Platform == model.WindowsDesktop {
						clientKey, err := ecdh.X25519().GenerateKey(rand.Reader)
						if err != nil {
							t.Fatal(err)
						}
						services := []wire.PrivateControlServiceV1{}
						for i, role := range []string{"device_config", "device_report"} {
							services = append(services, wire.PrivateControlServiceV1{ServiceID: "private-" + role, Role: role, OverlayIP: "10.250.0.1", Port: int64(44000 + i), CertificateProfileRef: "demo-private-tls", SPKIPins: []string{wire.HashRaw("demo-pin", []byte(role))}, AuthorizedSubjectProfiles: []string{"demo-device"}})
						}
						input.DeviceControlLinks = []wire.DeviceControlLinkV1{{Resource: wire.LinuxWireGuardResourceV1{ResourceID: "device-control-demo", LinkID: "device-control-demo", ListenerDeviceID: node.ID, DialerDeviceID: client.ID, ListenerGeneration: 1, EndpointAddress: "10.250.0.1", EndpointPort: 51998, ListenerPublicKey: node.Server.WGPublicKey, DialerPublicKey: base64.StdEncoding.EncodeToString(clientKey.PublicKey().Bytes()), ListenerTunnelPrefix: "10.250.0.3/32", DialerTunnelPrefix: "10.250.0.2/32"}, Services: services}}
						break
					}
				}
			}
			if carrier && node.Server != nil {
				var peer *model.Node
				for i := range source.Nodes {
					if source.Nodes[i].Server != nil && source.Nodes[i].ID != node.ID {
						peer = &source.Nodes[i]
						break
					}
				}
				link := &input.DeviceControlLinks[0]
				listener := node
				if node.ID == source.Nodes[0].ID {
					link.Resource.DialerDeviceID, link.Resource.DialerPublicKey = peer.ID, peer.Server.WGPublicKey
				} else {
					listener = *peer
					link.Resource.ListenerDeviceID, link.Resource.ListenerPublicKey = peer.ID, peer.Server.WGPublicKey
					link.Resource.DialerDeviceID, link.Resource.DialerPublicKey = node.ID, node.Server.WGPublicKey
				}
				link.Carrier = &wire.DeviceControlCarrierV1{Address: listener.PublicEndpoint, Port: int64(listener.Server.InboundPort),
					TLSServerName: listener.ID + ".node.internal", CredentialRef: wire.DeviceControlCarrierCredentialRef(*link)}
			}
			result, err := render.RenderLinuxRuntimeV2(input)
			if err != nil {
				t.Fatal(err)
			}
			again, err := render.RenderLinuxRuntimeV2(input)
			after, _ := json.Marshal(source)
			if err != nil || !bytes.Equal(before, after) || !bytes.Equal(result.Runtime.Content, again.Runtime.Content) || !bytes.Equal(result.Links.Content, again.Links.Content) {
				t.Fatal("渲染改变输入或不确定", err)
			}
			var links wire.LinuxLinkIntentArtifactV1
			var artifact wire.LinuxRuntimeArtifactV1
			if err := json.Unmarshal(result.Links.Content, &links); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(result.Runtime.Content, &artifact); err != nil {
				t.Fatal(err)
			}
			envelope := base
			envelope.Payload = views[node.ID]
			active := *envelope.Payload.Active
			envelope.Payload.Active = &active
			envelope.Payload.DeviceGeneration = 2
			envelope.Leaf.DeviceID, envelope.Leaf.DeviceGeneration = node.ID, 2
			active.EndpointBundle.DeviceGeneration = 2
			active.EndpointBundleHash, _ = wire.DeviceEndpointBundleHash(&active.EndpointBundle)
			// helper 在基准 Head 之后认证当前配置引用；基准证明本身不改变。
			links.Authority = wire.CertifiedHeadV1{}
			linkRaw := bindRuntimeArtifactToEnvelope(t, &envelope, &set, key, links)
			if !bytes.Equal(linkRaw, result.Links.Content) {
				t.Fatal("reader 与生产器承诺了不同 LinkIntent artifact")
			}
			active.ConfigArtifactRefs = []wire.DeviceConfigArtifactRefV1{result.Links.Ref, result.Runtime.Ref}
			resignRuntimeEnvelope(t, &envelope, &set, key)
			values := map[string]string{}
			credentials := []InstalledSecretV1{}
			for _, ref := range result.Runtime.CredentialRefs {
				values[ref] = "demo-private-value"
				credentials = append(credentials, InstalledSecretV1{SecretID: ref, Purpose: "data_plane_credential", SecretBytes: base64.RawURLEncoding.EncodeToString([]byte(values[ref])),
					SecretDigest: wire.HashRaw("loom-linux-installed-secret-v1", []byte(values[ref]))})
			}
			if links.LocalWireGuardKey != nil {
				values[links.LocalWireGuardKey.SecretID] = privateKeys[node.ID]
			}
			plan, err := BuildLinuxLinkRuntimePlan(&envelope, &set, nil, nil, linkRaw, credentials, time.Date(2026, 9, 12, 0, 0, 0, 0, time.UTC), nil)
			if err != nil {
				t.Fatal(err)
			}
			if node.Access != nil && (plan.EnableTUN || !plan.EnableMixed) {
				t.Fatal("Linux mixed 客户端被改成了 TUN")
			}
			if err := validateLinuxRuntimeBindings(&plan, &artifact); err != nil {
				t.Fatal(err)
			}
			files := map[string]string{}
			for _, file := range artifact.Files {
				value, missing := secret.Hydrate(file.Content, values)
				if len(missing) != 0 {
					t.Fatal(missing)
				}
				if file.Path == "agent/v2/config.json" && (strings.Contains(value, "self_report") || strings.Contains(value, "\"peers\"")) {
					t.Fatal("v2 runtime 仍引用旧 report endpoint")
				}
				files[file.Path] = value
			}
			if err := validateLinuxRuntimeConfigSemantics(&plan, &artifact, files); err != nil {
				t.Fatal(err)
			}
			if carrier && node.Server != nil && node.ID != source.Nodes[0].ID {
				installation := &DeviceInstallationV1{Configs: []InstalledConfigV1{{ArtifactID: wire.LinuxLinkIntentArtifactID, Config: result.Links.Content}}, Credentials: credentials}
				service := input.DeviceControlLinks[0].Services[0]
				dial, err := installedLinuxDeviceDial(installation, node.ID, service, time.Second)
				if err != nil || dial == nil {
					t.Fatal("Linux 私有请求仍会使用主机默认路由", err)
				}
				if conn, err := dial(context.Background(), "tcp", "192.0.2.123:443"); err == nil || conn != nil {
					t.Fatal("代理放行目录外目的")
				}
				installation.Credentials = nil
				if dial, err := installedLinuxDeviceDial(installation, node.ID, service, time.Second); err == nil || dial != nil {
					t.Fatal("缺凭据时允许主机默认回退")
				}
			}
			if len(input.DeviceControlLinks) > 0 {
				allowedPrefix := "10.250.0.2/32"
				if carrier && node.ID != source.Nodes[0].ID {
					allowedPrefix = "10.250.0.1/32"
				}
				mutations := []struct{ before, after string }{
					{`"allowed_ips":["` + allowedPrefix + `"]`, `"allowed_ips":["10.0.0.0/8"]`},
					{`"outbound":"device-control-block"`, `"outbound":"device-control-direct"`},
					{`"ip_cidr":["10.250.0.1/32"]`, `"ip_cidr":["10.0.0.0/8"]`},
					{`"system":false`, `"system":true`},
				}
				if carrier && node.ID != source.Nodes[0].ID {
					mutations = append(mutations, struct{ before, after string }{`"tag":"device-control-demo-carrier"`, `"tag":"demo-unbound-carrier"`},
						struct{ before, after string }{`"listen":"127.0.0.1","listen_port":61805`, `"listen":"0.0.0.0","listen_port":61805`})
				}
				for _, mutation := range mutations {
					broken := map[string]string{}
					for path, body := range files {
						broken[path] = body
					}
					path := "sing-box/v2/config.json"
					broken[path] = strings.Replace(broken[path], mutation.before, mutation.after, 1)
					if broken[path] == files[path] {
						t.Fatal("故障注入未命中")
					}
					if err := validateLinuxRuntimeConfigSemantics(&plan, &artifact, broken); err == nil {
						t.Fatal("接受扩大私有控制通道的配置")
					}
				}
			}
			if node.Server != nil && node.Access == nil {
				denied := map[string]wire.DeviceViewPayloadV2{}
				for id, view := range views {
					copy := *view.Active
					view.Active = &copy
					if source.NodeByID()[id].Access != nil {
						copy.Grants = wire.EnrollmentDestinationGrantsV1{Schema: 1, Values: []wire.EnrollmentDestinationGrantV1{}}
					}
					denied[id] = view
				}
				changedInput := input
				changedInput.Views = denied
				changed, err := render.RenderLinuxRuntimeV2(changedInput)
				if err != nil {
					t.Fatal(err)
				}
				for _, credential := range source.Credentials {
					if source.AccessNodeForCredential(credential.ID) != nil && bytes.Contains(changed.Runtime.Content, []byte("${secret:"+credential.Ref()+"}")) {
						t.Fatal("已撤销的客户端权限仍进入 server 凭据表")
					}
				}
			}
			deployment, _, err := linuxRuntimeDeployPlan(node.ID, t.TempDir(), files)
			if err != nil || len(deployment.Verify) == 0 {
				t.Fatal("实际 deploy plan 缺服务", err)
			}
			if len(links.PeerTransports) > 0 {
				peer := links.PeerTransports[0]
				if _, err := BuildLinuxLinkRuntimePlan(&envelope, &set, nil, nil, linkRaw, credentials, time.Now(), map[string]int64{peer.ResourceID: peer.ListenerGeneration + 1}); err == nil {
					t.Fatal("接受了 transport generation 回退")
				}
				broken := map[string]string{}
				for path, value := range files {
					broken[path] = strings.ReplaceAll(value, peer.TLSServerName, "other.example.test")
				}
				if err := validateLinuxRuntimeConfigSemantics(&plan, &artifact, broken); err == nil {
					t.Fatal("接受了改变的内部 TLS 身份")
				}
			}
		})
	}
}
