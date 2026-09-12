package controlplane

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"loom/internal/wire"
)

func TestLinuxLinkIntentArtifactProducerPublishesExactDeviceRef(t *testing.T) {
	parent := wire.HashRaw("linux-artifact-test", []byte("parent"))
	input := LinuxLinkIntentProjectionV1{
		ClusterID: "demo-cluster", DeviceID: "demo-device", DeviceGeneration: 3,
		Generation: 4, ParentHeadHash: parent,
		LinkIntents: []wire.LinkIntentV1{{
			Schema: 1, ClusterID: "demo-cluster", LinkID: "data-a",
			FromDeviceID: "demo-device", To: wire.LinkIntentDestinationV1{DeviceID: "demo-egress"},
			Purpose: "data_forward", AllowedTransports: []string{"hysteria2"}, Initiator: "from",
			ListenerResourceRefs: []string{"data-a"}, CredentialRefs: []string{"credential-a"},
			RouteScope: "egress-a", Generation: 2, ParentHeadHash: parent,
		}},
	}
	one, err := BuildLinuxLinkIntentArtifact(input)
	if err != nil {
		t.Fatal(err)
	}
	two, err := BuildLinuxLinkIntentArtifact(input)
	if err != nil || !bytes.Equal(one, two) {
		t.Fatalf("Linux artifact producer 不确定: err=%v", err)
	}
	root := t.TempDir()
	ref, publishedPath, err := PublishLinuxLinkIntentArtifact(root, input)
	if err != nil {
		t.Fatal(err)
	}
	if ref.ArtifactID != wire.LinuxLinkIntentArtifactID || ref.Generation != input.Generation ||
		ref.Platform != "linux-server" || ref.RenderContractID != wire.LinuxLinkIntentRenderContract ||
		ref.SizeBytes != int64(len(one)) {
		t.Fatalf("unexpected Linux artifact ref: %+v", ref)
	}
	wantHash, err := wire.DeviceConfigArtifactContentHash(one)
	if err != nil || ref.ContentHash != wantHash {
		t.Fatalf("content hash=%q want=%q err=%v", ref.ContentHash, wantHash, err)
	}
	published, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(strings.TrimPrefix(publishedPath, "/"))))
	if err != nil || !bytes.Equal(published, one) {
		t.Fatalf("published exact bytes mismatch: err=%v", err)
	}
}

func TestLinuxLinkIntentArtifactProducerRejectsForeignOrBootstrapEdges(t *testing.T) {
	parent := wire.HashRaw("linux-artifact-test", []byte("parent"))
	base := LinuxLinkIntentProjectionV1{
		ClusterID: "demo-cluster", DeviceID: "demo-device", DeviceGeneration: 1,
		Generation: 1, ParentHeadHash: parent,
		LinkIntents: []wire.LinkIntentV1{{
			Schema: 1, ClusterID: "demo-cluster", LinkID: "data-a", FromDeviceID: "foreign-a",
			To: wire.LinkIntentDestinationV1{DeviceID: "foreign-b"}, Purpose: "data_forward",
			AllowedTransports: []string{"wireguard"}, Initiator: "from",
			ListenerResourceRefs: []string{"data-a"}, CredentialRefs: []string{"credential-a"},
			RouteScope: "egress-a", Generation: 1, ParentHeadHash: parent,
		}},
	}
	if _, err := BuildLinuxLinkIntentArtifact(base); err == nil {
		t.Fatal("与目标 Device 无关的 edge 被发布")
	}
	base.LinkIntents[0].FromDeviceID = "demo-device"
	base.LinkIntents[0].To = wire.LinkIntentDestinationV1{ServiceID: "enroll"}
	base.LinkIntents[0].Purpose = "bootstrap"
	base.LinkIntents[0].AllowedTransports = []string{"hysteria2"}
	if _, err := BuildLinuxLinkIntentArtifact(base); err == nil {
		t.Fatal("bootstrap edge 被恢复进 active runtime artifact")
	}
}

func TestLinuxRuntimeArtifactProducerBindsExactLinkIntentAndPublishesTypedRef(t *testing.T) {
	parent := wire.HashRaw("linux-runtime-artifact-test", []byte("parent"))
	linkRaw, err := BuildLinuxLinkIntentArtifact(LinuxLinkIntentProjectionV1{
		ClusterID: "demo-cluster", DeviceID: "demo-device", DeviceGeneration: 3,
		Generation: 4, ParentHeadHash: parent,
		LinkIntents: []wire.LinkIntentV1{{
			Schema: 1, ClusterID: "demo-cluster", LinkID: "data-a",
			FromDeviceID: "demo-device", To: wire.LinkIntentDestinationV1{DeviceID: "demo-egress"},
			Purpose: "data_forward", AllowedTransports: []string{"hysteria2"}, Initiator: "from",
			ListenerResourceRefs: []string{"edge-a"}, CredentialRefs: []string{"credential-a"},
			RouteScope: "egress-a", Generation: 2, ParentHeadHash: parent,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	input := LinuxRuntimeProjectionV1{
		ClusterID: "demo-cluster", DeviceID: "demo-device", DeviceGeneration: 3,
		Generation: 7, LinkIntentRaw: linkRaw,
		Bindings: []wire.LinuxRuntimeBindingV1{
			{LinkID: "data-a", LinkGeneration: 2, Mode: "dial", Transport: "hysteria2",
				EndpointID: "edge-a", ListenerGeneration: 1,
				ConfigPath: "sing-box/v2/config.json", RuntimeTag: "edge-a-g1"},
			{LinkID: "data-a", LinkGeneration: 2, Mode: "dial", Transport: "hysteria2",
				EndpointID: "edge-a", ListenerGeneration: 2,
				ConfigPath: "sing-box/v2/config.json", RuntimeTag: "edge-a-g2"},
		},
		Files: []wire.LinuxRuntimeFileV1{
			{Path: "agent/v2/config.json", Content: `{"schema":1}`},
			{Path: "sing-box/v2/config.json", Content: `{"password":"${secret:credential-a}"}`},
		},
	}
	one, err := BuildLinuxRuntimeArtifact(input)
	if err != nil {
		t.Fatal(err)
	}
	two, err := BuildLinuxRuntimeArtifact(input)
	if err != nil || !bytes.Equal(one, two) {
		t.Fatalf("Linux runtime producer 不确定: err=%v", err)
	}
	root := t.TempDir()
	ref, publishedPath, err := PublishLinuxRuntimeArtifact(root, input)
	if err != nil {
		t.Fatal(err)
	}
	wantHash, _ := wire.DeviceConfigArtifactContentHash(one)
	if ref.ArtifactID != wire.LinuxRuntimeArtifactID || ref.Generation != 7 ||
		ref.RenderContractID != wire.LinuxRuntimeRenderContract || ref.ContentHash != wantHash ||
		ref.SizeBytes != int64(len(one)) {
		t.Fatalf("unexpected Linux runtime ref: %+v", ref)
	}
	published, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(strings.TrimPrefix(publishedPath, "/"))))
	if err != nil || !bytes.Equal(published, one) {
		t.Fatalf("published exact runtime bytes mismatch: err=%v", err)
	}

	input.Bindings[0].EndpointID = "foreign-edge"
	if _, err := BuildLinuxRuntimeArtifact(input); err == nil {
		t.Fatal("renderer binding 扩大 LinkIntent listener refs 未被拒绝")
	}
	input.Bindings[0].EndpointID = "edge-a"
	input.Files[1].Content = `{"password":"literal-secret"}`
	if _, err := BuildLinuxRuntimeArtifact(input); err == nil {
		t.Fatal("public runtime 敏感字段明文未被 producer 拒绝")
	}
	input.Files[1].Content = `{"password":"${secret:credential-a}"}`
	input.LinkIntentRaw = append([]byte(nil), linkRaw...)
	input.LinkIntentRaw[len(input.LinkIntentRaw)-1] = ' '
	if _, err := BuildLinuxRuntimeArtifact(input); err == nil {
		t.Fatal("非 exact canonical LinkIntent bytes 被 runtime producer 接受")
	}
}
