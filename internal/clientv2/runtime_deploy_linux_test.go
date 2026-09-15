//go:build linux

package clientv2

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"loom/internal/deploy"
	"loom/internal/wire"
)

func TestPrepareLinuxRuntimeDeploymentBindsDurableArtifactsAndBuildsIsolatedTransaction(t *testing.T) {
	statePath, runtimeStatePath, installStatePath, linkRaw, runtimeRaw := linuxRuntimeDeploymentFixture(t)

	plan, err := PrepareLinuxRuntimeDeployment(installStatePath, statePath, runtimeStatePath,
		linkRaw, runtimeRaw)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		linuxV2SingBoxConfigPath, linuxV2AgentConfigPath,
		linuxV2SingBoxUnitPath, linuxV2AgentUnitPath, installStatePath,
	} {
		if _, found := plan.Files[path]; !found {
			t.Fatalf("deploy plan 缺 %s", path)
		}
	}
	for path := range plan.Files {
		if path == "/etc/loom/sing-box/config.json" || path == "/etc/loom/agent/config.json" {
			t.Fatalf("v2 runtime 越界覆盖 v1 target: %s", path)
		}
	}
	if secret := "rotated-linux-secret"; !strings.Contains(plan.Files[linuxV2SingBoxConfigPath], secret) ||
		!strings.Contains(plan.Files[linuxV2AgentConfigPath], secret) ||
		strings.Contains(plan.Files[linuxV2SingBoxConfigPath], "${secret:") {
		t.Fatal("runtime secrets 未在本机 exact hydrate")
	}
	if len(plan.PreCheck) != 1 || !strings.Contains(plan.PreCheck[0],
		"sing-box check -c "+deploy.StagingRoot) {
		t.Fatalf("sing-box staging precheck 缺失: %v", plan.PreCheck)
	}
	if got, want := strings.Join(plan.Verify, ","),
		"loom-client-v2-sing-box,loom-client-v2-agent"; got != want {
		t.Fatalf("runtime verify order=%q want=%q", got, want)
	}
	if plan.InventoryGuard == nil || !plan.InventoryGuard.Absent ||
		plan.InventoryGuard.Path != installStatePath {
		t.Fatalf("首次安装缺 absent CAS guard: %+v", plan.InventoryGuard)
	}
	if _, err := os.Stat(installStatePath); !os.IsNotExist(err) {
		t.Fatalf("prepare 不应提前修改 install state: %v", err)
	}

	var installed LinuxRuntimeInstallStateV1
	body := []byte(plan.Files[installStatePath])
	canonical, err := wire.DecodeStrict(body, maximumLinuxRuntimeInstallStateBytes, &installed)
	if err != nil || !bytes.Equal(canonical, body) || validateLinuxRuntimeInstallState(&installed) != nil {
		t.Fatalf("plan 内 install state 不是 exact canonical LKG: %v", err)
	}
	staleWG := "/etc/wireguard/lmv2-deadbeef00.conf"
	installed.InstalledFiles = append(installed.InstalledFiles, staleWG)
	sort.Strings(installed.InstalledFiles)
	if err := persistProtectedCanonical(installStatePath, &installed); err != nil {
		t.Fatal(err)
	}
	second, err := PrepareLinuxRuntimeDeployment(installStatePath, statePath, runtimeStatePath,
		linkRaw, runtimeRaw)
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Remove) != 1 || second.Remove[0] != staleWG || second.InventoryGuard == nil ||
		second.InventoryGuard.Absent || second.InventoryGuard.SHA256 == "" {
		t.Fatalf("stale runtime/CAS guard 未进入事务: remove=%v guard=%+v",
			second.Remove, second.InventoryGuard)
	}
}

func TestLinuxRuntimeDeployPlanStartsWireGuardBeforeSingBoxAndAgent(t *testing.T) {
	plan, installed, err := linuxRuntimeDeployPlan("device-a", map[string]string{
		"wireguard/lmv2-deadbeef00.conf": "[Interface]\n[Peer]\n",
		"sing-box/v2/config.json":        `{"inbounds":[],"outbounds":[]}`,
		"agent/v2/config.json":           `{"node":"device-a"}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	wantVerify := "wg-quick@lmv2-deadbeef00,loom-client-v2-sing-box,loom-client-v2-agent"
	if got := strings.Join(plan.Verify, ","); got != wantVerify {
		t.Fatalf("verify order=%q want=%q", got, wantVerify)
	}
	if got := strings.Join(plan.Services(), ","); got != wantVerify {
		t.Fatalf("restart order=%q want=%q", got, wantVerify)
	}
	if len(plan.PreCheck) != 2 || len(installed) != 5 ||
		!strings.Contains(plan.Files[linuxV2SingBoxUnitPath], "After=wg-quick@lmv2-deadbeef00.service") {
		t.Fatalf("WG precheck/inventory/unit dependency 缺失: checks=%v installed=%v",
			plan.PreCheck, installed)
	}
	wgCheck := linuxWireGuardPreCheck("/etc/wireguard/lmv2-deadbeef00.conf")
	if !containsString(plan.PreCheck, wgCheck) ||
		strings.Contains(wgCheck, "wg-quick strip "+linuxRuntimeStagingPath("/etc/wireguard/lmv2-deadbeef00.conf")) ||
		!strings.HasSuffix(wgCheck, "wg-quick strip "+deploy.StagingRoot+"lmv2-deadbeef00.conf") {
		t.Fatalf("WireGuard precheck 未保留合法接口 basename: %q", wgCheck)
	}
}

func TestLinuxRuntimeWireGuardConfigRejectsHooksAndIncompleteKeySections(t *testing.T) {
	valid := "[Interface]\nPrivateKey = private\n[Peer]\nPublicKey = public\nEndpoint = edge.example.test:51820\n"
	if err := validateLinuxWireGuardConfig(valid); err != nil {
		t.Fatalf("valid WireGuard config 被拒绝: %v", err)
	}
	for _, invalid := range []string{
		"[Interface]\nPrivateKey = private\nPostUp = touch /tmp/owned\n[Peer]\nPublicKey = public\n",
		"[Interface]\nPrivateKey = private\n[Peer]\nEndpoint = edge.example.test:51820\n",
		"[Interface]\n[Peer]\nPublicKey = public\n",
	} {
		if err := validateLinuxWireGuardConfig(invalid); err == nil {
			t.Fatalf("unsafe/incomplete WireGuard config 被接受: %q", invalid)
		}
	}
}

func TestPrepareLinuxRuntimeDecommissionRequiresCertifiedTombstoneAndRemovesOnlyInventory(t *testing.T) {
	statePath, runtimeStatePath, installStatePath, linkRaw, runtimeRaw := linuxRuntimeDeploymentFixture(t)
	activePlan, err := PrepareLinuxRuntimeDeployment(installStatePath, statePath, runtimeStatePath,
		linkRaw, runtimeRaw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PrepareLinuxRuntimeDecommission(installStatePath, statePath); err == nil {
		t.Fatal("active Device 被允许下线 runtime")
	}
	var installed LinuxRuntimeInstallStateV1
	if _, err := wire.DecodeStrict([]byte(activePlan.Files[installStatePath]),
		maximumLinuxRuntimeInstallStateBytes, &installed); err != nil {
		t.Fatal(err)
	}
	if err := persistProtectedCanonical(installStatePath, &installed); err != nil {
		t.Fatal(err)
	}

	store, err := Open(statePath)
	if err != nil {
		t.Fatal(err)
	}
	current := *store.Envelope()
	set, configKey := clientControlSet(t)
	revoked := revokeClientEnvelope(t, current, &set, configKey)
	delivery := wire.DeviceConfigDeliveryV1{
		Schema: 1, ClusterID: current.Payload.ClusterID, DeviceID: current.Payload.DeviceID,
		Updates: []wire.DeviceConfigUpdateV1{
			{Schema: 1, Envelope: current, ControlSet: set},
			{Schema: 1, Envelope: revoked, ControlSet: set},
		},
	}
	if _, err := store.AcceptDeviceConfigDeliveryWithArtifacts(&delivery, nil, nil,
		current.Payload.DeviceID, current.Payload.Active.IdentitySPKIHash, nil, nil); err != nil {
		t.Fatal(err)
	}
	plan, err := PrepareLinuxRuntimeDecommission(installStatePath, statePath)
	if err != nil {
		t.Fatal(err)
	}
	if plan.InventoryGuard == nil || plan.InventoryGuard.Absent || plan.InventoryGuard.SHA256 == "" ||
		!containsString(plan.Remove, installStatePath) ||
		!containsString(plan.Remove, linuxV2SingBoxConfigPath) ||
		!containsString(plan.Remove, linuxV2AgentConfigPath) ||
		!containsString(plan.Remove, linuxV2SingBoxUnitPath) ||
		!containsString(plan.Remove, linuxV2AgentUnitPath) {
		t.Fatalf("terminal runtime transaction 不完整: remove=%v guard=%+v", plan.Remove, plan.InventoryGuard)
	}
	for _, path := range plan.Remove {
		if path != installStatePath && !validLinuxV2InstalledPath(path) {
			t.Fatalf("terminal runtime 删除越出自身 inventory: %s", path)
		}
	}
	if _, err := PrepareLinuxRuntimeDeployment(installStatePath, statePath, runtimeStatePath,
		linkRaw, runtimeRaw); err == nil {
		t.Fatal("terminal Device 仍可准备 active runtime")
	}
}

func TestPrepareLinuxRuntimeLocalUninstallRemovesOnlyRuntimeAndPreservesDeviceState(t *testing.T) {
	statePath, runtimeStatePath, installStatePath, linkRaw, runtimeRaw := linuxRuntimeDeploymentFixture(t)
	activePlan, err := PrepareLinuxRuntimeDeployment(installStatePath, statePath, runtimeStatePath,
		linkRaw, runtimeRaw)
	if err != nil {
		t.Fatal(err)
	}
	var installed LinuxRuntimeInstallStateV1
	if _, err := wire.DecodeStrict([]byte(activePlan.Files[installStatePath]),
		maximumLinuxRuntimeInstallStateBytes, &installed); err != nil {
		t.Fatal(err)
	}
	if err := persistProtectedCanonical(installStatePath, &installed); err != nil {
		t.Fatal(err)
	}

	plan, err := PrepareLinuxRuntimeLocalUninstall(installStatePath)
	if err != nil {
		t.Fatal(err)
	}
	if plan.InventoryGuard == nil || plan.InventoryGuard.Absent || plan.InventoryGuard.SHA256 == "" ||
		!containsString(plan.Remove, installStatePath) || len(plan.Remove) != len(installed.InstalledFiles)+1 {
		t.Fatalf("local uninstall transaction 不完整: remove=%v guard=%+v", plan.Remove, plan.InventoryGuard)
	}
	if got, want := strings.Join(plan.RetireServices(), ","),
		"loom-client-v2-sing-box,loom-client-v2-agent"; got != want {
		t.Fatalf("local uninstall 待停服务=%q want %q", got, want)
	}
	for _, preserved := range []string{statePath, runtimeStatePath,
		filepath.Join(filepath.Dir(statePath), "identity.json"),
		filepath.Join(filepath.Dir(statePath), "pending.json")} {
		if containsString(plan.Remove, preserved) {
			t.Fatalf("local uninstall 不得删除 Device identity/LKG: %s", preserved)
		}
	}
	for _, path := range plan.Remove {
		if path != installStatePath && !validLinuxV2InstalledPath(path) {
			t.Fatalf("local uninstall 删除越出 runtime inventory: %s", path)
		}
	}

	if err := os.Remove(installStatePath); err != nil {
		t.Fatal(err)
	}
	empty, err := PrepareLinuxRuntimeLocalUninstall(installStatePath)
	if err != nil || len(empty.Remove) != 0 || empty.InventoryGuard != nil {
		t.Fatalf("重复 local uninstall 应幂等: plan=%+v err=%v", empty, err)
	}
}

func TestPrepareLinuxRuntimeLocalUninstallRejectsUnsafeInventory(t *testing.T) {
	directory := t.TempDir()
	installStatePath := filepath.Join(directory, LinuxRuntimeInstallStateName)
	if err := os.WriteFile(installStatePath, []byte(`{"schema":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := PrepareLinuxRuntimeLocalUninstall(installStatePath); err == nil {
		t.Fatal("local uninstall 接受了非 canonical/不完整 inventory")
	}
	if _, err := PrepareLinuxRuntimeLocalUninstall(filepath.Join(directory, "other.json")); err == nil {
		t.Fatal("local uninstall 接受了非固定 inventory 路径")
	}
}

func linuxRuntimeDeploymentFixture(t *testing.T) (string, string, string, []byte, []byte) {
	t.Helper()
	now := time.Date(2026, 9, 12, 9, 30, 0, 0, time.UTC)
	statePath, identityPath, set, current, configKey := installedDeviceConfigStateWithKey(t, now)
	identity, err := LoadEnrollmentIdentityForResume(identityPath)
	if err != nil {
		t.Fatal(err)
	}
	secretRef, sealed, _ := linuxDynamicSecretFixture(t, identity,
		current.Payload.ClusterID, current.Payload.DeviceID, 2)

	parent := current.SignedCurrent.Head.HeadHash
	deviceGeneration := current.Payload.DeviceGeneration + 1
	grants := wire.EnrollmentDestinationGrantsV1{Schema: 1,
		Values: []wire.EnrollmentDestinationGrantV1{{Kind: "service", TargetID: "service-a"}}}
	grantsHash, _ := wire.HashObject("loom-enrollment-destination-grants-v1", grants)
	generation := func(number int64, state string) wire.ListenerGenerationV2 {
		return wire.ListenerGenerationV2{
			Schema: 2, ListenerGeneration: number, PublishedState: state,
			DialTargetFQDN: "edge.example.test", PublicPort: 443 + number,
			AddressFamilies: []string{"ipv4", "ipv6"}, TransportIdentityRefs: []string{secretRef.SecretID},
			CredentialGeneration: 2, CertificateIdentityProjectionHash: runtimePlanHash("certificate"),
			PublicProfileGeneration: 1, IntroducedRevision: number,
			ValidFrom: "2026-01-01T00:00:00Z", ValidUntil: "2027-01-01T00:00:00Z",
			RotationOperationHash: runtimePlanHash("rotation-" + string(rune('0'+number))),
		}
	}
	endpoint := wire.DataIngressEndpointV2{
		EndpointID: "edge-a", LogicalServerID: "server-a", Transport: "hysteria2",
		ListenerGenerations: []wire.ListenerGenerationV2{generation(1, "advertised"), generation(2, "preferred")},
		ListenerTombstones:  []wire.ListenerGenerationTombstoneV1{}, PathCapabilities: []string{"l3"},
	}
	endpointSet := wire.DataIngressEndpointSetV2{
		Schema: 2, ClusterID: set.ClusterID, EndpointSetID: "data-a", Generation: 1,
		ValidFrom: "2026-01-01T00:00:00Z", ValidUntil: "2027-01-01T00:00:00Z",
		Endpoints: []wire.DataIngressEndpointV2{endpoint}, GrantsRoot: grantsHash,
		ParentHeadHash: parent, ConfigQC: append([]byte(nil), current.SignedCurrent.QuorumCertificate...),
	}
	endpointSetHash, err := wire.DataIngressSetHash(&endpointSet)
	if err != nil {
		t.Fatal(err)
	}
	bundle := wire.DeviceEndpointBundleV1{
		Schema: 1, ClusterID: set.ClusterID, DeviceID: current.Payload.DeviceID,
		DeviceGeneration: deviceGeneration,
		DataIngressSets: []wire.DeviceDataIngressBindingV1{{
			EndpointSetID: endpointSet.EndpointSetID, EndpointSet: endpointSet, EndpointSetHash: endpointSetHash,
		}},
	}
	linkArtifact := wire.LinuxLinkIntentArtifactV1{
		Schema: 1, ClusterID: set.ClusterID, DeviceID: current.Payload.DeviceID,
		DeviceGeneration: deviceGeneration, Generation: 1,
		RenderContractID: wire.LinuxLinkIntentRenderContract, AuthorityHeadHash: parent,
		Authority: wire.CertifiedHeadV1{Head: current.SignedCurrent.Head, QC: current.SignedCurrent.QuorumCertificate},
		LinkIntents: []wire.LinkIntentV1{{
			Schema: 1, ClusterID: set.ClusterID, LinkID: "link-a", FromDeviceID: current.Payload.DeviceID,
			To: wire.LinkIntentDestinationV1{ServiceID: "service-a"}, Purpose: "data_forward",
			AllowedTransports: []string{"hysteria2"}, Initiator: "from",
			ListenerResourceRefs: []string{"edge-a"}, CredentialRefs: []string{secretRef.SecretID},
			RouteScope: "service-a", Generation: 1, ParentHeadHash: parent,
		}},
	}
	linkRaw, err := wire.MarshalCanonical(linkArtifact)
	if err != nil {
		t.Fatal(err)
	}
	linkHash, _ := wire.DeviceConfigArtifactContentHash(linkRaw)
	placeholder := "${secret:" + secretRef.SecretID + "}"
	agentRaw := mustLinuxRuntimeJSON(t, map[string]any{
		"api": "127.0.0.1:61800", "api_secret": placeholder,
		"declarations": []any{}, "node": current.Payload.DeviceID,
		"probe": "127.0.0.1:61801", "probe_secret": placeholder,
		"schema": 1, "selectors": []any{},
	})
	singBoxRaw := mustLinuxRuntimeJSON(t, map[string]any{
		"inbounds": []any{
			map[string]any{"tag": "tun-in", "type": "tun"},
			map[string]any{"listen": "127.0.0.1", "listen_port": 1080, "tag": "mixed-in", "type": "mixed"},
		},
		"outbounds": []any{
			map[string]any{"password": placeholder, "server": "edge.example.test", "server_port": 444,
				"tag": "edge-a-g1", "tls": map[string]any{"enabled": true, "server_name": "edge.example.test"}, "type": "hysteria2"},
			map[string]any{"password": placeholder, "server": "edge.example.test", "server_port": 445,
				"tag": "edge-a-g2", "tls": map[string]any{"enabled": true, "server_name": "edge.example.test"}, "type": "hysteria2"},
		},
	})
	runtimeArtifact := wire.LinuxRuntimeArtifactV1{
		Schema: 1, ClusterID: set.ClusterID, DeviceID: current.Payload.DeviceID,
		DeviceGeneration: deviceGeneration, Generation: 1,
		LinkIntentGeneration: 1, LinkIntentContentHash: linkHash,
		Bindings: []wire.LinuxRuntimeBindingV1{
			{LinkID: "link-a", LinkGeneration: 1, Mode: "dial", Transport: "hysteria2",
				EndpointID: "edge-a", ListenerGeneration: 1,
				ConfigPath: "sing-box/v2/config.json", RuntimeTag: "edge-a-g1"},
			{LinkID: "link-a", LinkGeneration: 1, Mode: "dial", Transport: "hysteria2",
				EndpointID: "edge-a", ListenerGeneration: 2,
				ConfigPath: "sing-box/v2/config.json", RuntimeTag: "edge-a-g2"},
		},
		Files: []wire.LinuxRuntimeFileV1{
			{Path: "agent/v2/config.json", Content: agentRaw},
			{Path: "sing-box/v2/config.json", Content: singBoxRaw},
		},
	}
	runtimeRaw, err := wire.MarshalCanonical(runtimeArtifact)
	if err != nil {
		t.Fatal(err)
	}
	configRef := func(id, contract string, generation int64, raw []byte) wire.DeviceConfigArtifactRefV1 {
		hash, _ := wire.DeviceConfigArtifactContentHash(raw)
		return wire.DeviceConfigArtifactRefV1{
			ArtifactID: id, Generation: generation, Platform: "linux-server",
			MediaType: "application/vnd.loom.config+json", RenderContractID: contract,
			SizeBytes: int64(len(raw)), ContentHash: hash,
		}
	}
	refs := []wire.DeviceConfigArtifactRefV1{
		configRef(wire.LinuxLinkIntentArtifactID, wire.LinuxLinkIntentRenderContract, 1, linkRaw),
		configRef(wire.LinuxRuntimeArtifactID, wire.LinuxRuntimeRenderContract, 1, runtimeRaw),
	}
	final := advanceClientEnvelopeWithArtifacts(t, current, &set, configKey,
		refs, []wire.SecretArtifactRefV2{secretRef})
	final.Payload.Active.Grants, final.Payload.Active.GrantsHash = grants, grantsHash
	final.Payload.Active.EndpointBundle = bundle
	final.Payload.Active.EndpointBundleHash, _ = wire.DeviceEndpointBundleHash(&bundle)
	resignRuntimeEnvelope(t, &final, &set, configKey)

	installed := make([]InstalledConfigV1, len(refs))
	for index, ref := range refs {
		raw := linkRaw
		if ref.ArtifactID == wire.LinuxRuntimeArtifactID {
			raw = runtimeRaw
		}
		installed[index] = InstalledConfigV1{
			ArtifactID: ref.ArtifactID, Generation: ref.Generation, Platform: ref.Platform,
			MediaType: ref.MediaType, RenderContractID: ref.RenderContractID,
			SizeBytes: ref.SizeBytes, ContentHash: ref.ContentHash, Config: json.RawMessage(raw),
		}
	}
	_, wrappingPrivate, err := identity.keys()
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := installLinuxSecrets([]wire.SecretArtifactRefV2{secretRef},
		[]wire.SealedSecretEnvelopeV1{sealed}, current.Payload.DeviceID,
		identity.WrappingPublicKeySPKI, wrappingPrivate)
	if err != nil {
		t.Fatal(err)
	}
	delivery := wire.DeviceConfigDeliveryV1{
		Schema: 1, ClusterID: set.ClusterID, DeviceID: current.Payload.DeviceID,
		Updates: []wire.DeviceConfigUpdateV1{
			{Schema: 1, Envelope: current, ControlSet: set},
			{Schema: 1, Envelope: final, ControlSet: set},
		},
		SecretEnvelopes: []wire.SealedSecretEnvelopeV1{sealed},
	}
	store, err := Open(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AcceptDeviceConfigDeliveryWithArtifacts(&delivery, nil, nil,
		current.Payload.DeviceID, current.Payload.Active.IdentitySPKIHash, &installed, &credentials); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Dir(statePath)
	runtimeStatePath := filepath.Join(directory, "link-runtime-state.json")
	if _, err := AcceptLinuxLinkRuntimePlan(runtimeStatePath, statePath, &final, nil,
		nil, nil, linkRaw, now); err != nil {
		t.Fatal(err)
	}
	return statePath, runtimeStatePath, filepath.Join(directory, LinuxRuntimeInstallStateName),
		linkRaw, runtimeRaw
}

func mustLinuxRuntimeJSON(t *testing.T, value any) string {
	t.Helper()
	body, err := wire.MarshalCanonical(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}
