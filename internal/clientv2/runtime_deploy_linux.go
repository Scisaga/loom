//go:build linux

package clientv2

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"unicode/utf8"

	"loom/internal/agent"
	"loom/internal/deploy"
	"loom/internal/render"
	"loom/internal/secret"
	"loom/internal/wire"
)

const (
	LinuxRuntimeInstallStateName         = "runtime-install-state.json"
	maximumLinuxRuntimeInstallStateBytes = 4 << 20
	linuxV2SingBoxConfigPath             = "/etc/loom/sing-box/v2/config.json"
	linuxV2AgentConfigPath               = "/etc/loom/agent/v2/config.json"
	linuxV2SingBoxUnitPath               = "/etc/systemd/system/loom-client-v2-sing-box.service"
	linuxV2AgentUnitPath                 = "/etc/systemd/system/loom-client-v2-agent.service"
)

type LinuxRuntimeInstallStateV1 struct {
	Schema                int                 `json:"schema"`
	ClusterID             string              `json:"cluster_id"`
	DeviceID              string              `json:"device_id"`
	AuthorityFloors       wire.ClientFloorsV2 `json:"authority_floors"`
	RuntimePlanHash       string              `json:"runtime_plan_hash"`
	RuntimeArtifactHash   string              `json:"runtime_artifact_hash"`
	LinkIntentContentHash string              `json:"link_intent_content_hash"`
	InstalledFiles        []string            `json:"installed_files"`
}

// PrepareLinuxRuntimeDeployment 从同一 durable Device LKG、已验收 runtime
// plan 和 Device view 承诺的 runtime artifact 生成本机 deploy transaction。
// 返回值尚未修改网络；调用方必须使用 deploy.Script 执行其原子预检/回滚边界。
func PrepareLinuxRuntimeDeployment(installStatePath, deviceStatePath, runtimeStatePath string,
	linkIntentRaw, runtimeRaw []byte,
) (*deploy.Plan, error) {
	if runtimeStatePath == "" || validateLinuxRuntimeInstallPaths(installStatePath, deviceStatePath) != nil {
		return nil, errors.New("[Linux runtime] install/device/runtime state path 无效")
	}
	if err := secureEnrollmentDirectory(filepath.Dir(installStatePath)); err != nil {
		return nil, err
	}
	deviceStore, err := Open(deviceStatePath)
	if err != nil {
		return nil, err
	}
	envelope := deviceStore.Envelope()
	installation := deviceStore.Installation()
	if envelope == nil || installation == nil || envelope.Payload.State != "active" || envelope.Payload.Active == nil {
		return nil, errors.New("[Linux runtime] active durable Device installation 缺失")
	}
	runtimeState, err := LoadLinuxLinkRuntimeState(runtimeStatePath)
	if err != nil {
		return nil, err
	}
	if runtimeState.ClusterID != envelope.Payload.ClusterID || runtimeState.DeviceID != envelope.Payload.DeviceID ||
		!wire.EqualCanonical(runtimeState.AuthorityFloors, deviceStore.Floors()) {
		return nil, errors.New("[Linux runtime] runtime plan 不是 current Device LKG")
	}

	var linkArtifact wire.LinuxLinkIntentArtifactV1
	canonical, err := wire.DecodeStrict(linkIntentRaw, 4<<20, &linkArtifact)
	if err != nil || !bytes.Equal(canonical, linkIntentRaw) ||
		validateLinuxLinkIntentArtifact(&linkArtifact, envelope) != nil ||
		bindLinuxLinkIntentArtifactRef(&linkArtifact, linkIntentRaw, envelope.Payload.Active.ConfigArtifactRefs) != nil {
		return nil, errors.New("[Linux runtime] deploy 未绑定 current exact LinkIntent artifact")
	}
	linkHash, err := wire.DeviceConfigArtifactContentHash(linkIntentRaw)
	if err != nil {
		return nil, err
	}
	var runtimeArtifact wire.LinuxRuntimeArtifactV1
	canonical, err = wire.DecodeStrict(runtimeRaw, maximumLinuxConfigArtifact, &runtimeArtifact)
	if err != nil || !bytes.Equal(canonical, runtimeRaw) || wire.ValidateLinuxRuntimeArtifact(&runtimeArtifact) != nil {
		return nil, errors.New("[Linux runtime] runtime artifact 不是 exact canonical wire")
	}
	if runtimeArtifact.ClusterID != runtimeState.ClusterID || runtimeArtifact.DeviceID != runtimeState.DeviceID ||
		runtimeArtifact.DeviceGeneration != runtimeState.Plan.DeviceGeneration ||
		runtimeArtifact.LinkIntentGeneration != runtimeState.Plan.ArtifactGeneration ||
		runtimeArtifact.LinkIntentContentHash != linkHash {
		return nil, errors.New("[Linux runtime] runtime artifact 与 accepted plan/LinkIntent 不一致")
	}
	if err := wire.ValidateLinuxRuntimeRedaction(&runtimeArtifact, &linkArtifact); err != nil {
		return nil, err
	}
	if err := bindLinuxRuntimeArtifactRef(&runtimeArtifact, runtimeRaw,
		envelope.Payload.Active.ConfigArtifactRefs); err != nil {
		return nil, err
	}
	if err := validateLinuxRuntimeBindings(&runtimeState.Plan, &runtimeArtifact); err != nil {
		return nil, err
	}

	files, err := hydrateLinuxRuntimeFiles(&runtimeState.Plan, &runtimeArtifact, installation.Credentials)
	if err != nil {
		return nil, err
	}
	plan, installedFiles, err := linuxRuntimeDeployPlan(runtimeState.DeviceID, files)
	if err != nil {
		return nil, err
	}
	runtimeHash, err := wire.DeviceConfigArtifactContentHash(runtimeRaw)
	if err != nil {
		return nil, err
	}
	next := LinuxRuntimeInstallStateV1{
		Schema: 1, ClusterID: runtimeState.ClusterID, DeviceID: runtimeState.DeviceID,
		AuthorityFloors: runtimeState.AuthorityFloors, RuntimePlanHash: runtimeState.PlanHash,
		RuntimeArtifactHash: runtimeHash, LinkIntentContentHash: linkHash, InstalledFiles: installedFiles,
	}
	if err := validateLinuxRuntimeInstallState(&next); err != nil {
		return nil, err
	}
	nextBody, err := wire.MarshalCanonical(next)
	if err != nil {
		return nil, err
	}

	previous, previousBody, err := readLinuxRuntimeInstallState(installStatePath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if previous != nil {
		if previous.ClusterID != next.ClusterID || previous.DeviceID != next.DeviceID {
			return nil, errors.New("[Linux runtime] installed runtime identity 分叉")
		}
		plan.Remove = staleLinuxRuntimeFiles(previous.InstalledFiles, installedFiles)
		sum := sha256.Sum256(previousBody)
		plan.InventoryGuard = &deploy.InventoryGuard{
			Path: installStatePath, SHA256: hex.EncodeToString(sum[:]),
		}
	} else {
		plan.InventoryGuard = &deploy.InventoryGuard{Path: installStatePath, Absent: true}
	}
	plan.Files[installStatePath] = string(nextBody)
	return plan, nil
}

// PrepareLinuxRuntimeDecommission 只接受 durable Device tombstone，并只删除
// 上一次 runtime install inventory 记录的固定 v2 文件及 inventory 自身。
// deploy.Script 会在同一 CAS/备份/回滚事务中先停 unit 再删除文件。
func PrepareLinuxRuntimeDecommission(installStatePath, deviceStatePath string) (*deploy.Plan, error) {
	if err := validateLinuxRuntimeInstallPaths(installStatePath, deviceStatePath); err != nil {
		return nil, err
	}
	if err := secureEnrollmentDirectory(filepath.Dir(installStatePath)); err != nil {
		return nil, err
	}
	deviceStore, err := Open(deviceStatePath)
	if err != nil {
		return nil, err
	}
	envelope := deviceStore.Envelope()
	if envelope == nil || (envelope.Payload.State != "revoked" && envelope.Payload.State != "decommissioned") ||
		envelope.Payload.Active != nil || envelope.Payload.Tombstone == nil {
		return nil, errors.New("[Linux runtime] 只有 certified Device tombstone 可触发 runtime 下线")
	}
	plan := &deploy.Plan{Node: envelope.Payload.DeviceID, Files: map[string]string{},
		Triggers: map[string][]string{}}
	previous, previousBody, err := readLinuxRuntimeInstallState(installStatePath)
	if errors.Is(err, os.ErrNotExist) {
		return plan, nil
	}
	if err != nil {
		return nil, err
	}
	if previous.ClusterID != envelope.Payload.ClusterID || previous.DeviceID != envelope.Payload.DeviceID ||
		validateLinuxRuntimeAuthorityAdvance(previous.AuthorityFloors, deviceStore.Floors()) != nil {
		return nil, errors.New("[Linux runtime] tombstone 与 installed runtime authority 分叉")
	}
	plan.Remove = append(append([]string(nil), previous.InstalledFiles...), installStatePath)
	sort.Strings(plan.Remove)
	sum := sha256.Sum256(previousBody)
	plan.InventoryGuard = &deploy.InventoryGuard{Path: installStatePath, SHA256: hex.EncodeToString(sum[:])}
	return plan, nil
}

// PrepareLinuxRuntimeLocalUninstall 为 root 发起的本机软件卸载生成与 certified
// tombstone 下线相同的 inventory/CAS 删除事务，但不把本机动作冒充控制面撤权。
// Device identity、正式 LKG、floors 和报告 journal 都不在 runtime inventory 中，
// 因而默认保留，重装后仍只能按当前 certified Device view 恢复。
func PrepareLinuxRuntimeLocalUninstall(installStatePath string) (*deploy.Plan, error) {
	if err := validateLinuxRuntimeInstallStatePath(installStatePath); err != nil {
		return nil, err
	}
	previous, previousBody, err := readLinuxRuntimeInstallState(installStatePath)
	if errors.Is(err, os.ErrNotExist) {
		return &deploy.Plan{Node: "linux-v2-local-uninstall", Files: map[string]string{},
			Triggers: map[string][]string{}}, nil
	}
	if err != nil {
		return nil, err
	}
	if err := secureEnrollmentDirectory(filepath.Dir(installStatePath)); err != nil {
		return nil, err
	}
	plan := &deploy.Plan{Node: previous.DeviceID, Files: map[string]string{},
		Triggers: map[string][]string{}}
	plan.Remove = append(append([]string(nil), previous.InstalledFiles...), installStatePath)
	sort.Strings(plan.Remove)
	sum := sha256.Sum256(previousBody)
	plan.InventoryGuard = &deploy.InventoryGuard{
		Path: installStatePath, SHA256: hex.EncodeToString(sum[:]),
	}
	return plan, nil
}

func validateLinuxRuntimeInstallPaths(installStatePath, deviceStatePath string) error {
	if deviceStatePath == "" || validateLinuxRuntimeInstallStatePath(installStatePath) != nil ||
		filepath.Dir(installStatePath) != filepath.Dir(deviceStatePath) ||
		!filepath.IsAbs(deviceStatePath) || filepath.Clean(deviceStatePath) != deviceStatePath {
		return errors.New("[Linux runtime] install/device state path 无效")
	}
	return nil
}

func validateLinuxRuntimeInstallStatePath(installStatePath string) error {
	if installStatePath == "" || filepath.Base(installStatePath) != LinuxRuntimeInstallStateName ||
		!filepath.IsAbs(installStatePath) || filepath.Clean(installStatePath) != installStatePath {
		return errors.New("[Linux runtime] install state path 无效")
	}
	return nil
}

func bindLinuxRuntimeArtifactRef(artifact *wire.LinuxRuntimeArtifactV1, raw []byte,
	refs []wire.DeviceConfigArtifactRefV1,
) error {
	hash, err := wire.DeviceConfigArtifactContentHash(raw)
	if err != nil {
		return err
	}
	matches := 0
	for _, ref := range refs {
		if ref.ArtifactID == wire.LinuxRuntimeArtifactID && ref.Generation > artifact.Generation {
			return errors.New("[Linux runtime] runtime artifact generation 低于 current Device view floor")
		}
		if ref.ArtifactID == wire.LinuxRuntimeArtifactID && ref.Generation == artifact.Generation &&
			ref.Platform == "linux-server" && ref.MediaType == "application/vnd.loom.config+json" &&
			ref.RenderContractID == wire.LinuxRuntimeRenderContract && ref.SizeBytes == int64(len(raw)) &&
			ref.ContentHash == hash {
			matches++
		}
	}
	if matches != 1 {
		return errors.New("[Linux runtime] runtime artifact 未被 current Device view exact ref 承诺")
	}
	return nil
}

func validateLinuxRuntimeBindings(plan *LinuxLinkRuntimePlanV1, artifact *wire.LinuxRuntimeArtifactV1) error {
	if plan == nil || artifact == nil {
		return errors.New("[Linux runtime] plan/artifact 缺失")
	}
	byLink := make(map[string][]wire.LinuxRuntimeBindingV1, len(plan.Actions))
	for _, binding := range artifact.Bindings {
		byLink[binding.LinkID] = append(byLink[binding.LinkID], binding)
	}
	usedPaths := make(map[string]bool)
	usedTags := make(map[string]bool)
	for _, action := range plan.Actions {
		bindings := byLink[action.LinkID]
		if len(bindings) == 0 {
			return errors.New("[Linux runtime] runtime artifact 未覆盖每条 accepted action")
		}
		if action.Mode == "dial" {
			if len(bindings) != len(action.DialCandidates) {
				return errors.New("[Linux runtime] dial bindings 未 exact 覆盖 generation candidates")
			}
			candidates := make(map[string]bool, len(action.DialCandidates))
			for _, candidate := range action.DialCandidates {
				candidates[linuxRuntimeEndpointKey(candidate.EndpointID, candidate.Transport,
					candidate.ListenerGeneration)] = true
			}
			for _, binding := range bindings {
				if binding.LinkGeneration != action.Generation || binding.Mode != action.Mode ||
					!candidates[linuxRuntimeEndpointKey(binding.EndpointID, binding.Transport,
						binding.ListenerGeneration)] {
					return errors.New("[Linux runtime] dial binding endpoint/generation 分叉")
				}
				delete(candidates, linuxRuntimeEndpointKey(binding.EndpointID, binding.Transport,
					binding.ListenerGeneration))
			}
			if len(candidates) != 0 {
				return errors.New("[Linux runtime] dial bindings 遗漏 generation candidate")
			}
		} else {
			seenRefs := make(map[string]bool)
			for _, binding := range bindings {
				if binding.LinkGeneration != action.Generation || binding.Mode != action.Mode ||
					binding.ListenerGeneration != 0 || !containsString(action.ListenerResourceRefs, binding.EndpointID) ||
					!containsString(action.AllowedTransports, binding.Transport) {
					return errors.New("[Linux runtime] listen binding 扩大 accepted action")
				}
				seenRefs[binding.EndpointID] = true
			}
			for _, ref := range action.ListenerResourceRefs {
				if !seenRefs[ref] {
					return errors.New("[Linux runtime] listen binding 未覆盖 listener resource")
				}
			}
		}
		for _, binding := range bindings {
			usedPaths[binding.ConfigPath] = true
			if binding.RuntimeTag != "" {
				if usedTags[binding.RuntimeTag] {
					return errors.New("[Linux runtime] runtime tag 被多个 binding 复用")
				}
				usedTags[binding.RuntimeTag] = true
			}
		}
		delete(byLink, action.LinkID)
	}
	if len(byLink) != 0 {
		return errors.New("[Linux runtime] runtime artifact 含未知 action binding")
	}
	files := make(map[string]string, len(artifact.Files))
	for _, file := range artifact.Files {
		files[file.Path] = file.Content
	}
	for path := range usedPaths {
		if _, found := files[path]; !found {
			return errors.New("[Linux runtime] binding 引用缺失 runtime file")
		}
	}
	for path := range files {
		if path == "agent/v2/config.json" || usedPaths[path] {
			continue
		}
		return errors.New("[Linux runtime] runtime artifact 含未绑定 config file")
	}
	if plan.EnableTUN || plan.EnableMixed {
		if _, found := files["sing-box/v2/config.json"]; !found {
			return errors.New("[Linux runtime] use_loom 缺 sing-box runtime")
		}
	}
	_, hasAgent := files["agent/v2/config.json"]
	if plan.EnableTUN || plan.EnableMixed {
		if !hasAgent {
			return errors.New("[Linux runtime] use_loom 缺 Linux Agent plan")
		}
	} else if hasAgent {
		return errors.New("[Linux runtime] 非 use_loom runtime 不应启动 Linux Agent")
	}
	return nil
}

func linuxRuntimeEndpointKey(endpointID, transport string, generation int64) string {
	return endpointID + "\x00" + transport + "\x00" + strconv.FormatInt(generation, 10)
}

func hydrateLinuxRuntimeFiles(plan *LinuxLinkRuntimePlanV1, artifact *wire.LinuxRuntimeArtifactV1,
	credentials []InstalledSecretV1,
) (map[string]string, error) {
	required := make(map[string]bool)
	for _, action := range plan.Actions {
		for _, ref := range action.CredentialRefs {
			required[ref] = true
		}
	}
	referenced := make(map[string]bool)
	for _, file := range artifact.Files {
		for _, ref := range secret.Refs(file.Content) {
			if !required[ref] {
				return nil, errors.New("[Linux runtime] runtime file 引用了未获 LinkIntent 授权的 secret")
			}
			referenced[ref] = true
		}
	}
	if len(referenced) != len(required) {
		return nil, errors.New("[Linux runtime] runtime files 未 exact 使用 LinkIntent credentials")
	}
	secrets := make(map[string]string, len(required))
	for _, credential := range credentials {
		if !required[credential.SecretID] {
			continue
		}
		if credential.Purpose != "data_plane_credential" && credential.Purpose != "tls_private_key" &&
			credential.Purpose != "control_peer_identity" {
			return nil, errors.New("[Linux runtime] LinkIntent 引用了错误 purpose credential")
		}
		decoded, err := base64.RawURLEncoding.DecodeString(credential.SecretBytes)
		value := string(decoded)
		if err != nil || len(decoded) == 0 || !utf8.Valid(decoded) || strings.TrimSpace(value) != value ||
			strings.ContainsAny(value, "\x00\r\n") || base64.RawURLEncoding.EncodeToString(decoded) != credential.SecretBytes {
			clear(decoded)
			return nil, errors.New("[Linux runtime] credential 不是规范单行 UTF-8")
		}
		secrets[credential.SecretID] = value
		clear(decoded)
	}
	if len(secrets) != len(required) {
		return nil, errors.New("[Linux runtime] installed credentials 未覆盖 runtime refs")
	}
	hydrated := make(map[string]string, len(artifact.Files))
	for _, file := range artifact.Files {
		content, missing := secret.Hydrate(file.Content, secrets)
		if len(missing) != 0 || secret.HasPlaceholder(content) {
			return nil, errors.New("[Linux runtime] runtime file hydrate 后仍缺 secret")
		}
		switch file.Path {
		case "sing-box/v2/config.json", "agent/v2/config.json":
			canonical, err := wire.NormalizeRuntimeJSON([]byte(content))
			var object map[string]json.RawMessage
			if err != nil || !bytes.Equal(canonical, []byte(content)) ||
				json.Unmarshal([]byte(content), &object) != nil || object == nil {
				return nil, errors.New("[Linux runtime] hydrated runtime config 不是 strict JSON object")
			}
		default:
			if err := validateLinuxWireGuardConfig(content); err != nil {
				return nil, err
			}
		}
		hydrated[file.Path] = content
	}
	if err := validateLinuxRuntimeConfigSemantics(plan, artifact, hydrated); err != nil {
		return nil, err
	}
	return hydrated, nil
}

type linuxRuntimeSingBoxEntry struct {
	Type       string `json:"type"`
	Tag        string `json:"tag"`
	Server     string `json:"server,omitempty"`
	ServerPort int64  `json:"server_port,omitempty"`
	TLS        *struct {
		Enabled    bool   `json:"enabled"`
		ServerName string `json:"server_name,omitempty"`
	} `json:"tls,omitempty"`
}

type linuxRuntimeSingBoxConfig struct {
	Inbounds  []linuxRuntimeSingBoxEntry `json:"inbounds"`
	Outbounds []linuxRuntimeSingBoxEntry `json:"outbounds"`
}

func validateLinuxRuntimeConfigSemantics(plan *LinuxLinkRuntimePlanV1, artifact *wire.LinuxRuntimeArtifactV1,
	files map[string]string,
) error {
	var singbox linuxRuntimeSingBoxConfig
	if body, found := files["sing-box/v2/config.json"]; found {
		if err := json.Unmarshal([]byte(body), &singbox); err != nil {
			return errors.New("[Linux runtime] sing-box config 无效")
		}
	}
	inbounds, outbounds := make(map[string]linuxRuntimeSingBoxEntry), make(map[string]linuxRuntimeSingBoxEntry)
	inboundTypes := make(map[string]bool)
	for _, entry := range singbox.Inbounds {
		if entry.Tag == "" || inbounds[entry.Tag].Tag != "" {
			return errors.New("[Linux runtime] sing-box inbound tag 空或重复")
		}
		inbounds[entry.Tag] = entry
		inboundTypes[entry.Type] = true
	}
	for _, entry := range singbox.Outbounds {
		if entry.Tag == "" || outbounds[entry.Tag].Tag != "" {
			return errors.New("[Linux runtime] sing-box outbound tag 空或重复")
		}
		outbounds[entry.Tag] = entry
	}
	for _, binding := range artifact.Bindings {
		if binding.Transport == "wireguard" {
			if binding.Mode == "dial" {
				candidate, found := linuxRuntimeCandidate(plan, binding)
				if !found || !wireGuardConfigMatchesEndpoint(files[binding.ConfigPath], candidate) {
					return errors.New("[Linux runtime] WireGuard config 未绑定 dial endpoint generation")
				}
			}
			continue
		}
		entry, found := inbounds[binding.RuntimeTag]
		if binding.Mode == "dial" {
			entry, found = outbounds[binding.RuntimeTag]
		}
		if !found || entry.Type != strings.ReplaceAll(binding.Transport, "_tls", "") {
			return errors.New("[Linux runtime] sing-box entry 未绑定 action transport/tag")
		}
		if binding.Mode == "dial" {
			candidate, found := linuxRuntimeCandidate(plan, binding)
			if !found || entry.Server != candidate.DialTargetFQDN || entry.ServerPort != candidate.PublicPort ||
				entry.TLS == nil || !entry.TLS.Enabled || entry.TLS.ServerName != candidate.DialTargetFQDN {
				return errors.New("[Linux runtime] sing-box outbound 未绑定 certified FQDN/port/TLS generation")
			}
		}
	}
	if plan.EnableTUN && !inboundTypes["tun"] {
		return errors.New("[Linux runtime] use_loom TUN plan 缺 tun inbound")
	}
	if plan.EnableMixed && !inboundTypes["mixed"] {
		return errors.New("[Linux runtime] use_loom mixed plan 缺 mixed inbound")
	}
	if body, found := files["agent/v2/config.json"]; found {
		config, err := agent.Load([]byte(body))
		if err != nil || config.Node != plan.DeviceID {
			return errors.New("[Linux runtime] Linux Agent config 未绑定本 Device")
		}
	}
	return nil
}

func linuxRuntimeCandidate(plan *LinuxLinkRuntimePlanV1,
	binding wire.LinuxRuntimeBindingV1,
) (LinuxLinkDialCandidateV1, bool) {
	for _, action := range plan.Actions {
		if action.LinkID != binding.LinkID {
			continue
		}
		for _, candidate := range action.DialCandidates {
			if candidate.EndpointID == binding.EndpointID && candidate.Transport == binding.Transport &&
				candidate.ListenerGeneration == binding.ListenerGeneration {
				return candidate, true
			}
		}
	}
	return LinuxLinkDialCandidateV1{}, false
}

func validateLinuxWireGuardConfig(content string) error {
	if len(content) == 0 || !strings.HasSuffix(content, "\n") {
		return errors.New("[Linux runtime] WireGuard config 必须是有界换行文本")
	}
	hasInterface, hasPrivateKey, hasPeer, peerHasPublicKey := false, false, false, false
	section := ""
	for _, raw := range strings.Split(strings.TrimSuffix(content, "\n"), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		switch line {
		case "[Interface]":
			if hasInterface || hasPeer {
				return errors.New("[Linux runtime] WireGuard Interface section 重复或乱序")
			}
			hasInterface = true
			section = "interface"
			continue
		case "[Peer]":
			if !hasInterface || hasPeer && !peerHasPublicKey {
				return errors.New("[Linux runtime] WireGuard Peer 缺 PublicKey")
			}
			hasPeer = true
			peerHasPublicKey = false
			section = "peer"
			continue
		}
		key, _, found := strings.Cut(line, "=")
		if !found || section == "" {
			return errors.New("[Linux runtime] WireGuard config 行无效")
		}
		switch key := strings.ToLower(strings.TrimSpace(key)); key {
		case "preup", "postup", "predown", "postdown", "saveconfig":
			return errors.New("[Linux runtime] WireGuard config 禁止执行 hook/saveconfig")
		case "privatekey":
			if section != "interface" || hasPrivateKey {
				return errors.New("[Linux runtime] WireGuard PrivateKey section/数量无效")
			}
			hasPrivateKey = true
		case "publickey":
			if section != "peer" || peerHasPublicKey {
				return errors.New("[Linux runtime] WireGuard PublicKey section/数量无效")
			}
			peerHasPublicKey = true
		}
	}
	if !hasInterface || !hasPrivateKey || !hasPeer || !peerHasPublicKey {
		return errors.New("[Linux runtime] WireGuard config 缺 Interface/PrivateKey/Peer/PublicKey")
	}
	return nil
}

func wireGuardConfigMatchesEndpoint(content string, candidate LinuxLinkDialCandidateV1) bool {
	want := candidate.DialTargetFQDN + ":" + strconv.FormatInt(candidate.PublicPort, 10)
	for _, line := range strings.Split(content, "\n") {
		key, value, found := strings.Cut(line, "=")
		if found && strings.EqualFold(strings.TrimSpace(key), "Endpoint") && strings.TrimSpace(value) == want {
			return true
		}
	}
	return false
}

func linuxRuntimeDeployPlan(deviceID string, hydrated map[string]string) (*deploy.Plan, []string, error) {
	plan := &deploy.Plan{Node: deviceID, Files: map[string]string{}, Triggers: map[string][]string{}}
	wgUnits := make([]string, 0)
	for path, content := range hydrated {
		absolute := render.InstallPath(path)
		if absolute == "" || !linuxV2RuntimeTarget(path, absolute) {
			return nil, nil, errors.New("[Linux runtime] runtime config 目标路径越界")
		}
		plan.Files[absolute] = content
		switch path {
		case "sing-box/v2/config.json":
			plan.Triggers[absolute] = []string{"loom-client-v2-sing-box"}
			plan.PreCheck = append(plan.PreCheck, "/usr/local/bin/sing-box check -c "+linuxRuntimeStagingPath(absolute))
		case "agent/v2/config.json":
			plan.Triggers[absolute] = []string{"loom-client-v2-agent"}
		default:
			unit := "wg-quick@" + strings.TrimSuffix(filepath.Base(path), ".conf")
			plan.Triggers[absolute] = []string{unit}
			plan.PreCheck = append(plan.PreCheck, linuxWireGuardPreCheck(absolute))
			wgUnits = append(wgUnits, unit)
		}
	}
	sort.Strings(wgUnits)
	plan.Verify = append(plan.Verify, wgUnits...)
	if _, found := plan.Files[linuxV2SingBoxConfigPath]; found {
		plan.Files[linuxV2SingBoxUnitPath] = linuxV2SingBoxUnit(wgUnits)
		plan.Triggers[linuxV2SingBoxUnitPath] = []string{"loom-client-v2-sing-box"}
		plan.Verify = append(plan.Verify, "loom-client-v2-sing-box")
	}
	if _, found := plan.Files[linuxV2AgentConfigPath]; found {
		plan.Files[linuxV2AgentUnitPath] = linuxV2AgentUnit
		plan.Triggers[linuxV2AgentUnitPath] = []string{"loom-client-v2-agent"}
		plan.Verify = append(plan.Verify, "loom-client-v2-agent")
	}
	sort.Strings(plan.PreCheck)
	installed := make([]string, 0, len(plan.Files))
	for path := range plan.Files {
		installed = append(installed, path)
	}
	sort.Strings(installed)
	return plan, installed, nil
}

func linuxV2RuntimeTarget(relative, absolute string) bool {
	if relative == "sing-box/v2/config.json" {
		return absolute == linuxV2SingBoxConfigPath
	}
	if relative == "agent/v2/config.json" {
		return absolute == linuxV2AgentConfigPath
	}
	return strings.HasPrefix(relative, "wireguard/lmv2-") &&
		absolute == "/etc/wireguard/"+strings.TrimPrefix(relative, "wireguard/")
}

func linuxRuntimeStagingPath(absolute string) string {
	return deploy.StagingRoot + strings.ReplaceAll(strings.TrimPrefix(absolute, "/"), "/", "%")
}

// wg-quick derives the interface name from the config basename even in strip
// mode. The deploy transaction intentionally flattens staged absolute paths
// with '%' separators, so passing that encoded filename directly makes every
// valid Loom interface fail the 15-byte Linux name check. A stage-local alias
// preserves the certified basename; the deploy lock serializes creation and
// the transaction cleanup removes the alias on both success and rollback.
func linuxWireGuardPreCheck(absolute string) string {
	staged := linuxRuntimeStagingPath(absolute)
	alias := deploy.StagingRoot + filepath.Base(absolute)
	return "/bin/ln -s " + staged + " " + alias + " && /usr/bin/wg-quick strip " + alias
}

func linuxV2SingBoxUnit(wgUnits []string) string {
	dependencies := ""
	if len(wgUnits) != 0 {
		units := make([]string, len(wgUnits))
		for index, unit := range wgUnits {
			units[index] = unit + ".service"
		}
		dependencies = "After=" + strings.Join(units, " ") + "\nWants=" + strings.Join(units, " ") + "\n"
	}
	return `[Unit]
Description=Loom v2 certified Linux data plane
After=network-online.target
Wants=network-online.target
` + dependencies + `
[Service]
Type=simple
ExecStart=/usr/local/bin/sing-box run -c /etc/loom/sing-box/v2/config.json
Restart=on-failure
RestartSec=5s
UMask=0077
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
`
}

const linuxV2AgentUnit = `[Unit]
Description=Loom v2 certified Linux route agent
After=loom-client-v2-sing-box.service
Requires=loom-client-v2-sing-box.service

[Service]
Type=simple
ExecStart=/usr/local/bin/loom agent -c /etc/loom/agent/v2/config.json -m /var/lib/loom/client-v2/measurements.jsonl -events /var/lib/loom/client-v2/events.jsonl
Restart=on-failure
RestartSec=5s
UMask=0077
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
`

func staleLinuxRuntimeFiles(previous, current []string) []string {
	present := make(map[string]bool, len(current))
	for _, path := range current {
		present[path] = true
	}
	stale := make([]string, 0)
	for _, path := range previous {
		if !present[path] {
			stale = append(stale, path)
		}
	}
	sort.Strings(stale)
	return stale
}

func readLinuxRuntimeInstallState(path string) (*LinuxRuntimeInstallStateV1, []byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o600 ||
		info.Size() < 1 || info.Size() > maximumLinuxRuntimeInstallStateBytes {
		return nil, nil, errors.New("[Linux runtime] install state 必须是 0600 有界普通文件")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || int(stat.Uid) != os.Geteuid() {
		return nil, nil, errors.New("[Linux runtime] install state owner 无效")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	var state LinuxRuntimeInstallStateV1
	canonical, err := wire.DecodeStrict(body, maximumLinuxRuntimeInstallStateBytes, &state)
	if err != nil || !bytes.Equal(canonical, body) || validateLinuxRuntimeInstallState(&state) != nil {
		return nil, nil, errors.New("[Linux runtime] install state 不是 exact canonical LKG")
	}
	return &state, body, nil
}

func validateLinuxRuntimeInstallState(state *LinuxRuntimeInstallStateV1) error {
	if state == nil || state.Schema != 1 || state.ClusterID == "" || state.DeviceID == "" ||
		!state.AuthorityFloors.V2Latched || state.AuthorityFloors.ClusterID != state.ClusterID ||
		state.InstalledFiles == nil {
		return errors.New("[Linux runtime] install state header/floors 无效")
	}
	if _, err := wire.AdvanceFloors(wire.ClientFloorsV2{}, state.AuthorityFloors); err != nil {
		return errors.New("[Linux runtime] install state floors wire 无效")
	}
	for _, hash := range []string{state.RuntimePlanHash, state.RuntimeArtifactHash, state.LinkIntentContentHash} {
		if _, err := wire.ParseHash(hash); err != nil {
			return err
		}
	}
	for index, path := range state.InstalledFiles {
		if !validLinuxV2InstalledPath(path) || index > 0 && state.InstalledFiles[index-1] >= path {
			return errors.New("[Linux runtime] installed file inventory 越界/未排序")
		}
	}
	return nil
}

func validLinuxV2InstalledPath(path string) bool {
	if path == linuxV2SingBoxConfigPath || path == linuxV2AgentConfigPath ||
		path == linuxV2SingBoxUnitPath || path == linuxV2AgentUnitPath {
		return true
	}
	const prefix, suffix = "/etc/wireguard/lmv2-", ".conf"
	if !strings.HasPrefix(path, prefix) || !strings.HasSuffix(path, suffix) {
		return false
	}
	id := strings.TrimSuffix(strings.TrimPrefix(path, prefix), suffix)
	if len(id) != 10 {
		return false
	}
	for _, character := range []byte(id) {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}
