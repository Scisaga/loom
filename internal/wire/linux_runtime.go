package wire

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"unicode/utf8"

	"loom/internal/model"
	"loom/internal/secret"
)

const (
	LinuxRuntimeArtifactID        = "linux-runtime"
	LinuxRuntimeRenderContract    = "linux-runtime-v1"
	maximumLinuxRuntimeFiles      = 64
	maximumLinuxRuntimeBindings   = 256
	maximumLinuxRuntimeFileBytes  = 4 << 20
	maximumLinuxRuntimeTotalBytes = 16 << 20
)

// LinuxRuntimeBindingV1 把一个已认证 LinkIntent action 绑定到 renderer
// 中的 exact runtime entry。dial binding 逐项覆盖 EndpointSet 当前可拨代；
// listen binding 的 EndpointID 则是 listener resource ref。
type LinuxRuntimeBindingV1 struct {
	LinkID             string `json:"link_id"`
	LinkGeneration     int64  `json:"link_generation"`
	Mode               string `json:"mode"`
	Transport          string `json:"transport"`
	EndpointID         string `json:"endpoint_id"`
	ListenerGeneration int64  `json:"listener_generation"`
	ConfigPath         string `json:"config_path"`
	RuntimeTag         string `json:"runtime_tag,omitempty"`
}

type LinuxRuntimeFileV1 struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

// LinuxRuntimeArtifactV1 只包含无秘密 renderer output；秘密仍由同一
// Device view 中的 sealed refs 单独交付并在 Linux 节点 hydrate。
type LinuxRuntimeArtifactV1 struct {
	Schema                int                     `json:"schema"`
	ClusterID             string                  `json:"cluster_id"`
	DeviceID              string                  `json:"device_id"`
	DeviceGeneration      int64                   `json:"device_generation"`
	Generation            int64                   `json:"generation"`
	LinkIntentGeneration  int64                   `json:"link_intent_generation"`
	LinkIntentContentHash string                  `json:"link_intent_content_hash"`
	Bindings              []LinuxRuntimeBindingV1 `json:"bindings"`
	Files                 []LinuxRuntimeFileV1    `json:"files"`
}

func ValidateLinuxRuntimeArtifact(artifact *LinuxRuntimeArtifactV1) error {
	if artifact == nil || artifact.Schema != 1 || artifact.Generation < 1 ||
		artifact.DeviceGeneration < 1 || artifact.LinkIntentGeneration < 1 ||
		!validIdentifier(artifact.ClusterID, 128) || !validIdentifier(artifact.DeviceID, 128) ||
		artifact.Bindings == nil || artifact.Files == nil ||
		len(artifact.Bindings) > maximumLinuxRuntimeBindings || len(artifact.Files) > maximumLinuxRuntimeFiles {
		return errors.New("[Linux runtime] runtime artifact header/count 无效")
	}
	if _, err := ParseHash(artifact.LinkIntentContentHash); err != nil {
		return err
	}
	total := 0
	for index := range artifact.Files {
		file := &artifact.Files[index]
		if !validLinuxRuntimeFilePath(file.Path) || file.Content == "" ||
			len(file.Content) > maximumLinuxRuntimeFileBytes || !utf8.ValidString(file.Content) ||
			strings.IndexByte(file.Content, 0) >= 0 ||
			(index > 0 && artifact.Files[index-1].Path >= file.Path) {
			return errors.New("[Linux runtime] runtime files 路径/内容/顺序无效")
		}
		total += len(file.Content)
		if total > maximumLinuxRuntimeTotalBytes {
			return errors.New("[Linux runtime] runtime files 超过总预算")
		}
	}
	for index := range artifact.Bindings {
		binding := &artifact.Bindings[index]
		if !validIdentifier(binding.LinkID, 128) || binding.LinkGeneration < 1 ||
			!oneOf(binding.Mode, "dial", "listen") ||
			!oneOf(binding.Transport, "wireguard", "hysteria2", "trojan_tls") ||
			!validIdentifier(binding.EndpointID, 128) ||
			(binding.Mode == "dial" && binding.ListenerGeneration < 1) ||
			(binding.Mode == "listen" && binding.ListenerGeneration != 0) ||
			!validLinuxRuntimeBindingTarget(binding) ||
			(index > 0 && linuxRuntimeBindingKey(artifact.Bindings[index-1]) >= linuxRuntimeBindingKey(*binding)) {
			return errors.New("[Linux runtime] runtime bindings 字段/顺序无效")
		}
	}
	return nil
}

// ValidateLinuxRuntimeRedaction 保证公开 runtime artifact 只引用该 Device
// LinkIntent 已授权的 secrets，且常见敏感字段不能携带明文。客户端在 hydrate
// 前重复执行同一检查，避免只依赖 producer 的诚实实现。
func ValidateLinuxRuntimeRedaction(runtime *LinuxRuntimeArtifactV1,
	links *LinuxLinkIntentArtifactV1,
) error {
	if err := ValidateLinuxRuntimeArtifact(runtime); err != nil {
		return err
	}
	if err := ValidateLinuxLinkIntentArtifact(links); err != nil {
		return err
	}
	allowed := make(map[string]bool)
	if links.LocalRuntime != nil {
		for _, ref := range links.LocalRuntime.CredentialRefs {
			allowed[ref] = true
		}
	}
	for _, intent := range links.LinkIntents {
		for _, ref := range intent.CredentialRefs {
			allowed[ref] = true
		}
	}
	referenced := make(map[string]bool)
	for _, file := range runtime.Files {
		for _, ref := range secret.Refs(file.Content) {
			if !allowed[ref] {
				return errors.New("[Linux runtime] public runtime 引用未获 LinkIntent 授权的 secret")
			}
			referenced[ref] = true
		}
		if err := validateLinuxRuntimeRedactedFile(file); err != nil {
			return err
		}
	}
	if len(referenced) != len(allowed) {
		return errors.New("[Linux runtime] public runtime 未 exact 引用 LinkIntent credentials")
	}
	return nil
}

func validateLinuxRuntimeRedactedFile(file LinuxRuntimeFileV1) error {
	if strings.HasSuffix(file.Path, ".json") {
		canonical, err := NormalizeRuntimeJSON([]byte(file.Content))
		var object map[string]any
		if err != nil || !bytes.Equal(canonical, []byte(file.Content)) ||
			json.Unmarshal([]byte(file.Content), &object) != nil || object == nil {
			return errors.New("[Linux runtime] public runtime config 不是 exact JSON object")
		}
		return validateLinuxRuntimeJSONSecrets(object)
	}
	for _, raw := range strings.Split(strings.TrimSuffix(file.Content, "\n"), "\n") {
		key, value, found := strings.Cut(raw, "=")
		if !found {
			continue
		}
		key, value = strings.ToLower(strings.TrimSpace(key)), strings.TrimSpace(value)
		if (key == "privatekey" || key == "presharedkey") && !exactLinuxRuntimeSecretRef(value) {
			return errors.New("[Linux runtime] WireGuard private material 必须是 secret ref")
		}
		if strings.Contains(value, "${secret:") && !exactLinuxRuntimeSecretRef(value) {
			return errors.New("[Linux runtime] WireGuard secret ref 必须占满字段")
		}
	}
	return nil
}

// ValidatePublicRuntimeJSON 检查各客户端公开配置共用的秘密占位边界。
// 它只检查公开编码；宿主仍须在验签和解封后验证运行语义。
func ValidatePublicRuntimeJSON(raw []byte) error {
	return validateLinuxRuntimeRedactedFile(LinuxRuntimeFileV1{Path: "config.json", Content: string(raw)})
}

func validateLinuxRuntimeJSONSecrets(value any) error {
	switch current := value.(type) {
	case map[string]any:
		for key, child := range current {
			if linuxRuntimeSensitiveJSONKey(key) {
				text, ok := child.(string)
				if !ok || !exactLinuxRuntimeSecretRef(text) {
					return errors.New("[Linux runtime] public runtime 敏感字段必须是 secret ref")
				}
			}
			if err := validateLinuxRuntimeJSONSecrets(child); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range current {
			if err := validateLinuxRuntimeJSONSecrets(child); err != nil {
				return err
			}
		}
	case string:
		if strings.Contains(current, "${secret:") && !exactLinuxRuntimeSecretRef(current) {
			return errors.New("[Linux runtime] JSON secret ref 必须占满字段")
		}
	}
	return nil
}

func linuxRuntimeSensitiveJSONKey(key string) bool {
	key = strings.ToLower(key)
	return key == "password" || strings.HasSuffix(key, "_password") ||
		key == "secret" || strings.HasSuffix(key, "_secret") ||
		key == "private_key" || key == "preshared_key" ||
		key == "token" || strings.HasSuffix(key, "_token")
}

func exactLinuxRuntimeSecretRef(value string) bool {
	refs := secret.Refs(value)
	return len(refs) == 1 && value == "${secret:"+refs[0]+"}"
}

func linuxRuntimeBindingKey(binding LinuxRuntimeBindingV1) string {
	return binding.LinkID + "\x00" + binding.EndpointID + "\x00" +
		leftPadDecimal(binding.ListenerGeneration, 20) + "\x00" + binding.Transport + "\x00" +
		binding.ConfigPath + "\x00" + binding.RuntimeTag
}

func leftPadDecimal(value int64, width int) string {
	digits := "0"
	if value > 0 {
		digits = ""
		for ; value > 0; value /= 10 {
			digits = string(byte('0'+value%10)) + digits
		}
	}
	return strings.Repeat("0", width-len(digits)) + digits
}

func validLinuxRuntimeBindingTarget(binding *LinuxRuntimeBindingV1) bool {
	if binding.Transport == "wireguard" {
		if binding.ConfigPath == "sing-box/v2/config.json" && strings.HasPrefix(binding.RuntimeTag, "device-control-") && validIdentifier(binding.RuntimeTag, 128) {
			return true
		}
		return binding.RuntimeTag == "" && validLinuxWireGuardConfigPath(binding.ConfigPath)
	}
	return binding.ConfigPath == "sing-box/v2/config.json" && validIdentifier(binding.RuntimeTag, 128)
}

func validLinuxRuntimeFilePath(path string) bool {
	return path == "sing-box/v2/config.json" || path == "agent/v2/config.json" || path == "report/v2/config.json" ||
		validLinuxWireGuardConfigPath(path)
}

func validLinuxWireGuardConfigPath(path string) bool {
	if strings.HasPrefix(path, "wireguard/wg-") && strings.HasSuffix(path, ".conf") {
		peer := strings.TrimSuffix(strings.TrimPrefix(path, "wireguard/wg-"), ".conf")
		return model.ValidNodeID(peer) && len(model.IfaceName(peer)) <= 15
	}
	const prefix = "wireguard/lmv2-"
	const suffix = ".conf"
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
