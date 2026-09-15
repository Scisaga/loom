package loomcore

import (
	"encoding/base64"
	"errors"
	"sort"
	"strings"
	"unicode/utf8"

	"loom/internal/wire"
)

const (
	androidRuntimeArtifactID       = "android-runtime"
	androidRuntimeRenderContractID = "android-runtime-v1"
)

type preparedAndroidV2Runtime struct {
	Schema           int    `json:"schema"`
	DeviceID         string `json:"device_id"`
	HeadHash         string `json:"head_hash"`
	DeviceGeneration int64  `json:"device_generation"`
	SingBoxConfig    string `json:"sing_box_config"`
	RoutePlan        string `json:"route_plan,omitempty"`
}

// PrepareAndroidV2Runtime 只从已原子安装且重新校验的 Device state
// 生成内存态 libbox 运行投影。它不持久 hydrate 后的秘密，也不会把
// 旧 v1 current 当成 v2 latch 的回退配置（Issue #14）。
func PrepareAndroidV2Runtime(stateJSON []byte) ([]byte, error) {
	state, err := decodeAndroidV2DeviceState(stateJSON)
	if err != nil {
		return nil, err
	}
	if state.ControlSet == nil || state.material() == nil || state.material().Configs == nil ||
		state.Envelope.Payload.State != "active" || state.Envelope.Payload.Active == nil ||
		!containsAndroidString(state.Envelope.Payload.Active.Responsibilities.Values, "use_loom") {
		return nil, errors.New("[Android runtime] active Device/ControlSet/installation 不完整")
	}
	installed, err := selectAndroidRuntimeConfig(state.material().Configs)
	if err != nil {
		return nil, err
	}
	secrets, err := androidRuntimeSecrets(state.material().Credentials)
	if err != nil {
		return nil, err
	}
	preparedJSON, err := PrepareAndroidRuntime(installed.Config, secrets)
	clear(secrets)
	if err != nil {
		return nil, err
	}
	var prepared preparedAndroidRuntime
	if err := decodeStrictJSON(preparedJSON, androidMaximumConfigArtifactBytes, &prepared); err != nil {
		return nil, err
	}
	if prepared.Schema != 1 {
		return nil, errors.New("[Android runtime] prepared runtime schema 无效")
	}
	if prepared.RoutePlan == "" {
		return nil, errors.New("[Android runtime] android-runtime 缺移动 route plan")
	}
	if err := ValidateAndroidV2RuntimeHost([]byte(prepared.SingBoxConfig)); err != nil {
		return nil, err
	}
	return wire.MarshalCanonical(preparedAndroidV2Runtime{
		Schema: 1, DeviceID: state.Envelope.Payload.DeviceID,
		HeadHash: state.Floors.HeadHash, DeviceGeneration: state.Floors.DeviceGeneration,
		SingBoxConfig: prepared.SingBoxConfig, RoutePlan: prepared.RoutePlan,
	})
}

func selectAndroidRuntimeConfig(configs []androidInstalledConfigV1) (*androidInstalledConfigV1, error) {
	var selected *androidInstalledConfigV1
	for index := range configs {
		candidate := &configs[index]
		if candidate.ArtifactID != androidRuntimeArtifactID {
			continue
		}
		if candidate.Platform != "android" ||
			candidate.MediaType != "application/vnd.loom.config+json" ||
			candidate.RenderContractID != androidRuntimeRenderContractID {
			return nil, errors.New("[Android runtime] android-runtime 制品合约无效")
		}
		if selected == nil || candidate.Generation > selected.Generation {
			selected = candidate
		}
	}
	if selected == nil {
		return nil, errors.New("[Android runtime] Device view 缺 android-runtime 制品")
	}
	return selected, nil
}

func androidRuntimeSecrets(credentials []androidInstalledSecretV1) ([]byte, error) {
	latest := make(map[string]androidInstalledSecretV1)
	for _, credential := range credentials {
		if credential.Purpose != "data_plane_credential" {
			continue
		}
		previous, found := latest[credential.SecretID]
		if !found || credential.Generation > previous.Generation {
			latest[credential.SecretID] = credential
		}
	}
	if len(latest) == 0 {
		return nil, errors.New("[Android runtime] 缺 data_plane_credential")
	}
	ids := make([]string, 0, len(latest))
	for id := range latest {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var builder strings.Builder
	for _, id := range ids {
		decoded, err := base64.RawURLEncoding.DecodeString(latest[id].SecretBytes)
		value := string(decoded)
		if err != nil || !utf8.Valid(decoded) || value == "" || strings.TrimSpace(value) != value ||
			strings.ContainsAny(value, "\x00\r\n") {
			clear(decoded)
			return nil, errors.New("[Android runtime] data plane credential 不是规范单行 UTF-8")
		}
		builder.WriteString(id)
		builder.WriteByte('=')
		builder.Write(decoded)
		builder.WriteByte('\n')
		clear(decoded)
	}
	return []byte(builder.String()), nil
}

func containsAndroidString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
