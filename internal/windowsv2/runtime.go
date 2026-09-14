package windowsv2

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"unicode/utf8"

	"loom/internal/secret"
	"loom/internal/wire"
)

type RuntimeMaterialV1 struct {
	Artifact       wire.WindowsRuntimeArtifactV1
	ContentHash    string
	CABundlePEM    []byte
	SingBoxConfig  []byte
	AgentConfig    []byte
	HydratedSHA256 string
}

// PrepareRuntimeMaterial 只从一个已经完整验证的 DPAPI LKG 中选取
// windows-runtime，并把 exact credential refs hydrate 到短生命周期副本。
func PrepareRuntimeMaterial(state *StateV1) (RuntimeMaterialV1, error) {
	if err := validateState(state); err != nil {
		return RuntimeMaterialV1{}, err
	}
	if state.Envelope.Payload.State != "active" || state.Envelope.Payload.Active == nil {
		return RuntimeMaterialV1{}, errors.New("[D131 Windows runtime] tombstone Device 禁止启动数据面")
	}
	var selected *InstalledConfigV1
	for index := range state.Enrollment.Configs {
		config := &state.Enrollment.Configs[index]
		if config.ArtifactID != wire.WindowsRuntimeArtifactID {
			continue
		}
		if selected != nil {
			return RuntimeMaterialV1{}, errors.New("[D131 Windows runtime] windows-runtime artifact 不唯一")
		}
		selected = config
	}
	if selected == nil || selected.Platform != "windows-desktop" ||
		selected.MediaType != "application/vnd.loom.config+json" ||
		selected.RenderContractID != wire.WindowsRuntimeRenderContract {
		return RuntimeMaterialV1{}, errors.New("[D131 Windows runtime] certified windows-runtime ref 缺失或 contract 无效")
	}
	var artifact wire.WindowsRuntimeArtifactV1
	canonical, err := wire.DecodeStrict(selected.Config, maximumConfigArtifactBytes, &artifact)
	if err != nil || !bytes.Equal(canonical, selected.Config) ||
		wire.ValidateWindowsRuntimeArtifact(&artifact) != nil {
		return RuntimeMaterialV1{}, errors.New("[D131 Windows runtime] windows-runtime bytes 无效")
	}
	if artifact.ClusterID != state.Envelope.Payload.ClusterID ||
		artifact.DeviceID != state.Envelope.Payload.DeviceID ||
		artifact.DeviceGeneration != state.Envelope.Payload.DeviceGeneration ||
		artifact.Generation != selected.Generation {
		return RuntimeMaterialV1{}, errors.New("[D131 Windows runtime] artifact 未绑定 current Device generation")
	}
	secrets := make(map[string]string, len(artifact.CredentialRefs))
	for _, ref := range artifact.CredentialRefs {
		var credential *InstalledSecretV1
		for index := range state.Enrollment.Credentials {
			candidate := &state.Enrollment.Credentials[index]
			if candidate.SecretID == ref {
				if credential != nil {
					return RuntimeMaterialV1{}, errors.New("[D124 Windows runtime] credential ID 不唯一")
				}
				credential = candidate
			}
		}
		if credential == nil || !slices.Contains([]string{
			"data_plane_credential", "tls_private_key", "control_peer_identity",
		}, credential.Purpose) {
			return RuntimeMaterialV1{}, errors.New("[D124 Windows runtime] runtime credential 缺失或 purpose 无效")
		}
		decoded, decodeErr := base64.RawURLEncoding.DecodeString(credential.SecretBytes)
		if decodeErr != nil || len(decoded) == 0 || !utf8.Valid(decoded) ||
			strings.IndexByte(string(decoded), 0) >= 0 ||
			base64.RawURLEncoding.EncodeToString(decoded) != credential.SecretBytes {
			clear(decoded)
			return RuntimeMaterialV1{}, errors.New("[D124 Windows runtime] credential bytes 无效")
		}
		secrets[ref] = string(decoded)
		clear(decoded)
	}
	files := make(map[string][]byte, 2)
	for _, file := range artifact.Files {
		hydrated, missing := secret.Hydrate(file.Content, secrets)
		if len(missing) != 0 || secret.HasPlaceholder(hydrated) {
			clearStringValues(secrets)
			return RuntimeMaterialV1{}, errors.New("[D124 Windows runtime] hydrate 后仍缺 credential")
		}
		body := []byte(hydrated)
		canonical, canonicalErr := wire.CanonicalizeStrict(body)
		var object map[string]json.RawMessage
		if canonicalErr != nil || !bytes.Equal(canonical, body) ||
			json.Unmarshal(body, &object) != nil || object == nil {
			clear(body)
			clearStringValues(secrets)
			return RuntimeMaterialV1{}, errors.New("[D131 Windows runtime] hydrated config 不是 exact canonical JSON")
		}
		files[file.Path] = body
	}
	clearStringValues(secrets)
	encoded, err := wire.MarshalCanonical(map[string]string{
		"agent/config.json":    string(files["agent/config.json"]),
		"sing-box/config.json": string(files["sing-box/config.json"]),
	})
	if err != nil {
		clear(files["agent/config.json"])
		clear(files["sing-box/config.json"])
		return RuntimeMaterialV1{}, err
	}
	digest := sha256.Sum256(encoded)
	clear(encoded)
	return RuntimeMaterialV1{Artifact: artifact, ContentHash: selected.ContentHash,
		CABundlePEM:   []byte(artifact.CABundlePEM),
		SingBoxConfig: files["sing-box/config.json"], AgentConfig: files["agent/config.json"],
		HydratedSHA256: hex.EncodeToString(digest[:])}, nil
}

func (material *RuntimeMaterialV1) Clear() {
	if material == nil {
		return
	}
	clear(material.CABundlePEM)
	clear(material.SingBoxConfig)
	clear(material.AgentConfig)
	material.CABundlePEM, material.SingBoxConfig, material.AgentConfig = nil, nil, nil
}

func clearStringValues(values map[string]string) {
	for key := range values {
		delete(values, key)
	}
}
