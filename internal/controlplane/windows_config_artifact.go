package controlplane

import (
	"errors"
	"slices"

	"loom/internal/distribution"
	"loom/internal/wire"
)

type WindowsRuntimeProjectionV1 struct {
	ClusterID        string
	DeviceID         string
	DeviceGeneration int64
	Generation       int64
	SingBoxVersion   string
	CABundlePEM      []byte
	CredentialRefs   []string
	SingBoxConfig    []byte
	AgentConfig      []byte
}

// BuildWindowsRuntimeArtifact 把 renderer 的 sing-box/Agent pair 固定为一个
// content-addressed Device config；producer 不接触 credential 明文。
func BuildWindowsRuntimeArtifact(input WindowsRuntimeProjectionV1) ([]byte, error) {
	refs := append([]string(nil), input.CredentialRefs...)
	slices.Sort(refs)
	if !slices.Equal(refs, input.CredentialRefs) {
		return nil, errors.New("[D124 Windows artifact] credential refs 必须由调用方规范排序")
	}
	artifact := wire.WindowsRuntimeArtifactV1{
		Schema: 1, ClusterID: input.ClusterID, DeviceID: input.DeviceID,
		DeviceGeneration: input.DeviceGeneration, Generation: input.Generation,
		SingBoxVersion: input.SingBoxVersion, CABundlePEM: string(input.CABundlePEM), CredentialRefs: refs,
		Files: []wire.WindowsRuntimeFileV1{
			{Path: "agent/config.json", Content: string(input.AgentConfig)},
			{Path: "sing-box/config.json", Content: string(input.SingBoxConfig)},
		},
	}
	if err := wire.ValidateWindowsRuntimeArtifact(&artifact); err != nil {
		return nil, err
	}
	return wire.MarshalCanonical(artifact)
}

func PublishWindowsRuntimeArtifact(staticRoot string,
	input WindowsRuntimeProjectionV1) (wire.DeviceConfigArtifactRefV1, string, error) {
	body, err := BuildWindowsRuntimeArtifact(input)
	if err != nil {
		return wire.DeviceConfigArtifactRefV1{}, "", err
	}
	return distribution.PublishDeviceConfigArtifact(staticRoot,
		wire.WindowsRuntimeArtifactID, "windows-desktop",
		"application/vnd.loom.config+json", wire.WindowsRuntimeRenderContract,
		input.Generation, body)
}
