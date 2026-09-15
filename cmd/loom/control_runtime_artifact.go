package main

import (
	"errors"

	"loom/internal/wire"
)

func validateControlRuntimeArtifact(config controlPublishedConfigV1, clusterID, deviceID string, deviceGeneration int64) error {
	ref, raw := config.Ref, config.Content
	switch ref.Platform {
	case "android":
		var bundle struct {
			Owner string            `json:"owner"`
			Files map[string]string `json:"files"`
		}
		if _, err := wire.DecodeStrict(raw, 3<<20, &bundle); err != nil || bundle.Owner != deviceID || len(bundle.Files) != 2 ||
			ref.ArtifactID != "android-runtime" || ref.RenderContractID != "android-runtime-v1" {
			return errors.New("[配置发布] Android 配置未绑定本设备的运行合约")
		}
		for _, path := range []string{"agent/config.json", "sing-box/config.json"} {
			if err := wire.ValidatePublicRuntimeJSON([]byte(bundle.Files[path])); err != nil {
				return err
			}
		}
	case "windows-desktop":
		var artifact wire.WindowsRuntimeArtifactV1
		if _, err := wire.DecodeStrict(raw, 3<<20, &artifact); err != nil || artifact.ClusterID != clusterID || artifact.DeviceID != deviceID ||
			artifact.DeviceGeneration != deviceGeneration || artifact.Generation != ref.Generation ||
			ref.ArtifactID != wire.WindowsRuntimeArtifactID || ref.RenderContractID != wire.WindowsRuntimeRenderContract {
			return errors.New("[配置发布] Windows 配置未绑定本设备与配置代")
		}
		return wire.ValidateWindowsRuntimeArtifact(&artifact)
	case "linux-server":
		switch ref.ArtifactID {
		case wire.LinuxRuntimeArtifactID:
			var artifact wire.LinuxRuntimeArtifactV1
			if _, err := wire.DecodeStrict(raw, 3<<20, &artifact); err != nil || artifact.ClusterID != clusterID || artifact.DeviceID != deviceID ||
				artifact.DeviceGeneration != deviceGeneration || artifact.Generation != ref.Generation || ref.RenderContractID != wire.LinuxRuntimeRenderContract {
				return errors.New("[配置发布] Linux runtime 未绑定本设备与配置代")
			}
			return wire.ValidateLinuxRuntimeArtifact(&artifact)
		case wire.LinuxLinkIntentArtifactID:
			var artifact wire.LinuxLinkIntentArtifactV1
			if _, err := wire.DecodeStrict(raw, 3<<20, &artifact); err != nil || artifact.ClusterID != clusterID || artifact.DeviceID != deviceID ||
				artifact.DeviceGeneration != deviceGeneration || artifact.Generation != ref.Generation || ref.RenderContractID != wire.LinuxLinkIntentRenderContract {
				return errors.New("[配置发布] Linux link intent 未绑定本设备与配置代")
			}
			return wire.ValidateLinuxLinkIntentArtifact(&artifact)
		default:
			return errors.New("[配置发布] 未登记的 Linux 制品")
		}
	default:
		return errors.New("[配置发布] 未登记的设备平台")
	}
	return nil
}

func validateControlRuntimeSet(configs []controlPublishedConfigV1, platform, parent string) error {
	if platform != "linux-server" {
		if len(configs) != 1 {
			return errors.New("[配置发布] 客户端只接受一个当前运行制品")
		}
		return nil
	}
	if len(configs) != 2 {
		return errors.New("[配置发布] Linux 需要同时发布 link intent 与 runtime")
	}
	var links wire.LinuxLinkIntentArtifactV1
	var runtime wire.LinuxRuntimeArtifactV1
	var linkHash string
	for _, config := range configs {
		if config.Ref.ArtifactID == wire.LinuxLinkIntentArtifactID {
			if _, err := wire.DecodeStrict(config.Content, 3<<20, &links); err != nil {
				return err
			}
			linkHash = config.Ref.ContentHash
		} else {
			if _, err := wire.DecodeStrict(config.Content, 3<<20, &runtime); err != nil {
				return err
			}
		}
	}
	if links.AuthorityHeadHash != parent || links.Authority.Head.HeadHash != parent || runtime.LinkIntentContentHash != linkHash ||
		runtime.LinkIntentGeneration != links.Generation {
		return errors.New("[配置发布] Linux 配置与前序认证 Head/LinkIntent 不一致")
	}
	return wire.ValidateLinuxRuntimeRedaction(&runtime, &links)
}
