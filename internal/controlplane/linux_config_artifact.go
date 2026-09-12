package controlplane

import (
	"errors"

	"loom/internal/distribution"
	"loom/internal/wire"
)

// LinuxLinkIntentProjectionV1 是 certified Device view 的前置确定性输入。
// ParentHeadHash 必须是待生成 Head 的 parent；调用方把返回的 ref 放入
// Device view 后再形成新 Head/QC，从而避免 artifact/head 自引用（D105、D131）。
type LinuxLinkIntentProjectionV1 struct {
	ClusterID        string
	DeviceID         string
	DeviceGeneration int64
	Generation       int64
	ParentHeadHash   string
	LinkIntents      []wire.LinkIntentV1
}

func BuildLinuxLinkIntentArtifact(input LinuxLinkIntentProjectionV1) ([]byte, error) {
	if input.LinkIntents == nil {
		return nil, errors.New("[D131 Linux artifact] LinkIntent projection 缺失")
	}
	artifact := wire.LinuxLinkIntentArtifactV1{
		Schema: 1, ClusterID: input.ClusterID, DeviceID: input.DeviceID,
		DeviceGeneration: input.DeviceGeneration, Generation: input.Generation,
		RenderContractID:  wire.LinuxLinkIntentRenderContract,
		AuthorityHeadHash: input.ParentHeadHash,
		LinkIntents:       append([]wire.LinkIntentV1(nil), input.LinkIntents...),
	}
	if err := wire.ValidateLinuxLinkIntentArtifact(&artifact); err != nil {
		return nil, err
	}
	return wire.MarshalCanonical(artifact)
}

// PublishLinuxLinkIntentArtifact 只发布上面 exact producer 的 canonical bytes，
// 并返回可直接放入下一张 Device view 的 typed content ref。
func PublishLinuxLinkIntentArtifact(staticRoot string,
	input LinuxLinkIntentProjectionV1,
) (wire.DeviceConfigArtifactRefV1, string, error) {
	body, err := BuildLinuxLinkIntentArtifact(input)
	if err != nil {
		return wire.DeviceConfigArtifactRefV1{}, "", err
	}
	return distribution.PublishDeviceConfigArtifact(staticRoot,
		wire.LinuxLinkIntentArtifactID, "linux-server", "application/vnd.loom.config+json",
		wire.LinuxLinkIntentRenderContract, input.Generation, body)
}
