package controlplane

import (
	"bytes"
	"errors"

	"loom/internal/distribution"
	"loom/internal/wire"
)

// LinuxLinkIntentProjectionV1 是 certified Device view 的前置确定性输入。
// Authority 是生成配置时已认证的 Head；调用方把返回的 ref 放入 Device view，
// 再形成 provisional/completion 或配置更新 Head，不能反向引用未来 Head（D105、D131）。
type LinuxLinkIntentProjectionV1 struct {
	ClusterID          string
	DeviceID           string
	DeviceGeneration   int64
	Generation         int64
	ParentHeadHash     string
	Authority          wire.CertifiedHeadV1
	ControlSet         *wire.ControlSetV1
	PreviousControlSet *wire.ControlSetV1
	LinkIntents        []wire.LinkIntentV1
}

type LinuxRuntimeProjectionV1 struct {
	ClusterID        string
	DeviceID         string
	DeviceGeneration int64
	Generation       int64
	LinkIntentRaw    []byte
	Bindings         []wire.LinuxRuntimeBindingV1
	Files            []wire.LinuxRuntimeFileV1
}

// BuildLinuxRuntimeArtifact 把 renderer output 绑定到先前生成的 exact
// linux-link-intents bytes。调用方不能自报 LinkIntent hash/generation。
func BuildLinuxRuntimeArtifact(input LinuxRuntimeProjectionV1) ([]byte, error) {
	var linkArtifact wire.LinuxLinkIntentArtifactV1
	canonical, err := wire.DecodeStrict(input.LinkIntentRaw, 4<<20, &linkArtifact)
	if err != nil || !bytes.Equal(canonical, input.LinkIntentRaw) ||
		wire.ValidateLinuxLinkIntentArtifact(&linkArtifact) != nil {
		return nil, errors.New("[D131 Linux artifact] runtime 未绑定 exact LinkIntent artifact")
	}
	if input.ClusterID != linkArtifact.ClusterID || input.DeviceID != linkArtifact.DeviceID ||
		input.DeviceGeneration != linkArtifact.DeviceGeneration {
		return nil, errors.New("[D131 Linux artifact] runtime/LinkIntent Device binding 不一致")
	}
	linkHash, err := wire.DeviceConfigArtifactContentHash(input.LinkIntentRaw)
	if err != nil {
		return nil, err
	}
	artifact := wire.LinuxRuntimeArtifactV1{
		Schema: 1, ClusterID: input.ClusterID, DeviceID: input.DeviceID,
		DeviceGeneration: input.DeviceGeneration, Generation: input.Generation,
		LinkIntentGeneration: linkArtifact.Generation, LinkIntentContentHash: linkHash,
		Bindings: append([]wire.LinuxRuntimeBindingV1(nil), input.Bindings...),
		Files:    append([]wire.LinuxRuntimeFileV1(nil), input.Files...),
	}
	if err := wire.ValidateLinuxRuntimeArtifact(&artifact); err != nil {
		return nil, err
	}
	if err := validateLinuxRuntimeProjectionBindings(&linkArtifact, artifact.Bindings); err != nil {
		return nil, err
	}
	if err := wire.ValidateLinuxRuntimeRedaction(&artifact, &linkArtifact); err != nil {
		return nil, err
	}
	return wire.MarshalCanonical(artifact)
}

func PublishLinuxRuntimeArtifact(staticRoot string,
	input LinuxRuntimeProjectionV1,
) (wire.DeviceConfigArtifactRefV1, string, error) {
	body, err := BuildLinuxRuntimeArtifact(input)
	if err != nil {
		return wire.DeviceConfigArtifactRefV1{}, "", err
	}
	return distribution.PublishDeviceConfigArtifact(staticRoot,
		wire.LinuxRuntimeArtifactID, "linux-server", "application/vnd.loom.config+json",
		wire.LinuxRuntimeRenderContract, input.Generation, body)
}

func validateLinuxRuntimeProjectionBindings(linkArtifact *wire.LinuxLinkIntentArtifactV1,
	bindings []wire.LinuxRuntimeBindingV1,
) error {
	if linkArtifact == nil {
		return errors.New("[D131 Linux artifact] LinkIntent 缺失")
	}
	byLink := make(map[string][]wire.LinuxRuntimeBindingV1, len(linkArtifact.LinkIntents))
	for _, binding := range bindings {
		byLink[binding.LinkID] = append(byLink[binding.LinkID], binding)
	}
	for _, intent := range linkArtifact.LinkIntents {
		selected := byLink[intent.LinkID]
		if len(selected) == 0 {
			return errors.New("[D131 Linux artifact] runtime bindings 未覆盖每条 LinkIntent")
		}
		mode := "listen"
		if intent.Initiator == "from" && intent.FromDeviceID == linkArtifact.DeviceID ||
			intent.Initiator == "to" && intent.To.DeviceID == linkArtifact.DeviceID {
			mode = "dial"
		}
		for _, binding := range selected {
			if binding.LinkGeneration != intent.Generation || binding.Mode != mode ||
				!containsLinuxArtifactValue(intent.AllowedTransports, binding.Transport) ||
				!containsLinuxArtifactValue(intent.ListenerResourceRefs, binding.EndpointID) {
				return errors.New("[D131 Linux artifact] runtime binding 扩大或偏离 LinkIntent")
			}
		}
		delete(byLink, intent.LinkID)
	}
	if len(byLink) != 0 {
		return errors.New("[D131 Linux artifact] runtime binding 引用了未知 LinkIntent")
	}
	return nil
}

func containsLinuxArtifactValue(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func BuildLinuxLinkIntentArtifact(input LinuxLinkIntentProjectionV1) ([]byte, error) {
	if input.LinkIntents == nil {
		return nil, errors.New("[D131 Linux artifact] LinkIntent projection 缺失")
	}
	if input.ControlSet == nil {
		return nil, errors.New("[D131 Linux artifact] 缺已认证的 ControlSet")
	}
	if err := wire.VerifyConfigQCAuthority(input.ParentHeadHash, input.Authority.QC,
		&input.Authority.Head, input.ControlSet, input.PreviousControlSet); err != nil {
		return nil, err
	}
	artifact := wire.LinuxLinkIntentArtifactV1{
		Schema: 1, ClusterID: input.ClusterID, DeviceID: input.DeviceID,
		DeviceGeneration: input.DeviceGeneration, Generation: input.Generation,
		RenderContractID:  wire.LinuxLinkIntentRenderContract,
		AuthorityHeadHash: input.ParentHeadHash,
		Authority:         input.Authority,
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
