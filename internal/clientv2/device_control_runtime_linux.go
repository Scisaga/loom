//go:build linux

package clientv2

import (
	"encoding/json"
	"errors"

	"loom/internal/wire"
)

func validateLinuxDeviceControlEndpoints(plan *LinuxLinkRuntimePlanV1, artifact *wire.LinuxRuntimeArtifactV1, body string) error {
	var doc struct {
		Endpoints []json.RawMessage `json:"endpoints"`
		Outbounds []json.RawMessage `json:"outbounds"`
		Route     struct {
			Rules []json.RawMessage `json:"rules"`
		} `json:"route"`
	}
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		return err
	}
	var links []wire.DeviceControlLinkV1
	if plan.LocalRuntime != nil {
		links = plan.LocalRuntime.DeviceControlLinks
	}
	if len(doc.Endpoints) != len(links) {
		return errors.New("[设备控制链路] 存在未认证的 endpoint")
	}
	for i, link := range links {
		var endpoint wire.DeviceControlEndpointV1
		if _, err := wire.DecodeStrict(doc.Endpoints[i], 4<<20, &endpoint); err != nil {
			return err
		}
		if wireGuardPublicKey(endpoint.PrivateKey) != link.Resource.ListenerPublicKey || !wire.EqualCanonical(endpoint, wire.DeviceControlEndpoint(link, endpoint.PrivateKey)) {
			return errors.New("[设备控制链路] endpoint、公钥或来源前缀偏离认证资源")
		}
		matches := 0
		for _, binding := range artifact.Bindings {
			if binding.LinkID == link.Resource.LinkID && binding.Mode == "listen" && binding.Transport == "wireguard" && binding.ConfigPath == "sing-box/v2/config.json" && binding.RuntimeTag == endpoint.Tag {
				matches++
			}
		}
		if matches != 1 {
			return errors.New("[设备控制链路] endpoint 缺唯一认证 LinkIntent binding")
		}
	}
	if len(links) == 0 {
		return nil
	}
	expected := wire.DeviceControlRoutes(links)
	if len(doc.Route.Rules) < len(expected) {
		return errors.New("[设备控制链路] 缺私有目的限制")
	}
	for i, want := range expected {
		raw, _ := wire.MarshalCanonical(want)
		actual, err := wire.NormalizeRuntimeJSON(doc.Route.Rules[i])
		if err != nil || string(raw) != string(actual) {
			return errors.New("[设备控制链路] 必须首先执行 exact 私有服务放行与默认拒绝")
		}
	}
	found := map[string]bool{}
	for _, raw := range doc.Outbounds {
		var outbound struct {
			Type string `json:"type"`
			Tag  string `json:"tag"`
		}
		if err := json.Unmarshal(raw, &outbound); err != nil {
			return err
		}
		want := ""
		switch outbound.Tag {
		case wire.DeviceControlDirectTag:
			want = "direct"
		case wire.DeviceControlBlockTag:
			want = "block"
		default:
			continue
		}
		if _, err := wire.DecodeStrict(raw, 64<<10, &outbound); err != nil || outbound.Type != want || found[outbound.Tag] {
			return errors.New("[设备控制链路] 私有服务出站含覆盖或重复字段")
		}
		found[outbound.Tag] = true
	}
	if len(found) != 2 {
		return errors.New("[设备控制链路] 缺专用放行与拒绝出站")
	}
	return nil
}
