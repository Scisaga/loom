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
		public, mode := link.Resource.ListenerPublicKey, "listen"
		if plan.DeviceID == link.Resource.DialerDeviceID {
			public, mode = link.Resource.DialerPublicKey, "dial"
		}
		if wireGuardPublicKey(endpoint.PrivateKey) != public || !wire.EqualCanonical(endpoint, wire.DeviceControlEndpointForDevice(link, plan.DeviceID, endpoint.PrivateKey)) {
			return errors.New("[设备控制链路] endpoint、公钥或来源前缀偏离认证资源")
		}
		matches := 0
		for _, binding := range artifact.Bindings {
			if binding.LinkID == link.Resource.LinkID && binding.Mode == mode && binding.Transport == "wireguard" && binding.ConfigPath == "sing-box/v2/config.json" && binding.RuntimeTag == endpoint.Tag {
				matches++
			}
		}
		if matches != 1 {
			return errors.New("[设备控制链路] endpoint 缺唯一认证 LinkIntent binding")
		}
		if err := validateLinuxDeviceControlCarrier(link, plan.DeviceID, body); err != nil {
			return err
		}
	}
	if len(links) == 0 {
		return nil
	}
	expected := wire.DeviceControlRoutesForDevice(links, plan.DeviceID)
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

func validateLinuxDeviceControlCarrier(link wire.DeviceControlLinkV1, device, body string) error {
	if link.Carrier == nil {
		return nil
	}
	var doc struct{ Inbounds, Outbounds []json.RawMessage }
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		return err
	}
	carrier := link.Carrier
	if device == link.Resource.ListenerDeviceID {
		matches := 0
		for _, raw := range doc.Inbounds {
			var inbound struct {
				Type, Tag  string
				ListenPort int64 `json:"listen_port"`
				Users      []struct{ Name, Password string }
			}
			if err := json.Unmarshal(raw, &inbound); err != nil {
				return err
			}
			for _, user := range inbound.Users {
				if user.Name != link.Resource.ResourceID {
					continue
				}
				if inbound.Tag != "in" || inbound.Type != "hysteria2" || inbound.ListenPort != carrier.Port || user.Password == "" {
					return errors.New("[设备控制链路] 承载身份不属于认证 HY2 listener")
				}
				matches++
			}
		}
		if matches != 1 {
			return errors.New("[设备控制链路] 承载身份缺失或重复")
		}
		return nil
	}
	var password string
	outbounds := 0
	for _, raw := range doc.Outbounds {
		var tag struct{ Tag string }
		if err := json.Unmarshal(raw, &tag); err != nil {
			return err
		}
		if tag.Tag != wire.DeviceControlCarrierTag(link) {
			continue
		}
		var outbound struct {
			Type     string `json:"type"`
			Tag      string `json:"tag"`
			Server   string `json:"server"`
			Port     int64  `json:"server_port"`
			Password string `json:"password"`
			TLS      struct {
				Enabled    bool     `json:"enabled"`
				ServerName string   `json:"server_name"`
				CA         string   `json:"certificate_path"`
				ALPN       []string `json:"alpn"`
			} `json:"tls"`
		}
		if _, err := wire.DecodeStrict(raw, 64<<10, &outbound); err != nil {
			return err
		}
		if outbound.Type != "hysteria2" || outbound.Server != carrier.Address || outbound.Port != carrier.Port || outbound.Password == "" ||
			!outbound.TLS.Enabled || outbound.TLS.ServerName != carrier.TLSServerName || outbound.TLS.CA != "/etc/loom/tls/ca.crt" || !wire.EqualCanonical(outbound.TLS.ALPN, []string{"h3"}) {
			return errors.New("[设备控制链路] 发起端承载偏离认证 tuple、原 CA 或 TLS 身份")
		}
		password = outbound.Password
		outbounds++
	}
	locals := 0
	for _, raw := range doc.Inbounds {
		var tag struct{ Tag string }
		if err := json.Unmarshal(raw, &tag); err != nil {
			return err
		}
		if tag.Tag != wire.DeviceControlLocalTag {
			continue
		}
		var inbound struct {
			Type   string `json:"type"`
			Tag    string `json:"tag"`
			Listen string `json:"listen"`
			Port   int    `json:"listen_port"`
			Users  []struct {
				Username string `json:"username"`
				Password string `json:"password"`
			} `json:"users"`
		}
		if _, err := wire.DecodeStrict(raw, 64<<10, &inbound); err != nil {
			return err
		}
		if inbound.Type != "mixed" || inbound.Listen != "127.0.0.1" || inbound.Port != wire.DeviceControlLocalPort || len(inbound.Users) != 1 ||
			inbound.Users[0].Username != link.Resource.ResourceID || password == "" || inbound.Users[0].Password != password {
			return errors.New("[设备控制链路] 本机代理必须监听回环并使用本设备专用认证")
		}
		locals++
	}
	if locals != 1 || outbounds != 1 {
		return errors.New("[设备控制链路] 缺唯一认证的本机代理或外层承载")
	}
	return nil
}
