package wire

import (
	"errors"
	"net/netip"
)

// 私有数据传输保留网络内部 CA 的服务身份。它不是公网 EndpointSet，
// 不得用它宣告 bootstrap/distribution 的外部可用性。
type LinuxPeerTransportV1 struct {
	ResourceID         string `json:"resource_id"`
	LinkID             string `json:"link_id"`
	ListenerDeviceID   string `json:"listener_device_id"`
	ListenerGeneration int64  `json:"listener_generation"`
	Transport          string `json:"transport"`
	Address            string `json:"address"`
	Port               int64  `json:"port"`
	TLSServerName      string `json:"tls_server_name"`
}

type LinuxLocalListenerV1 struct {
	Tag       string `json:"tag"`
	Transport string `json:"transport"`
	Address   string `json:"address"`
	Port      int64  `json:"port"`
}

// 本机 API/probe 口令不是另一条网络边的凭据；访问模式和共享 listener
// 由同一认证制品明确列出，不能从 use_loom 推导出默认接管主机路由。
type LinuxLocalRuntimeV1 struct {
	AccessMode         string                 `json:"access_mode"`
	CredentialRefs     []string               `json:"credential_refs"`
	Listeners          []LinuxLocalListenerV1 `json:"listeners"`
	DeviceControlLinks []DeviceControlLinkV1  `json:"device_control_links,omitempty"`
}

func ValidateLinuxLocalRuntime(artifact *LinuxLinkIntentArtifactV1) error {
	if local := artifact.LocalRuntime; local != nil {
		if !oneOf(local.AccessMode, "none", "mixed", "tun", "mixed_tun") || local.CredentialRefs == nil ||
			!sortedUnique(local.CredentialRefs) || local.Listeners == nil {
			return errors.New("[Linux runtime] 本机访问模式或凭据集合无效")
		}
		for _, ref := range local.CredentialRefs {
			if !validIdentifier(ref, 128) {
				return errors.New("[Linux runtime] 本机凭据引用无效")
			}
		}
		for i, listener := range local.Listeners {
			address, err := netip.ParseAddr(listener.Address)
			if !validIdentifier(listener.Tag, 128) || !oneOf(listener.Transport, "hysteria2", "trojan_tls") ||
				err != nil || address.String() != listener.Address || address.IsMulticast() || listener.Port < 1 || listener.Port > 65535 ||
				(i > 0 && local.Listeners[i-1].Tag >= listener.Tag) {
				return errors.New("[Linux runtime] 本机 listener tuple 或顺序无效")
			}
		}
		ports := map[int64]bool{}
		for i, link := range local.DeviceControlLinks {
			if err := ValidateDeviceControlLink(&link); err != nil {
				return err
			}
			if link.Resource.ListenerDeviceID != artifact.DeviceID || ports[link.Resource.EndpointPort] ||
				i > 0 && local.DeviceControlLinks[i-1].Resource.ResourceID >= link.Resource.ResourceID {
				return errors.New("[Linux runtime] 私有控制链路 listener 归属、顺序或端口冲突")
			}
			ports[link.Resource.EndpointPort] = true
			found := false
			for _, resource := range artifact.WireGuardResources {
				found = found || EqualCanonical(resource, link.Resource)
			}
			if !found {
				return errors.New("[Linux runtime] 私有控制链路缺同源 WireGuard 资源")
			}
			if artifact.LocalWireGuardKey == nil {
				return errors.New("[Linux runtime] 私有控制链路缺承载节点原密钥")
			}
			found = false
			for _, intent := range artifact.LinkIntents {
				found = found || EqualCanonical(intent, DeviceControlLinkIntent(artifact.ClusterID, link.Resource, artifact.AuthorityHeadHash, artifact.LocalWireGuardKey.SecretID))
			}
			if !found {
				return errors.New("[Linux runtime] 私有控制链路未绑定受限 LinkIntent")
			}
		}
	}
	ids := map[string]bool{}
	for _, resource := range artifact.WireGuardResources {
		ids[resource.ResourceID] = true
	}
	links := map[string]LinkIntentV1{}
	for _, intent := range artifact.LinkIntents {
		links[intent.LinkID] = intent
	}
	for i, resource := range artifact.PeerTransports {
		if !validIdentifier(resource.ResourceID, 128) || !validIdentifier(resource.ListenerDeviceID, 128) ||
			!validIdentifier(resource.LinkID, 128) || resource.ListenerDeviceID == artifact.DeviceID ||
			resource.ListenerGeneration < 1 || !oneOf(resource.Transport, "hysteria2", "trojan_tls") ||
			resource.Port < 1 || resource.Port > 65535 || !ValidFQDN(resource.TLSServerName) || ids[resource.ResourceID] ||
			(i > 0 && artifact.PeerTransports[i-1].ResourceID >= resource.ResourceID) {
			return errors.New("[Linux runtime] 私有传输资源字段、归属或顺序无效")
		}
		address, err := netip.ParseAddr(resource.Address)
		if err != nil {
			if !ValidFQDN(resource.Address) {
				return errors.New("[Linux runtime] 私有传输地址无效")
			}
		} else if address.String() != resource.Address || address.Is4In6() || address.IsUnspecified() || address.IsMulticast() || address.IsLoopback() || address.IsLinkLocalUnicast() {
			return errors.New("[Linux runtime] 私有传输地址不是可拨 peer")
		}
		intent, found := links[resource.LinkID]
		if !found || intent.Initiator != "from" || intent.FromDeviceID != artifact.DeviceID ||
			intent.To.DeviceID != resource.ListenerDeviceID || intent.Purpose != "data_forward" ||
			!EqualCanonical(intent.AllowedTransports, []string{resource.Transport}) ||
			!EqualCanonical(intent.ListenerResourceRefs, []string{resource.ResourceID}) {
			return errors.New("[Linux runtime] 私有传输未 exact 绑定本机发起的 LinkIntent")
		}
		ids[resource.ResourceID] = true
	}
	return nil
}
