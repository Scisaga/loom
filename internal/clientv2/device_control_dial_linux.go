//go:build linux

package clientv2

import (
	"context"
	"encoding/base64"
	"errors"
	"net"
	"strconv"
	"time"

	"golang.org/x/net/proxy"
	"loom/internal/wire"
)

// 私有请求只消费已安装认证配置中的本机代理。代理失败不回退主机默认
// 路由；mTLS、IP SAN 和目录 pin 仍由上层逐请求验证。
func installedLinuxDeviceDial(installation *DeviceInstallationV1, device string, service wire.PrivateControlServiceV1, timeout time.Duration) (TunnelDialContext, error) {
	var found bool
	for _, config := range installation.Configs {
		found = found || config.ArtifactID == wire.LinuxLinkIntentArtifactID
	}
	if !found {
		return nil, nil
	}
	body, err := LinuxInstalledConfigArtifact(installation, wire.LinuxLinkIntentArtifactID)
	if err != nil {
		return nil, err
	}
	var links wire.LinuxLinkIntentArtifactV1
	if _, err := wire.DecodeStrict(body, 32<<20, &links); err != nil {
		return nil, err
	}
	if err := wire.ValidateLinuxLinkIntentArtifact(&links); err != nil {
		return nil, err
	}
	if links.DeviceID != device {
		return nil, errors.New("[Linux private] 私有通道不属于本设备")
	}
	if links.LocalRuntime == nil {
		return nil, nil
	}
	for _, link := range links.LocalRuntime.DeviceControlLinks {
		if link.Resource.DialerDeviceID != device {
			continue
		}
		authorized := false
		for _, allowed := range link.Services {
			authorized = authorized || wire.EqualCanonical(allowed, service)
		}
		if !authorized || link.Carrier == nil {
			return nil, errors.New("[Linux private] 目的服务没有当前私有通道授权")
		}
		var password string
		for _, credential := range installation.Credentials {
			if credential.SecretID != link.Carrier.CredentialRef {
				continue
			}
			secret, err := base64.RawURLEncoding.Strict().DecodeString(credential.SecretBytes)
			if err != nil || len(secret) == 0 || len(secret) > 255 || credential.Purpose != "data_plane_credential" ||
				wire.HashRaw("loom-linux-installed-secret-v1", secret) != credential.SecretDigest || password != "" {
				clear(secret)
				return nil, errors.New("[Linux private] 本机代理凭据缺失、冲突或摘要不符")
			}
			password = string(secret)
			clear(secret)
		}
		if password == "" {
			return nil, errors.New("[Linux private] 本机代理凭据尚未安装")
		}
		dialer, err := proxy.SOCKS5("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(wire.DeviceControlLocalPort)),
			&proxy.Auth{User: link.Resource.ResourceID, Password: password}, &net.Dialer{Timeout: timeout})
		if err != nil {
			return nil, err
		}
		expected := net.JoinHostPort(service.OverlayIP, strconv.FormatInt(service.Port, 10))
		return func(ctx context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" || address != expected {
				return nil, errors.New("[Linux private] 私有通道拒绝目录以外的目的")
			}
			return dialer.(proxy.ContextDialer).DialContext(ctx, network, address)
		}, nil
	}
	return nil, nil
}
