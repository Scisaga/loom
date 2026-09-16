//go:build linux

package clientv2

import (
	"crypto/ecdh"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
	"loom/internal/wire"
)

func loadLinuxLocalWireGuardKey(path, expectedPublic string) (string, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return "", errors.New("[Linux runtime] 原本地 WireGuard key 不可读；不生成替代 key")
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return "", errors.New("[Linux runtime] 无法打开原 WireGuard key")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || !ownedByCurrentUser(info) || info.Size() < 1 || info.Size() > 128 {
		return "", errors.New("[Linux runtime] 原 WireGuard key 必须是本机账号持有的私有普通文件")
	}
	body, err := io.ReadAll(io.LimitReader(file, 129))
	if err != nil || len(body) > 128 {
		return "", errors.New("[Linux runtime] 原 WireGuard key 长度无效")
	}
	defer clear(body)
	value := strings.TrimSpace(string(body))
	if wireGuardPublicKey(value) != expectedPublic || expectedPublic == "" {
		return "", errors.New("[Linux runtime] 原 WireGuard key 与认证公钥不匹配")
	}
	return value, nil
}

func wireGuardPublicKey(value string) string {
	bytes, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(bytes) != 32 || base64.StdEncoding.EncodeToString(bytes) != value {
		return ""
	}
	defer clear(bytes)
	key, err := ecdh.X25519().NewPrivateKey(bytes)
	if err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(key.PublicKey().Bytes())
}

// 认证资源约束完整 peer 配置，不能只检查 Endpoint 后放过另一 peer key、
// 扩大的 AllowedIPs 或额外路由/hook。私钥值只在本机检查，不进入错误消息。
func validateLinuxPeerWireGuardConfig(content, deviceID string, resource wire.LinuxWireGuardResourceV1) error {
	if err := validateLinuxWireGuardConfig(content); err != nil {
		return err
	}
	public, peer, localPrefix, peerPrefix := resource.ListenerPublicKey, resource.DialerPublicKey, resource.ListenerTunnelPrefix, resource.DialerTunnelPrefix
	dial := deviceID == resource.DialerDeviceID
	if dial {
		public, peer, localPrefix, peerPrefix = peer, public, peerPrefix, localPrefix
	} else if deviceID != resource.ListenerDeviceID {
		return errors.New("[Linux runtime] 本机不属于认证 WireGuard 资源")
	}
	want := map[string]string{"interface.address": localPrefix, "peer.publickey": peer, "peer.allowedips": peerPrefix}
	if dial {
		want["peer.endpoint"] = net.JoinHostPort(resource.EndpointAddress, strconv.FormatInt(resource.EndpointPort, 10))
		want["peer.persistentkeepalive"] = "25"
	} else {
		want["interface.listenport"] = strconv.FormatInt(resource.EndpointPort, 10)
	}
	section := ""
	keySeen := false
	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if line == "[Interface]" || line == "[Peer]" {
			section = strings.ToLower(strings.Trim(line, "[]"))
			continue
		}
		key, value, found := strings.Cut(line, "=")
		key, value = section+"."+strings.ToLower(strings.TrimSpace(key)), strings.TrimSpace(value)
		if !found {
			return errors.New("[Linux runtime] WireGuard 行无效")
		}
		if key == "interface.privatekey" {
			if keySeen || wireGuardPublicKey(value) != public {
				return errors.New("[Linux runtime] WireGuard 私钥与认证资源公钥不匹配")
			}
			keySeen = true
			continue
		}
		if expected, found := want[key]; !found || expected != value {
			return errors.New("[Linux runtime] WireGuard 字段超出认证 peer 资源或重复")
		}
		delete(want, key)
	}
	if !keySeen || len(want) != 0 {
		return errors.New("[Linux runtime] WireGuard 缺认证资源要求的字段")
	}
	return nil
}
