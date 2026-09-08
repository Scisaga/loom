//go:build windows

package clientruntime

import (
	"context"
	"errors"
	"net"
	"time"
)

var errTUNCapture = errors.New("TUN 接管未生效")

// §16.1：只检查本机监听与托管网卡，不发送 DNS、TLS 或业务请求。
// healthy 仅说明本机运行面检查通过；业务可用性由 Agent reason 明确保持未测量。
func CheckWindowsHealth(ctx context.Context, plan *WindowsHealthPlan) []string {
	if plan == nil {
		return []string{"缺少已激活的本机运行配置"}
	}
	if err := ctx.Err(); err != nil {
		return []string{"本机运行检查已取消"}
	}
	if plan.profile != WindowsPortableMixedProfile {
		if _, err := managedTUNInterface(); err != nil {
			return []string{"托管 TUN 网卡未就绪"}
		}
	}
	c, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp4", "127.0.0.1:1080")
	if err != nil {
		return []string{"本地代理监听未就绪"}
	}
	c.Close()
	return nil
}

func managedTUNInterface() (*net.Interface, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, errTUNCapture
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addresses, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, address := range addresses {
			if address.String() == "172.19.0.1/30" {
				return &iface, nil
			}
		}
	}
	return nil, errTUNCapture
}
