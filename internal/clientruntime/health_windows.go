//go:build windows

package clientruntime

import (
	"context"
	"golang.org/x/sys/windows"
	"net"
	"net/http"
)

func CheckWindowsHealth(ctx context.Context, plan *WindowsHealthPlan) []string {
	if plan == nil || plan.target == "" {
		return []string{"已激活配置缺少可探测的具体服务地址"}
	}
	if plan.profile == WindowsPortableMixedProfile {
		return plan.check(ctx, mixedHealthTransport())
	}
	// §7.2.1：不以 Mixed 的成功代替 TUN；只检查托管 IPv4 接管面，禁止 IPv6/环境代理旁路。
	iface, err := managedTUNInterface()
	if err != nil {
		return []string{plan.probeProblem(errTUNCapture, "TUN 接管")}
	}
	transport := &http.Transport{DisableKeepAlives: true, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			if err := requireTUNRoute(net.IPv4(172, 19, 0, 2), iface.Index); err != nil {
				return nil, err
			}
			return dialTUN(ctx, network, "172.19.0.2:53")
		}}
		addresses, err := resolver.LookupIP(ctx, "ip4", host)
		if err != nil {
			return nil, err
		}
		if len(addresses) == 0 {
			return nil, &net.DNSError{IsNotFound: true}
		}
		ip := addresses[0]
		if err := requireTUNRoute(ip, iface.Index); err != nil {
			return nil, err
		}
		return dialTUN(ctx, "tcp", net.JoinHostPort(ip.String(), port))
	}}
	return plan.check(ctx, transport)
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

func requireTUNRoute(ip net.IP, index int) error {
	ipv4 := ip.To4()
	if ipv4 == nil || !ip.IsGlobalUnicast() {
		return errTUNCapture
	}
	address := &windows.SockaddrInet4{}
	copy(address.Addr[:], ipv4)
	var best uint32
	if windows.GetBestInterfaceEx(address, &best) != nil || best != uint32(index) {
		return errTUNCapture
	}
	return nil
}

func dialTUN(ctx context.Context, network, address string) (net.Conn, error) {
	source := net.IPv4(172, 19, 0, 1)
	var local net.Addr = &net.TCPAddr{IP: source}
	if network == "udp" {
		local = &net.UDPAddr{IP: source}
	}
	dialer := net.Dialer{LocalAddr: local}
	return dialer.DialContext(ctx, network+"4", address)
}
