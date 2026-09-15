//go:build windows

package clientruntime

import (
	"errors"
	"net/netip"
	"reflect"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestWindowsUnderlayCallbackRegistrationAndPartialFailure(t *testing.T) {
	for _, failAt := range []int{-1, 1, 2} {
		var registrations []windowsUnderlayRegistration
		for i := range 3 {
			registrations = append(registrations, func(family uint16, callback uintptr, caller unsafe.Pointer, initial bool, handle *windows.Handle) error {
				if family != windows.AF_UNSPEC || callback != 123 || caller != nil || initial {
					t.Fatal("IP Helper callback 的 ABI 参数或初始通知设置不正确")
				}
				if i == failAt {
					return errors.New("demo subscription failure")
				}
				*handle = windows.Handle(i + 1)
				return nil
			})
		}
		var canceled []windows.Handle
		stop, err := registerWindowsUnderlayCallbacks(123, registrations, func(handle windows.Handle) error {
			canceled = append(canceled, handle)
			return nil
		})
		count := failAt
		if failAt < 0 {
			if err != nil {
				t.Fatal(err)
			}
			stop()
			stop()
			count = 3
		} else if err == nil || stop != nil {
			t.Fatal("部分订阅失败未明确返回错误")
		}
		var want []windows.Handle
		for i := range count {
			want = append(want, windows.Handle(i+1))
		}
		if !reflect.DeepEqual(canceled, want) {
			t.Fatal("取消遗漏或重复注销了 IP Helper handle")
		}
	}
}

func demoWindowsSocket(address string) windows.SocketAddress {
	socket := &windows.RawSockaddrInet4{Family: windows.AF_INET, Addr: netip.MustParseAddr(address).As4()}
	return windows.SocketAddress{Sockaddr: (*syscall.RawSockaddrAny)(unsafe.Pointer(socket)), SockaddrLength: int32(unsafe.Sizeof(*socket))}
}

func demoWindowsAdapter(index uint32, source, gateway string) *windows.IpAdapterAddresses {
	return &windows.IpAdapterAddresses{Luid: uint64(index), IfIndex: index, OperStatus: windows.IfOperStatusUp,
		Ipv4Metric: 10, FirstUnicastAddress: &windows.IpAdapterUnicastAddress{Address: demoWindowsSocket(source)},
		FirstGatewayAddress: &windows.IpAdapterGatewayAddress{Address: demoWindowsSocket(gateway)}}
}

func demoWindowsRoute(index uint32, address string, bits uint8, metric uint32) windows.MibIpForwardRow2 {
	row := windows.MibIpForwardRow2{InterfaceLuid: uint64(index), InterfaceIndex: index, Metric: metric}
	prefix := (*windows.RawSockaddrInet4)(unsafe.Pointer(&row.DestinationPrefix.Prefix))
	*prefix = windows.RawSockaddrInet4{Family: windows.AF_INET, Addr: netip.MustParseAddr(address).As4()}
	row.DestinationPrefix.PrefixLength = bits
	return row
}

func TestWindowsUnderlaySnapshotIgnoresManagedTUNAndCaptureRoutes(t *testing.T) {
	physical := demoWindowsAdapter(1, "192.0.2.10", "192.0.2.254")
	tun := demoWindowsAdapter(2, "172.19.0.1", "172.19.0.2")
	defaultRoute := demoWindowsRoute(1, "0.0.0.0", 0, 20)
	before := buildWindowsUnderlay(physical, []windows.MibIpForwardRow2{defaultRoute})
	physical.Next = tun
	// TUN 为业务接管新增两个 /1，物理接口新增入口绕行 /32，不能重开预算。
	after := buildWindowsUnderlay(physical, []windows.MibIpForwardRow2{defaultRoute,
		demoWindowsRoute(2, "0.0.0.0", 1, 1), demoWindowsRoute(2, netip.AddrFrom4([4]byte{128}).String(), 1, 1),
		demoWindowsRoute(1, "198.51.100.1", 32, 1)})
	if before.key != after.key || after.source("198.51.100.1") != "192.0.2.10" || after.source("203.0.113.1") != "192.0.2.10" {
		t.Fatal("TUN 启动改变了 underlay 代次或截获了源接口")
	}
	defaultRoute.Metric++
	changed := buildWindowsUnderlay(physical, []windows.MibIpForwardRow2{defaultRoute})
	if changed.key == before.key {
		t.Fatal("真实默认路由 metric 改变没有推进 underlay 快照")
	}
	physical.OperStatus = windows.IfOperStatusDown
	offline := buildWindowsUnderlay(physical, []windows.MibIpForwardRow2{defaultRoute})
	if offline.key == before.key || len(offline.routes) != 0 {
		t.Fatal("物理网卡离线后仍把 TUN 当作可用 underlay")
	}
}
