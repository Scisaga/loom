//go:build windows

package clientruntime

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"sort"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// 快照不写日志或协议；只包含有效 gateway underlay，排除本客户端 TUN。
func readWindowsUnderlay() (windowsUnderlaySnapshot, error) {
	var snapshot windowsUnderlaySnapshot
	const flags = windows.GAA_FLAG_INCLUDE_GATEWAYS |
		windows.GAA_FLAG_SKIP_ANYCAST |
		windows.GAA_FLAG_SKIP_MULTICAST |
		windows.GAA_FLAG_SKIP_DNS_SERVER
	var size uint32
	err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, flags, 0, nil, &size)
	if !errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) || size == 0 {
		return snapshot, errors.New("无法读取 Windows underlay generation")
	}
	buffer := make([]byte, size)
	first := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buffer[0]))
	if err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, flags, 0, first, &size); err != nil {
		return snapshot, errors.New("无法读取 Windows underlay adapters")
	}
	var table *windows.MibIpForwardTable2
	if err := windows.GetIpForwardTable2(windows.AF_INET, &table); err != nil {
		return snapshot, errors.New("无法读取 Windows underlay routes")
	}
	defer windows.FreeMibTable(unsafe.Pointer(table))
	return buildWindowsUnderlay(first, table.Rows()), nil
}

func buildWindowsUnderlay(first *windows.IpAdapterAddresses, routes []windows.MibIpForwardRow2) windowsUnderlaySnapshot {
	var snapshot windowsUnderlaySnapshot
	var rows [][]byte
	type sourceInterface struct {
		address string
		metric  uint32
	}
	sources := make(map[uint64]sourceInterface)
	for adapter := first; adapter != nil; adapter = adapter.Next {
		if adapter.OperStatus != windows.IfOperStatusUp ||
			adapter.IfType == windows.IF_TYPE_SOFTWARE_LOOPBACK || adapter.FirstGatewayAddress == nil {
			continue
		}
		managed := false
		for value := adapter.FirstUnicastAddress; value != nil; value = value.Next {
			managed = managed || value.Address.IP().Equal(net.IPv4(172, 19, 0, 1))
		}
		if managed {
			continue
		}
		row := make([]byte, 0, 256)
		var number [8]byte
		binary.BigEndian.PutUint64(number[:], adapter.Luid)
		row = append(row, number[:]...)
		binary.BigEndian.PutUint32(number[:4], adapter.IfIndex)
		row = append(row, number[:4]...)
		binary.BigEndian.PutUint32(number[:4], adapter.Ipv6IfIndex)
		row = append(row, number[:4]...)
		binary.BigEndian.PutUint32(number[:4], adapter.Ipv4Metric)
		row = append(row, number[:4]...)
		binary.BigEndian.PutUint32(number[:4], adapter.Ipv6Metric)
		row = append(row, number[:4]...)
		guid := adapter.NetworkGuid
		row = append(row, (*[16]byte)(unsafe.Pointer(&guid))[:]...)
		var addresses []string
		for value := adapter.FirstUnicastAddress; value != nil; value = value.Next {
			if ip := value.Address.IP(); ip != nil {
				addresses = append(addresses, "u:"+ip.String())
			}
		}
		for value := adapter.FirstGatewayAddress; value != nil; value = value.Next {
			if ip := value.Address.IP(); ip != nil {
				addresses = append(addresses, "g:"+ip.String())
			}
		}
		sort.Strings(addresses)
		for _, address := range addresses {
			row = append(row, 0)
			row = append(row, address...)
		}
		var ipv4 []string
		for value := adapter.FirstUnicastAddress; value != nil; value = value.Next {
			if ip := value.Address.IP().To4(); ip != nil {
				ipv4 = append(ipv4, ip.String())
			}
		}
		sort.Strings(ipv4)
		if len(ipv4) > 0 {
			sources[adapter.Luid] = sourceInterface{address: ipv4[0], metric: adapter.Ipv4Metric}
		}
		rows = append(rows, row)
	}
	for _, route := range routes {
		source, ok := sources[route.InterfaceLuid]
		if !ok || route.Loopback != 0 {
			continue
		}
		address := (*windows.RawSockaddrInet4)(unsafe.Pointer(&route.DestinationPrefix.Prefix))
		prefix := netip.PrefixFrom(netip.AddrFrom4(address.Addr), int(route.DestinationPrefix.PrefixLength)).Masked()
		snapshot.routes = append(snapshot.routes, windowsUnderlayRoute{prefix: prefix, source: source.address,
			metric: uint64(source.metric) + uint64(route.Metric), index: route.InterfaceIndex})
		// TUN 激活可能向物理接口添加精确绕行路由。这些路由参与选源，
		// 但不代表新 underlay；只有物理默认路由变化进入代次摘要。
		if prefix.Bits() == 0 {
			row := make([]byte, 16)
			binary.BigEndian.PutUint64(row, route.InterfaceLuid)
			binary.BigEndian.PutUint32(row[8:], route.Metric)
			nextHop := (*windows.RawSockaddrInet4)(unsafe.Pointer(&route.NextHop))
			copy(row[12:], nextHop.Addr[:])
			rows = append(rows, row)
		}
	}
	sort.Slice(rows, func(left, right int) bool { return string(rows[left]) < string(rows[right]) })
	digest := sha256.New()
	for _, row := range rows {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(row)))
		_, _ = digest.Write(length[:])
		_, _ = digest.Write(row)
	}
	snapshot.key = hex.EncodeToString(digest.Sum(nil))
	return snapshot
}

// 各 API 的 callback ABI 都是 VOID(PVOID, row*, MIB_NOTIFICATION_TYPE)。
// 不保留由 Windows 管理的 row 指针，重新读取完整快照；每次注册均用 AF_UNSPEC。
// https://learn.microsoft.com/windows/win32/api/netioapi/nf-netioapi-notifyipinterfacechange
func registerWindowsUnderlayChanges(notify func()) (func(), error) {
	callback := windows.NewCallback(func(_, _, _ uintptr) uintptr { notify(); return 0 })
	return registerWindowsUnderlayCallbacks(callback, []windowsUnderlayRegistration{
		windows.NotifyIpInterfaceChange, windows.NotifyUnicastIpAddressChange, windows.NotifyRouteChange2,
	}, windows.CancelMibChangeNotify2)
}

type windowsUnderlayRegistration func(uint16, uintptr, unsafe.Pointer, bool, *windows.Handle) error

func registerWindowsUnderlayCallbacks(callback uintptr, registrations []windowsUnderlayRegistration,
	cancel func(windows.Handle) error,
) (func(), error) {
	var handles []windows.Handle
	var once sync.Once
	stop := func() {
		once.Do(func() {
			for _, handle := range handles {
				_ = cancel(handle)
			}
		})
	}
	for _, register := range registrations {
		var handle windows.Handle
		if err := register(windows.AF_UNSPEC, callback, nil, false, &handle); err != nil {
			stop()
			return nil, errors.New("Windows 底层网络事件订阅失败")
		}
		handles = append(handles, handle)
	}
	return stop, nil
}
