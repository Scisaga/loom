//go:build windows

package clientruntime

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"sort"
	"unsafe"

	"golang.org/x/sys/windows"
)

// WindowsUnderlayGeneration 对探测发生前的 Windows 有效网卡、NetworkGuid、
// unicast 与 gateway 坐标取进程内 opaque digest。digest 不写日志或协议，只用于
// 判定何时允许下一轮“一入口一个 ICMP”探测。
func WindowsUnderlayGeneration() (string, error) {
	const flags = windows.GAA_FLAG_INCLUDE_GATEWAYS |
		windows.GAA_FLAG_SKIP_ANYCAST |
		windows.GAA_FLAG_SKIP_MULTICAST |
		windows.GAA_FLAG_SKIP_DNS_SERVER
	var size uint32
	err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, flags, 0, nil, &size)
	if !errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) || size == 0 {
		return "", errors.New("无法读取 Windows underlay generation")
	}
	buffer := make([]byte, size)
	first := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buffer[0]))
	if err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, flags, 0, first, &size); err != nil {
		return "", errors.New("无法读取 Windows underlay adapters")
	}
	var rows [][]byte
	for adapter := first; adapter != nil; adapter = adapter.Next {
		if adapter.OperStatus != windows.IfOperStatusUp ||
			adapter.IfType == windows.IF_TYPE_SOFTWARE_LOOPBACK || adapter.FirstGatewayAddress == nil {
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
		rows = append(rows, row)
	}
	if len(rows) == 0 {
		return "", errors.New("Windows 没有可用的 gateway underlay")
	}
	sort.Slice(rows, func(left, right int) bool { return string(rows[left]) < string(rows[right]) })
	digest := sha256.New()
	for _, row := range rows {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(row)))
		_, _ = digest.Write(length[:])
		_, _ = digest.Write(row)
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}
