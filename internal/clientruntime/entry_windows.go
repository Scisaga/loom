//go:build windows

package clientruntime

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"loom/internal/agent"
)

var icmpDLL = windows.NewLazySystemDLL("iphlpapi.dll")
var icmpCreate = icmpDLL.NewProc("IcmpCreateFile")
var icmpClose = icmpDLL.NewProc("IcmpCloseHandle")
var icmpSend = icmpDLL.NewProc("IcmpSendEcho2Ex")

// §7.2.1：TUN 启动前只读系统路由，不改路由，也不发送探测包。
func entrySource(address string) string {
	var dest windows.SockaddrInet4
	if ip := net.ParseIP(address).To4(); ip != nil {
		copy(dest.Addr[:], ip)
	}
	var index uint32
	if windows.GetBestInterfaceEx(&dest, &index) != nil {
		return ""
	}
	iface, err := net.InterfaceByIndex(int(index))
	if err != nil {
		return ""
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		ip, _, _ := net.ParseCIDR(a.String())
		if ip.To4() != nil && !ip.Equal(net.IPv4(172, 19, 0, 1)) {
			return ip.String()
		}
	}
	return ""
}

// §5.6：每入口只发一个 ICMP echo；失败保持未知，不重试或降级为业务探测。
// Win32 契约：https://learn.microsoft.com/windows/win32/api/icmpapi/nf-icmpapi-icmpsendecho2ex
func pingWindowsEntry(ctx context.Context, e agent.ClientEntry) (time.Duration, error) {
	unknown := errors.New("入口单次 ping 未获响应")
	source := net.ParseIP(e.Source).To4()
	if source == nil {
		return 0, errors.New("入口探测缺少 TUN 之外的源地址")
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	ip := net.ParseIP(e.Address).To4()
	if ip == nil {
		ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", e.Address)
		if err != nil || len(ips) == 0 {
			return 0, unknown
		}
		ip = ips[0].To4()
	}
	if ip == nil {
		return 0, unknown
	}
	remaining := time.Second
	if deadline, ok := ctx.Deadline(); ok {
		remaining = min(remaining, time.Until(deadline))
	}
	if remaining <= 0 || ctx.Err() != nil {
		return 0, context.DeadlineExceeded
	}
	handle, _, _ := icmpCreate.Call()
	if handle == ^uintptr(0) {
		return 0, unknown
	}
	defer icmpClose.Call(handle)
	payload := [8]byte{'l', 'o', 'o', 'm', 'p', 'i', 'n', 'g'}
	// ICMP_ECHO_REPLY 的前三个 DWORD 在 amd64/arm64 布局相同；额外空间容纳载荷与系统字段。
	reply := make([]byte, 256)
	n, _, _ := icmpSend.Call(handle, 0, 0, 0, uintptr(binary.LittleEndian.Uint32(source)), uintptr(binary.LittleEndian.Uint32(ip)),
		uintptr(unsafe.Pointer(&payload[0])), uintptr(len(payload)), 0, uintptr(unsafe.Pointer(&reply[0])), uintptr(len(reply)), uintptr(max(1, remaining.Milliseconds())))
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if n == 0 || binary.LittleEndian.Uint32(reply[4:8]) != 0 {
		return 0, unknown
	}
	return time.Duration(binary.LittleEndian.Uint32(reply[8:12])) * time.Millisecond, nil
}
