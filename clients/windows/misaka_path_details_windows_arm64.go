package main

import (
	"runtime"
	"syscall"
	"unsafe"
)

func misakaTextLayoutBridgeAddress() uintptr

func misakaCreateTextLayout(method uintptr, args *misakaTextLayoutArgs) uintptr {
	// §7.2：沿用文字格式的系统栈桥，将宽高分别放入 ARM64 的 S0/S1。
	hr, _, _ := syscall.SyscallN(misakaTextLayoutBridgeAddress(), method, uintptr(unsafe.Pointer(args)))
	runtime.KeepAlive(args)
	return hr
}
