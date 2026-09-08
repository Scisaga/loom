package main

import (
	"runtime"
	"syscall"
	"unsafe"
)

func misakaTextFormatBridgeAddress() uintptr

func misakaCreateTextFormat(method uintptr, args *misakaTextFormatArgs) uintptr {
	// §7.2：SyscallN 先切到系统栈；原生桥再把字号写入 S0，
	// 满足 Windows ARM64 浮点参数 ABI。
	hr, _, _ := syscall.SyscallN(misakaTextFormatBridgeAddress(), method, uintptr(unsafe.Pointer(args)))
	runtime.KeepAlive(args)
	return hr
}
