package main

import (
	"runtime"
	"syscall"
	"unsafe"
)

func misakaCreateTextLayout(method uintptr, args *misakaTextLayoutArgs) uintptr {
	// §7.2：x64 的宽高浮点参数在栈中，按低 32 位原样传入系统 COM 方法。
	hr, _, _ := syscall.SyscallN(method, uintptr(unsafe.Pointer(args.factory)), uintptr(unsafe.Pointer(args.text)), args.length,
		uintptr(unsafe.Pointer(args.format)), args.width, args.height, uintptr(unsafe.Pointer(args.output)))
	runtime.KeepAlive(args)
	return hr
}
