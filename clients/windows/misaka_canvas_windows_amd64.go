package main

import (
	"runtime"
	"syscall"
	"unsafe"
)

func misakaCreateTextFormat(method uintptr, args *misakaTextFormatArgs) uintptr {
	// §7.2：第七个 C 参数位于 x64 栈中；SyscallN 原样复制其低 32 位，
	// 满足 Windows x64 ABI 对 float 字号参数的要求。
	hr, _, _ := syscall.SyscallN(method, uintptr(unsafe.Pointer(args.factory)), uintptr(unsafe.Pointer(args.family)), args.collection,
		args.weight, args.style, args.stretch, args.size, uintptr(unsafe.Pointer(args.locale)), uintptr(unsafe.Pointer(args.output)))
	runtime.KeepAlive(args)
	return hr
}
