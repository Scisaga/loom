//go:build windows

package main

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	windowsJoinLockName      = `Global\LoomWindowsNetworkJoinV1`
	windowsPortableLockName  = `Global\LoomWindowsPortableStateV1`
	windowsDataPlaneLockName = `Global\LoomWindowsDataPlaneV1`
	windowsLockSDDL          = `D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x00100000;;;AU)`
)

// windowsNamedLock uses the lifetime of a named kernel event as an
// owner-independent process lock. Unlike a Windows mutex, closing it is not
// tied to the OS thread on which a Go goroutine acquired it. Kernel handles
// also close automatically if a process crashes.
type windowsNamedLock struct {
	handle windows.Handle
}

func acquireWindowsNamedLock(name, busyMessage string) (*windowsNamedLock, error) {
	wideName, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	descriptor, err := windows.SecurityDescriptorFromString(windowsLockSDDL)
	if err != nil {
		return nil, fmt.Errorf("build Windows client lock security descriptor: %w", err)
	}
	attributes := &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: descriptor,
	}
	handle, createErr := windows.CreateEventEx(attributes, wideName, 0, windows.SYNCHRONIZE)
	if handle == 0 {
		return nil, fmt.Errorf("create Windows client lock: %w", createErr)
	}
	if errors.Is(createErr, windows.ERROR_ALREADY_EXISTS) {
		_ = windows.CloseHandle(handle)
		return nil, errors.New(busyMessage)
	}
	if createErr != nil {
		_ = windows.CloseHandle(handle)
		return nil, fmt.Errorf("create Windows client lock: %w", createErr)
	}
	return &windowsNamedLock{handle: handle}, nil
}

func (lock *windowsNamedLock) close() {
	if lock == nil || lock.handle == 0 {
		return
	}
	_ = windows.CloseHandle(lock.handle)
	lock.handle = 0
}

func acquireWindowsJoinLock() (*windowsNamedLock, error) {
	return acquireWindowsNamedLock(windowsJoinLockName, "另一个 Loom 设备加入操作正在进行")
}

func acquireWindowsClientUILock() (*windowsNamedLock, error) {
	return acquireWindowsNamedLock(windowsPortableLockName, "另一个 Loom Windows 客户端正在运行")
}

func acquireWindowsDataPlaneLock() (*windowsNamedLock, error) {
	return acquireWindowsNamedLock(windowsDataPlaneLockName, "另一个 Loom 客户端已经占用数据面")
}
