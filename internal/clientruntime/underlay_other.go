//go:build !windows

package clientruntime

// 非 Windows 构建只为共享激活测试提供稳定、没有探测源地址的事件源。
func readWindowsUnderlay() (windowsUnderlaySnapshot, error) {
	return windowsUnderlaySnapshot{key: "non-windows-activation-test"}, nil
}

func registerWindowsUnderlayChanges(func()) (func(), error) { return func() {}, nil }
