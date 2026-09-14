//go:build !windows

package clientruntime

// WindowsUnderlayGeneration 在非 Windows 构建中只为共享激活事务测试提供稳定代次。
// 生产 Windows 二进制使用 GetAdaptersAddresses 生成不落盘的真实 underlay 摘要。
func WindowsUnderlayGeneration() (string, error) {
	return "non-windows-activation-test-v1", nil
}
