//go:build windows

package clientruntime

import (
	"context"
	"loom/internal/clientadapter"
	"os"
	"path/filepath"
	"testing"
)

// 按 §7.2.1 只执行固定版本的 check，验证本地接管适配，不创建网卡或改路由。
func TestOfficialWindowsTUNCaptureCheck(t *testing.T) {
	executable := os.Getenv("LOOM_SING_BOX_EXECUTABLE")
	if executable == "" {
		t.Skip("set LOOM_SING_BOX_EXECUTABLE for Windows syntax check")
	}
	root := t.TempDir()
	for _, profile := range []WindowsRuntimeProfile{WindowsPortableTUNProfile, WindowsPortableMixedProfile} {
		t.Run(string(profile), func(t *testing.T) {
			config, err := DeriveWindowsRuntimeConfig(windowsViewFixture(t), profile, "demo-api", clientadapter.WebsiteAccess{}, new([]string{}))
			if err != nil {
				t.Fatal(err)
			}
			defer config.Clear()
			if err := PreflightWindowsRuntime(context.Background(), executable, config,
				filepath.Join(root, "runtime")); err != nil {
				t.Fatal(err)
			}
		})
	}
}
