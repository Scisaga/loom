//go:build windows

package clientruntime

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 按 §7.2.1 只执行固定版本的 check，验证本地接管适配，不创建网卡或改路由。
func TestOfficialWindowsTUNCaptureCheck(t *testing.T) {
	executable := os.Getenv("LOOM_SING_BOX_EXECUTABLE")
	if executable == "" {
		t.Skip("set LOOM_SING_BOX_EXECUTABLE for Windows syntax check")
	}
	root := t.TempDir()
	source := strings.NewReplacer("${secret:vault:cred/win01}", "fixture-password",
		"${secret:api/win01}", "fixture-api").Replace(validWindowsConfig("warn"))
	for _, profile := range []WindowsRuntimeProfile{WindowsPortableTUNProfile, WindowsPortableMixedProfile} {
		t.Run(string(profile), func(t *testing.T) {
			config, err := DeriveWindowsRuntimeConfig([]byte(source), profile, []string{"192.0.2.53"})
			if err != nil {
				t.Fatal(err)
			}
			defer clear(config)
			if err := PreflightWindowsRuntime(context.Background(), executable, config,
				filepath.Join(root, "runtime"), profile); err != nil {
				t.Fatal(err)
			}
		})
	}
}
