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
	caSource := os.Getenv("LOOM_TEST_CA_CERTIFICATE")
	if executable == "" || caSource == "" {
		t.Skip("set LOOM_SING_BOX_EXECUTABLE and LOOM_TEST_CA_CERTIFICATE for the official Windows config check")
	}
	caBody, err := os.ReadFile(caSource)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	caPath := filepath.Join(root, "tls", "ca.crt")
	if err := os.MkdirAll(filepath.Dir(caPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(caPath, caBody, 0o600); err != nil {
		t.Fatal(err)
	}
	source := strings.NewReplacer("${secret:vault:cred/win01}", "fixture-password",
		"${secret:api/win01}", "fixture-api").Replace(validWindowsConfig("warn"))
	for _, profile := range []WindowsRuntimeProfile{WindowsPortableTUNProfile, WindowsPortableMixedProfile} {
		t.Run(string(profile), func(t *testing.T) {
			config, err := DeriveWindowsRuntimeConfig([]byte(source), profile, caPath)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(config)
			if err := PreflightWindowsRuntime(context.Background(), executable, config,
				filepath.Join(root, "runtime"), profile, caPath); err != nil {
				t.Fatal(err)
			}
		})
	}
}
