//go:build windows

package clientruntime

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestWindowsHealthMissingPlan(t *testing.T) {
	if got := CheckWindowsHealth(context.Background(), nil); len(got) == 0 {
		t.Fatal("missing runtime plan accepted")
	}
}

// §7.2.1：显式选择正在运行的已派生配置，实际请求只读，不修改网卡或已加入身份。
func TestWindowsHealthLive(t *testing.T) {
	configPath := os.Getenv("LOOM_HEALTH_RUNTIME_CONFIG")
	if configPath == "" {
		t.Skip("set LOOM_HEALTH_RUNTIME_CONFIG, LOOM_HEALTH_PROFILE and LOOM_HEALTH_CA for a live health check")
	}
	body, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal("cannot read active runtime config")
	}
	defer clear(body)
	plan, err := BuildWindowsHealthPlan(body, WindowsRuntimeProfile(os.Getenv("LOOM_HEALTH_PROFILE")), os.Getenv("LOOM_HEALTH_CA"))
	if err != nil {
		t.Fatal("cannot derive active health plan")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if problems := CheckWindowsHealth(ctx, plan); len(problems) != 0 {
		t.Fatalf("live health: %v", problems)
	}
}
