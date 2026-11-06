package control

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// Parse the real locally derived access configuration with the reviewed native
// executable. The check command never starts capture, listeners or transports.
func TestNativeAcceptsLocallyDerivedStableAuthorizationRuntime(t *testing.T) {
	executable := os.Getenv("LOOM_SING_BOX_EXECUTABLE")
	if executable == "" {
		t.Skip("requires the reviewed native executable")
	}
	p := relayProjectionFixture(t)
	for i := range p.NetworkIntent.Resources {
		if p.NetworkIntent.Resources[i].Kind == "wireguard" {
			p.NetworkIntent.Resources[i].AccessEnabled = true
		}
	}
	view, err := ProjectDeviceView(p, "demo-access")
	if err != nil {
		t.Fatal(err)
	}
	execution, err := ProjectDeviceExecution(view, testPolicyIDs(view))
	if err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(t.TempDir(), "demo-runtime.json")
	if err := os.WriteFile(config, []byte(execution.RuntimeProfile.Config), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if output, err := exec.CommandContext(ctx, executable, "check", "-c", config).CombinedOutput(); err != nil {
		if len(output) > 4096 {
			output = output[:4096]
		}
		t.Fatalf("native parser rejected stable-authorization runtime: %v\n%s", err, output)
	}
}
