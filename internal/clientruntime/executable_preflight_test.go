//go:build !windows

package clientruntime

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestReviewedTUNDNSExecutorFromEnvironment(t *testing.T) {
	root := os.Getenv("LOOM_WINDOWS_DATAPLANE_DIR")
	if root == "" || runtime.GOOS != "linux" {
		t.Skip("requires the current reviewed Linux executable")
	}
	config := []byte(`{"dns":{"fakeip":{"enabled":true}}}`)
	executable := filepath.Join(root, "sing-box-linux-"+runtime.GOARCH)
	if err := RequireTUNDNSExecutor(context.Background(), executable, config); err != nil {
		t.Fatal(err)
	}
	if previous := os.Getenv("LOOM_PREVIOUS_DATAPLANE_DIR"); previous != "" {
		if err := RequireTUNDNSExecutor(context.Background(), filepath.Join(previous, "sing-box-linux-"+runtime.GOARCH), config); err == nil {
			t.Fatal("current runtime accepted a superseded bundled executor")
		}
	}
}

func TestRunSingBoxCheckUsesEphemeralConfigAndSuppressesOutput(t *testing.T) {
	root := t.TempDir()
	executable := filepath.Join(root, "sing-box")
	script := "#!/bin/sh\ncase \"$1\" in check) ;; *) exit 91;; esac\n[ \"$2\" = -c ] || exit 92\n[ -f \"$3\" ] || exit 93\ngrep -q fixture-value \"$3\" || exit 94\nprintf 'sensitive diagnostic fixture-value' >&2\nexit 0\n"
	if err := os.WriteFile(executable, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	runtimeDir := filepath.Join(root, "runtime")
	if err := RunSingBoxCheck(context.Background(), executable, []byte(`{"fixture":"fixture-value"}`), runtimeDir); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(runtimeDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("plaintext preflight file leaked: %v", entries)
	}
}

func TestRunSingBoxCheckFailureDoesNotEchoDiagnostic(t *testing.T) {
	root := t.TempDir()
	executable := filepath.Join(root, "sing-box")
	if err := os.WriteFile(executable, []byte("#!/bin/sh\nprintf 'do-not-log-this-secret' >&2\nexit 7\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	err := RunSingBoxCheck(context.Background(), executable, []byte(`{"secret":"do-not-log-this-secret"}`), filepath.Join(root, "runtime"))
	if err == nil || strings.Contains(err.Error(), "do-not-log-this-secret") || !strings.Contains(err.Error(), "suppressed") {
		t.Fatalf("unexpected safe diagnostic error: %v", err)
	}
}
