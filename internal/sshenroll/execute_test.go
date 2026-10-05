package sshenroll

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"loom/internal/localconfig"
)

func TestExecutorUsesSelectedInputsAndBoundsPrivateTransport(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("SSH shell adapter runs on the control host")
	}
	root := t.TempDir()
	config := localconfig.Config{DeployHosts: []string{"demo-local", "demo-remote"}, LocalNode: "demo-local", SSHConfig: filepath.Join(root, ".ssh_config"), SigningKey: filepath.Join(root, "demo.key"), PublishOutputs: []string{"/srv/demo-releases"}, Nodes: []localconfig.NodeNetwork{
		{ID: "demo-local", ManagementHost: "127.0.0.1", ManagementPort: 2222, HostAddresses: []string{"192.0.2.1"}, Ingress: []localconfig.IngressMapping{}},
		{ID: "demo-remote", ManagementHost: "192.0.2.20", ManagementPort: 2222, HostAddresses: []string{"192.0.2.20"}, Ingress: []localconfig.IngressMapping{}},
	}}
	yaml, err := localconfig.EncodeDeployment(config, root)
	if err != nil {
		t.Fatal(err)
	}
	envPath := filepath.Join(root, ".env")
	for name, body := range map[string][]byte{".env": []byte("GANDI_PAT_TOKEN=demo-secret\nLOOM_DEPLOY_CONFIG='deploy.yaml'\n"), "deploy.yaml": yaml, ".ssh_config": []byte("Host demo-remote\n  HostName demo-target.example\n")} {
		if err := os.WriteFile(filepath.Join(root, name), body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	fake := `#!/bin/sh
set -eu
[ -z "${GANDI_PAT_TOKEN+x}" ] || exit 72
printf '%s\n' "$@" > "$DEMO_ARGS"
for arg do
 if [ "$arg" = '-G' ]; then printf 'hostname demo-target.example\nport 2222\n'; exit 0; fi
done
if [ "${DEMO_WAIT:-}" = 1 ]; then exec sleep 60; fi
cat > "$DEMO_STDIN"
printf 'demo-private-banner\n' >&2
exit "${DEMO_EXIT:-0}"
`
	if err := os.WriteFile(filepath.Join(root, "ssh"), []byte(fake), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", root+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("GANDI_PAT_TOKEN", "demo-environment-secret")
	t.Setenv("DEMO_ARGS", filepath.Join(root, "args"))
	t.Setenv("DEMO_STDIN", filepath.Join(root, "stdin"))
	executor, err := New(envPath)
	if err != nil {
		t.Fatal(err)
	}
	target, err := executor.Resolve(context.Background(), "demo-remote")
	if err != nil || !target.CoordinatesDiffer || target.ResolvedHost != "demo-target.example" || target.ConfiguredHost != "192.0.2.20" {
		t.Fatal("SSH coordinates silently replaced deployment coordinates", err)
	}
	const input = "demo sensitive invitation stays on stdin\n"
	if _, err := executor.Run(context.Background(), "demo-remote", input); err != nil {
		t.Fatal(err)
	}
	args, _ := os.ReadFile(filepath.Join(root, "args"))
	stdin, _ := os.ReadFile(filepath.Join(root, "stdin"))
	if string(stdin) != input || strings.Contains(string(args), input) {
		t.Fatal("input escaped stdin")
	}
	for _, required := range []string{config.SSHConfig, "BatchMode=yes", "StrictHostKeyChecking=yes", "ClearAllForwardings=yes", "ControlPath=none", "demo-remote"} {
		if !strings.Contains(string(args), required) {
			t.Fatal("missing SSH boundary", required)
		}
	}
	for _, invalid := range []string{"demo-unknown", "-oProxyCommand=bad", "demo-target;bad", "user@demo-remote"} {
		if _, err := executor.Run(context.Background(), invalid, input); err == nil {
			t.Fatal("unselected or invalid target executed")
		}
	}
	for _, test := range []struct{ exit, code string }{{"42", "target_command_failed"}, {"255", "connection_unconfirmed"}} {
		t.Setenv("DEMO_EXIT", test.exit)
		_, err := executor.Run(context.Background(), "demo-remote", input)
		var failure *Failure
		if !errors.As(err, &failure) || failure.Code != test.code || strings.Contains(err.Error(), "private-banner") {
			t.Fatal("execution and connection results conflated or private error exposed", err)
		}
	}
	t.Setenv("DEMO_WAIT", "1")
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := executor.Run(ctx, "demo-remote", input); err == nil || err.Error() != "connection_interrupted" {
		t.Fatal("timeout claimed a target execution result", err)
	}
	if os.Geteuid() == 0 {
		body, err := executor.Run(context.Background(), "demo-local", "printf 'demo local execution\\n'\n")
		if err != nil || string(body) != "demo local execution\n" {
			t.Fatal("local target went through SSH", err)
		}
	}
	actual, _ := os.ReadFile(filepath.Join(root, "deploy.yaml"))
	if string(actual) != string(yaml) {
		t.Fatal("execution rewrote deployment inputs")
	}
}
