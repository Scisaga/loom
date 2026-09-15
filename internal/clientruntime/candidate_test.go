package clientruntime

import (
	"bytes"
	"fmt"
	"loom/internal/secret"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func validWindowsConfig(logLevel string) string {
	return fmt.Sprintf(`{
  "log": {"level": %q},
  "dns": {"servers": [{"tag":"dns0","address":"1.1.1.1","detour":"dns-out"}]},
  "inbounds": [
    {"type":"tun","tag":"tun-in","address":["172.19.0.1/30"],"auto_route":true,"stack":"system"},
    {"type":"mixed","tag":"in-1080","listen":"127.0.0.1","listen_port":1080}
  ],
  "outbounds": [
    {"type":"direct","tag":"dns-out"},
    {"type":"hysteria2","tag":"cand:auto:edge","server":"edge.example.com","server_port":443,"password":"${secret:vault:cred/win01}","tls":{"enabled":true,"server_name":"edge.node.internal","certificate_path":"C:\\ProgramData\\Loom\\tls\\ca.crt","alpn":["h3"]}},
    {"type":"selector","tag":"decl:auto","outbounds":["cand:auto:edge"],"default":"cand:auto:edge"},
    {"type":"block","tag":"block"}
  ],
  "route": {"rules":[{"inbound":["tun-in","in-1080"],"outbound":"decl:auto"}],"final":"block"},
  "experimental": {"clash_api":{"external_controller":"127.0.0.1:61800","secret":"${secret:api/win01}"}}
}`, logLevel)
}

func validWindowsBundle(node, level string) map[string]string {
	config := validWindowsConfig(level)
	config = strings.Replace(config, `"inbounds": [`, `"inbounds": [{"type":"mixed","tag":"probe-in","listen":"127.0.0.1","listen_port":61801,"users":[{"username":"demo-probe","password":"${secret:api/win01}"}]},`, 1)
	config = strings.Replace(config, `"rules":[`, `"rules":[{"inbound":["probe-in"],"auth_user":["demo-probe"],"outbound":"cand:auto:edge"},`, 1)
	plan := fmt.Sprintf(`{"schema":1,"node":%q,"api":"127.0.0.1:61800","api_secret":"${secret:api/win01}","probe":"127.0.0.1:61801","probe_secret":"${secret:api/win01}","declarations":[{"id":"auto","selector":"decl:auto","objective":"latency","targets":["https://demo-target.example/"],"tuning_period":"1s","window":"1m","min_samples":3,"stale_after":"1m","switch_threshold":0.2,"candidates":[{"tag":"cand:auto:edge","chain":["demo-edge"],"probe_user":"demo-probe"}]}]}`, node)
	return map[string]string{"sing-box/config.json": config, "agent/config.json": plan}
}

func TestWindowsStructuralPreflightRejectsUnsafeShapes(t *testing.T) {
	valid := strings.NewReplacer(
		"${secret:vault:cred/win01}", "password",
		"${secret:api/win01}", "api",
	).Replace(validWindowsConfig("warn"))
	if err := ValidateWindowsSingBox([]byte(valid)); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ name, body, want string }{
		{"unresolved", strings.Replace(valid, `"password":"password"`, `"password":"${secret:bad}"`, 1), "unresolved"},
		{"public mixed", strings.Replace(valid, `"listen":"127.0.0.1"`, `"listen":"0.0.0.0"`, 1), "loopback"},
		{"no tun", strings.Replace(valid, `"type":"tun"`, `"type":"mixed"`, 1), "loopback"},
		{"not fail closed", strings.Replace(valid, `"final":"block"`, `"final":"direct"`, 1), "route.final"},
		{"wrong CA", strings.Replace(valid, `C:\\ProgramData\\Loom\\tls\\ca.crt`, `/etc/loom/tls/ca.crt`, 1), "Linux"},
		{"duplicate field", strings.Replace(valid, `"route": {`, `"route": {"final":"block",`, 1), "duplicate"},
		{"unknown selector member", strings.Replace(valid, `"outbounds":["cand:auto:edge"]`, `"outbounds":["missing"]`, 1), "invalid member"},
		{"unknown detour", strings.Replace(valid, `"server":"edge.example.com"`, `"detour":"missing","server":"edge.example.com"`, 1), "detour"},
		{"unknown route inbound", strings.Replace(valid, `"inbound":["tun-in","in-1080"]`, `"inbound":["tun-in","missing"]`, 1), "unknown inbound"},
		{"split managed rule", strings.Replace(valid, `"inbound":["tun-in","in-1080"]`, `"inbound":["tun-in"]`, 1), "share a routing rule"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := ValidateWindowsSingBox([]byte(test.body)); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("preflight result = %v, want %q", err, test.want)
			}
		})
	}
}

func TestDeriveWindowsRuntimeConfigSeparatesPortableCaptureSurfaces(t *testing.T) {
	source := strings.NewReplacer(
		"${secret:vault:cred/win01}", "password",
		"${secret:api/win01}", "api",
	).Replace(validWindowsConfig("warn"))
	source = strings.Replace(source,
		`"rules":[{"inbound":["tun-in","in-1080"],"outbound":"decl:auto"}]`,
		`"rules":[{"inbound":["tun-in"],"domain":["tun-only.example"],"outbound":"decl:auto"},{"inbound":["tun-in","in-1080"],"outbound":"decl:auto"}]`, 1)
	portableCA := `C:\Users\fixture\AppData\Local\LoomPortable\tls\ca.crt`

	mixed, err := DeriveWindowsRuntimeConfig([]byte(source), WindowsPortableMixedProfile, portableCA)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(mixed)
	if bytes.Contains(mixed, []byte(`"type": "tun"`)) || bytes.Contains(mixed, []byte(`"tun-in"`)) {
		t.Fatalf("Portable Mixed retained a TUN surface: %s", mixed)
	}
	if bytes.Contains(mixed, []byte("tun-only.example")) {
		t.Fatal("a TUN-only rule was broadened instead of removed")
	}
	if !bytes.Contains(mixed, []byte(`"in-1080"`)) || !bytes.Contains(mixed, []byte(`C:\\Users\\fixture`)) {
		t.Fatalf("Portable Mixed lost its managed inbound or portable CA: %s", mixed)
	}
	if err := ValidateWindowsRuntimeConfig(mixed, WindowsPortableMixedProfile, portableCA); err != nil {
		t.Fatal(err)
	}
	if err := ValidateWindowsSingBox(mixed); err == nil {
		t.Fatal("derived Portable Mixed config was accepted as a signed full Windows config")
	}

	for _, profile := range []WindowsRuntimeProfile{WindowsPortableTUNProfile, WindowsInstalledProfile} {
		caPath := portableCA
		if profile == WindowsInstalledProfile {
			caPath = WindowsInstalledCAPath
		}
		derived, err := DeriveWindowsRuntimeConfig([]byte(source), profile, caPath)
		if err != nil {
			t.Fatalf("derive %s: %v", profile, err)
		}
		if !bytes.Contains(derived, []byte(`"tun-in"`)) {
			t.Fatalf("%s unexpectedly removed TUN", profile)
		}
		clear(derived)
	}
}

func TestDeriveWindowsRuntimeConfigRejectsUnmanagedTarget(t *testing.T) {
	source := strings.NewReplacer(
		"${secret:vault:cred/win01}", "password",
		"${secret:api/win01}", "api",
	).Replace(validWindowsConfig("warn"))
	for _, caPath := range []string{
		`..\tls\ca.crt`,
		`C:\Users\fixture\..\escape\tls\ca.crt`,
		`\\server\share\tls\ca.crt`,
		`C:/Users/fixture/LoomPortable/tls/ca.crt`,
	} {
		if _, err := DeriveWindowsRuntimeConfig([]byte(source), WindowsPortableMixedProfile, caPath); err == nil {
			t.Fatalf("unsafe portable CA path was accepted: %q", caPath)
		}
	}
	if _, err := DeriveWindowsRuntimeConfig([]byte(source), "renamed", WindowsInstalledCAPath); err == nil {
		t.Fatal("unknown runtime profile was accepted")
	}
}

func TestWindowsStructuralPreflightAcceptsRenderedGolden(t *testing.T) {
	body, err := os.ReadFile("../../testdata/matrix/golden/workstation/sing-box/config.json")
	if err != nil {
		t.Fatal(err)
	}
	values := map[string]string{}
	for _, ref := range secret.Refs(string(body)) {
		values[ref] = "test-secret"
	}
	hydrated, missing := secret.Hydrate(string(body), values)
	if len(missing) != 0 {
		t.Fatalf("golden hydration is missing refs: %v", missing)
	}
	if err := ValidateWindowsSingBox([]byte(hydrated)); err != nil {
		t.Fatalf("rendered Windows golden failed structural preflight: %v", err)
	}
}

func TestWindowsAgentPairAcceptsCurrentRenderedGolden(t *testing.T) {
	files := map[string]string{}
	for _, path := range []string{"sing-box/config.json", "agent/config.json"} {
		body, err := os.ReadFile(filepath.Join("..", "..", "testdata", "matrix", "golden", "workstation", filepath.FromSlash(path)))
		if err != nil {
			t.Fatal(err)
		}
		values := map[string]string{}
		for _, ref := range secret.Refs(string(body)) {
			values[ref] = "demo-secret"
		}
		hydrated, missing := secret.Hydrate(string(body), values)
		if len(missing) != 0 {
			t.Fatal(missing)
		}
		files[path] = hydrated
	}
	if _, err := validateWindowsAgentPair([]byte(files["sing-box/config.json"]), []byte(files["agent/config.json"]), "workstation"); err != nil {
		t.Fatal(err)
	}
}
