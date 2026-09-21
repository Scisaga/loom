package linuxclient

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"loom/internal/control"
)

func TestMigrationOverlayStagesAppliesAndFinalizesExactBoundary(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "legacy.json")
	overlayPath := filepath.Join(root, "migration.json")
	legacy := `{
  "log":{"level":"warn"},
  "inbounds":[{"type":"hysteria2","tag":"in","listen":"::","listen_port":443,
    "users":[{"name":"demo-old","password":"demo-old-password"}],"tls":{"enabled":true}}],
  "outbounds":[{"type":"direct","tag":"egress"},{"type":"direct","tag":"via-peer","bind_interface":"wg-demo-peer"}],
  "route":{"rules":[
    {"auth_user":["demo-old"],"domain":["example.com"],"outbound":"egress"},
    {"auth_user":["demo-old"],"ip_cidr":["192.0.2.9/32"],"port":[443],"outbound":"via-peer"}
  ],"final":"block"}}
`
	if err := os.WriteFile(source, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	digest, err := StageMigrationOverlay(source, overlayPath)
	if err != nil {
		t.Fatal(err)
	}
	if info, err := os.Lstat(overlayPath); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("overlay permissions = %v, %v", info, err)
	}
	if repeated, err := StageMigrationOverlay(source, overlayPath); err != nil || repeated != digest {
		t.Fatalf("staging the same source was not idempotent: digest=%q err=%v", repeated, err)
	}
	different := filepath.Join(root, "different.json")
	if err := os.WriteFile(different, []byte(strings.Replace(legacy, "demo-old-password", "changed-password", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := StageMigrationOverlay(different, overlayPath); err == nil {
		t.Fatal("a different source replaced the staged migration overlay")
	}
	profile := control.ServerRuntimeProfile{Kind: "sing_box", Protocol: "hysteria2", ListenPort: 443,
		Users: []control.ServerRuntimeUser{{Name: "demo-new", Password: strings.Repeat("A", 43)}},
		ACL:   []control.ServerRuntimeACL{{User: "demo-new", Action: "egress", DestinationMatchers: []string{"new.example"}}}}
	config, err := renderServerRuntime(profile, "/demo/cert", "/demo/key")
	if err != nil {
		t.Fatal(err)
	}
	merged, exact, err := applyMigrationOverlay(config, controlServerProfile{Protocol: "hysteria2", ListenPort: 443}, overlayPath)
	if err != nil {
		t.Fatal(err)
	}
	if exact {
		t.Fatal("runtime with migration overlay was reported exact")
	}
	for _, value := range []string{"demo-new", "demo-old", "wg-demo-peer", "example.com", "192.0.2.9/32"} {
		if !strings.Contains(merged, value) {
			t.Fatalf("merged runtime lost %q: %s", value, merged)
		}
	}
	var document struct {
		Route struct {
			Rules []map[string]any `json:"rules"`
		} `json:"route"`
	}
	if err := json.Unmarshal([]byte(merged), &document); err != nil {
		t.Fatal(err)
	}
	if got := document.Route.Rules[len(document.Route.Rules)-1]["outbound"]; got != "loom-server-block" {
		t.Fatalf("migration rules escaped the fail-closed boundary: final outbound=%v", got)
	}
	if err := FinalizeMigrationOverlay(overlayPath, strings.Repeat("0", 64)); err == nil {
		t.Fatal("finalize accepted the wrong source digest")
	}
	if err := FinalizeMigrationOverlay(overlayPath, digest); err != nil {
		t.Fatal(err)
	}
	plain, exact, err := applyMigrationOverlay(config, controlServerProfile{Protocol: "hysteria2", ListenPort: 443}, overlayPath)
	if err != nil || !exact || plain != config {
		t.Fatalf("finalized runtime is not exact: exact=%v err=%v", exact, err)
	}
}

func TestMigrationOverlayRejectsUnsupportedLegacyAuthority(t *testing.T) {
	for name, body := range map[string]string{
		"unknown authenticated rule": `{"inbounds":[{"type":"hysteria2","tag":"in","listen_port":443,"users":[{"name":"demo","password":"secret"}],"tls":{}}],"outbounds":[{"type":"direct","tag":"egress"}],"route":{"rules":[{"auth_user":["demo"],"rule_set":["old-policy"],"outbound":"egress"}]}}`,
		"non direct outbound":        `{"inbounds":[{"type":"hysteria2","tag":"in","listen_port":443,"users":[{"name":"demo","password":"secret"}],"tls":{}}],"outbounds":[{"type":"hysteria2","tag":"relay"}],"route":{"rules":[{"auth_user":["demo"],"outbound":"relay"}]}}`,
		"duplicate field":            `{"inbounds":[],"inbounds":[],"outbounds":[],"route":{"rules":[]}}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := extractMigrationOverlay([]byte(body)); err == nil {
				t.Fatal("unsafe legacy runtime was accepted")
			}
		})
	}
}

func TestMigrationOverlayKeepsOnlyThePublicServerInboundAuthority(t *testing.T) {
	legacy := `{
  "inbounds":[
    {"type":"mixed","tag":"local-auth","listen_port":1080,"users":[{"username":"local-user","password":"local-secret"}]},
    {"type":"hysteria2","tag":"server-in","listen_port":443,"users":[{"name":"server-user","password":"server-secret"}],"tls":{}}
  ],
	  "outbounds":[{"type":"direct","tag":"egress"},{"type":"block","tag":"deny"}],
	  "route":{"rules":[
	    {"auth_user":["local-user"],"inbound":["local-auth"],"outbound":"egress"},
	    {"auth_user":["server-user","local-user"],"inbound":["server-in"],"domain":["example.com"],"outbound":"egress"},
	    {"auth_user":["server-user"],"inbound":["server-in"],"ip_cidr":["192.0.2.1/32"],"outbound":"deny"},
	    {"auth_user":["local-user"],"outbound":"egress"}
	  ]}}
`
	overlay, err := extractMigrationOverlay([]byte(legacy))
	if err != nil {
		t.Fatal(err)
	}
	if len(overlay.Users) != 1 || overlay.Users[0].Name != "server-user" || len(overlay.Rules) != 2 ||
		len(overlay.Rules[0].Users) != 1 || overlay.Rules[0].Users[0] != "server-user" {
		t.Fatalf("non-server authenticated authority escaped the migration boundary: %+v", overlay)
	}
	foundBlock := false
	for _, outbound := range overlay.Outbounds {
		foundBlock = foundBlock || outbound.Kind == "block"
	}
	if !foundBlock {
		t.Fatalf("server fail-closed authority was not retained: %+v", overlay.Outbounds)
	}
}

func TestMigrationOverlayRequiresCertifiedListenerMatch(t *testing.T) {
	overlay := migrationOverlay{Schema: 1, SourceSHA256: strings.Repeat("0", 64), Protocol: "hysteria2", ListenPort: 443,
		Users: []migrationUser{{Name: "demo-old", Password: "secret"}}}
	body, _ := json.Marshal(overlay)
	path := filepath.Join(t.TempDir(), "overlay.json")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := applyMigrationOverlay(`{"inbounds":[],"outbounds":[],"route":{"rules":[]}}`,
		controlServerProfile{Protocol: "trojan", ListenPort: 443}, path); err == nil {
		t.Fatal("migration overlay changed the certified listener")
	}
}
