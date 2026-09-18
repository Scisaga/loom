package localconfig

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const validConfig = "GANDI_PAT_TOKEN=demo-token\n" +
	"LOOM_DEPLOY_HOSTS='demo-b demo-a'\n" +
	"LOOM_LOCAL_NODE='demo-a'\n" +
	"LOOM_SSH_CONFIG='.ssh_config'\n" +
	"LOOM_SIGNING_KEY='keys/platform.key'\n" +
	"LOOM_PUBLISH_OUTPUTS='/srv/releases,ssh://demo-b/srv/releases'\n"

func TestRoundTripCanonicalSixKeys(t *testing.T) {
	anchor := t.TempDir()
	got, err := Decode([]byte(validConfig), anchor)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := Encode(got, anchor)
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Replace(validConfig, "demo-b demo-a", "demo-a demo-b", 1)
	if string(encoded) != want {
		t.Fatalf("canonical encoding mismatch:\n%s", encoded)
	}
	again, err := Decode(encoded, anchor)
	if err != nil || !reflect.DeepEqual(got, again) {
		t.Fatalf("round trip: got=%+v err=%v", again, err)
	}
}

func TestRejectsAmbiguousOrUnsafeInput(t *testing.T) {
	tests := map[string]string{
		"unknown key":     validConfig + "LOOM_EXTRA='x'\n",
		"missing key":     strings.Replace(validConfig, "LOOM_LOCAL_NODE='demo-a'\n", "", 1),
		"duplicate key":   validConfig + "LOOM_LOCAL_NODE='demo-a'\n",
		"shell expansion": strings.Replace(validConfig, "keys/platform.key", "${HOME}/key", 1),
		"duplicate host":  strings.Replace(validConfig, "demo-b demo-a", "demo-a demo-a", 1),
		"invalid target":  strings.Replace(validConfig, "/srv/releases,ssh://demo-b/srv/releases", "relative/output", 1),
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Decode([]byte(input), t.TempDir()); err == nil {
				t.Fatal("unsafe input accepted")
			}
		})
	}
}

func TestLoadRejectsWidePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(path, []byte(validConfig), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("wide permissions accepted")
	}
}

func TestMigrateHistoricalPublishListOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".env")
	historical := strings.Replace(validConfig,
		"'/srv/releases,ssh://demo-b/srv/releases'",
		"'[\"/srv/releases\",\"ssh://demo-b/srv/releases\"]'", 1)
	if err := os.WriteFile(path, []byte("# local input\n"+historical), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("normal loader accepted historical representation")
	}
	if err := Migrate(path); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != strings.Replace(validConfig, "demo-b demo-a", "demo-a demo-b", 1) {
		t.Fatalf("migration was not canonical: %s", first)
	}
	if err := Migrate(path); err != nil {
		t.Fatal(err)
	}
	second, _ := os.ReadFile(path)
	if !reflect.DeepEqual(first, second) {
		t.Fatal("idempotent migration changed canonical bytes")
	}
}
