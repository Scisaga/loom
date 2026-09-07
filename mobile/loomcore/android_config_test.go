package loomcore

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRelocateAndroidCARewritesEveryExactDefault(t *testing.T) {
	digest := strings.Repeat("a", 64)
	wanted := "tls/ca-" + digest + ".crt"
	input := []byte(`{
  "outbounds": [
    {"tls":{"certificate_path":"tls/ca.crt"}},
    {"nested":[{"certificate_path":"tls/ca.crt"}]}
  ],
  "large": 9007199254740993
}`)
	body, err := RelocateAndroidCA(input, wanted)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(body), wanted) != 2 || strings.Contains(string(body), androidDefaultCAPath) ||
		!strings.Contains(string(body), "9007199254740993") {
		t.Fatalf("relocated=%s", body)
	}
	var document map[string]any
	if err := json.Unmarshal(body, &document); err != nil {
		t.Fatal(err)
	}
}

func TestRelocateAndroidCAFailsClosed(t *testing.T) {
	validPath := "tls/ca-" + strings.Repeat("b", 64) + ".crt"
	for _, test := range []struct {
		name, config, path string
	}{
		{"absolute target", `{"certificate_path":"tls/ca.crt"}`, "/data/ca.crt"},
		{"uppercase digest", `{"certificate_path":"tls/ca.crt"}`, "tls/ca-" + strings.Repeat("A", 64) + ".crt"},
		{"traversal", `{"certificate_path":"tls/ca.crt"}`, "tls/../ca-" + strings.Repeat("a", 64) + ".crt"},
		{"missing field", `{"tls":{"enabled":true}}`, validPath},
		{"wrong source", `{"certificate_path":"/etc/loom/ca.crt"}`, validPath},
		{"non-string source", `{"certificate_path":null}`, validPath},
		{"duplicate key", `{"certificate_path":"tls/ca.crt","certificate_path":"tls/ca.crt"}`, validPath},
		{"array root", `[{"certificate_path":"tls/ca.crt"}]`, validPath},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := RelocateAndroidCA([]byte(test.config), test.path); err == nil {
				t.Fatal("unsafe CA relocation was accepted")
			}
		})
	}
}
