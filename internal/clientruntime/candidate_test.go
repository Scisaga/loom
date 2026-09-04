package clientruntime

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"loom/internal/clientsecret"
	"loom/internal/clientupdate"
	"loom/internal/publish"
	"loom/internal/secret"
)

type runtimeProtector struct{}

func (runtimeProtector) Protect(purpose string, plaintext []byte) ([]byte, error) {
	out := append([]byte(purpose+"\x00"), plaintext...)
	for index := len(purpose) + 1; index < len(out); index++ {
		out[index] ^= 0x5a
	}
	return out, nil
}

func (runtimeProtector) Unprotect(purpose string, ciphertext []byte) ([]byte, error) {
	prefix := []byte(purpose + "\x00")
	if !bytes.HasPrefix(ciphertext, prefix) {
		return nil, errors.New("purpose mismatch")
	}
	out := append([]byte(nil), ciphertext[len(prefix):]...)
	for index := range out {
		out[index] ^= 0x5a
	}
	return out, nil
}

type runtimeTree struct {
	current, manifest, signature, bundle []byte
}

func makeRuntimeTree(t *testing.T, private ed25519.PrivateKey, generation uint64, snapshotID, node string,
	files map[string]string) runtimeTree {
	t.Helper()
	bundle := struct {
		Owner string            `json:"owner"`
		Files map[string]string `json:"files"`
	}{Owner: node, Files: files}
	bundleBody, _ := json.MarshalIndent(&bundle, "", "  ")
	bundleBody = append(bundleBody, '\n')
	manifest := struct {
		ID        string `json:"id"`
		CreatedAt string `json:"created_at"`
		SSOTHash  string `json:"ssot_hash"`
		Bundles   []struct {
			Owner string `json:"owner"`
			Hash  string `json:"hash"`
		} `json:"bundles"`
	}{ID: snapshotID, CreatedAt: "2026-09-02T12:00:00Z", SSOTHash: "sha256:" + strings.Repeat("a", 64)}
	manifest.Bundles = append(manifest.Bundles, struct {
		Owner string `json:"owner"`
		Hash  string `json:"hash"`
	}{Owner: node, Hash: runtimeBundleHash(files)})
	manifestBody, _ := json.MarshalIndent(&manifest, "", "  ")
	manifestBody = append(manifestBody, '\n')
	current := &publish.DeploymentCurrent{
		Schema: publish.DeploymentCurrentSchema, Generation: generation, Snapshot: snapshotID,
		PublishedAt: "2026-09-02T12:00:00Z",
	}
	if err := current.Sign(private); err != nil {
		t.Fatal(err)
	}
	currentBody, _ := current.Bytes()
	return runtimeTree{
		current: currentBody, manifest: manifestBody,
		signature: ed25519.Sign(private, manifestBody), bundle: bundleBody,
	}
}

func runtimeBundleHash(files map[string]string) string {
	paths := make([]string, 0, len(files))
	for path := range files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	hash := sha256.New()
	for _, path := range paths {
		content := files[path]
		fmt.Fprintf(hash, "%s\x00%d\x00%s\x00", path, len(content), content)
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func serveRuntimeTree(t *testing.T, tree *runtimeTree, node string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var body []byte
		switch {
		case request.URL.Path == "/current.json":
			body = tree.current
		case strings.HasSuffix(request.URL.Path, "/snapshot.json"):
			body = tree.manifest
		case strings.HasSuffix(request.URL.Path, "/snapshot.sig"):
			body = tree.signature
		case strings.HasSuffix(request.URL.Path, "/nodes/"+node+".json"):
			body = tree.bundle
		default:
			http.NotFound(writer, request)
			return
		}
		_, _ = writer.Write(body)
	}))
}

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

func installVerifiedRuntimeBundle(t *testing.T, root, node string, public ed25519.PublicKey,
	tree *runtimeTree) (*clientupdate.Updater, *httptest.Server) {
	t.Helper()
	server := serveRuntimeTree(t, tree, node)
	updater := &clientupdate.Updater{
		Client: server.Client(), Config: clientupdate.Config{
			Schema: clientupdate.ConfigSchema, NodeID: node, DistributionURLs: []string{server.URL},
		},
		PublicKey: public, StateRoot: root,
	}
	if _, err := updater.PullOnce(context.Background()); err != nil {
		server.Close()
		t.Fatal(err)
	}
	return updater, server
}

func TestPrepareWindowsCandidateHydratesPreflightsAndProtects(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	node, root := "win01", t.TempDir()
	tree := makeRuntimeTree(t, private, 1, "111111111111", node,
		map[string]string{"sing-box/config.json": validWindowsConfig("warn")})
	_, server := installVerifiedRuntimeBundle(t, root, node, public, &tree)
	defer server.Close()
	vaultPath := filepath.Join(root, "secrets", "vault.json.dpapi")
	secrets := map[string]string{"vault:cred/win01": "password-value", "api/win01": "api-value"}
	if err := clientsecret.WriteVault(vaultPath, secrets, runtimeProtector{}); err != nil {
		t.Fatal(err)
	}
	result, err := PrepareWindowsCandidate(root, node, public, vaultPath, runtimeProtector{})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Changed || result.SecretsUsed != 2 || result.Version.Generation != 1 {
		t.Fatalf("prepare result = %+v", result)
	}
	protectedBody, err := os.ReadFile(filepath.Join(root, "candidates", result.CandidateRef))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(protectedBody, []byte("password-value")) || bytes.Contains(protectedBody, []byte("api-value")) {
		t.Fatal("candidate persisted hydrated secrets in plaintext")
	}
	config, state, err := ReadCandidateConfig(root, runtimeProtector{})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(config)
	if !bytes.Contains(config, []byte("password-value")) || state.Current != result.Version {
		t.Fatalf("candidate did not round trip: state=%+v", state)
	}

	again, err := PrepareWindowsCandidate(root, node, public, vaultPath, runtimeProtector{})
	if err != nil || again.Changed {
		t.Fatalf("idempotent prepare = %+v, %v", again, err)
	}
}

func TestPrepareWindowsCandidateTracksPrevious(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	node, root := "win01", t.TempDir()
	tree := makeRuntimeTree(t, private, 1, "111111111111", node,
		map[string]string{"sing-box/config.json": validWindowsConfig("warn")})
	updater, server := installVerifiedRuntimeBundle(t, root, node, public, &tree)
	defer server.Close()
	vaultPath := filepath.Join(root, "secrets", "vault.json.dpapi")
	if err := clientsecret.WriteVault(vaultPath, map[string]string{
		"vault:cred/win01": "password", "api/win01": "api",
	}, runtimeProtector{}); err != nil {
		t.Fatal(err)
	}
	first, err := PrepareWindowsCandidate(root, node, public, vaultPath, runtimeProtector{})
	if err != nil {
		t.Fatal(err)
	}
	tree = makeRuntimeTree(t, private, 2, "222222222222", node,
		map[string]string{"sing-box/config.json": validWindowsConfig("info")})
	if _, err := updater.PullOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	second, err := PrepareWindowsCandidate(root, node, public, vaultPath, runtimeProtector{})
	if err != nil || !second.Changed {
		t.Fatalf("second prepare = %+v, %v", second, err)
	}
	state, err := ReadCandidateState(root, runtimeProtector{})
	if err != nil || state.Previous == nil || *state.Previous != first.Version || state.Current != second.Version {
		t.Fatalf("candidate state = %+v, %v", state, err)
	}
}

func TestPrepareWindowsCandidateFailsClosedOnMissingSecretOrExtraFile(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	node := "win01"
	for _, test := range []struct {
		name    string
		files   map[string]string
		secrets map[string]string
		want    string
	}{
		{"missing secret", map[string]string{"sing-box/config.json": validWindowsConfig("warn")}, map[string]string{"api/win01": "api"}, "missing refs"},
		{"extra file", map[string]string{"sing-box/config.json": validWindowsConfig("warn"), "systemd/bad.service": "bad"}, map[string]string{"vault:cred/win01": "password", "api/win01": "api"}, "exactly"},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			tree := makeRuntimeTree(t, private, 1, "111111111111", node, test.files)
			_, server := installVerifiedRuntimeBundle(t, root, node, public, &tree)
			defer server.Close()
			vaultPath := filepath.Join(root, "secrets", "vault.json.dpapi")
			if err := clientsecret.WriteVault(vaultPath, test.secrets, runtimeProtector{}); err != nil {
				t.Fatal(err)
			}
			if _, err := PrepareWindowsCandidate(root, node, public, vaultPath, runtimeProtector{}); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("prepare result = %v, want %q", err, test.want)
			}
			if _, err := ReadCandidateState(root, runtimeProtector{}); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("failed prepare committed candidate state: %v", err)
			}
		})
	}
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

func TestCandidateReadersRejectRelativeRoot(t *testing.T) {
	if _, err := ReadCandidateState("relative", runtimeProtector{}); err == nil {
		t.Fatal("relative candidate root was accepted")
	}
	if _, _, err := ReadCandidateConfig("relative", runtimeProtector{}); err == nil {
		t.Fatal("relative candidate root was accepted")
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
