package clientupdate

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"loom/internal/publish"
	"loom/internal/releasefloor"
)

type signedTree struct {
	current  []byte
	manifest []byte
	sig      []byte
	bundle   []byte
}

func makeSignedTree(t *testing.T, private ed25519.PrivateKey, generation uint64, snapshotID, node string, files map[string]string) signedTree {
	t.Helper()
	bundle := bundleWire{Owner: node, Files: files}
	bundleBody, err := jsonBytes(bundle)
	if err != nil {
		t.Fatal(err)
	}
	manifest := &manifestWire{
		ID: snapshotID, CreatedAt: "2026-09-02T12:00:00Z", SSOTHash: strings.Repeat("a", 64),
		Bundles:    []bundleRefWire{{Owner: node, Hash: bundleHash(files)}},
		Components: []componentRefWire{{Node: node, SingBox: "1.11.4", WireGuard: "1.0.20250521"}},
	}
	manifestBody, err := jsonBytes(manifest)
	if err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(private, manifestBody)
	current := &publish.DeploymentCurrent{
		Schema: publish.DeploymentCurrentSchema, Generation: generation, Snapshot: snapshotID,
		PublishedAt: "2026-09-02T12:00:00Z",
	}
	if err := current.Sign(private); err != nil {
		t.Fatal(err)
	}
	currentBody, err := current.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return signedTree{current: currentBody, manifest: manifestBody, sig: signature, bundle: bundleBody}
}

func TestValidateManifestRejectsDuplicateOrMissingComponentNode(t *testing.T) {
	node := "win01"
	manifest := &manifestWire{
		ID: "111111111111", Bundles: []bundleRefWire{{Owner: node, Hash: strings.Repeat("a", 64)}},
		Components: []componentRefWire{{Node: node, SingBox: "1.11.4"}, {Node: node, SingBox: "1.11.5"}},
	}
	if _, err := validateManifest(manifest, manifest.ID, node); err == nil || !strings.Contains(err.Error(), "duplicate component") {
		t.Fatalf("duplicate component error = %v", err)
	}
	manifest.Components = []componentRefWire{{Node: "other", SingBox: "1.11.4"}}
	if _, err := validateManifest(manifest, manifest.ID, node); err == nil || !strings.Contains(err.Error(), "no component versions") {
		t.Fatalf("missing component error = %v", err)
	}
}

func jsonBytes(value any) ([]byte, error) {
	body, err := json.MarshalIndent(value, "", "  ")
	return append(body, '\n'), err
}

func serveTree(t *testing.T, tree *signedTree, node string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var body []byte
		switch {
		case request.URL.Path == "/current.json":
			body = tree.current
		case strings.HasSuffix(request.URL.Path, "/snapshot.json"):
			body = tree.manifest
		case strings.HasSuffix(request.URL.Path, "/snapshot.sig"):
			body = tree.sig
		case strings.HasSuffix(request.URL.Path, "/nodes/"+node+".json"):
			body = tree.bundle
		default:
			http.NotFound(writer, request)
			return
		}
		_, _ = writer.Write(body)
	}))
}

func newUpdater(t *testing.T, server *httptest.Server, public ed25519.PublicKey, root, node string) *Updater {
	t.Helper()
	return &Updater{
		Client: server.Client(), Config: Config{
			Schema: ConfigSchema, NodeID: node, DistributionURLs: []string{server.URL},
		},
		PublicKey: public, StateRoot: root,
	}
}

func TestPullOnceVerifiesCachesAndTracksPrevious(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	node := "win01"
	tree := makeSignedTree(t, private, 1, "111111111111", node,
		map[string]string{"sing-box/config.json": "first\n"})
	server := serveTree(t, &tree, node)
	defer server.Close()
	root := t.TempDir()
	updater := newUpdater(t, server, public, root, node)

	first, err := updater.PullOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !first.Changed || first.Generation != 1 || first.Snapshot != "111111111111" {
		t.Fatalf("first result = %+v", first)
	}
	again, err := updater.PullOnce(context.Background())
	if err != nil || again.Changed {
		t.Fatalf("idempotent result = %+v, %v", again, err)
	}

	tree = makeSignedTree(t, private, 2, "222222222222", node,
		map[string]string{"sing-box/config.json": "second\n"})
	second, err := updater.PullOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !second.Changed || second.Generation != 2 {
		t.Fatalf("second result = %+v", second)
	}
	state, err := ReadVerifiedState(root)
	if err != nil {
		t.Fatal(err)
	}
	if state.Current.Snapshot != "222222222222" || state.Previous == nil || state.Previous.Snapshot != "111111111111" {
		t.Fatalf("verified state = %+v", state)
	}
	loaded, err := LoadVerifiedBundle(root, node, public)
	if err != nil || loaded.Version != state.Current || loaded.Files["sing-box/config.json"] != "second\n" {
		t.Fatalf("loaded verified bundle = %+v, %v", loaded, err)
	}
	floor, err := releasefloor.Read(statePath(root, "release-floor.json"))
	if err != nil || floor.Generation != 2 || floor.SelectedSnapshot != "222222222222" {
		t.Fatalf("release floor = %+v, %v", floor, err)
	}
}

func TestLoadVerifiedBundleRejectsLocalCacheTampering(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	node := "win01"
	tree := makeSignedTree(t, private, 1, "111111111111", node,
		map[string]string{"sing-box/config.json": "config\n"})
	server := serveTree(t, &tree, node)
	defer server.Close()
	root := t.TempDir()
	updater := newUpdater(t, server, public, root, node)
	if _, err := updater.PullOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	state, err := ReadVerifiedState(root)
	if err != nil {
		t.Fatal(err)
	}
	bundlePath := filepath.Join(packagePath(root, state.Current), "bundle.json")
	if err := os.WriteFile(bundlePath, []byte(`{"owner":"win01","files":{"sing-box/config.json":"tampered"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadVerifiedBundle(root, node, public); err == nil || !strings.Contains(err.Error(), "signed manifest") {
		t.Fatalf("tampered cache result = %v", err)
	}
}

func TestPullLatchesFloorBeforeWithheldPayload(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	node := "win01"
	tree := makeSignedTree(t, private, 1, "111111111111", node,
		map[string]string{"sing-box/config.json": "first\n"})
	server := serveTree(t, &tree, node)
	defer server.Close()
	root := t.TempDir()
	updater := newUpdater(t, server, public, root, node)
	if _, err := updater.PullOnce(context.Background()); err != nil {
		t.Fatal(err)
	}

	tree = makeSignedTree(t, private, 2, "222222222222", node,
		map[string]string{"sing-box/config.json": "second\n"})
	tree.manifest = nil
	if _, err := updater.PullOnce(context.Background()); err == nil {
		t.Fatal("withheld manifest was accepted")
	}
	floor, err := releasefloor.Read(statePath(root, "release-floor.json"))
	if err != nil || floor.Generation != 2 {
		t.Fatalf("authenticated generation was not latched: %+v, %v", floor, err)
	}
	state, err := ReadVerifiedState(root)
	if err != nil || state.Current.Snapshot != "111111111111" {
		t.Fatalf("last verified package was not preserved: %+v, %v", state, err)
	}

	tree = makeSignedTree(t, private, 1, "111111111111", node,
		map[string]string{"sing-box/config.json": "first\n"})
	if _, err := updater.PullOnce(context.Background()); err == nil || !strings.Contains(err.Error(), "rejected current") {
		t.Fatalf("stale generation result = %v", err)
	}
}

func TestPullRequiresExpectedCurrentForLateFirstGeneration(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	node := "win01"
	tree := makeSignedTree(t, private, 7, "777777777777", node,
		map[string]string{"sing-box/config.json": "config\n"})
	server := serveTree(t, &tree, node)
	defer server.Close()
	root := t.TempDir()
	updater := newUpdater(t, server, public, root, node)
	if _, err := updater.PullOnce(context.Background()); err == nil || !strings.Contains(err.Error(), "expected-current is required") {
		t.Fatalf("late first generation result = %v", err)
	}

	expected := filepath.Join(root, "expected-current.json")
	if err := os.WriteFile(expected, tree.current, 0o600); err != nil {
		t.Fatal(err)
	}
	updater.ExpectedCurrentPath = expected
	if result, err := updater.PullOnce(context.Background()); err != nil || result.Generation != 7 {
		t.Fatalf("anchored pull = %+v, %v", result, err)
	}
}

func TestPullRejectsSameGenerationMirrorFork(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	node := "win01"
	first := makeSignedTree(t, private, 1, "111111111111", node,
		map[string]string{"sing-box/config.json": "first\n"})
	second := makeSignedTree(t, private, 1, "222222222222", node,
		map[string]string{"sing-box/config.json": "second\n"})
	serverA := serveTree(t, &first, node)
	defer serverA.Close()
	serverB := serveTree(t, &second, node)
	defer serverB.Close()
	updater := &Updater{
		Client: serverA.Client(), Config: Config{
			Schema: ConfigSchema, NodeID: node, DistributionURLs: []string{serverA.URL, serverB.URL},
		},
		PublicKey: public, StateRoot: t.TempDir(),
	}
	if _, err := updater.PullOnce(context.Background()); err == nil || !strings.Contains(err.Error(), "mirror fork") {
		t.Fatalf("fork result = %v", err)
	}
}

func TestPullRejectsWrongSignatureOwnerHashAndUnsafePath(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	otherPublic, _, _ := ed25519.GenerateKey(rand.Reader)
	node := "win01"
	tests := []struct {
		name   string
		mutate func(*signedTree)
		key    ed25519.PublicKey
		want   string
	}{
		{"wrong signature", func(*signedTree) {}, otherPublic, "rejected current"},
		{"wrong owner", func(tree *signedTree) { tree.bundle = []byte(`{"owner":"other","files":{"sing-box/config.json":"x"}}`) }, public, "bundle binding"},
		{"tampered bundle", func(tree *signedTree) {
			tree.bundle = []byte(`{"owner":"win01","files":{"sing-box/config.json":"changed"}}`)
		}, public, "bundle hash"},
		{"unsafe path", func(tree *signedTree) { tree.bundle = []byte(`{"owner":"win01","files":{"../escape":"x"}}`) }, public, "unsafe bundle path"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tree := makeSignedTree(t, private, 1, "111111111111", node,
				map[string]string{"sing-box/config.json": "config\n"})
			test.mutate(&tree)
			server := serveTree(t, &tree, node)
			defer server.Close()
			_, err := newUpdater(t, server, test.key, t.TempDir(), node).PullOnce(context.Background())
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("result = %v, want %q", err, test.want)
			}
		})
	}
}

func TestConfigAndTrustRootAreStrict(t *testing.T) {
	credentialedURL := "https://" + "demo-user:demo-password@example.com/loom"
	for _, body := range []string{
		`{"schema":1,"schema":1,"node_id":"win01","distribution_urls":["https://example.com/loom"]}`,
		`{"schema":1,"node_id":"win01","distribution_urls":["` + credentialedURL + `"]}`,
		`{"schema":1,"node_id":"win01","distribution_urls":["https://example.com/loom"],"unknown":true}`,
	} {
		path := filepath.Join(t.TempDir(), "client.json")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := ReadConfig(path); err == nil {
			t.Fatalf("invalid config accepted: %s", body)
		}
	}

	public, _, _ := ed25519.GenerateKey(rand.Reader)
	keyPath := filepath.Join(t.TempDir(), "platform.pub")
	if err := os.WriteFile(keyPath, []byte(base64.StdEncoding.EncodeToString(public)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := ReadPublicKey(keyPath)
	if err != nil || !reflect.DeepEqual(got, public) {
		t.Fatalf("read key = %x, %v", got, err)
	}
	if err := os.WriteFile(keyPath, []byte(base64.RawStdEncoding.EncodeToString(public)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPublicKey(keyPath); err == nil {
		t.Fatal("non-canonical base64 trust root was accepted")
	}
}

func TestVerifiedStateRejectsCorruption(t *testing.T) {
	root := t.TempDir()
	path := statePath(root, "verified.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"schema":1,"current":{"generation":1,"payload_sha256":"bad","snapshot":"111111111111","bundle_sha256":"bad"}}`)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadVerifiedState(root); err == nil {
		t.Fatal("corrupt verified state was accepted")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("corrupt state was modified or removed")
	}
}

func TestConfigPullIntervalBounds(t *testing.T) {
	base := Config{Schema: 1, NodeID: "win01", DistributionURLs: []string{"https://example.com/loom"}}
	if base.PullInterval() != 45*time.Second {
		t.Fatalf("default interval = %s", base.PullInterval())
	}
	base.PullIntervalSeconds = 15
	if err := base.Validate(); err != nil || base.PullInterval() != 15*time.Second {
		t.Fatalf("explicit interval = %s, %v", base.PullInterval(), err)
	}
}
