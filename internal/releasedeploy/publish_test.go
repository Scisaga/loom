package releasedeploy

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"loom/internal/clientrelease"
	"loom/internal/control"
	"loom/internal/localconfig"
)

var reviewedStore = flag.String("release-store-dir", "", "explicit real signed catalog for publication integration")
var reviewedPublic = flag.String("release-pubkey", "", "independently fixed verification key")

type demoTransport struct {
	key                           ed25519.PublicKey
	catalog                       string
	identities                    map[string]control.DeviceIdentityReadback
	uploads, selections           int
	failedIdentity, failSelection string
	httpComplete                  func() bool
	transferredBytes              int64
}

func (d *demoTransport) Resolve(_ context.Context, alias string) (control.SSHTargetReadback, error) {
	return control.SSHTargetReadback{Alias: alias, Local: alias == "demo-a"}, nil
}

var rootPattern = regexp.MustCompile(`-root '([^']+)'`)
var expectedPattern = regexp.MustCompile(`-expected-current '([^']*)'`)

func (d *demoTransport) Run(_ context.Context, alias, script string) ([]byte, error) {
	if strings.Contains(script, "# Inspect existing release files;") {
		return exec.Command("sh", "-c", script).Output()
	}
	if strings.Contains(script, "client inspect") {
		id := d.identities[alias]
		if alias == d.failedIdentity {
			id.DevicePublicKey = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x39}, 32))
		}
		return json.Marshal(id)
	}
	match := rootPattern.FindStringSubmatch(script)
	if len(match) != 2 {
		return nil, errors.New("missing exact target")
	}
	root := match[1]
	if strings.Contains(script, "release target") {
		value := TargetReadback{Identity: d.identities[alias]}
		if _, err := os.Stat(filepath.Join(root, "current.json")); err == nil {
			store, _ := clientrelease.New(root, d.key)
			set, err := store.Read()
			if err != nil {
				return nil, err
			}
			value.CatalogDigest, value.Generation = set.ID, set.Catalog.Generation
		} else if !os.IsNotExist(err) {
			return nil, err
		}
		return json.Marshal(value)
	}
	if !d.httpComplete() {
		return nil, errors.New("pointer selected before complete HTTP readback")
	}
	if alias == d.failSelection {
		return nil, errors.New("demo connection lost; remote result unconfirmed")
	}
	expected := expectedPattern.FindStringSubmatch(script)
	if len(expected) != 2 {
		return nil, errors.New("missing conditional comparison")
	}
	set, err := clientrelease.Import(root, root, d.catalog, d.key, expected[1])
	if err != nil {
		return nil, err
	}
	d.selections++
	return demoCatalogReadback(set), nil
}
func (d *demoTransport) Stream(_ context.Context, _ string, script string, input io.Reader) ([]byte, error) {
	root := rootPattern.FindStringSubmatch(script)
	expected := expectedPattern.FindStringSubmatch(script)
	if len(root) != 2 || len(expected) != 2 || !strings.Contains(script, "-prepare-only") {
		return nil, errors.New("upload tried to select a pointer")
	}
	// Exercise the same target-side assembly with the unchanged strict receiver.
	index := strings.Index(script, "\nloom release import ")
	if index < 0 {
		return nil, errors.New("missing formal import command")
	}
	command := exec.Command("sh", "-c", script[:index]+"\ncat \"$release_tmp/incoming.tar\"\n")
	command.Stdin = &countedTransfer{Reader: input, count: &d.transferredBytes}
	output, err := command.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err = command.Start(); err != nil {
		return nil, err
	}
	directory, err := clientrelease.ReceiveArchive(output, d.catalog, d.key)
	output.Close()
	completed := command.Wait()
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(directory)
	if completed != nil {
		return nil, completed
	}
	set, err := clientrelease.Prepare(directory, root[1], d.catalog, d.key, expected[1])
	if err != nil {
		return nil, err
	}
	d.uploads++
	return demoCatalogReadback(set), nil
}

type countedTransfer struct {
	io.Reader
	count *int64
}

func (r *countedTransfer) Read(body []byte) (int, error) {
	n, err := r.Reader.Read(body)
	*r.count += int64(n)
	return n, err
}
func demoCatalogReadback(set control.ReleaseSet) []byte {
	body, _ := json.Marshal(map[string]any{"catalog_digest": set.ID, "generation": set.Catalog.Generation, "entries": set.Catalog.Entries})
	return body
}

type demoHTTP func(*http.Request) (*http.Response, error)

func (f demoHTTP) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestReviewedAllTargetsRequireIdentityHTTPAndConditionalReadback(t *testing.T) {
	if *reviewedStore == "" || *reviewedPublic == "" {
		t.Skip("requires real signed package store")
	}
	key, err := control.ReadReleasePublicKey(*reviewedPublic)
	if err != nil {
		t.Fatal(err)
	}
	source, err := clientrelease.New(*reviewedStore, key)
	if err != nil {
		t.Fatal(err)
	}
	set, err := source.Read()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	a, b := filepath.Join(root, "local"), filepath.Join(root, "remote")
	config := localconfig.Config{DeployHosts: []string{"demo-a", "demo-b"}, LocalNode: "demo-a", PublishOutputs: []string{a, "ssh://demo-b" + b}}
	public := base64.RawURLEncoding.EncodeToString(key)
	inputs := control.ReleaseDeploymentInputs{NetworkID: "demo-network", GenesisDigest: control.ReleaseDigest([]byte("demo-genesis")), ControlConfigID: control.ReleaseDigest([]byte("demo-config")), Nodes: []control.ReleaseDeploymentNode{{NodeID: "demo-a", PublicKey: public}, {NodeID: "demo-b", PublicKey: public}}, DistributionURLs: []string{"https://a.example/", "https://b.example/"}}
	transport := &demoTransport{key: key, catalog: set.ID, identities: map[string]control.DeviceIdentityReadback{}}
	for _, alias := range config.DeployHosts {
		transport.identities[alias] = control.DeviceIdentityReadback{NetworkID: inputs.NetworkID, GenesisDigest: inputs.GenesisDigest, DeviceID: alias, TransactionID: "demo-join", InviteMaterialID: control.ReleaseDigest([]byte("demo-invite")), ClaimRequestID: "demo-claim", DevicePublicKey: public, Platform: "linux", Joined: true}
	}
	httpCalls := 0
	badHTTP := false
	transport.httpComplete = func() bool { return httpCalls == len(set.Catalog.Entries)*len(inputs.DistributionURLs) }
	client := &http.Client{Transport: demoHTTP(func(request *http.Request) (*http.Response, error) {
		httpCalls++
		name := strings.TrimPrefix(request.URL.Path, "/bin/")
		file, err := os.Open(filepath.Join(*reviewedStore, "bin", name))
		if err != nil {
			return nil, err
		}
		var body io.ReadCloser = file
		if badHTTP {
			file.Close()
			body = io.NopCloser(strings.NewReader("demo wrong bytes"))
		}
		return &http.Response{StatusCode: http.StatusOK, Body: body, Header: http.Header{}}, nil
	})}
	events := []Result{}
	options := Options{Config: config, ReloadConfig: func() (localconfig.Config, error) { return config, nil }, Inputs: func(context.Context) (control.ReleaseDeploymentInputs, error) { return inputs, nil }, Transport: transport, Source: *reviewedStore, Catalog: set.ID, PublicKey: key, HTTP: client, Observe: func(r Result) { events = append(events, r) }}
	run := func() error { httpCalls = 0; return Publish(context.Background(), options) }
	t.Log("reject mismatched identity before upload")
	transport.failedIdentity = "demo-b"
	if err = run(); err == nil || transport.uploads != 0 {
		t.Fatal("identity mismatch reached upload")
	}
	transport.failedIdentity = ""
	t.Log("prepare every target, then reject wrong HTTPS bytes")
	badHTTP = true
	if err = run(); err == nil || transport.uploads != 2 || transport.selections != 0 {
		t.Fatal("bad HTTP selected a pointer", err, transport.uploads, transport.selections)
	}
	for _, path := range []string{a, b} {
		if _, err = os.Stat(filepath.Join(path, "current.json")); !os.IsNotExist(err) {
			t.Fatal("failed HTTP changed target current")
		}
	}
	t.Log("preserve partial selection and report failure")
	// The unselected cache lost one signature; send exactly that missing file.
	if err = os.Remove(filepath.Join(a, "catalogs", strings.TrimPrefix(set.ID, "sha256:"), "catalog.sig")); err != nil {
		t.Fatal(err)
	}
	badHTTP = false
	transport.failSelection = "demo-b"
	events = nil
	if err = run(); err == nil || transport.selections != 1 {
		t.Fatal("partial selection was not reported as incomplete", err)
	}
	for _, event := range events {
		if event.Operation == "prepare" && event.Verified {
			want := 0
			if event.Target == 1 {
				want = 1
			}
			if event.Transfer == nil || event.Transfer.SentFiles != want || event.Transfer.SentBytes != int64(want*ed25519.SignatureSize) || event.Transfer.ReusedFiles == 0 {
				t.Fatal("unchanged public content was retransmitted", event)
			}
		}
		if event.Operation == "complete" {
			t.Fatal("partial result claimed completion")
		}
	}
	if _, err = os.Stat(filepath.Join(b, "current.json")); !os.IsNotExist(err) {
		t.Fatal("unconfirmed target was marked selected")
	}
	t.Log("retry original catalog after partial selection")
	transport.failSelection = ""
	networkBefore := transport.transferredBytes
	if err = run(); err != nil {
		t.Fatal("same catalog retry could not recover partial publication", err)
	}
	if transport.transferredBytes-networkBefore != 2*1024 {
		t.Fatal("complete target caches received more than two empty tar envelopes")
	}
	for _, path := range []string{a, b} {
		store, _ := clientrelease.New(path, key)
		got, err := store.Read()
		if err != nil || got.ID != set.ID {
			t.Fatal("independent final target read failed", err)
		}
	}
	// A changed authority while transferring must stop before either selection.
	t.Log("reject authorization changes before selection")
	saved := inputs
	calls := 0
	options.Inputs = func(context.Context) (control.ReleaseDeploymentInputs, error) {
		calls++
		value := saved
		if calls > 5 {
			value.DistributionURLs = []string{"https://changed.example/"}
		}
		return value, nil
	}
	before := transport.selections
	if err = run(); err == nil || transport.selections != before {
		t.Fatal("changed authority authorized further pointer writes", err)
	}
}

func TestTargetsRejectUnjoinedLocalAndDuplicateAliases(t *testing.T) {
	for _, config := range []localconfig.Config{
		{DeployHosts: []string{"demo-a"}, PublishOutputs: []string{"/srv/demo"}},
		{DeployHosts: []string{"demo-a"}, LocalNode: "demo-a", PublishOutputs: []string{"/srv/demo", "ssh://demo-a/srv/demo"}},
		{DeployHosts: []string{"demo-a"}, LocalNode: "demo-a", PublishOutputs: []string{"ssh://demo-b/srv/demo"}},
	} {
		if _, err := targets(config); err == nil {
			t.Fatal("target without a unique deployment join accepted")
		}
	}
}
