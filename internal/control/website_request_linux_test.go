package control

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestWebsiteRequestIdentityRetryAndOfflineVerification(t *testing.T) {
	root, node, genesis := authorityFixture(t)
	authority, err := InitializeAuthority(root, node, genesis)
	if err != nil {
		t.Fatal(err)
	}
	before := authority.Snapshot()
	request, err := PrepareWebsiteRequest(root, "demo-web", 1)
	if err != nil {
		t.Fatal(err)
	}
	expected := WebsiteRequestExpectation{node.NetworkID, node.GenesisID, before.ControlConfigID,
		node.ControlID, node.NodeID, "demo-web", 1}
	csr, err := VerifyWebsiteRequest(request, expected)
	if err != nil || len(csr.DNSNames) != 1 || csr.DNSNames[0] != "control.loom" {
		t.Fatal("offline CSR verification failed", err)
	}
	directory := websiteRequestDirectory(root, "demo-web", 1)
	key, _ := os.ReadFile(filepath.Join(directory, "key.pem"))
	body, _ := os.ReadFile(filepath.Join(directory, "request.json"))
	if bytes.Contains(body, key) || bytes.Contains(body, []byte("PRIVATE KEY")) {
		t.Fatal("public request contains a private key")
	}
	var decoded WebsiteRequest
	if err := DecodeCanonical(body, &decoded, ContractDecodeLimits{MaxBytes: 8 << 20, MaxDepth: 128, MaxItems: 1 << 20}); err != nil {
		t.Fatal(err)
	}
	encoded, err := CanonicalEncode(decoded)
	if err != nil || !bytes.Equal(encoded, body) {
		t.Fatal("signing handoff did not preserve canonical bytes", err)
	}
	retry, err := PrepareWebsiteRequest(root, "demo-web", 1)
	if err != nil || !reflect.DeepEqual(retry, request) {
		t.Fatal("retry regenerated an existing request", err)
	}
	afterKey, _ := os.ReadFile(filepath.Join(directory, "key.pem"))
	afterBody, _ := os.ReadFile(filepath.Join(directory, "request.json"))
	if !bytes.Equal(key, afterKey) || !bytes.Equal(body, afterBody) {
		t.Fatal("retry changed original request or leaf key")
	}
	reopened, err := OpenAuthority(root)
	if err != nil || !reflect.DeepEqual(before, reopened.Snapshot()) {
		t.Fatal("CSR preparation changed authority facts", err)
	}
	for name, change := range map[string]func(*WebsiteRequestExpectation){
		"network": func(v *WebsiteRequestExpectation) { v.NetworkID = "demo-other-network" },
		"anchor":  func(v *WebsiteRequestExpectation) { v.GenesisDigest = endpointByteDigest([]byte("demo-other-anchor")) },
		"current membership": func(v *WebsiteRequestExpectation) {
			v.ControlConfigID = endpointByteDigest([]byte("demo-other-members"))
		},
		"member":     func(v *WebsiteRequestExpectation) { v.ControlID = "demo-other-control" },
		"node":       func(v *WebsiteRequestExpectation) { v.NodeID = "demo-other-node" },
		"endpoint":   func(v *WebsiteRequestExpectation) { v.EndpointID = "demo-other-web" },
		"generation": func(v *WebsiteRequestExpectation) { v.Generation++ },
	} {
		t.Run(name, func(t *testing.T) {
			wrong := expected
			change(&wrong)
			if _, err := VerifyWebsiteRequest(request, wrong); err == nil {
				t.Fatal("untrusted request selected its own trust or intended endpoint")
			}
		})
	}
	for _, change := range []func(*WebsiteRequest){
		func(v *WebsiteRequest) { v.EndpointID = "demo-substituted-web" },
		func(v *WebsiteRequest) { v.CSRDER = v.CSRDER[:len(v.CSRDER)-2] + "AA" },
		func(v *WebsiteRequest) { v.Signature = v.Signature[:len(v.Signature)-2] + "AA" },
	} {
		wrong := request
		change(&wrong)
		if wrong.Validate() == nil {
			t.Fatal("modified signed handoff was accepted")
		}
	}
}

func TestWebsiteRequestFailurePreservesMaterial(t *testing.T) {
	root, node, genesis := authorityFixture(t)
	if _, err := InitializeAuthority(root, node, genesis); err != nil {
		t.Fatal(err)
	}
	if _, err := PrepareWebsiteRequest(root, "demo-web", 2); err == nil {
		t.Fatal("new endpoint skipped its first generation")
	}
	directory := websiteRequestDirectory(root, "demo-web", 1)
	if _, err := os.Lstat(directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed preparation published a partial request")
	}
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	partial := []byte("demo-existing-partial-material")
	if err := os.WriteFile(filepath.Join(directory, "key.pem"), partial, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := PrepareWebsiteRequest(root, "demo-web", 1); err == nil {
		t.Fatal("partial existing input was silently replaced")
	}
	got, _ := os.ReadFile(filepath.Join(directory, "key.pem"))
	if !bytes.Equal(got, partial) {
		t.Fatal("failed retry changed existing material")
	}
	other := filepath.Join(t.TempDir(), "demo-unowned")
	if err := os.Symlink(other, websiteRequestDirectory(root, "demo-linked", 1)); err != nil {
		t.Fatal(err)
	}
	if _, err := PrepareWebsiteRequest(root, "demo-linked", 1); err == nil {
		t.Fatal("linked generation directory was accepted")
	}
}
