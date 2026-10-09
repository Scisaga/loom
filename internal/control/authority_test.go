package control

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func authorityFixture(t *testing.T) (string, NodeConfig, Material) {
	t.Helper()
	parent := t.TempDir()
	root := filepath.Join(parent, "authority")
	seed := sha256.Sum256([]byte("demo-authority-signing-key"))
	key := ed25519.NewKeyFromSeed(seed[:])
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyFile := filepath.Join(parent, "demo-control-key.pem")
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	public := base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
	keyID, err := KeyID(public)
	if err != nil {
		t.Fatal(err)
	}
	member := Member{ControlID: "demo-control", NodeID: "demo-node", PublicKey: public}
	config := ControlConfig{Schema: 3, NetworkID: "demo-network", PreviousConfigID: "", Operation: "genesis", Members: []Member{member}, SealedKeys: []ControlSealedKey{}}
	genesis, err := SignMaterial(Material{Schema: 3, NetworkID: "demo-network", IssuerControlID: member.ControlID, IssuerKeyID: keyID, Operation: "genesis", Payload: Genesis{ControlConfig: config, NetworkIntent: EmptyNetworkIntent(), AdminCertificates: []AdminCertificate{}}}, key)
	if err != nil {
		t.Fatal(err)
	}
	id, err := MaterialID(genesis)
	if err != nil {
		t.Fatal(err)
	}
	return root, NodeConfig{Schema: 3, NetworkID: "demo-network", ControlID: member.ControlID, NodeID: member.NodeID, GenesisID: id, SigningKeyFile: keyFile}, genesis
}
func authorityService(id, request string) Operation {
	return Operation{Schema: 3, RequestID: request, Operation: "service.put", TargetKind: "service", TargetID: id, Dependencies: []string{}, Payload: Service{ID: id, Name: "Demo service", Kind: "internet", Matchers: []ServiceMatcher{{Kind: "dns_exact", Value: id + ".example"}}}}
}
func submitAuthority(t *testing.T, runtime *Runtime, op Operation) Submission {
	t.Helper()
	body, err := EncodeOperation(op)
	if err != nil {
		t.Fatal(err)
	}
	result, err := runtime.Submit(context.Background(), body)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestAuthorityOrdinaryOperationsSurviveRestart(t *testing.T) {
	root, config, genesis := authorityFixture(t)
	if _, err := InitializeAuthority(root, config, genesis); err != nil {
		t.Fatal(err)
	}
	runtime, err := OpenRuntime(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !runtime.Writable() {
		t.Fatal("fresh qualified local signer is not writable")
	}
	op := authorityService("demo-service", "demo-service-create")
	service := submitAuthority(t, runtime, op)
	anyScope := PolicyScope{Mode: "any", NodeIDs: []string{}}
	policy := Operation{Schema: 3, RequestID: "demo-policy-create", Operation: "policy.put", TargetKind: "policy", TargetID: "demo-policy", Dependencies: []string{service.MaterialID}, Payload: NetworkPolicy{ID: "demo-policy", Name: "Demo policy", ServiceID: "demo-service", Action: "allow", EntryScope: anyScope, RelayScope: anyScope, ExitScope: new(anyScope), AllowDirect: new(true), LocalEgressDevices: new([]string{})}}
	saved := submitAuthority(t, runtime, policy)
	raw, err := runtime.Authority.Material(saved.MaterialID)
	if err != nil {
		t.Fatal(err)
	}
	runtime.Close()
	runtime, err = OpenRuntime(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	projection := runtime.Authority.Snapshot()
	if len(projection.NetworkIntent.Services) != 1 || len(projection.NetworkIntent.Policies) != 1 || projection.NetworkIntent.Policies[0].ServiceID != "demo-service" {
		t.Fatal("restarted authority lost ordinary Service/Policy state")
	}
	replay := submitAuthority(t, runtime, policy)
	if replay.MaterialID != saved.MaterialID {
		t.Fatal("request retry signed another fact")
	}
	after, err := runtime.Authority.Material(saved.MaterialID)
	if err != nil || !bytes.Equal(raw, after) {
		t.Fatal("restart or retry changed original signed bytes")
	}
	projection.NetworkIntent.Policies[0].ServiceID = "demo-untrusted"
	if runtime.Authority.Snapshot().NetworkIntent.Policies[0].ServiceID != "demo-service" {
		t.Fatal("readback aliases writable authority state")
	}
	changed := policy
	changed.Payload = NetworkPolicy{ID: "demo-policy", Name: "Changed", ServiceID: "demo-service", Action: "allow", EntryScope: anyScope, RelayScope: anyScope, ExitScope: new(anyScope), AllowDirect: new(true), LocalEgressDevices: new([]string{})}
	body, _ := EncodeOperation(changed)
	if _, err := runtime.Submit(context.Background(), body); err == nil {
		t.Fatal("same request ID accepted different content")
	}
	stale := op
	stale.RequestID = "demo-stale-edit"
	body, _ = EncodeOperation(stale)
	if _, err := runtime.Submit(context.Background(), body); err == nil {
		t.Fatal("stale target update was accepted")
	}
	frontier := runtime.Authority.Frontier()
	if len(frontier) != 1 || frontier[0].Sequence != 2 {
		t.Fatalf("retry changed signing frontier: %#v", frontier)
	}
}

func TestAuthorityRepeatedReloadReadsNewAndChangedOriginals(t *testing.T) {
	root, config, genesis := authorityFixture(t)
	reader, err := InitializeAuthority(root, config, genesis)
	if err != nil {
		t.Fatal(err)
	}
	writer, err := OpenRuntime(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	reload := func() error {
		_, err := reader.pendingControlChange(context.Background(), config, time.UnixMilli(1))
		return err
	}
	first := submitAuthority(t, writer, authorityService("demo-first", "demo-first-create"))
	for range 3 {
		if err := reload(); err != nil || len(reader.Snapshot().NetworkIntent.Services) != 1 {
			t.Fatal("unchanged reload lost the verified service", err)
		}
	}
	submitAuthority(t, writer, authorityService("demo-second", "demo-second-create"))
	if err := reload(); err != nil || len(reader.Snapshot().NetworkIntent.Services) != 2 {
		t.Fatal("existing reader missed another writer's signed fact", err)
	}
	path, err := reader.materialPath(first.MaterialID)
	if err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	changed := bytes.Replace(original, []byte("Demo service"), []byte("Fake service"), 1)
	if len(changed) != len(original) || bytes.Equal(changed, original) {
		t.Fatal("fixture did not change one same-length original")
	}
	if err := os.WriteFile(path, changed, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	if err := reload(); err == nil || reader.blocked == nil {
		t.Fatal("projection reuse hid changed original bytes")
	}
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := reload(); err != nil || reader.blocked != nil || len(reader.Snapshot().NetworkIntent.Services) != 2 {
		t.Fatal("restored originals did not rebuild the verified projection", err)
	}
	restarted, err := OpenAuthority(root)
	if err != nil || len(restarted.Snapshot().NetworkIntent.Services) != 2 {
		t.Fatal("restarted authority did not rebuild from original facts", err)
	}
}

func TestAuthorityInitializationPreservesExistingEvidence(t *testing.T) {
	for _, name := range []string{"consensus.json", "certified.json", "node.json", "floor.json", "latch.json", "unrecognized-evidence"} {
		t.Run(name, func(t *testing.T) {
			root, config, genesis := authorityFixture(t)
			if err := os.Mkdir(root, 0o700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(root, name)
			original := []byte("demo-existing-immutable-evidence")
			if err := os.WriteFile(path, original, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := InitializeAuthority(root, config, genesis); err == nil {
				t.Fatal("nonempty directory was initialized")
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(after, original) {
				t.Fatal("initialization changed existing bytes")
			}
		})
	}
}

func TestAuthorityProcessWriter(t *testing.T) {
	for index, value := range os.Args {
		if value != "--authority-worker" {
			continue
		}
		if len(os.Args) != index+3 {
			t.Fatal("invalid authority worker arguments")
		}
		runtime, err := OpenRuntime(os.Args[index+1], nil)
		if err != nil {
			t.Fatal(err)
		}
		defer runtime.Close()
		suffix := os.Args[index+2]
		submitAuthority(t, runtime, authorityService("demo-service-"+suffix, "demo-request-"+suffix))
		return
	}
}
func TestAuthoritySerializesSeparateProcesses(t *testing.T) {
	root, config, genesis := authorityFixture(t)
	if _, err := InitializeAuthority(root, config, genesis); err != nil {
		t.Fatal(err)
	}
	commands := []*exec.Cmd{}
	outputs := []*bytes.Buffer{}
	for _, suffix := range []string{"a", "b", "c"} {
		command := exec.Command(os.Args[0], "-test.run=^TestAuthorityProcessWriter$", "--", "--authority-worker", root, suffix)
		output := &bytes.Buffer{}
		command.Stdout, command.Stderr = output, output
		commands = append(commands, command)
		outputs = append(outputs, output)
		if err := command.Start(); err != nil {
			t.Fatal(err)
		}
	}
	for index, command := range commands {
		if err := command.Wait(); err != nil {
			t.Fatalf("independent writer failed: %v %s", err, outputs[index].String())
		}
	}
	authority, err := OpenAuthority(root)
	if err != nil {
		t.Fatal(err)
	}
	frontier := authority.Frontier()
	if len(frontier) != 1 || frontier[0].Sequence != 3 {
		t.Fatalf("lost or reused signing sequence: %#v", frontier)
	}
	if len(authority.Snapshot().NetworkIntent.Services) != 3 {
		t.Fatal("independent writers overwrote ordinary targets")
	}
	bodies, err := authority.MaterialsAfter(frontier[0].KeyID, 0)
	if err != nil {
		t.Fatal(err)
	}
	previous := emptyAuthorityChainID()
	for index, body := range bodies {
		material, id, err := EncodeMaterialFromBytes(body)
		if err != nil || material.Sequence != U64(index+1) || material.PreviousMaterialID != previous {
			t.Fatal("durable signed sequence is not contiguous")
		}
		previous = id
	}
}

func TestAuthorityLostPredecessorStopsLocalSigning(t *testing.T) {
	root, config, genesis := authorityFixture(t)
	if _, err := InitializeAuthority(root, config, genesis); err != nil {
		t.Fatal(err)
	}
	runtime, err := OpenRuntime(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	first := submitAuthority(t, runtime, authorityService("demo-service-a", "demo-create-a"))
	submitAuthority(t, runtime, authorityService("demo-service-b", "demo-create-b"))
	runtime.Close()
	path := filepath.Join(root, "materials", strings.TrimPrefix(first.MaterialID, "sha256:")+".json")
	if err := os.Rename(path, filepath.Join(filepath.Dir(root), "demo-retained-fact.json")); err != nil {
		t.Fatal(err)
	}
	runtime, err = OpenRuntime(root, nil)
	if err != nil {
		return
	}
	defer runtime.Close()
	if runtime.Writable() {
		t.Fatal("signing remained available after a required prefix was lost")
	}
	body, _ := EncodeOperation(authorityService("demo-service-c", "demo-create-c"))
	if _, err := runtime.Submit(context.Background(), body); err == nil {
		t.Fatal("writer reused a sequence from an unresolved signing chain")
	}
}
