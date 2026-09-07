package loomcore

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func TestSignedCurrentMatchesAuthoritativeVector(t *testing.T) {
	publicKey, err := hex.DecodeString("2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12")
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{
  "schema": 1,
  "generation": 7,
  "snapshot": "777777777777",
  "assignments": [
    {
      "node": "android-a",
      "snapshot": "0123456789ab"
    },
    {
      "node": "z-node",
      "snapshot": "aaaaaaaaaaaa"
    }
  ],
  "published_at": "2026-09-07T12:34:56.123456789Z",
  "signature": "cUZ+aMC/dqPvsQaD/MywjcidRZQ05VRwlkcmIW/j1CUi1iOdtT12sZDnzIAdvrBNqVEjXaDMXfczqUrmZ2DYCA=="
}
`)
	verifiedJSON, err := VerifyCurrent(body, publicKey, "android-a", body, nil)
	if err != nil {
		t.Fatal(err)
	}
	var verified currentVerification
	if err := decodeStrictJSON(verifiedJSON, maxCurrentBytes, &verified); err != nil {
		t.Fatal(err)
	}
	if verified.PayloadSHA256 != "dc1ea6641a487aa163cba8696911758db1f4228b0b37ebac63f9ad5c53f847e2" ||
		verified.SelectedSnapshot != "0123456789ab" {
		t.Fatalf("authoritative vector mismatch: %+v", verified)
	}
}

type pullFixture struct {
	current, manifest, signature, bundle []byte
}

func makePullFixture(t *testing.T, privateKey ed25519.PrivateKey, generation uint64, snapshot, nodeID string,
	files map[string]string) pullFixture {
	t.Helper()
	bundle := &bundleWire{Owner: nodeID, Files: files}
	bundleJSON, err := marshalCanonical(bundle)
	if err != nil {
		t.Fatal(err)
	}
	manifest := &manifestWire{
		ID: snapshot, CreatedAt: "2026-09-07T12:00:00Z", SSOTHash: strings.Repeat("a", 64),
		Bundles:    []bundleRefWire{{Owner: nodeID, Hash: bundleHash(files)}},
		Components: []componentRefWire{{Node: nodeID, SingBox: "1.11.4"}},
	}
	manifestJSON, err := marshalCanonical(manifest)
	if err != nil {
		t.Fatal(err)
	}
	return pullFixture{
		current:  signedCurrentFixture(t, privateKey, generation, snapshot, ""),
		manifest: manifestJSON, signature: ed25519.Sign(privateKey, manifestJSON), bundle: bundleJSON,
	}
}

func currentFloorJSON(t *testing.T, verification []byte) []byte {
	t.Helper()
	var result currentVerification
	if err := decodeStrictJSON(verification, maxCurrentBytes, &result); err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(&result.NextFloor)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestVerifyCurrentAndPullProduceDurableCoordinates(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	fixture := makePullFixture(t, privateKey, 1, "111111111111", "android-a",
		map[string]string{"sing-box/config.json": `{"log":{"level":"warn"}}`})
	currentResult, err := VerifyCurrent(fixture.current, publicKey, "android-a", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	floor := currentFloorJSON(t, currentResult)
	verifiedJSON, err := VerifyPull(fixture.current, fixture.manifest, fixture.signature, fixture.bundle,
		publicKey, "android-a", nil, floor)
	if err != nil {
		t.Fatal(err)
	}
	var verified pullVerification
	if err := decodeStrictJSON(verifiedJSON, maxBundleBytes, &verified); err != nil {
		t.Fatal(err)
	}
	if verified.Generation != 1 || verified.Snapshot != "111111111111" ||
		verified.BundleSHA256 != bundleHash(map[string]string{"sing-box/config.json": `{"log":{"level":"warn"}}`}) ||
		verified.CanonicalBundle != string(fixture.bundle) || verified.Components.SingBox != "1.11.4" {
		t.Fatalf("verified=%+v", verified)
	}
}

func TestVerifyCurrentRejectsRollbackForkAndUnanchoredLateInstall(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	first := signedCurrentFixture(t, privateKey, 7, "777777777777", "")
	anchored, err := VerifyCurrent(first, publicKey, "android-a", first, nil)
	if err != nil {
		t.Fatal(err)
	}
	floor := currentFloorJSON(t, anchored)
	stale := signedCurrentFixture(t, privateKey, 6, "666666666666", "")
	if _, err := VerifyCurrent(stale, publicKey, "android-a", nil, floor); err == nil || !strings.Contains(err.Error(), "below") {
		t.Fatalf("stale current error=%v", err)
	}
	fork := signedCurrentFixture(t, privateKey, 7, "aaaaaaaaaaaa", "")
	if _, err := VerifyCurrent(fork, publicKey, "android-a", nil, floor); err == nil || !strings.Contains(err.Error(), "different payload") {
		t.Fatalf("same-generation fork error=%v", err)
	}
	if _, err := VerifyCurrent(first, publicKey, "android-a", nil, nil); err == nil || !strings.Contains(err.Error(), "expected-current") {
		t.Fatalf("late first install error=%v", err)
	}
}

func TestVerifyCachedPullAllowsLastGoodBelowNewerLatchedFloor(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	old := makePullFixture(t, privateKey, 1, "111111111111", "android-a",
		map[string]string{"sing-box/config.json": `{"log":{}}`})
	newCurrent := signedCurrentFixture(t, privateKey, 2, "222222222222", "")
	newVerification, err := VerifyCurrent(newCurrent, publicKey, "android-a", nil,
		currentFloorJSON(t, mustVerifyCurrent(t, old.current, publicKey)))
	if err != nil {
		t.Fatal(err)
	}
	newFloor := currentFloorJSON(t, newVerification)
	if _, err := VerifyPull(old.current, old.manifest, old.signature, old.bundle,
		publicKey, "android-a", nil, newFloor); err == nil {
		t.Fatal("incoming pull accepted a generation below the floor")
	}
	if _, err := VerifyCachedPull(old.current, old.manifest, old.signature, old.bundle,
		publicKey, "android-a", newFloor); err != nil {
		t.Fatalf("last known-good cache was not preserved: %v", err)
	}
}

func mustVerifyCurrent(t *testing.T, current, publicKey []byte) []byte {
	t.Helper()
	result, err := VerifyCurrent(current, publicKey, "android-a", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestSelectVerifiedCurrentsChoosesHighestAndRejectsMirrorFork(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	first := signedCurrentFixture(t, privateKey, 1, "111111111111", "")
	second := signedCurrentFixture(t, privateKey, 2, "222222222222", "")
	candidates, _ := json.Marshal(&currentCandidatesWire{Schema: 1, Candidates: []currentCandidateWire{
		{ID: "mirror-a", CurrentJSON: string(first)}, {ID: "mirror-b", CurrentJSON: string(second)},
		{ID: "untrusted", CurrentJSON: `{"schema":1}`},
	}})
	selectedJSON, err := SelectVerifiedCurrents(candidates, publicKey, "android-a", second, nil)
	if err != nil {
		t.Fatal(err)
	}
	var selected selectedCurrent
	if err := decodeStrictJSON(selectedJSON, maxCurrentBytes*2, &selected); err != nil {
		t.Fatal(err)
	}
	if selected.Generation != 2 || selected.CurrentJSON != string(second) || selected.SelectedSnapshot != "222222222222" {
		t.Fatalf("selected=%+v", selected)
	}

	fork := signedCurrentFixture(t, privateKey, 2, "aaaaaaaaaaaa", "")
	candidates, _ = json.Marshal(&currentCandidatesWire{Schema: 1, Candidates: []currentCandidateWire{
		{ID: "mirror-a", CurrentJSON: string(second)}, {ID: "mirror-b", CurrentJSON: string(fork)},
	}})
	if _, err := SelectVerifiedCurrents(candidates, publicKey, "android-a", nil, nil); err == nil || !strings.Contains(err.Error(), "mirror fork") {
		t.Fatalf("fork error=%v", err)
	}
}

func TestVerifyPullRejectsEveryPayloadBindingBreak(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	base := makePullFixture(t, privateKey, 1, "111111111111", "android-a",
		map[string]string{"sing-box/config.json": `{"log":{}}`})
	tests := []struct {
		name   string
		mutate func(*pullFixture)
	}{
		{"manifest signature", func(fixture *pullFixture) { fixture.signature[0] ^= 0x80 }},
		{"manifest id", func(fixture *pullFixture) {
			var manifest manifestWire
			_ = json.Unmarshal(fixture.manifest, &manifest)
			manifest.ID = "222222222222"
			fixture.manifest, _ = marshalCanonical(&manifest)
			fixture.signature = ed25519.Sign(privateKey, fixture.manifest)
		}},
		{"bundle owner", func(fixture *pullFixture) {
			fixture.bundle = []byte(`{"owner":"other","files":{"sing-box/config.json":"{}"}}`)
		}},
		{"bundle hash", func(fixture *pullFixture) {
			fixture.bundle = []byte(`{"owner":"android-a","files":{"sing-box/config.json":"changed"}}`)
		}},
		{"unsafe bundle path", func(fixture *pullFixture) {
			fixture.bundle = []byte(`{"owner":"android-a","files":{"../escape":"x"}}`)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := pullFixture{
				current: append([]byte(nil), base.current...), manifest: append([]byte(nil), base.manifest...),
				signature: append([]byte(nil), base.signature...), bundle: append([]byte(nil), base.bundle...),
			}
			test.mutate(&fixture)
			if _, err := VerifyPull(fixture.current, fixture.manifest, fixture.signature, fixture.bundle,
				publicKey, "android-a", nil, nil); err == nil {
				t.Fatal("broken binding was accepted")
			}
		})
	}
}
