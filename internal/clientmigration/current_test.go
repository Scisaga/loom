package clientmigration_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"loom/internal/clientmigration"
	"loom/internal/publish"
)

func TestMigrationAcceptsPublisherBytesAndPreservesLocalFloor(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	current := publish.DeploymentCurrent{Schema: 1, Generation: 17, Snapshot: "abcdef123456",
		Assignments: []publish.DeploymentAssignment{{Node: "demo-device", Snapshot: "abcdef123456"}},
		PublishedAt: time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC).Format(time.RFC3339)}
	if err := current.Sign(private); err != nil {
		t.Fatal(err)
	}
	body, err := current.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	floor := clientmigration.Floor{Schema: 1, Generation: 16, PayloadSHA256: strings.Repeat("0", 64), SelectedSnapshot: "123456abcdef"}
	leaf, err := clientmigration.VerifyFloor(body, public, "demo-device", floor)
	if err != nil {
		t.Fatal(err)
	}
	exact := clientmigration.Floor{Schema: 1, Generation: 17, PayloadSHA256: strings.TrimPrefix(leaf.V1PayloadHash, "sha256:"), SelectedSnapshot: current.Snapshot}
	if _, err := clientmigration.VerifyFloor(body, public, "demo-device", exact); err != nil {
		t.Fatal(err)
	}
	tests := map[string]struct {
		body   []byte
		key    ed25519.PublicKey
		device string
		floor  clientmigration.Floor
	}{
		"higher floor":                        {body, public, "demo-device", clientmigration.Floor{Schema: 1, Generation: 18, PayloadSHA256: exact.PayloadSHA256, SelectedSnapshot: exact.SelectedSnapshot}},
		"same generation fork":                {body, public, "demo-device", clientmigration.Floor{Schema: 1, Generation: 17, PayloadSHA256: strings.Repeat("0", 64), SelectedSnapshot: exact.SelectedSnapshot}},
		"same generation different selection": {body, public, "demo-device", clientmigration.Floor{Schema: 1, Generation: 17, PayloadSHA256: exact.PayloadSHA256, SelectedSnapshot: "123456abcdef"}},
		"wrong device":                        {body, public, "demo-other", floor},
		"wrong platform":                      {body, make(ed25519.PublicKey, ed25519.PublicKeySize), "demo-device", floor},
		"missing floor":                       {body, public, "demo-device", clientmigration.Floor{}},
		"unsigned pointer":                    {[]byte(`{"snapshot":"abcdef123456","published_at":"2025-01-02T03:04:05Z"}`), public, "demo-device", floor},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := clientmigration.VerifyFloor(test.body, test.key, test.device, test.floor); err == nil {
				t.Fatal("untrusted history accepted")
			}
		})
	}
	encoded, _ := json.Marshal(exact)
	parsed, err := clientmigration.ParseFloor(encoded)
	if err != nil || parsed != exact {
		t.Fatalf("floor did not round trip: %v", err)
	}
	duplicate := []byte(`{"schema":1,"schema":1,"generation":17,"payload_sha256":"` + exact.PayloadSHA256 + `","selected_snapshot":"abcdef123456"}`)
	if _, err := clientmigration.ParseFloor(duplicate); err == nil {
		t.Fatal("duplicate floor field accepted")
	}
}
