package control

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"loom/internal/publish"
	"loom/internal/version"
)

func TestDeploymentPublisherDoesNotInventDeviceApplication(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	current := publish.DeploymentCurrent{Schema: publish.DeploymentCurrentSchema, Generation: 7,
		Snapshot: "0123456789ab", PublishedAt: now.Add(-time.Minute).Format(time.RFC3339)}
	if err := current.Sign(private); err != nil {
		t.Fatal(err)
	}
	observation := publish.PublisherObservation{Schema: publish.PublisherObservationSchema, Current: current,
		ObservedAt: now.Format(time.RFC3339Nano), IntervalSeconds: 60,
		Version: version.Coordinate{Commit: "demo-commit", Platform: "linux/amd64"}, Success: true,
		DistributionChecks: []publish.PublisherDistributionCheck{{URL: "https://dist.example/current.json",
			Snapshot: current.Snapshot, SourceDigest: "sha256:" + strings.Repeat("1", 64),
			CheckedAt: now.Format(time.RFC3339Nano), Success: true}}}
	if err := observation.Sign(private); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	observationPath, keyPath := filepath.Join(root, "publisher.json.signed"), filepath.Join(root, "platform.pub")
	if err := observation.Write(observationPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte(base64.StdEncoding.EncodeToString(public)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	server := Server{PublisherObservationPath: observationPath, ReleaseKey: keyPath, Now: func() time.Time { return now }}
	projection := WebSnapshot{Schema: 3, Devices: []Device{{ID: "demo-device"}}, Deployments: []Deployment{}}
	if err := server.projectDeployments(&projection); err != nil {
		t.Fatal(err)
	}
	if projection.Publisher == nil || projection.Publisher.Distribution != "verified" || len(projection.Deployments) != 1 || projection.Deployments[0].Status != "unknown" || projection.Deployments[0].AppliedSnapshot != "" {
		t.Fatal("publisher distribution manufactured a device application readback")
	}
	body, err := os.ReadFile(observationPath)
	if err != nil {
		t.Fatal(err)
	}
	body = append(body, 'x')
	if err := os.WriteFile(observationPath, body, 0600); err != nil {
		t.Fatal(err)
	}
	if err := server.projectDeployments(&projection); err == nil {
		t.Fatal("invalid publisher signature/bytes were projected")
	}
}
