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

func TestDeploymentRequiresExactPublisherAndDeviceEvidence(t *testing.T) {
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
	payload, err := current.PayloadSHA256()
	if err != nil {
		t.Fatal(err)
	}
	server := Server{PublisherObservationPath: observationPath, ReleaseKey: keyPath, Now: func() time.Time { return now }}
	projection := WebProjection{Schema: 1, Devices: []Device{{ID: "demo-device"}}}
	report := DeviceReport{Schema: enrollmentSchemaV2, DeviceID: "demo-device", ReportedAt: now.Format(time.RFC3339),
		Runtime: &RuntimeReadback{State: "running", AppliedViewDigest: "sha256:" + strings.Repeat("3", 64), Exact: true},
		Deployment: &DeploymentReadback{Generation: current.Generation, PayloadSHA256: payload,
			SelectedSnapshot: current.Snapshot, AppliedSnapshot: current.Snapshot, Version: "v1", RolloutVerified: true}}
	if err := server.projectDeployments(&projection, []DeviceReport{report}); err != nil {
		t.Fatal(err)
	}
	if len(projection.Deployments) != 1 || projection.Deployments[0].Stage != "verified" ||
		projection.Deployments[0].Status != "current" || projection.Devices[0].Deployment != "current" {
		t.Fatalf("exact evidence did not project current: %+v", projection)
	}
	report.Runtime.Exact = false
	if err := server.projectDeployments(&projection, []DeviceReport{report}); err != nil {
		t.Fatal(err)
	}
	if projection.Deployments[0].Stage != "applied" || projection.Deployments[0].Status != "waiting" {
		t.Fatalf("non-exact runtime projected as %q", projection.Deployments[0].Status)
	}
	report.Runtime.Exact = true
	report.Deployment.PayloadSHA256 = strings.Repeat("2", 64)
	if err := server.projectDeployments(&projection, []DeviceReport{report}); err != nil {
		t.Fatal(err)
	}
	if projection.Deployments[0].Stage != "unknown" || projection.Deployments[0].Status != "mismatch" {
		t.Fatalf("digest mismatch projected as %q", projection.Deployments[0].Status)
	}
	report.Deployment.PayloadSHA256 = payload
	report.Deployment.AppliedSnapshot = "aaaaaaaaaaaa"
	report.Deployment.RolloutVerified = false
	if err := server.projectDeployments(&projection, []DeviceReport{report}); err != nil {
		t.Fatal(err)
	}
	if projection.Deployments[0].Stage != "selected" {
		t.Fatalf("selected target projected as %+v", projection.Deployments[0])
	}
	report.Deployment.AppliedSnapshot = current.Snapshot
	if err := server.projectDeployments(&projection, []DeviceReport{report}); err != nil {
		t.Fatal(err)
	}
	if projection.Deployments[0].Stage != "applied" {
		t.Fatalf("applied target projected as %+v", projection.Deployments[0])
	}
	if err := server.projectDeployments(&projection, nil); err != nil {
		t.Fatal(err)
	}
	if projection.Deployments[0].Stage != "distributed" {
		t.Fatalf("distributed target projected as %+v", projection.Deployments[0])
	}
}
