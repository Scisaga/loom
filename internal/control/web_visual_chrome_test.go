package control

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"loom/internal/clientrelease"
)

// TestWebVisualScenariosChrome renders the nine product routes through the
// real control handler and real browser. It is opt-in because the PNGs are
// review evidence, not a second UI implementation or a source of authority.
func TestWebVisualScenariosChrome(t *testing.T) {
	if os.Getenv("LOOM_WEB_VISUAL_TEST") != "1" {
		t.Skip("set LOOM_WEB_VISUAL_TEST=1 to render the Chrome visual review")
	}
	chrome, err := exec.LookPath("google-chrome")
	if err != nil {
		t.Fatal("google-chrome is required for Web visual review")
	}
	state := testState()
	state.Projection = visualWebProjection()
	server := testWritableRuntimeServer(t, state)
	// The legacy fixture activates the same certified Web projection used by
	// migration tests. Add the schema-2 intent directly to this in-memory visual
	// authority so capabilities and policy selectors exercise the current UI;
	// no production or persistent head is written by this renderer.
	intent := testNetworkIntent(t)
	server.Runtime.Authority.mu.Lock()
	server.Runtime.Authority.projection.NetworkIntent = &intent
	server.Runtime.Authority.certified.Projection.NetworkIntent = &intent
	server.Runtime.Authority.mu.Unlock()
	installVisualReleaseCatalog(t, server)
	httpServer := httptest.NewServer(server.AdminHandler())
	defer httpServer.Close()

	repository, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(repository, "out", "ui-review", "web", "current")
	if err := os.RemoveAll(output); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(output, 0o755); err != nil {
		t.Fatal(err)
	}
	scenarios := []struct{ name, path string }{
		{"overview", "/"},
		{"nodes", "/devices"},
		{"node-detail", "/devices/demo-access"},
		{"topology", "/topology"},
		{"live-paths", "/routing"},
		{"services", "/services"},
		{"deployments", "/deployments"},
		{"events", "/events"},
		{"ssot", "/ssot"},
		{"releases-linux", "/releases?platform=linux"},
		{"releases-android", "/releases?platform=android"},
		{"releases-windows", "/releases?platform=windows"},
		{"add-device", "/devices?new=1"},
	}
	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			target := filepath.Join(output, scenario.name+".png")
			profile := filepath.Join(t.TempDir(), "chrome-profile")
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, chrome,
				"--headless=new", "--no-sandbox", "--disable-gpu", "--hide-scrollbars",
				"--force-device-scale-factor=1", "--window-size=1586,992", "--virtual-time-budget=2500",
				"--user-data-dir="+profile, "--screenshot="+target, httpServer.URL+scenario.path)
			var output bytes.Buffer
			command.Stdout, command.Stderr = &output, &output
			if err := command.Run(); err != nil {
				t.Fatalf("Chrome render failed: %v: %s", err, output.String())
			}
			body, err := os.ReadFile(target)
			if err != nil || len(body) < 16<<10 || !bytes.HasPrefix(body, []byte("\x89PNG\r\n\x1a\n")) {
				t.Fatalf("Chrome did not produce a bounded PNG: bytes=%d err=%v", len(body), err)
			}
		})
	}
}

func installVisualReleaseCatalog(t *testing.T, server *Server) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	keyPath := filepath.Join(t.TempDir(), "release.pub")
	if err := os.WriteFile(keyPath, []byte(base64.StdEncoding.EncodeToString(public)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	artifacts := []clientrelease.Artifact{}
	for _, value := range []struct{ platform, title, name string }{
		{"linux-server", "Loom for Linux", "loom-linux-amd64"},
		{"android", "Loom for Android", "loom-android-arm64.apk"},
		{"windows-desktop", "Loom for Windows", "loom-windows-amd64.exe"},
		{"windows-desktop", "Loom for Windows · debug symbols", "loom-windows-debug.zip"},
	} {
		body := []byte("signed visual artifact for " + value.name)
		file := writeReleaseFile(t, root, value.name, body)
		checksum := writeReleaseFile(t, root, value.name+".sha256", []byte(file.SHA256+"  "+value.name+"\n"))
		signature := writeReleaseFile(t, root, value.name+".sig", []byte("demo-signature"))
		sbom := writeReleaseFile(t, root, value.name+".spdx.json", []byte(`{"spdxVersion":"SPDX-2.3"}`))
		variant := "stable"
		if strings.Contains(value.name, "debug") {
			variant = "debug"
		}
		artifacts = append(artifacts, clientrelease.Artifact{File: file, Filename: value.name, Title: value.title,
			Platform: value.platform, Arch: "amd64", Variant: variant, Version: "2.0.0", SourceCommit: strings.Repeat("a", 40),
			Signing: "ed25519", Checksum: checksum, Signature: signature, SBOM: &sbom})
	}
	catalog := clientrelease.Catalog{Schema: 1, Artifacts: artifacts}
	body, err := json.Marshal(catalog)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	digest := hex.EncodeToString(sum[:])
	directory := filepath.Join(root, "catalogs", digest)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "catalog.json"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	signed := ed25519.Sign(private, append([]byte("loom-client-releases-v1\n"), body...))
	if err := os.WriteFile(filepath.Join(directory, "catalog.sig"), []byte(base64.StdEncoding.EncodeToString(signed)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	pointer, _ := json.Marshal(map[string]string{"catalog": "catalogs/" + digest + "/catalog.json"})
	if err := os.WriteFile(filepath.Join(root, "current.json"), pointer, 0o600); err != nil {
		t.Fatal(err)
	}
	server.ReleaseRoot, server.ReleaseKey = root, keyPath
	if verified, err := server.catalog(); err != nil || len(verified.Artifacts) != len(artifacts) {
		t.Fatalf("visual release catalog was not independently verified: artifacts=%d err=%v", len(verified.Artifacts), err)
	}
}

func visualWebProjection() WebProjection {
	head := "sha256:" + strings.Repeat("0", 64)
	reported := "2030-01-02T03:04:05Z"
	runtime := &RuntimeReadback{State: "running", AppliedViewDigest: "sha256:" + strings.Repeat("1", 64), Exact: true,
		StartedAt: "2030-01-02T02:00:00Z"}
	devices := []Device{
		{ID: "demo-access", Name: "Demo workstation", Platform: "windows", Roles: []string{"access"}, Authorized: true,
			Availability: "available", Presence: "available", Components: "current", Deployment: "current", LastReportAt: reported,
			Evidence: &DeviceEvidence{ReportedAt: reported, ViewDigest: runtime.AppliedViewDigest, Runtime: runtime,
				Selections:   []ReportSelection{{Scope: "policy:demo-policy", CandidateID: "demo-relay"}},
				Components:   []ComponentReadback{{Name: "agent", Version: "2.0.0"}},
				Measurements: []Observation{{CandidateID: "demo-relay", Result: "available"}}}},
		{ID: "demo-cn", Name: "Demo relay", Platform: "linux", Roles: []string{"server"}, Authorized: true,
			Availability: "available", Presence: "available", RuntimeState: "running", Components: "current", Direction: "direct_only",
			Endpoint: "relay.example:443", Location: "CN", LastReportAt: reported},
		{ID: "demo-exit", Name: "Demo exit", Platform: "linux", Roles: []string{"server"}, Authorized: true,
			Availability: "available", Presence: "available", RuntimeState: "running", Components: "current", Direction: "reverse_only",
			Endpoint: "exit.example:443", Location: "DE", EgressCapable: true, LastReportAt: reported},
	}
	return WebProjection{Schema: 1, UIState: UIState{Head: head, Revision: 7, Writable: false}, Devices: devices,
		Links: []Link{{ID: "demo-link", From: "demo-cn", To: "demo-exit", Transport: "wireguard", Authorized: true,
			Availability: "available", LatencyMS: 37}},
		Paths: []Path{
			{CandidateID: "demo-direct", Device: "demo-access", Scope: "policy:demo-policy", FinalExit: "direct", Availability: "available"},
			{CandidateID: "demo-relay", Device: "demo-access", Scope: "policy:demo-policy", FinalExit: "demo-exit",
				Chain: []string{"demo-cn", "demo-exit"}, Selected: true, Availability: "available"},
		},
		Services: []Service{{ID: "demo-web", Name: "Demo web", Matchers: []string{"example.com", ".example.net"}, Policy: "demo-policy"}},
		Deployments: []Deployment{{Device: "demo-access", Generation: 3, TargetSnapshot: "0123456789ab", AppliedSnapshot: "0123456789ab",
			PublisherAt: reported, DeviceReportedAt: reported, Stage: "verified", Status: "current", Detail: "verified"}},
		Publisher: &PublisherStatus{ObservedAt: reported, IntervalSeconds: 60, Generation: 3, Snapshot: "0123456789ab",
			Commit: strings.Repeat("a", 40), Binary: strings.Repeat("b", 64), Status: "healthy", Distribution: "verified"},
		Events: []Event{{ID: "demo-event", At: reported, Kind: "path", Subject: "demo-access", From: "demo-direct", To: "demo-relay",
			Detail: "Selected the authorized relay candidate.", Level: "information"}},
		Traffic: []TrafficBucket{{Device: "demo-cn", LinkID: "demo-link", Hour: "2030-01-02T03:00:00Z", TXBytes: 4096,
			RXBytes: 2048, ForwardBytes: 4096}},
	}
}

func TestVisualWebProjectionHasNineRouteEvidence(t *testing.T) {
	projection := visualWebProjection()
	if len(projection.Devices) < 3 || len(projection.Links) == 0 || len(projection.Paths) < 2 ||
		len(projection.Services) == 0 || len(projection.Events) == 0 || len(projection.Traffic) == 0 {
		t.Fatal(errors.New("Web visual fixture does not cover the product surfaces"))
	}
}
