//go:build !windows

package publish

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func certifiedInputFixture(t *testing.T) []byte {
	t.Helper()
	input := CertifiedPublisherInput{Schema: 2, Head: "sha256:" + strings.Repeat("1", 64), Index: 7,
		ProjectionDigest: "sha256:" + strings.Repeat("2", 64), DistributionURLs: []string{},
		Devices: []CertifiedPublisherDevice{
			{ID: "demo-access", Platform: "windows", Roles: []string{"access"},
				Components: []CertifiedPublisherComponent{{Name: "sing-box", Version: "1.11.4"}}},
			{ID: "demo-server", Platform: "linux", Roles: []string{"server"},
				Components: []CertifiedPublisherComponent{{Name: "agent", Version: "2.0.0"}}},
		}}
	body, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func TestRunConsumesCertifiedAuthorityInputInsteadOfSSOTPath(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	target, err := ParseTarget(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	body := certifiedInputFixture(t)
	reads := 0
	err = Run(context.Background(), Options{AuthorityInput: func(context.Context) ([]byte, error) {
		reads++
		return append([]byte(nil), body...), nil
	}, SSOTPath: filepath.Join(t.TempDir(), "must-not-be-read.yaml"), Key: private, Target: target,
		ArchiveDir: "", PinDir: t.TempDir(), ReleaseDir: t.TempDir(), Once: true,
		Now: func() time.Time { return time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC) }, Log: io.Discard})
	if err != nil {
		t.Fatal(err)
	}
	if reads < 2 {
		t.Fatalf("certified input was not re-read under the publish lock: reads=%d", reads)
	}
	currentBody, found, err := target.ReadFile("current.json")
	if err != nil || !found {
		t.Fatalf("current found=%v err=%v", found, err)
	}
	current, err := DecodeDeploymentCurrent(currentBody)
	if err != nil || current.Verify(private.Public().(ed25519.PublicKey)) != nil {
		t.Fatalf("current=%+v err=%v", current, err)
	}
}

func TestRunUsesCertifiedDistributionURLs(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	distributionRoot := t.TempDir()
	target, err := ParseTarget(distributionRoot, "")
	if err != nil {
		t.Fatal(err)
	}
	requests := 0
	served := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests++
		name := strings.TrimPrefix(request.URL.Path, "/")
		if filepath.Clean(name) != name || strings.HasPrefix(name, "../") {
			http.NotFound(writer, request)
			return
		}
		body, readErr := os.ReadFile(filepath.Join(distributionRoot, filepath.FromSlash(name)))
		if readErr != nil {
			http.NotFound(writer, request)
			return
		}
		_, _ = writer.Write(body)
	}))
	defer served.Close()
	var input CertifiedPublisherInput
	if err := json.Unmarshal(certifiedInputFixture(t), &input); err != nil {
		t.Fatal(err)
	}
	input.DistributionURLs = []string{served.URL}
	body, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	healthPath := filepath.Join(t.TempDir(), "publisher.json")
	err = Run(context.Background(), Options{AuthorityInput: func(context.Context) ([]byte, error) {
		return append([]byte(nil), body...), nil
	}, Key: private, Target: target, ArchiveDir: "", PinDir: t.TempDir(), ReleaseDir: t.TempDir(),
		HealthPath: healthPath, LockPath: filepath.Join(t.TempDir(), "publisher.lock"), Once: true,
		Now: func() time.Time { return time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC) }, Log: io.Discard})
	if err != nil {
		t.Fatal(err)
	}
	health, err := ReadHealth(healthPath)
	if err != nil || health == nil || requests == 0 || len(health.DistributionChecks) != 1 ||
		!health.DistributionChecks[0].Success || health.DistributionChecks[0].URL != served.URL {
		t.Fatalf("requests=%d health=%+v err=%v", requests, health, err)
	}
}

func TestCertifiedPublisherInputStrictCanonicalRoundTrip(t *testing.T) {
	body := certifiedInputFixture(t)
	input, err := DecodeCertifiedPublisherInput(body)
	if err != nil || input.Index != 7 || len(input.Devices) != 2 {
		t.Fatalf("input=%+v err=%v", input, err)
	}
	if _, err := DecodeCertifiedPublisherInput(append(body, '\n')); err == nil {
		t.Fatal("accepted non-canonical publisher input")
	}
	unknown := append(append([]byte(nil), body[:len(body)-1]...), []byte(`,"runtime_key":"leak"}`)...)
	if _, err := DecodeCertifiedPublisherInput(unknown); err == nil {
		t.Fatal("accepted unknown secret-shaped field")
	}
}

func TestCertifiedPublisherInputRejectsUnsafeOrUnsortedDistributionURLs(t *testing.T) {
	var input CertifiedPublisherInput
	if err := json.Unmarshal(certifiedInputFixture(t), &input); err != nil {
		t.Fatal(err)
	}
	for _, values := range [][]string{
		{"https://z.example/loom/", "https://a.example/loom/"},
		{"https://user@example.com/loom/"},
		{"file:///srv/loom"},
	} {
		copy := input
		copy.DistributionURLs = values
		if err := copy.Validate(); err == nil {
			t.Fatalf("accepted distribution URLs %+v", values)
		}
	}
}

func TestBuildCertifiedPublishesOnlyReleaseCoordinates(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tree, err := BuildCertified(certifiedInputFixture(t), private, Meta{CreatedAt: "2026-09-20T12:00:00Z",
		Binaries: map[string][]byte{"linux/amd64": []byte("agent")}})
	if err != nil {
		t.Fatal(err)
	}
	if len(tree.Owners()) != 2 || tree.Files[tree.Snapshot+"/nodes/demo-server.json"] == nil {
		t.Fatalf("tree=%+v owners=%v", tree, tree.Owners())
	}
	for path, body := range tree.Files {
		text := string(body)
		if strings.Contains(text, "runtime_key") || strings.Contains(text, "private_key") || strings.Contains(text, "users") {
			t.Fatalf("secret/runtime configuration leaked in %s", path)
		}
	}
}
