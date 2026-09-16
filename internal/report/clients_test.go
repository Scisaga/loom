package report

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"loom/internal/clientdist"
	"loom/internal/webui"
)

func TestVerifiedClientPackageCacheReusesStableFilesAndInvalidatesReplacement(t *testing.T) {
	dir := t.TempDir()
	paths := []string{
		filepath.Join(dir, "archive"), filepath.Join(dir, "checksum"),
		filepath.Join(dir, "signature"), filepath.Join(dir, "public-key"),
	}
	for _, path := range paths {
		if err := os.WriteFile(path, []byte(filepath.Base(path)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	verifyCalls := 0
	cache := verifiedClientPackageCache{
		paths: paths,
		verify: func() (clientdist.Published, error) {
			verifyCalls++
			return clientdist.Published{SHA256: string(rune('0' + verifyCalls))}, nil
		},
	}
	first, err := cache.load()
	if err != nil {
		t.Fatal(err)
	}
	second, err := cache.load()
	if err != nil || second.SHA256 != first.SHA256 || verifyCalls != 1 {
		t.Fatalf("stable package was reverified: first=%+v second=%+v calls=%d err=%v", first, second, verifyCalls, err)
	}
	replacement := filepath.Join(dir, "replacement")
	if err := os.WriteFile(replacement, []byte("new checksum"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, paths[1]); err != nil {
		t.Fatal(err)
	}
	third, err := cache.load()
	if err != nil || third.SHA256 == first.SHA256 || verifyCalls != 2 {
		t.Fatalf("replaced package member did not invalidate cache: first=%+v third=%+v calls=%d err=%v", first, third, verifyCalls, err)
	}
}

func TestVerifiedClientPackageCacheRetainsFailureUntilFilesChange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "archive")
	if err := os.WriteFile(path, []byte("broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	verifyCalls := 0
	cache := verifiedClientPackageCache{
		paths: []string{path},
		verify: func() (clientdist.Published, error) {
			verifyCalls++
			return clientdist.Published{}, errors.New("invalid package")
		},
	}
	for range 2 {
		if _, err := cache.load(); err == nil {
			t.Fatal("invalid package unexpectedly passed verification")
		}
	}
	if verifyCalls != 1 {
		t.Fatalf("unchanged invalid package was repeatedly verified: calls=%d", verifyCalls)
	}
	replacement := filepath.Join(dir, "replacement")
	if err := os.WriteFile(replacement, []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
	_, _ = cache.load()
	if verifyCalls != 2 {
		t.Fatalf("replacement did not retry verification: calls=%d", verifyCalls)
	}
}

func TestInvalidEnrollmentURLDoesNotCreateInvitationState(t *testing.T) {
	dir := t.TempDir()
	ssotPath := filepath.Join(dir, "ssot.yaml")
	if err := os.WriteFile(ssotPath, []byte("nodes: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	registryPath := filepath.Join(dir, "registry.json")
	deps := newClientControlDeps(&Control{
		SSOTPath: ssotPath, ClientRegistryPath: registryPath,
		ClientEnrollmentURL: "http://control.example/api/client/enroll?token=bad",
	}, nil)
	if _, err := deps.CreateInvite(accessInviteInput("device", "linux-server")); err == nil {
		t.Fatal("insecure enrollment URL was accepted")
	}
	if _, err := os.Stat(registryPath); !os.IsNotExist(err) {
		t.Fatalf("invalid URL left registry state: %v", err)
	}
}

func TestPublicClientBaseAndInstallerAreDeploymentConfigured(t *testing.T) {
	base, err := validClientPublicBaseURL(" https://download.example/loom/device-dist ")
	if err != nil || base != "https://download.example/loom/device-dist/" {
		t.Fatalf("public base=%q err=%v", base, err)
	}
	for _, invalid := range []string{"", "http://download.example/", "https://user@download.example/", "https://download.example/?token=x"} {
		if _, err := validClientPublicBaseURL(invalid); err == nil {
			t.Errorf("invalid public base %q accepted", invalid)
		}
	}
	script := string(linuxPublicInstallScript(webui.LinuxClientPackageView{
		Filename:  "loom-client-linux-amd64.tar.gz",
		PublicURL: "https://download.example/loom/device-dist/loom-client-linux-amd64.tar.gz",
	}))
	for _, want := range []string{"--proto '=https'", "sha256sum -c", "install.sh\" --no-enroll", "loom client enroll -stdin"} {
		if !strings.Contains(script, want) {
			t.Errorf("public installer missing %q", want)
		}
	}
	for _, forbidden := range []string{"loom://", "invite-file", "client_id", "10.99."} {
		if strings.Contains(script, forbidden) {
			t.Errorf("public installer contains private/enrollment material %q", forbidden)
		}
	}
}

func accessInviteInput(name, platform string) webui.ClientInviteInput {
	return webui.ClientInviteInput{
		Name: name, Platform: platform, Responsibilities: []string{"use_loom"},
		DestinationGrants: []string{"best-egress"},
	}
}
