package webui

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func TestLinuxClientDownloadRequiresAuthAndServesOnlyVerifiedBytes(t *testing.T) {
	d := clientUIDeps()
	body := []byte("verified deterministic tar.gz bytes")
	hash := sha256.Sum256(body)
	called := 0
	d.Control.Clients.DownloadLinuxPackage = func() (LinuxClientPackageView, []byte, error) {
		called++
		return LinuxClientPackageView{
			Filename: "loom-client-linux-amd64.tar.gz", URL: "/devices/download/linux-amd64",
			SHA256: fmt.Sprintf("%x", hash[:]), Version: "0123456789ab",
			Arch: "linux/amd64", Size: int64(len(body)),
		}, append([]byte(nil), body...), nil
	}

	unauthorized := misakaRequest(t, d, http.MethodGet, "/devices/download/linux-amd64", nil, false)
	if unauthorized.Code != http.StatusSeeOther || called != 0 {
		t.Fatalf("unauthorized status=%d called=%d", unauthorized.Code, called)
	}
	authorized := misakaRequest(t, d, http.MethodGet, "/devices/download/linux-amd64", nil, true)
	if authorized.Code != http.StatusOK || authorized.Body.String() != string(body) || called != 1 {
		t.Fatalf("authorized status=%d body=%q called=%d", authorized.Code, authorized.Body.String(), called)
	}
	if got := authorized.Header().Get("Content-Disposition"); !strings.Contains(got, "attachment") || !strings.Contains(got, "loom-client-linux-amd64.tar.gz") {
		t.Fatalf("Content-Disposition=%q", got)
	}
	if authorized.Header().Get("Cache-Control") != "private, no-store" || authorized.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("download security headers=%v", authorized.Header())
	}
}

func TestLinuxClientDownloadRejectsCallbackMismatch(t *testing.T) {
	d := clientUIDeps()
	d.Control.Clients.DownloadLinuxPackage = func() (LinuxClientPackageView, []byte, error) {
		return LinuxClientPackageView{
			Filename: "loom-client-linux-amd64.tar.gz", URL: "/devices/download/linux-amd64",
			SHA256: strings.Repeat("0", 64), Arch: "linux/amd64", Size: 4,
		}, []byte("body"), nil
	}
	response := misakaRequest(t, d, http.MethodGet, "/devices/download/linux-amd64", nil, true)
	if response.Code != http.StatusServiceUnavailable || strings.Contains(response.Body.String(), "body") {
		t.Fatalf("mismatched callback status=%d body=%q", response.Code, response.Body.String())
	}
}

func TestPublicDeviceDistributionDoesNotRequireOperatorSession(t *testing.T) {
	d := clientUIDeps()
	d.Control.Clients.PublicLinuxArtifact = func(name string) (PublicDeviceArtifact, error) {
		if name != "loom-client-linux-amd64.tar.gz.sha256" {
			return PublicDeviceArtifact{}, fmt.Errorf("not found")
		}
		return PublicDeviceArtifact{
			Filename: name, ContentType: "text/plain; charset=utf-8", Body: []byte("abc  loom-client-linux-amd64.tar.gz\n"),
		}, nil
	}
	d.Control.Clients.LinuxInstallScript = func() ([]byte, error) {
		return []byte("#!/bin/sh\nset -eu\n"), nil
	}

	artifact := misakaRequest(t, d, http.MethodGet, "/device-dist/loom-client-linux-amd64.tar.gz.sha256", nil, false)
	if artifact.Code != http.StatusOK || !strings.Contains(artifact.Body.String(), "loom-client-linux-amd64") {
		t.Fatalf("public artifact status=%d body=%q", artifact.Code, artifact.Body.String())
	}
	installer := misakaRequest(t, d, http.MethodGet, "/device-dist/install.sh", nil, false)
	if installer.Code != http.StatusOK || installer.Header().Get("Content-Type") != "text/x-shellscript; charset=utf-8" {
		t.Fatalf("public installer status=%d headers=%v", installer.Code, installer.Header())
	}
	if strings.Contains(artifact.Header().Get("Cache-Control"), "private") || strings.Contains(installer.Body.String(), "loom://") {
		t.Fatal("public generic distribution leaked an invitation boundary or private cache policy")
	}
	missing := misakaRequest(t, d, http.MethodGet, "/device-dist/private-device.json", nil, false)
	if missing.Code != http.StatusNotFound {
		t.Fatalf("unknown public artifact status=%d", missing.Code)
	}
}
