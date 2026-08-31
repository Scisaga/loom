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
			Filename: "loom-client-linux-amd64.tar.gz", URL: "/clients/download/linux-amd64",
			SHA256: fmt.Sprintf("%x", hash[:]), Version: "0123456789ab",
			Arch: "linux/amd64", Size: int64(len(body)),
		}, append([]byte(nil), body...), nil
	}

	unauthorized := misakaRequest(t, d, http.MethodGet, "/clients/download/linux-amd64", nil, false)
	if unauthorized.Code != http.StatusSeeOther || called != 0 {
		t.Fatalf("unauthorized status=%d called=%d", unauthorized.Code, called)
	}
	authorized := misakaRequest(t, d, http.MethodGet, "/clients/download/linux-amd64", nil, true)
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
			Filename: "loom-client-linux-amd64.tar.gz", URL: "/clients/download/linux-amd64",
			SHA256: strings.Repeat("0", 64), Arch: "linux/amd64", Size: 4,
		}, []byte("body"), nil
	}
	response := misakaRequest(t, d, http.MethodGet, "/clients/download/linux-amd64", nil, true)
	if response.Code != http.StatusServiceUnavailable || strings.Contains(response.Body.String(), "body") {
		t.Fatalf("mismatched callback status=%d body=%q", response.Code, response.Body.String())
	}
}
