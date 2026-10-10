package control

import (
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func releaseDownloadBase(catalog, artifact string) string {
	return "/api/control/releases/" + strings.TrimPrefix(catalog, "sha256:") + "/" + strings.TrimPrefix(artifact, "sha256:") + "/"
}

func releaseChecksum(value ReleaseArtifact) []byte {
	return []byte(strings.TrimPrefix(value.Digest, "sha256:") + "  " + value.Name + "\n")
}

func projectReleases(snapshot *WebSnapshot, set ReleaseSet) {
	result := []Release{}
	for _, pkg := range set.Packages {
		// The generic bootstrap is consumed by the invitation delivery flow, not
		// displayed as another installed application or architecture download.
		if pkg.Entry.ComponentID == "linux-bootstrap-script" {
			continue
		}
		file := pkg.Entry.Artifact
		platform, arch, _ := strings.Cut(pkg.Entry.Platform, "-")
		title, variant := "Loom Linux client", "Mixed archive"
		if pkg.Entry.ComponentID == "windows-dataplane" {
			title, variant = "Windows data plane", "Signed component ZIP"
		}
		if pkg.Entry.ComponentID == "android-application" {
			title, variant, arch = "Loom Android", "Signed APK", "ARM64 + x86_64"
		}
		switch pkg.Entry.ComponentID {
		case "windows-client-installed":
			title, variant = "Loom Windows", "Installed MSI · preview"
		case "windows-client-portable-tun":
			title, variant = "Loom Windows", "Portable TUN ZIP · preview"
		case "windows-client-portable-mixed":
			title, variant = "Loom Windows", "Portable Mixed ZIP · preview"
		}
		if pkg.Version == "devel" {
			variant = "Developer archive"
		}
		url := releaseDownloadBase(set.ID, file.Digest)
		checksum := releaseChecksum(file)
		result = append(result, Release{CatalogDigest: set.ID, ManifestDigest: pkg.Entry.ManifestDigest, Components: append([]ComponentReadback{}, pkg.Components...), Path: "bin/" + strings.TrimPrefix(file.Digest, "sha256:"), Name: file.Name, Title: title, Platform: platform, Arch: arch, Variant: variant, Version: pkg.Version, SourceCommit: pkg.SourceCommit, SHA256: strings.TrimPrefix(file.Digest, "sha256:"), Size: int64(file.Size), Signing: "Platform Ed25519 manifest and catalog", URL: url + "download",
			Checksum:  &ReleaseFile{Name: file.Name + ".sha256", SHA256: strings.TrimPrefix(ReleaseDigest(checksum), "sha256:"), Size: int64(len(checksum)), URL: url + "checksum"},
			Manifest:  &ReleaseFile{Name: file.Name + ".manifest.json", SHA256: strings.TrimPrefix(ReleaseDigest(pkg.ManifestBody), "sha256:"), Size: int64(len(pkg.ManifestBody)), URL: url + "manifest"},
			Signature: &ReleaseFile{Name: file.Name + ".sig", SHA256: strings.TrimPrefix(ReleaseDigest(pkg.Signature), "sha256:"), Size: int64(len(pkg.Signature)), URL: url + "signature"}})
	}
	snapshot.Releases = result
}

func (server *Server) releaseDownload(w http.ResponseWriter, r *http.Request) {
	catalogID, artifactID := "sha256:"+r.PathValue("catalog"), "sha256:"+r.PathValue("artifact")
	if server.Releases == nil || ValidateDigest(catalogID) != nil || ValidateDigest(artifactID) != nil || r.URL.RawQuery != "" {
		http.NotFound(w, r)
		return
	}
	set, err := server.Releases.ReadCatalog(catalogID)
	if err != nil {
		http.Error(w, "signed release unavailable", http.StatusServiceUnavailable)
		return
	}
	for _, pkg := range set.Packages {
		file := pkg.Entry.Artifact
		if file.Digest != artifactID {
			continue
		}
		name, media := file.Name, file.MediaType
		var body []byte
		switch r.PathValue("file") {
		case "download":
			reader, err := server.Releases.Open(catalogID, file)
			if err != nil {
				http.Error(w, "verified artifact unavailable", http.StatusServiceUnavailable)
				return
			}
			defer reader.Close()
			w.Header().Set("Content-Type", media)
			w.Header().Set("Content-Length", strconv.FormatUint(uint64(file.Size), 10))
			w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", name))
			_, _ = copyRelease(w, reader, 2*time.Minute)
			return
		case "checksum":
			name, media, body = name+".sha256", "text/plain; charset=utf-8", releaseChecksum(file)
		case "manifest":
			name, media, body = name+".manifest.json", "application/json", pkg.ManifestBody
		case "signature":
			name, media, body = name+".sig", "application/octet-stream", pkg.Signature
		default:
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", media)
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", name))
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		_, _ = w.Write(body)
		return
	}
	http.NotFound(w, r)
}

// Keep each blocked write bounded without truncating an immutable download
// merely because the complete transfer takes longer than an ordinary API call.
func copyRelease(w http.ResponseWriter, reader io.Reader, wait time.Duration) (int64, error) {
	// Verified in-memory artifacts expose WriterTo, which would otherwise send
	// the entire package in one Write and recreate the total-transfer deadline.
	return io.Copy(releaseWriter{w, http.NewResponseController(w), wait}, struct{ io.Reader }{reader})
}

type releaseWriter struct {
	writer     io.Writer
	controller *http.ResponseController
	wait       time.Duration
}

func (writer releaseWriter) Write(body []byte) (int, error) {
	if err := writer.controller.SetWriteDeadline(time.Now().Add(writer.wait)); err != nil {
		return 0, err
	}
	return writer.writer.Write(body)
}
