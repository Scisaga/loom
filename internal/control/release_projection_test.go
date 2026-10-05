package control

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The source is the already-verified package boundary; real archive verification
// and publication are exercised independently by clientrelease integration.
type demoReleaseSource struct {
	set  ReleaseSet
	body []byte
	err  error
}

func (s *demoReleaseSource) Read() (ReleaseSet, error) { return s.set, s.err }
func (s *demoReleaseSource) ReadCatalog(id string) (ReleaseSet, error) {
	if id != s.set.ID {
		return ReleaseSet{}, errors.New("catalog missing")
	}
	return s.Read()
}
func (s *demoReleaseSource) Open(id string, artifact ReleaseArtifact) (io.ReadCloser, error) {
	if _, err := s.ReadCatalog(id); err != nil {
		return nil, err
	}
	if artifact != s.set.Packages[0].Entry.Artifact {
		return nil, errors.New("artifact missing")
	}
	return io.NopCloser(bytes.NewReader(s.body)), nil
}

func TestReleaseDownloadsUseVerifiedCoordinatesAndFailClosed(t *testing.T) {
	root, config, genesis := authorityFixture(t)
	if _, err := InitializeAuthority(root, config, genesis); err != nil {
		t.Fatal(err)
	}
	runtime, err := OpenRuntime(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	catalog := demoReleaseCatalog()
	body := []byte("demo exact package bytes")
	catalog.Entries[0].Artifact.Digest = ReleaseDigest(body)
	catalog.Entries[0].Artifact.Size = U64(len(body))
	pkg := ReleasePackage{Entry: catalog.Entries[0], ManifestBody: []byte("demo original manifest"), Signature: bytes.Repeat([]byte{0x4b}, 64), Version: "demo-release", SourceCommit: "demo-source"}
	source := &demoReleaseSource{set: ReleaseSet{ID: ReleaseDigest([]byte("demo catalog")), Catalog: catalog, Packages: []ReleasePackage{pkg}}, body: body}
	server := &Server{Runtime: runtime, Config: config, Releases: source}
	request := func(path string) *httptest.ResponseRecorder {
		response := httptest.NewRecorder()
		server.AdminHandler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		return response
	}
	response := request("/api/control/ui/snapshot")
	var snapshot WebSnapshot
	if err := json.Unmarshal(response.Body.Bytes(), &snapshot); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusOK || len(snapshot.Releases) != 1 || len(snapshot.Deployments) != 0 {
		t.Fatal("verified download manufactured deployment status")
	}
	release := snapshot.Releases[0]
	base := releaseDownloadBase(source.set.ID, pkg.Entry.Artifact.Digest)
	if release.URL != base+"download" || release.SHA256 != strings.TrimPrefix(pkg.Entry.Artifact.Digest, "sha256:") {
		t.Fatal("download lost its exact catalog binding")
	}
	for file, expected := range map[string][]byte{"download": body, "checksum": releaseChecksum(pkg.Entry.Artifact), "manifest": pkg.ManifestBody, "signature": pkg.Signature} {
		response := request(base + file)
		if response.Code != http.StatusOK || !bytes.Equal(response.Body.Bytes(), expected) || response.Header().Get("Content-Disposition") == "" {
			t.Fatal("download bytes changed", file)
		}
	}
	for _, suffix := range []string{"undefined", "download?path=demo", "../download"} {
		if response := request(base + suffix); response.Code == http.StatusOK {
			t.Fatal("noncanonical file request accepted")
		}
	}
	unauthorized := httptest.NewRecorder()
	server.Handler().ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, base+"download", nil))
	if unauthorized.Code == http.StatusOK || bytes.Equal(unauthorized.Body.Bytes(), body) {
		t.Fatal("public caller downloaded private API artifact")
	}
	source.err = errors.New("demo private storage detail")
	response = request("/api/control/ui/snapshot")
	if err := json.Unmarshal(response.Body.Bytes(), &snapshot); err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Releases) != 0 || len(snapshot.UIState.Warnings) == 0 || strings.Contains(response.Body.String(), source.err.Error()) {
		t.Fatal("damaged release source retained cards or exposed local paths")
	}
	if response := request(base + "download"); response.Code != http.StatusServiceUnavailable {
		t.Fatal("damaged source served cached package")
	}
}
