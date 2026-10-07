package control

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The source is the already-verified package boundary; real archive verification
// and publication are exercised independently by clientrelease integration.
type demoReleaseSource struct {
	set  ReleaseSet
	body []byte
	err  error
}

// Coordinate-only handler tests have no network connection to time out.
// The real HTTP tests below exercise both progress and blocked-write deadlines.
type releaseResponseRecorder struct{ *httptest.ResponseRecorder }

func (releaseResponseRecorder) SetWriteDeadline(time.Time) error { return nil }

func TestPrivateReleaseDownloadStopsWhenReceiverStopsReading(t *testing.T) {
	finished := make(chan error, 1)
	body := bytes.Repeat([]byte("demo"), 16<<20)
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprint(len(body)))
		_, err := copyRelease(w, bytes.NewReader(body), 25*time.Millisecond)
		finished <- err
	}))
	defer endpoint.Close()
	address, err := net.ResolveTCPAddr("tcp", strings.TrimPrefix(endpoint.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	connection, err := net.DialTCP("tcp", nil, address)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if err := connection.SetReadBuffer(1024); err != nil {
		t.Fatal(err)
	}
	if err := connection.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprintf(connection, "GET / HTTP/1.1\r\nHost: demo.example\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	if _, err := http.ReadResponse(bufio.NewReader(connection), &http.Request{Method: http.MethodGet}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-finished:
		var timeout net.Error
		if !errors.As(err, &timeout) || !timeout.Timeout() {
			t.Fatal("abandoned download did not exit at its write deadline", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("abandoned download retained its writer")
	}
}

type delayedReleaseReader struct {
	io.Reader
}

func (reader delayedReleaseReader) Read(body []byte) (int, error) {
	time.Sleep(5 * time.Millisecond)
	return reader.Reader.Read(body)
}

type delayedReleaseSource struct{ *demoReleaseSource }

func (source delayedReleaseSource) Open(id string, artifact ReleaseArtifact) (io.ReadCloser, error) {
	reader, err := source.demoReleaseSource.Open(id, artifact)
	if err != nil {
		return nil, err
	}
	return io.NopCloser(delayedReleaseReader{reader}), nil
}

func TestPrivateReleaseDownloadContinuesWhileMakingProgress(t *testing.T) {
	body := bytes.Repeat([]byte("demo artifact bytes\n"), 1<<16)
	catalog := demoReleaseCatalog()
	catalog.Entries[0].Artifact.Digest, catalog.Entries[0].Artifact.Size = ReleaseDigest(body), U64(len(body))
	pkg := ReleasePackage{Entry: catalog.Entries[0]}
	source := delayedReleaseSource{&demoReleaseSource{set: ReleaseSet{ID: ReleaseDigest([]byte("demo catalog")), Catalog: catalog, Packages: []ReleasePackage{pkg}}, body: body}}
	server := &Server{Releases: source}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/control/releases/{catalog}/{artifact}/{file}", server.releaseDownload)
	endpoint := httptest.NewUnstartedServer(mux)
	endpoint.Config.WriteTimeout = 25 * time.Millisecond
	endpoint.Start()
	defer endpoint.Close()
	response, err := endpoint.Client().Get(endpoint.URL + releaseDownloadBase(source.set.ID, pkg.Entry.Artifact.Digest) + "download")
	if err != nil {
		t.Fatal("continuous download stopped at the ordinary API deadline", err)
	}
	defer response.Body.Close()
	actual, err := io.ReadAll(response.Body)
	if err != nil || response.StatusCode != http.StatusOK || !bytes.Equal(actual, body) {
		t.Fatal("active download was truncated instead of retaining its exact signed bytes", err)
	}
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
		server.AdminHandler().ServeHTTP(releaseResponseRecorder{response}, httptest.NewRequest(http.MethodGet, path, nil))
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
