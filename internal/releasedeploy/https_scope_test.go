package releasedeploy

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"loom/internal/control"
)

type demoCatalogSource map[string]control.ReleaseSet

func (source demoCatalogSource) Read() (control.ReleaseSet, error) {
	return control.ReleaseSet{}, errors.New("no implicit current")
}
func (source demoCatalogSource) ReadCatalog(id string) (control.ReleaseSet, error) {
	set, ok := source[id]
	if !ok {
		return control.ReleaseSet{}, errors.New("original metadata unavailable")
	}
	return set, nil
}
func (source demoCatalogSource) Open(string, control.ReleaseArtifact) (io.ReadCloser, error) {
	return nil, errors.New("metadata comparison must not open an artifact")
}

func demoPublicArtifact(body string) control.ReleaseArtifact {
	return control.ReleaseArtifact{Name: "demo-package.zip", Digest: control.ReleaseDigest([]byte(body)), Size: control.U64(len(body)), Audience: "public", MediaType: "application/zip"}
}

func TestRetainedPublicArtifactsRequireEveryPreviousCatalog(t *testing.T) {
	shared, oldOnly := demoPublicArtifact("demo-shared"), demoPublicArtifact("demo-old-only")
	a, b := control.ReleaseDigest([]byte("demo-a")), control.ReleaseDigest([]byte("demo-b"))
	source := demoCatalogSource{
		a: {ID: a, Catalog: control.ReleaseCatalog{Entries: []control.ReleaseEntry{{Artifact: shared}, {Artifact: oldOnly}}}},
		b: {ID: b, Catalog: control.ReleaseCatalog{Entries: []control.ReleaseEntry{{Artifact: shared}}}},
	}
	retained := retainedPublicArtifacts(source, []target{{previous: a}, {previous: b}})
	if len(retained) != 1 || !retained[shared] {
		t.Fatal("reuse did not take the intersection of actual old catalogs")
	}
	for _, prior := range []string{"", control.ReleaseDigest([]byte("demo-missing"))} {
		if len(retainedPublicArtifacts(source, []target{{previous: a}, {previous: prior}})) != 0 {
			t.Fatal("missing or unauthenticated old catalog reduced HTTPS verification")
		}
	}
	changed := shared
	changed.Size++
	source[b] = control.ReleaseSet{ID: b, Catalog: control.ReleaseCatalog{Entries: []control.ReleaseEntry{{Artifact: changed}}}}
	if len(retainedPublicArtifacts(source, []target{{previous: a}, {previous: b}})) != 0 {
		t.Fatal("different artifact coordinates were reused")
	}
}

func TestHTTPSDownloadsOnlyChangedBodiesAndRejectsMissingEvidence(t *testing.T) {
	oldText, newText := "demo old package", "demo new package"
	old, fresh := demoPublicArtifact(oldText), demoPublicArtifact(newText)
	set := control.ReleaseSet{Catalog: control.ReleaseCatalog{Entries: []control.ReleaseEntry{{Artifact: old}, {Artifact: fresh}}}}
	for _, mode := range []string{"cold", "mixed", "unchanged", "bad-metadata", "bad-body"} {
		t.Run(mode, func(t *testing.T) {
			retained := map[control.ReleaseArtifact]bool{}
			if mode != "cold" {
				retained[old] = true
			}
			if mode == "unchanged" {
				retained[fresh] = true
			}
			var gets, heads, verifiedBytes, closed atomic.Int64
			client := &http.Client{Transport: demoHTTP(func(request *http.Request) (*http.Response, error) {
				text, artifact := newText, fresh
				if strings.HasSuffix(request.URL.Path, strings.TrimPrefix(old.Digest, "sha256:")) {
					text, artifact = oldText, old
				}
				size := int64(artifact.Size)
				if request.Method == http.MethodHead {
					heads.Add(1)
					text = ""
					if mode == "bad-metadata" && artifact == old {
						size++
					}
				} else {
					gets.Add(1)
					if mode == "bad-body" && artifact == fresh {
						text = strings.Repeat("x", len(text))
					}
				}
				return &http.Response{StatusCode: http.StatusOK, ContentLength: size, Header: http.Header{},
					Body: &closedBody{Reader: strings.NewReader(text), closed: &closed}}, nil
			})}
			err := verifyHTTPS(context.Background(), client, []string{"https://a.example/", "https://b.example/"}, set, func(result Result) {
				if result.Verified {
					verifiedBytes.Add(result.ReadBytes)
				}
			}, retained)
			if (err != nil) != (mode == "bad-metadata" || mode == "bad-body") || closed.Load() != gets.Load()+heads.Load() {
				t.Fatal("HTTPS scope accepted wrong evidence or retained a connection", err)
			}
			if err != nil {
				return
			}
			wantGets, wantBytes := int64(2), int64(2*len(newText))
			if mode == "cold" {
				wantGets, wantBytes = 4, int64(2*(len(newText)+len(oldText)))
			} else if mode == "unchanged" {
				wantGets, wantBytes = 0, 0
			}
			if gets.Load() != wantGets || heads.Load() != 4-wantGets || verifiedBytes.Load() != wantBytes {
				t.Fatal("unchanged body was downloaded or changed body was not fully verified", gets.Load(), heads.Load(), verifiedBytes.Load())
			}
		})
	}
}
