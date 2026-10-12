package control

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

type deviceReleaseFixtureSource struct {
	*retainedReleaseSource
	body   []byte
	opened string
}

func (source *deviceReleaseFixtureSource) Open(id string, artifact ReleaseArtifact) (io.ReadCloser, error) {
	source.opened = id
	return io.NopCloser(bytes.NewReader(source.body)), nil
}

func TestDeviceReleaseUsesExactExpectationAndAcceptedView(t *testing.T) {
	server, invite, _, claim, _, _ := enrollmentAuthorityFixture(t)
	if enrollmentHTTP(t, server, "/enrollment/claim", claim, enrollmentTunnel(invite)).Code != http.StatusOK {
		t.Fatal("fixture join failed")
	}
	retained, value := expectedReleaseFixture()
	retained.original.CatalogBody = []byte("demo original independently verified catalog")
	retained.original.CatalogSignature = bytes.Repeat([]byte{1}, 64)
	pkg := &retained.original.Packages[0]
	pkg.ManifestBody = []byte("demo original independently verified manifest")
	pkg.Signature = bytes.Repeat([]byte{2}, 64)
	retained.current = ReleaseSet{ID: ReleaseDigest([]byte("demo different newer current"))}
	source := &deviceReleaseFixtureSource{retainedReleaseSource: retained, body: []byte("demo exact archive")}
	pkg.Entry.Artifact.Size = U64(len(source.body))
	retained.original.Catalog.Entries[0] = pkg.Entry
	server.Releases = source
	submitAuthority(t, server.Runtime, expectedOperation(server.Runtime.Authority.Snapshot(), value, "demo-expect-original"))
	envelope, err := server.deviceEnvelope(invite.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	identity := tunnelIdentity{Mode: "device", DeviceID: invite.DeviceID}
	request := DeviceReleaseRequest{Schema: 3, Platform: "linux-amd64", ViewDigest: envelope.ViewDigest}
	response := enrollmentHTTP(t, server, "/device/release", request, identity)
	if response.Code != http.StatusOK {
		t.Fatal("exact expected metadata refused", response.Body.String())
	}
	var delivery DeviceReleaseDelivery
	if err := DecodeCanonical(response.Body.Bytes(), &delivery, ContractDecodeLimits{MaxBytes: 2 << 20, MaxDepth: 8, MaxItems: 128}); err != nil {
		t.Fatal(err)
	}
	if delivery.CatalogBody != string(retained.original.CatalogBody) || delivery.ManifestSignature != base64.RawURLEncoding.EncodeToString(pkg.Signature) {
		t.Fatal("original signed bytes replaced by current or synthesized values")
	}
	download := DeviceReleaseDownload{Schema: 3, Platform: request.Platform, ViewDigest: request.ViewDigest, CatalogDigest: value.CatalogDigest, ArtifactDigest: pkg.Entry.Artifact.Digest}
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		server.DeviceHandler().ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), tunnelIdentityKey{}, identity)))
	}))
	defer endpoint.Close()
	downloadBody, err := CanonicalEncode(download)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := endpoint.Client().Post(endpoint.URL+"/device/release/download", "application/json", bytes.NewReader(downloadBody))
	if err != nil {
		t.Fatal(err)
	}
	body, readErr := io.ReadAll(actual.Body)
	actual.Body.Close()
	if actual.StatusCode != http.StatusOK || readErr != nil || !bytes.Equal(body, source.body) || source.opened != value.CatalogDigest {
		t.Fatal("exact expected download failed")
	}
	for _, test := range []struct {
		name   string
		change func(*DeviceReleaseRequest, *tunnelIdentity)
	}{
		{"bootstrap", func(_ *DeviceReleaseRequest, i *tunnelIdentity) { i.Mode = "bootstrap" }},
		{"different Device", func(_ *DeviceReleaseRequest, i *tunnelIdentity) { i.DeviceID = "demo-other" }},
		{"different View", func(r *DeviceReleaseRequest, _ *tunnelIdentity) { r.ViewDigest = retained.current.ID }},
		{"other architecture without expectation", func(r *DeviceReleaseRequest, _ *tunnelIdentity) { r.Platform = "linux-arm64" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			r, i := request, identity
			test.change(&r, &i)
			if enrollmentHTTP(t, server, "/device/release", r, i).Code == http.StatusOK {
				t.Fatal("unauthorized release metadata supplied")
			}
		})
	}
	download.CatalogDigest = retained.current.ID
	if enrollmentHTTP(t, server, "/device/release/download", download, identity).Code == http.StatusOK {
		t.Fatal("arbitrary download current admitted")
	}
	retained.unavailable = true
	if enrollmentHTTP(t, server, "/device/release", request, identity).Code == http.StatusOK {
		t.Fatal("missing reference became an empty expectation")
	}
}
