package control

import (
	"encoding/base64"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"
)

// DeviceReleaseRequest selects only the package authorized by the already
// accepted DeviceView. It cannot request arbitrary release-store contents.
type DeviceReleaseRequest struct {
	Schema     int    `json:"schema"`
	Platform   string `json:"platform"`
	ViewDigest string `json:"view_digest"`
}

func (value DeviceReleaseRequest) Validate() error {
	if value.Schema != 3 || value.Platform != "linux-amd64" && value.Platform != "linux-arm64" || ValidateDigest(value.ViewDigest) != nil {
		return errors.New("device release request is invalid")
	}
	return nil
}

// DeviceReleaseDelivery carries original immutable bytes, not another
// manifest, authorization, installation receipt or persistent value.
type DeviceReleaseDelivery struct {
	Schema            int    `json:"schema"`
	Platform          string `json:"platform"`
	ViewDigest        string `json:"view_digest"`
	CatalogBody       string `json:"catalog_body"`
	CatalogSignature  string `json:"catalog_signature"`
	ManifestBody      string `json:"manifest_body"`
	ManifestSignature string `json:"manifest_signature"`
}

func (value DeviceReleaseDelivery) Validate() error {
	if (DeviceReleaseRequest{Schema: value.Schema, Platform: value.Platform, ViewDigest: value.ViewDigest}).Validate() != nil || len(value.CatalogBody) == 0 || len(value.CatalogBody) > 1<<20 || len(value.ManifestBody) == 0 || len(value.ManifestBody) > 64<<10 || !canonicalReleaseSignature(value.CatalogSignature) || !canonicalReleaseSignature(value.ManifestSignature) {
		return errors.New("device release original bytes are invalid")
	}
	return nil
}

type DeviceReleaseDownload struct {
	Schema         int    `json:"schema"`
	Platform       string `json:"platform"`
	ViewDigest     string `json:"view_digest"`
	CatalogDigest  string `json:"catalog_digest"`
	ArtifactDigest string `json:"artifact_digest"`
}

func (value DeviceReleaseDownload) Validate() error {
	if (DeviceReleaseRequest{Schema: value.Schema, Platform: value.Platform, ViewDigest: value.ViewDigest}).Validate() != nil || ValidateDigest(value.CatalogDigest) != nil || ValidateDigest(value.ArtifactDigest) != nil {
		return errors.New("device release download coordinates are invalid")
	}
	return nil
}

func (server *Server) deviceReleasePackage(r *http.Request, request DeviceReleaseRequest) (ReleaseSet, ReleasePackage, error) {
	var zero ReleaseSet
	identity, authenticated := tunnelAuth(r)
	if !authenticated || identity.Mode != "device" || request.Validate() != nil || server.Releases == nil {
		return zero, ReleasePackage{}, errors.New("device release authentication required")
	}
	projection := server.Runtime.Authority.Snapshot()
	sets := server.expectedReleaseSets(projection)
	view, err := ProjectDeviceView(projection, identity.DeviceID, sets...)
	if err != nil || !strings.HasPrefix(request.Platform, view.Platform+"-") {
		return zero, ReleasePackage{}, errors.New("current device authorization unavailable")
	}
	digest, err := DeviceViewDigest(view)
	if err != nil || digest != request.ViewDigest {
		return zero, ReleasePackage{}, errors.New("device must first accept the current configuration")
	}
	var chosen *ExpectedComponent
	for i := range projection.NetworkIntent.ExpectedComponents {
		value := &projection.NetworkIntent.ExpectedComponents[i]
		if value.NodeID == identity.DeviceID && value.Platform == request.Platform && (chosen == nil || value.ComponentID == "agent") {
			chosen = value
		}
	}
	if chosen == nil {
		return zero, ReleasePackage{}, errors.New("no package expectation for this device")
	}
	for _, set := range sets {
		if set.ID != chosen.CatalogDigest {
			continue
		}
		for _, pkg := range set.Packages {
			if pkg.Entry.ManifestDigest != chosen.ManifestDigest || pkg.Entry.ComponentID != "linux-client-bootstrap" || pkg.Entry.Platform != request.Platform {
				continue
			}
			for _, expected := range view.ExpectedComponents {
				if expected.Platform == request.Platform && !slices.Contains(pkg.Components, expected) {
					return zero, ReleasePackage{}, errors.New("package would change an independently expected component")
				}
			}
			if len(set.CatalogBody) == 0 || len(set.CatalogSignature) != 64 {
				return zero, ReleasePackage{}, errors.New("original signed catalog is unavailable")
			}
			return set, pkg, nil
		}
	}
	return zero, ReleasePackage{}, errors.New("exact expected signed package unavailable")
}

func (server *Server) deviceRelease(w http.ResponseWriter, r *http.Request) {
	var request DeviceReleaseRequest
	if !readDeviceJSON(w, r, &request) {
		return
	}
	set, pkg, err := server.deviceReleasePackage(r, request)
	if err != nil {
		http.Error(w, "expected release unavailable", http.StatusConflict)
		return
	}
	writeCanonical(w, http.StatusOK, DeviceReleaseDelivery{Schema: 3, Platform: request.Platform, ViewDigest: request.ViewDigest, CatalogBody: string(set.CatalogBody), CatalogSignature: base64.RawURLEncoding.EncodeToString(set.CatalogSignature), ManifestBody: string(pkg.ManifestBody), ManifestSignature: base64.RawURLEncoding.EncodeToString(pkg.Signature)})
}

func (server *Server) deviceReleaseDownload(w http.ResponseWriter, r *http.Request) {
	var request DeviceReleaseDownload
	if !readDeviceJSON(w, r, &request) {
		return
	}
	set, pkg, err := server.deviceReleasePackage(r, DeviceReleaseRequest{Schema: request.Schema, Platform: request.Platform, ViewDigest: request.ViewDigest})
	if err != nil || set.ID != request.CatalogDigest || pkg.Entry.Artifact.Digest != request.ArtifactDigest {
		http.Error(w, "exact expected release unavailable", http.StatusConflict)
		return
	}
	reader, err := server.Releases.Open(set.ID, pkg.Entry.Artifact)
	if err != nil {
		http.Error(w, "verified release body unavailable", http.StatusServiceUnavailable)
		return
	}
	defer reader.Close()
	w.Header().Set("Content-Type", pkg.Entry.Artifact.MediaType)
	w.Header().Set("Content-Length", strconv.FormatUint(uint64(pkg.Entry.Artifact.Size), 10))
	_, _ = copyRelease(w, reader, 2*time.Minute)
}

func canonicalReleaseSignature(value string) bool {
	body, err := base64.RawURLEncoding.DecodeString(value)
	return err == nil && len(body) == 64 && base64.RawURLEncoding.EncodeToString(body) == value
}
