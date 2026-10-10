package control

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

type snapshotReleaseSource struct {
	*retainedReleaseSource
	currentError               error
	currentReads, catalogReads int
}

func (s *snapshotReleaseSource) Read() (ReleaseSet, error) {
	s.currentReads++
	return s.current, s.currentError
}
func (s *snapshotReleaseSource) ReadCatalog(id string) (ReleaseSet, error) {
	s.catalogReads++
	return s.retainedReleaseSource.ReadCatalog(id)
}

func TestSnapshotReusesOnlyThisRequestsVerifiedCurrentRelease(t *testing.T) {
	server, invite, _, claim, _, _ := enrollmentAuthorityFixture(t)
	if enrollmentHTTP(t, server, "/enrollment/claim", claim, enrollmentTunnel(invite)).Code != http.StatusOK {
		t.Fatal("fixture claim failed")
	}
	original, expected := expectedReleaseFixture()
	source := &snapshotReleaseSource{retainedReleaseSource: original}
	server.Releases = source
	if _, _, err := server.HandleOperation(context.Background(), expectedOperation(server.Runtime.Authority.Snapshot(), expected, "demo-expected")); err != nil {
		t.Fatal(err)
	}
	read := func(wantCatalogReads int, wantExpected, wantDownload bool) WebSnapshot {
		t.Helper()
		source.currentReads, source.catalogReads = 0, 0
		response := httptest.NewRecorder()
		server.AdminHandler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/control/ui/snapshot", nil))
		if response.Code != http.StatusOK {
			t.Fatal("formal snapshot failed", response.Code, response.Body.String())
		}
		var value WebSnapshot
		if err := json.Unmarshal(response.Body.Bytes(), &value); err != nil {
			t.Fatal(err)
		}
		if source.currentReads != 1 || source.catalogReads != wantCatalogReads {
			t.Fatalf("snapshot verified catalogs %d+%d times, want 1+%d", source.currentReads, source.catalogReads, wantCatalogReads)
		}
		found := false
		for _, device := range value.Devices {
			if device.ID == invite.DeviceID {
				found = true
				if (len(device.ExpectedComponents) == 1) != wantExpected || (device.ComponentError == "") != wantExpected {
					t.Fatal("expected component lost its independent verification", device.ComponentError)
				}
				if wantExpected && device.ExpectedComponents[0] != source.original.Packages[0].Components[0] {
					t.Fatal("current selection rewrote the signed expectation")
				}
			}
		}
		if !found {
			t.Fatal("authorized device disappeared")
		}
		if (len(value.Releases) > 0) != wantDownload {
			t.Fatal("download did not reflect verified current selection")
		}
		warning := false
		for _, v := range value.UIState.Warnings {
			warning = warning || v.Code == "release_catalog_unavailable"
		}
		if warning == wantDownload {
			t.Fatal("current verification failure was hidden or invented")
		}
		return value
	}
	read(0, true, true)
	// A later request must read the new current, while the unchanged signed
	// expectation continues to resolve its exact retained catalog.
	source.current.ID = ReleaseDigest([]byte("demo changed download selection"))
	changed := read(1, true, true)
	if changed.Releases[0].CatalogDigest != source.current.ID {
		t.Fatal("snapshot reused the preceding request's current")
	}
	// A failing Read may return a partial value. It is never a verified input,
	// even if its ID matches the independently addressable retained catalog.
	source.current = source.original
	source.currentError = errors.New("demo current verification failed")
	read(1, true, false)
	source.unavailable = true
	read(1, false, false)
	source.currentError = nil
	source.unavailable = false
	read(0, true, true)
}
