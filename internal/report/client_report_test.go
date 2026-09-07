package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"loom/internal/attest"
	"loom/internal/clientregistry"
)

type clientReportHarness struct {
	receiver     *clientReportReceiver
	table        *table
	observation  Observation
	registryPath string
	publicKey    string
	now          time.Time
}

func newClientReportHarness(t *testing.T) clientReportHarness {
	t.Helper()
	return newClientReportHarnessFor(t, "workstation", "windows-desktop")
}

func newClientReportHarnessFor(t *testing.T, node, platform string) clientReportHarness {
	t.Helper()
	now := time.Date(2026, 9, 5, 15, 20, 0, 0, time.UTC)
	ca, key, cert := reportTestIdentity(t, node)
	observation := Observation{
		Node: node, TS: now.Format(time.RFC3339), Applied: "snapshot-v5",
	}
	_, current := claimsForObservation(&observation, 5)
	var err error
	// Phase B producers put canonical v5 directly in the primary attachment.
	// attest_extended exists only for the old-reader rolling migration and is
	// deliberately absent from the NAT client's minimum wire shape.
	observation.Attest, err = attest.Sign(current, key, cert)
	if err != nil {
		t.Fatal(err)
	}
	observation.SelfCheck, err = attest.SignSelfCheck(attest.SelfCheckClaim{
		Version: attest.SelfCheckClaimVersion, Node: observation.Node, TS: observation.TS, Healthy: true,
	}, key, cert)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := clientReportPublicKey(&observation)
	if err != nil {
		t.Fatal(err)
	}

	ssotPath, err := filepath.Abs("../../testdata/matrix/ssot.yaml")
	if err != nil {
		t.Fatal(err)
	}
	registryPath := filepath.Join(t.TempDir(), "registry.json")
	writeClientReportRegistryFor(t, registryPath, node, platform, "ready", publicKey)
	tbl := newTable(5)
	tbl.verify = func(got *Observation, at time.Time, maxAge time.Duration) error {
		_, err := VerifyObservationAtLeast(got, ca, at, maxAge, 5)
		return err
	}
	tbl.verifySelfCheck = func(got *Observation, at time.Time, maxAge time.Duration) error {
		_, err := verifySelfCheckAttachment(got, ca, at, maxAge)
		return err
	}
	receiver := newClientReportReceiver(tbl, &Control{
		SSOTPath: ssotPath, ClientRegistryPath: registryPath,
	}, func() time.Time { return now }, 10*time.Minute, nil)
	receiver.readCA = func(string) ([]byte, error) { return ca, nil }
	return clientReportHarness{
		receiver: receiver, table: tbl, observation: observation,
		registryPath: registryPath, publicKey: publicKey, now: now,
	}
}

func writeClientReportRegistry(t *testing.T, path, status, publicKey string) {
	t.Helper()
	writeClientReportRegistryFor(t, path, "workstation", "windows-desktop", status, publicKey)
}

func writeClientReportRegistryFor(t *testing.T, path, node, platform, status, publicKey string) {
	t.Helper()
	body, err := json.Marshal(struct {
		Schema  int                     `json:"schema"`
		Clients []clientregistry.Client `json:"clients"`
	}{
		Schema: clientregistry.Schema,
		Clients: []clientregistry.Client{{
			ID: node, Name: node, Platform: platform,
			IdentitySource: "enrollment", PublicKey: publicKey, Status: status,
			CreatedAt: "2026-09-05T15:00:00Z", EnrolledAt: "2026-09-05T15:01:00Z",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(body, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

func postClientReport(t *testing.T, receiver http.Handler, observation any) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(observation)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/client/report", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	receiver.ServeHTTP(response, req)
	return response
}

func TestClientReportReceiverAcceptsDirectV5ObservationIntoGossipTable(t *testing.T) {
	h := newClientReportHarness(t)
	if h.observation.Attest == nil || h.observation.Attest.CanonicalVersion != 5 ||
		h.observation.AttestExtended != nil {
		t.Fatalf("client report fixture is not direct canonical v5: %+v", h.observation)
	}
	response := postClientReport(t, h.receiver, &h.observation)
	if response.Code != http.StatusNoContent || response.Body.Len() != 0 {
		t.Fatalf("client report response = %d %q", response.Code, response.Body.String())
	}
	learned := h.table.snapshot("control", h.now, 10*time.Minute)
	if len(learned) != 1 || learned[0].Node != h.observation.Node ||
		learned[0].Applied != h.observation.Applied || learned[0].SelfCheck == nil {
		t.Fatalf("accepted client report did not enter gossip table: %+v", learned)
	}
}

func TestClientReportReceiverAcceptsAndroidDirectV5Observation(t *testing.T) {
	h := newClientReportHarnessFor(t, "phone", "android")
	if h.observation.Attest == nil || h.observation.Attest.CanonicalVersion != 5 ||
		h.observation.SelfCheck == nil || h.observation.SelfCheck.Version != attest.SelfCheckClaimVersion {
		t.Fatalf("Android report fixture is not v5 + self-check v1: %+v", h.observation)
	}
	response := postClientReport(t, h.receiver, &h.observation)
	if response.Code != http.StatusNoContent || response.Body.Len() != 0 {
		t.Fatalf("Android client report response = %d %q", response.Code, response.Body.String())
	}
	learned := h.table.snapshot("control", h.now, 10*time.Minute)
	if len(learned) != 1 || learned[0].Node != "phone" || learned[0].Applied != h.observation.Applied ||
		learned[0].SelfCheck == nil {
		t.Fatalf("accepted Android report did not enter gossip table: %+v", learned)
	}
}

func TestClientReportReceiverRejectsTamperMissingProofAndRevokedIdentity(t *testing.T) {
	t.Run("tampered applied", func(t *testing.T) {
		h := newClientReportHarness(t)
		h.observation.Applied = "tampered"
		if got := postClientReport(t, h.receiver, &h.observation); got.Code != http.StatusForbidden {
			t.Fatalf("tampered report response = %d %q", got.Code, got.Body.String())
		}
		if learned := h.table.snapshot("control", h.now, 10*time.Minute); len(learned) != 0 {
			t.Fatalf("tampered report entered gossip table: %+v", learned)
		}
	})
	t.Run("missing self-check", func(t *testing.T) {
		h := newClientReportHarness(t)
		h.observation.SelfCheck = nil
		if got := postClientReport(t, h.receiver, &h.observation); got.Code != http.StatusForbidden {
			t.Fatalf("report without self-check response = %d %q", got.Code, got.Body.String())
		}
	})
	t.Run("revoked registry identity", func(t *testing.T) {
		h := newClientReportHarness(t)
		writeClientReportRegistry(t, h.registryPath, "revoked", h.publicKey)
		if got := postClientReport(t, h.receiver, &h.observation); got.Code != http.StatusForbidden {
			t.Fatalf("revoked report response = %d %q", got.Code, got.Body.String())
		}
	})
	t.Run("not ready registry identity", func(t *testing.T) {
		h := newClientReportHarness(t)
		writeClientReportRegistry(t, h.registryPath, "provisioning", h.publicKey)
		if got := postClientReport(t, h.receiver, &h.observation); got.Code != http.StatusForbidden {
			t.Fatalf("not-ready report response = %d %q", got.Code, got.Body.String())
		}
	})
	t.Run("wrong registry SPKI", func(t *testing.T) {
		h := newClientReportHarness(t)
		_, otherKey, otherCert := reportTestIdentity(t, h.observation.Node)
		other := h.observation
		_, current := claimsForObservation(&other, 5)
		var err error
		other.Attest, err = attest.Sign(current, otherKey, otherCert)
		if err != nil {
			t.Fatal(err)
		}
		other.SelfCheck, err = attest.SignSelfCheck(attest.SelfCheckClaim{
			Version: attest.SelfCheckClaimVersion, Node: other.Node, TS: other.TS, Healthy: true,
		}, otherKey, otherCert)
		if err != nil {
			t.Fatal(err)
		}
		otherPublicKey, err := clientReportPublicKey(&other)
		if err != nil {
			t.Fatal(err)
		}
		writeClientReportRegistry(t, h.registryPath, "ready", otherPublicKey)
		if got := postClientReport(t, h.receiver, &h.observation); got.Code != http.StatusForbidden {
			t.Fatalf("wrong-SPKI report response = %d %q", got.Code, got.Body.String())
		}
	})
	t.Run("registry platform differs from SSOT", func(t *testing.T) {
		h := newClientReportHarnessFor(t, "phone", "android")
		writeClientReportRegistryFor(t, h.registryPath, "phone", "windows-desktop", "ready", h.publicKey)
		if got := postClientReport(t, h.receiver, &h.observation); got.Code != http.StatusForbidden {
			t.Fatalf("platform-mismatch report response = %d %q", got.Code, got.Body.String())
		}
	})
}

func TestClientReportReceiverRejectsLinuxAccessDevice(t *testing.T) {
	h := newClientReportHarnessFor(t, "ci-runner", "linux-server")
	if got := postClientReport(t, h.receiver, &h.observation); got.Code != http.StatusForbidden {
		t.Fatalf("Linux client report response = %d %q", got.Code, got.Body.String())
	}
}

func TestClientReportReceiverReportsLocalTableFailureAsUnavailable(t *testing.T) {
	h := newClientReportHarness(t)
	h.table.verify = func(*Observation, time.Time, time.Duration) error {
		return errors.New("local verifier unavailable")
	}
	response := postClientReport(t, h.receiver, &h.observation)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("local table failure response = %d %q", response.Code, response.Body.String())
	}
}

func TestClientReportReceiverEnforcesHTTPBoundary(t *testing.T) {
	h := newClientReportHarness(t)

	request := httptest.NewRequest(http.MethodGet, "/api/client/report", nil)
	response := httptest.NewRecorder()
	h.receiver.ServeHTTP(response, request)
	if response.Code != http.StatusMethodNotAllowed || response.Header().Get("Allow") != "POST" {
		t.Fatalf("GET response = %d Allow=%q", response.Code, response.Header().Get("Allow"))
	}

	request = httptest.NewRequest(http.MethodPost, "/api/client/report", strings.NewReader("{}"))
	response = httptest.NewRecorder()
	h.receiver.ServeHTTP(response, request)
	if response.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("missing content type response = %d", response.Code)
	}

	request = httptest.NewRequest(http.MethodPost, "/api/client/report", strings.NewReader("{broken"))
	request.Header.Set("Content-Type", "application/json")
	response = httptest.NewRecorder()
	h.receiver.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("malformed JSON response = %d", response.Code)
	}

	request = httptest.NewRequest(http.MethodPost, "/api/client/report",
		strings.NewReader(strings.Repeat("x", clientReportMaxBody+1)))
	request.Header.Set("Content-Type", "application/json")
	response = httptest.NewRecorder()
	h.receiver.ServeHTTP(response, request)
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized response = %d", response.Code)
	}
}
