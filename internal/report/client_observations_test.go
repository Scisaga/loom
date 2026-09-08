package report

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"loom/internal/attest"
)

func seedClientServerObservation(t *testing.T, h *clientReportHarness, node string) Observation {
	t.Helper()
	ca, key, cert := reportTestIdentity(t, node)
	previousCA, err := h.receiver.readCA("")
	if err != nil {
		t.Fatal(err)
	}
	combinedCA := append(append([]byte(nil), previousCA...), ca...)
	h.receiver.readCA = func(string) ([]byte, error) { return combinedCA, nil }
	h.table.verify = func(o *Observation, at time.Time, maxAge time.Duration) error {
		roots, _ := h.receiver.readCA("")
		_, err := VerifyObservationAtLeast(o, roots, at, maxAge, 5)
		return err
	}
	h.table.verifySelfCheck = func(o *Observation, at time.Time, maxAge time.Duration) error {
		roots, _ := h.receiver.readCA("")
		_, err := verifySelfCheckAttachment(o, roots, at, maxAge)
		return err
	}
	o := Observation{
		Node: node, TS: h.now.Add(-time.Minute).Format(time.RFC3339), Applied: "demo-snapshot",
		Edges:   []Edge{{To: "demo-neighbor", RTTMs: 42, Samples: 5}},
		Targets: []Reach{{Target: "https://demo.example?x=%20&y=1", Samples: 5, Failures: 5, Error: "refused"}},
	}
	_, claim := claimsForObservation(&o, 5)
	o.Attest, err = attest.Sign(claim, key, cert)
	if err != nil {
		t.Fatal(err)
	}
	o.SelfCheck, err = attest.SignSelfCheck(attest.SelfCheckClaim{
		Version: attest.SelfCheckClaimVersion, Node: node, TS: o.TS, Healthy: true,
	}, key, cert)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.table.put(&o, h.now, h.receiver.maxAge); err != nil {
		t.Fatal(err)
	}
	return o
}

// §16.1.2 通过同一已认证 POST 转述现有观测；身份、原始目标与签名必须完整保留。
func TestClientObservationsReuseSignedGossipWithCurrentCandidateScope(t *testing.T) {
	h := newClientReportHarnessFor(t, "phone", "android")
	want := seedClientServerObservation(t, &h, "sg-vps")
	seedClientServerObservation(t, &h, "jp-vps") // 不在 phone 的 sg-fixed 候选链中。
	seedClientServerObservation(t, &h, "demo-removed")
	seedClientServerObservation(t, &h, "workstation") // 其他客户端不是服务器。
	response := postClientReportURL(t, h.receiver, &h.observation, "/api/client/report?observations=1")
	if response.Code != http.StatusOK || response.Header().Get("Content-Type") != "application/json" ||
		response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("opt-in response = %d %v %s", response.Code, response.Header(), response.Body.String())
	}
	var got []Observation
	if err := json.Unmarshal(response.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Node != want.Node {
		t.Fatalf("response escaped candidate scope: %s", response.Body.String())
	}
	before, _ := json.Marshal(want)
	after, _ := json.Marshal(got[0])
	if !bytes.Equal(before, after) {
		t.Fatalf("relay changed signed observation: %s -> %s", before, after)
	}
	ca, _ := h.receiver.readCA("")
	trusted, err := VerifyObservationAtLeast(&got[0], ca, h.now, h.receiver.maxAge, 5)
	if err != nil || !trusted.MeasurementsVerified {
		t.Fatalf("returned measurements failed verification: %v", err)
	}
	if _, err := verifySelfCheckAttachment(&got[0], ca, h.now, h.receiver.maxAge); err != nil {
		t.Fatalf("returned self-check failed verification: %v", err)
	}
	got[0].Targets = append([]Reach(nil), got[0].Targets...)
	got[0].Targets[0].Target = "https://demo.example/?x=%20&y=1"
	if _, err := VerifyObservationAtLeast(&got[0], ca, h.now, h.receiver.maxAge, 5); err == nil {
		t.Fatal("rewriting even an equivalent signed URL must break the signature")
	}
	if h.table.by[h.observation.Node] == nil {
		t.Fatal("opt-in bypassed normal report insertion")
	}
	if got := postClientReport(t, h.receiver, &h.observation); got.Code != http.StatusNoContent || got.Body.Len() != 0 {
		t.Fatalf("old producer contract changed: %d %q", got.Code, got.Body.String())
	}
}

func TestClientObservationsMissingOrUntrustedRemainAbsent(t *testing.T) {
	for _, scenario := range []string{"missing", "stale", "future", "unsigned", "tampered"} {
		t.Run(scenario, func(t *testing.T) {
			h := newClientReportHarness(t)
			if scenario != "missing" {
				o := seedClientServerObservation(t, &h, "sg-vps")
				switch scenario {
				case "stale":
					o.TS = h.now.Add(-time.Hour).Format(time.RFC3339)
				case "future":
					o.TS = h.now.Add(time.Hour).Format(time.RFC3339)
				case "unsigned":
					o.Attest = nil
				case "tampered":
					o.Targets = append([]Reach(nil), o.Targets...)
					o.Targets[0].Error = "forged"
				}
				// 模拟旧兼容表残留或损坏，读取门仍须拒绝整份证据。
				h.table.by[o.Node] = &o
			}
			got := postClientReportURL(t, h.receiver, &h.observation, "/api/client/report?observations=1")
			if got.Code != http.StatusOK || strings.TrimSpace(got.Body.String()) != "[]" {
				t.Fatalf("unknown evidence became data: %d %s", got.Code, got.Body.String())
			}
		})
	}
}

func TestClientObservationsRetainReportAuthentication(t *testing.T) {
	for _, scenario := range []string{"revoked", "tampered", "no self-check", "GET"} {
		t.Run(scenario, func(t *testing.T) {
			h := newClientReportHarness(t)
			seedClientServerObservation(t, &h, "sg-vps")
			want := http.StatusForbidden
			switch scenario {
			case "revoked":
				writeClientReportRegistry(t, h.registryPath, "revoked", h.publicKey)
			case "tampered":
				h.observation.Applied = "forged"
			case "no self-check":
				h.observation.SelfCheck = nil
			case "GET":
				want = http.StatusMethodNotAllowed
			}
			var got *httptest.ResponseRecorder
			if scenario == "GET" {
				got = httptest.NewRecorder()
				h.receiver.ServeHTTP(got, httptest.NewRequest(http.MethodGet, "/api/client/report?observations=1", nil))
			} else {
				got = postClientReportURL(t, h.receiver, &h.observation, "/api/client/report?observations=1")
			}
			if got.Code != want || strings.Contains(got.Body.String(), "demo.example") {
				t.Fatalf("unauthorized observation read: %d %s", got.Code, got.Body.String())
			}
		})
	}
}
