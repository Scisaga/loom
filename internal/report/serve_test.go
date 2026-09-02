package report

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestPhaseBStatusIsUnavailableBeforeFirstValidSelfObservation(t *testing.T) {
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	cfg := &Config{Node: "demo-d", AttestationMinVersion: 5}
	st := &Status{Node: cfg.Node, TS: now.Format(time.RFC3339)}

	attachObservationState(cfg, newTable(5), st, now, 10*time.Minute)
	rr := httptest.NewRecorder()
	writeStatus(rr, st, now)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("phase-B 首个有效 v5 自观测前 /status=%d，期望 503；body=%s",
			rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), phaseBAttestationNotReady) {
		t.Fatalf("503 没说明 attestation 尚未 ready: %s", rr.Body.String())
	}
}

func TestPhaseAStatusDoesNotRequireV5Readiness(t *testing.T) {
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	cfg := &Config{Node: "demo-d"}
	st := &Status{Node: cfg.Node, TS: now.Format(time.RFC3339)}

	attachObservationState(cfg, newTable(), st, now, 10*time.Minute)
	for _, err := range st.Errors {
		if err == phaseBAttestationNotReady {
			t.Fatal("phase A 被错误套用了 v5 readiness 门禁")
		}
	}
}
