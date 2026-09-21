package publish

import (
	"bytes"
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"loom/internal/version"
)

func signedPublisherObservation(t *testing.T) (PublisherObservation, ed25519.PublicKey) {
	t.Helper()
	private := key(t)
	current := DeploymentCurrent{Schema: DeploymentCurrentSchema, Generation: 3,
		Snapshot: "0123456789ab", PublishedAt: "2026-09-20T12:00:00Z"}
	if err := current.Sign(private); err != nil {
		t.Fatal(err)
	}
	observation := PublisherObservation{Schema: PublisherObservationSchema, Current: current,
		ObservedAt: "2026-09-20T12:00:00Z", IntervalSeconds: 60,
		Version: version.Coordinate{Commit: "demo-commit", Platform: "linux/amd64"}, Success: true,
		DistributionChecks: []PublisherDistributionCheck{{URL: "https://dist.example/current.json",
			Snapshot: current.Snapshot, SourceDigest: "sha256:" + strings.Repeat("1", 64),
			CheckedAt: time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC).Format(time.RFC3339Nano), Success: true}}}
	if err := observation.Sign(private); err != nil {
		t.Fatal(err)
	}
	return observation, private.Public().(ed25519.PublicKey)
}

func TestPublisherObservationCanonicalRoundTrip(t *testing.T) {
	observation, public := signedPublisherObservation(t)
	body, err := observation.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodePublisherObservation(body)
	if err != nil {
		t.Fatal(err)
	}
	if err := decoded.Verify(public); err != nil {
		t.Fatal(err)
	}
	again, _ := decoded.Bytes()
	if !bytes.Equal(body, again) {
		t.Fatal("publisher observation canonical bytes changed after decode")
	}
}

func TestPublisherObservationRejectsDiagnosticTextAndUnknownCodes(t *testing.T) {
	observation, _ := signedPublisherObservation(t)
	body, _ := observation.Bytes()
	withDiagnostic := bytes.Replace(body, []byte(`"success":true`),
		[]byte(`"success":true,"error":"private diagnostic"`), 1)
	if _, err := DecodePublisherObservation(withDiagnostic); err == nil {
		t.Fatal("publisher observation accepted diagnostic text")
	}
	observation.Success = false
	observation.ErrorCode = "arbitrary_failure"
	observation.Signature = ""
	if err := observation.Sign(key(t)); err == nil {
		t.Fatal("publisher observation accepted an unbounded error code")
	}
}
