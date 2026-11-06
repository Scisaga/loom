package deviceclient

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"loom/internal/control"
	"sync"
	"testing"
)

func TestConfirmedMeasurementCacheKeepsOriginalIdentityAndRetriesUnconfirmedSamples(t *testing.T) {
	cache := reportMeasurementCache{ring: make([][sha256.Size]byte, 2)}
	seed := sha256.Sum256([]byte("demo-report-measurements"))
	key := ed25519.NewKeyFromSeed(seed[:])
	public := base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
	sample := control.Observation{Level: "egress", Target: "https://demo-service.example/health", Action: "https_request", SpecDigest: control.ReleaseDigest([]byte("demo-spec")),
		NetworkGeneration: "demo-underlay", Result: "available", ObservedAt: 1000, ValidUntil: 61_000, DurationMS: new(int64(5))}
	report := control.DeviceReport{NetworkID: "demo-network", DeviceID: "demo-egress", NetworkGeneration: sample.NetworkGeneration, Observations: []control.Observation{sample}}
	read := func(value control.DeviceReport, want int) {
		t.Helper()
		pending, err := cache.pending(value, public)
		if err != nil || len(pending) != want {
			t.Fatal("unexpected pending samples", err, len(pending), want)
		}
	}
	read(report, 1)
	read(report, 1) // Preparing or cancelling a request is not confirmation.
	if err := cache.remember(report, public); err != nil {
		t.Fatal(err)
	}
	read(report, 0)
	report.ReportSequence, report.ReportedAt = 200, 30_000
	read(report, 0) // A metadata/report change does not create a new measurement.
	other := report
	other.DeviceID = "demo-other-egress"
	read(other, 1)
	other = report
	other.Observations = append([]control.Observation{}, report.Observations...)
	other.Observations[0].ObservedAt++
	other.Observations[0].ValidUntil++
	read(other, 1)
	if err := cache.remember(other, public); err != nil {
		t.Fatal(err)
	}
	// Filling a bounded cache only retransmits an evicted sample. It never
	// invents an ACK for a sample or changes the original result/expiry.
	third := other
	third.DeviceID = "demo-third-egress"
	if err := cache.remember(third, public); err != nil {
		t.Fatal(err)
	}
	read(report, 1)
	read(other, 0)
	read(third, 0)
	if report.Observations[0].ObservedAt != sample.ObservedAt || report.Observations[0].ValidUntil != sample.ValidUntil {
		t.Fatal("filtering rewrote an original sample")
	}
	invalid := other
	invalid.NetworkGeneration = "demo-other-underlay"
	if _, err := cache.pending(invalid, public); err == nil {
		t.Fatal("a previously confirmed digest hid invalid source generation")
	}
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			for range 10 {
				if _, err := cache.pending(third, public); err != nil {
					t.Error(err)
				}
				if err := cache.remember(third, public); err != nil {
					t.Error(err)
				}
			}
		})
	}
	workers.Wait()
}
