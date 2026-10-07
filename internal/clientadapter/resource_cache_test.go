package clientadapter

import (
	"bytes"
	"encoding/base64"
	"reflect"
	"strings"
	"testing"
	"time"

	"loom/internal/control"
)

func resourceCacheFixture(t *testing.T) (control.DeviceViewEnvelope, []control.Observation) {
	t.Helper()
	view, _, at := resourceProbeFixture(t)
	probes, err := control.FirstHopProbes(view)
	if err != nil {
		t.Fatal(err)
	}
	lkg := control.DeviceViewEnvelope{NetworkID: "demo-network", GenesisDigest: "sha256:" + strings.Repeat("2", 64), View: view}
	duration := int64(12)
	samples := []control.Observation{}
	for i, probe := range probes {
		result, window := "available", 10*time.Minute
		if i == 1 {
			result, window = "unavailable", 30*time.Second
		}
		samples = append(samples, control.Observation{Level: "resource", ResourceID: probe.Resource.ID, Target: probe.Target(),
			Action: "hysteria2_tls", SpecDigest: probe.SpecDigest, NetworkGeneration: "demo-underlay", Result: result,
			ObservedAt: at.UnixMilli(), ValidUntil: at.Add(window).UnixMilli(), DurationMS: &duration})
	}
	return lkg, samples
}

func TestResourceCacheRestoresOriginalSuccessAndFailureWindows(t *testing.T) {
	lkg, samples := resourceCacheFixture(t)
	body, err := EncodeResourceObservations(lkg, samples)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := DecodeResourceObservations(body, lkg, "demo-underlay")
	if err != nil || !reflect.DeepEqual(restored, samples) {
		t.Fatal("cache changed a result or its original time", restored, err)
	}
	roundTrip, err := EncodeResourceObservations(lkg, restored)
	if err != nil || !bytes.Equal(roundTrip, body) {
		t.Fatal("cache did not preserve canonical bytes", err)
	}
	lkg.View.Name = "Renamed demo device"
	restored, err = DecodeResourceObservations(body, lkg, "demo-underlay")
	if err != nil || !reflect.DeepEqual(restored, samples) {
		t.Fatal("unrelated View change refreshed or removed a real sample", err)
	}
	lkg.View.DNSServers = []string{"192.0.2.53"}
	if values, err := DecodeResourceObservations(body, lkg, "demo-underlay"); err != nil || len(values) != 0 {
		t.Fatal("changed execution inputs retained previous authentication", values, err)
	}
}

func TestResourceCacheCannotCrossIdentityOrNetworkGeneration(t *testing.T) {
	lkg, samples := resourceCacheFixture(t)
	body, err := EncodeResourceObservations(lkg, samples)
	if err != nil {
		t.Fatal(err)
	}
	otherRoot := lkg
	otherRoot.GenesisDigest = "sha256:" + strings.Repeat("3", 64)
	otherDeviceKey := lkg
	otherDeviceKey.View.DevicePublicKey = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
	for _, next := range []struct {
		lkg        control.DeviceViewEnvelope
		generation string
	}{{otherRoot, "demo-underlay"}, {otherDeviceKey, "demo-underlay"}, {lkg, "demo-other-underlay"}} {
		if values, err := DecodeResourceObservations(body, next.lkg, next.generation); err != nil || len(values) != 0 {
			t.Fatal("diagnostic cache crossed an identity or network boundary", values, err)
		}
	}
}

func TestResourceCacheRejectsNoncanonicalAndAmbiguousSamples(t *testing.T) {
	lkg, samples := resourceCacheFixture(t)
	body, err := EncodeResourceObservations(lkg, samples)
	if err != nil {
		t.Fatal(err)
	}
	for _, invalid := range [][]byte{
		append(append([]byte{}, body...), '\n'),
		bytes.Replace(body, []byte(`"schema":3`), []byte(`"schema":3,"unknown":true`), 1),
		bytes.Replace(body, []byte(`"schema":3`), []byte(`"schema":3,"schema":3`), 1),
	} {
		if _, err := DecodeResourceObservations(invalid, lkg, "demo-underlay"); err == nil {
			t.Fatal("noncanonical cache input was accepted")
		}
	}
	if _, err := EncodeResourceObservations(lkg, []control.Observation{samples[0], samples[0]}); err == nil {
		t.Fatal("two samples for the same resource were stored")
	}
	samples[0].SpecDigest = "sha256:" + strings.Repeat("4", 64)
	if _, err := EncodeResourceObservations(lkg, samples); err == nil {
		t.Fatal("cache writer rebound a sample to different execution inputs")
	}
}
