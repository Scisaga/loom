package control

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"net"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestWebRoundTripsUseDistinctCurrentScopeSamplesAndPreserveOriginals(t *testing.T) {
	p := relayProjectionFixture(t)
	key := testKey(t)
	for i := range p.DeviceAuthorizations {
		if p.DeviceAuthorizations[i].ID == "demo-entry" {
			p.DeviceAuthorizations[i].DevicePublicKey = base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
		}
	}
	identity, _ := authorizationFor(p, "demo-entry")
	view, err := ProjectDeviceView(p, identity.ID)
	if err != nil {
		t.Fatal(err)
	}
	link := view.Links[0]
	spec, _ := LinkSpecDigest(view, link.ID)
	digest, _ := DeviceViewDigest(view)
	now := time.Date(2026, 1, 2, 12, 30, 0, 0, time.UTC)
	base := Observation{Level: "link", LinkID: link.ID, ResourceID: link.ResourceID, SpecDigest: spec, Target: net.JoinHostPort(link.ProbeTarget.Host, "53"), Action: "wireguard_dns", NetworkGeneration: "demo-generation", Result: "available", DurationMS: new(int64(100))}
	reports := []DeviceReport{}
	add := func(age time.Duration, value int64, mutate func(*DeviceReport)) {
		t.Helper()
		sample := base
		sample.ObservedAt, sample.ValidUntil = now.Add(-age).UnixMilli(), now.Add(-age+30*time.Second).UnixMilli()
		sample.RoundTripMS = new(value)
		report := DeviceReport{Schema: 3, NetworkID: p.NetworkID, DeviceID: identity.ID, ReportSequence: U64(len(reports) + 1), ViewDigest: digest, NetworkGeneration: sample.NetworkGeneration, ReportedAt: now.UnixMilli(), Selections: []ReportSelection{}, Observations: []Observation{sample}, Runtime: RuntimeReadback{State: "running", AppliedViewDigest: digest}, Components: []ComponentReadback{}}
		if mutate != nil {
			mutate(&report)
		}
		report, err = SignDeviceReport(report, key)
		if err != nil {
			t.Fatal(err)
		}
		reports = append(reports, report)
	}
	add(15*time.Minute+time.Millisecond, 99, nil)
	add(15*time.Minute, 5, nil)
	add(14*time.Minute, 10, nil)
	add(10*time.Minute, 20, nil)
	add(10*time.Minute, 20, nil) // Same original sample relayed again.
	add(8*time.Minute, 30, nil)
	add(8*time.Minute, 40, nil) // Contradiction excludes this timestamp.
	add(7*time.Minute, 90, func(r *DeviceReport) {
		r.NetworkGeneration = "demo-old-network"
		r.Observations[0].NetworkGeneration = r.NetworkGeneration
	})
	add(6*time.Minute, 90, func(r *DeviceReport) { r.Observations[0].SpecDigest = "sha256:" + strings.Repeat("f", 64) })
	add(5*time.Minute, 90, nil)
	reports[len(reports)-1], err = SignDeviceReport(reports[len(reports)-1], testKey(t))
	if err != nil {
		t.Fatal(err)
	}
	add(4*time.Minute, 90, nil)
	sequence := reports[len(reports)-1].ReportSequence
	add(4*time.Minute, 95, func(r *DeviceReport) { r.ReportSequence = sequence })
	add(3*time.Minute, 90, func(r *DeviceReport) { r.Observations[0].Result = "unavailable"; r.Observations[0].RoundTripMS = nil })
	add(2*time.Minute, 90, func(r *DeviceReport) { r.Observations[0].RoundTripMS = nil })
	add(time.Minute, 0, nil)
	add(-time.Millisecond, 99, nil) // Future sample cannot enter the distribution.
	add(time.Second, 10, nil)
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	testSetObservationReports(t, root, reports)
	original := testObservationBytes(t, root)
	var previous WebLinkHistory
	for attempt := 0; attempt < 2; attempt++ {
		store, err := testOpenObservationStore(t, root)
		if err != nil {
			t.Fatal(err)
		}
		got, err := store.linkHistory(context.Background(), p.NetworkID, identity, link, spec, now)
		if err != nil {
			t.Fatal(err)
		}
		v := got.RoundTrips
		if v == nil || v.Samples != 5 || v.P50MS == nil || *v.P50MS != 10 || v.P95MS == nil || *v.P95MS != 20 || v.SpreadMS == nil || *v.SpreadMS != 10 || v.NetworkGeneration != base.NetworkGeneration || v.ReportSequence != reports[len(reports)-1].ReportSequence {
			t.Fatalf("wrong distinct scoped distribution: %+v", v)
		}
		store.cache.clear()
		cold, err := store.linkHistory(context.Background(), p.NetworkID, identity, link, spec, now)
		if err != nil || !reflect.DeepEqual(got, cold) || attempt > 0 && !reflect.DeepEqual(previous, got) || !bytes.Equal(original, testObservationBytes(t, store)) {
			t.Fatal("index or reopen changed original evidence", err)
		}
		previous = got
		stale, err := store.linkHistory(context.Background(), p.NetworkID, identity, link, spec, now.Add(time.Minute))
		if err != nil || stale.RoundTrips != nil {
			t.Fatal("expired highest Link revived an older distribution", err)
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
	}
	for _, mode := range []string{"one", "zero", "missing", "failure", "stopped", "fork", "wrong-key", "new-network", "changed-spec"} {
		t.Run(mode, func(t *testing.T) {
			pending := reports[len(reports)-1]
			pending.Observations = append([]Observation{}, pending.Observations...)
			pending.Observations[0].RoundTripMS = new(int64(10))
			values := []DeviceReport{pending}
			next := pending
			next.ReportSequence++
			next.Observations = append([]Observation{}, pending.Observations...)
			next.Observations[0].ObservedAt++
			next.Observations[0].ValidUntil++
			signing := key
			switch mode {
			case "missing":
				next.Observations[0].RoundTripMS = nil
			case "failure":
				next.Observations[0].Result = "unavailable"
				next.Observations[0].RoundTripMS = nil
			case "stopped":
				next.Runtime = RuntimeReadback{State: "stopped"}
			case "fork":
				next.ReportSequence = pending.ReportSequence
			case "wrong-key":
				signing = testKey(t)
			case "new-network":
				next.NetworkGeneration = "demo-new-network"
				next.Observations[0].NetworkGeneration = next.NetworkGeneration
			case "changed-spec":
				next.Observations[0].SpecDigest = "sha256:" + strings.Repeat("f", 64)
			}
			if mode != "one" {
				next, err = SignDeviceReport(next, signing)
				if err != nil {
					t.Fatal(err)
				}
				values = append(values, next)
			}
			root := t.TempDir()
			if err := os.Chmod(root, 0700); err != nil {
				t.Fatal(err)
			}
			testSetObservationReports(t, root, values)
			store, err := testOpenObservationStore(t, root)
			if err != nil {
				t.Fatal(err)
			}
			got, err := store.linkHistory(context.Background(), p.NetworkID, identity, link, spec, now)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "one" || mode == "new-network" {
				if got.RoundTrips == nil || got.RoundTrips.Samples != 1 || got.RoundTrips.SpreadMS != nil {
					t.Fatal("one sample invented variation", got.RoundTrips)
				}
			} else if mode == "zero" {
				if got.RoundTrips == nil || got.RoundTrips.Samples != 2 || got.RoundTrips.SpreadMS == nil || *got.RoundTrips.SpreadMS != 0 {
					t.Fatal("real zero variation became unknown", got.RoundTrips)
				}
			} else if got.RoundTrips != nil {
				t.Fatal("unqualified highest report revived old measurements", got.RoundTrips)
			}
		})
	}
}
