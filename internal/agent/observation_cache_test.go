package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"loom/internal/attest"
	"loom/internal/observation"
)

type observationIdentity struct{ key, cert, ca []byte }

func newObservationIdentity(t *testing.T, node string) observationIdentity {
	t.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "demo-observation-ca"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: node + ".node.internal"}, DNSNames: []string{node + ".node.internal"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, root, &key.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return observationIdentity{pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})}
}

func signedCacheObservation(t *testing.T, id observationIdentity, at time.Time, failed bool) observation.Observation {
	t.Helper()
	o := observation.Observation{Node: "demo-exit", TS: at.Format(time.RFC3339Nano), Targets: []observation.Reach{{Target: "https://service.example", Samples: 5, FirstByteMs: 12}}}
	if failed {
		o.Targets[0].Failures = 5
		o.Targets[0].Error = "synthetic connection failure"
		o.Targets[0].FirstByteMs = 0
	}
	var err error
	o.Attest, err = attest.Sign(attest.Claim{CanonicalVersion: 5, Node: o.Node, TS: o.TS, MeasurementsSHA256: observation.MeasurementDigest(&o)}, id.key, id.cert)
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func rawCacheObservation(t *testing.T, o observation.Observation) []json.RawMessage {
	t.Helper()
	body, err := json.Marshal(o)
	if err != nil {
		t.Fatal(err)
	}
	return []json.RawMessage{body}
}

func newTestObservationCache(t *testing.T) *ObservationCache {
	t.Helper()
	c, err := NewObservationCache(&Config{Node: "demo-client", ObservationStale: "10m", Declarations: []Decl{{Targets: []string{"https://service.example/"}, Candidates: []Cand{{Tag: "demo-direct"}, {Tag: "demo-proxy", Chain: []string{"demo-entry", "demo-exit"}}}}}})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestClientObservationCacheReadyRequiresAcceptedSource(t *testing.T) {
	var absent *ObservationCache
	if absent.Ready() != nil {
		t.Fatal("nil cache produced a readiness event")
	}
	now := time.Now().UTC().Truncate(time.Second)
	id := newObservationIdentity(t, "demo-exit")
	positive := signedCacheObservation(t, id, now, false)
	for _, batch := range []string{"positive", "mixed"} {
		t.Run(batch, func(t *testing.T) {
			c := newTestObservationCache(t)
			ready := c.Ready()
			assertPending := func() {
				t.Helper()
				select {
				case <-ready:
					t.Fatal("cache became ready without accepting a trusted source")
				default:
				}
			}
			assertPending()
			if err := c.Ingest(context.Background(), nil, id.ca, now); err != nil {
				t.Fatal(err)
			}
			assertPending()
			if err := c.Ingest(context.Background(), []json.RawMessage{json.RawMessage(`{}`)}, id.ca, now); err == nil {
				t.Fatal("invalid source was accepted")
			}
			assertPending()
			expired := signedCacheObservation(t, id, now.Add(-11*time.Minute), false)
			if err := c.Ingest(context.Background(), rawCacheObservation(t, expired), id.ca, now); err == nil {
				t.Fatal("expired source was accepted")
			}
			assertPending()
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if err := c.Ingest(ctx, rawCacheObservation(t, positive), id.ca, now); err == nil {
				t.Fatal("canceled ingest was accepted")
			}
			assertPending()
			changes := c.Changes()
			raw := rawCacheObservation(t, positive)
			if batch == "mixed" {
				raw = append(raw, json.RawMessage(`{}`))
			}
			err := c.Ingest(context.Background(), raw, id.ca, now)
			if (err != nil) != (batch == "mixed") {
				t.Fatalf("batch rejection result: %v", err)
			}
			select {
			case <-ready:
			default:
				t.Fatal("accepted positive source did not release initial waiters")
			}
			select {
			case <-changes:
				t.Fatal("positive readiness manufactured a pruning change")
			default:
			}
			if err := c.Ingest(context.Background(), rawCacheObservation(t, positive), id.ca, now); err != nil {
				t.Fatal(err)
			}
			if c.Ready() != ready {
				t.Fatal("duplicate batch replaced permanent readiness notification")
			}
		})
	}
}

func TestClientObservationCacheAuthenticatesBeforePruningAndPreservesTime(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	id := newObservationIdentity(t, "demo-exit")
	c := newTestObservationCache(t)
	failed := signedCacheObservation(t, id, now, true)
	raw := rawCacheObservation(t, failed)
	wake := c.Changes()
	if err := c.Ingest(context.Background(), raw, id.ca, now); err != nil {
		t.Fatal(err)
	}
	select {
	case <-wake:
	default:
		t.Fatal("new failure did not wake subscribers")
	}
	if got := c.unreachable("https://service.example/", now, time.Hour); got["demo-exit"] != failed.Targets[0].Error || len(got) != 1 {
		t.Fatalf("pruning=%v", got)
	}
	if len(c.unreachable("https://service.example/other", now, time.Hour)) != 0 {
		t.Fatal("unmeasured target became failed")
	}
	stored, _ := json.Marshal(c.by["demo-exit"])
	if string(stored) != string(raw[0]) {
		t.Fatal("consumer rewrote signed source")
	}
	wake = c.Changes()
	if err := c.Ingest(context.Background(), raw, id.ca, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	newer := signedCacheObservation(t, id, now.Add(time.Minute), true)
	if err := c.Ingest(context.Background(), rawCacheObservation(t, newer), id.ca, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-wake:
		t.Fatal("same failure with refreshed timestamp caused another probe wake")
	default:
	}
	older := signedCacheObservation(t, id, now.Add(30*time.Second), false)
	if err := c.Ingest(context.Background(), rawCacheObservation(t, older), id.ca, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if len(c.unreachable("https://service.example/", now.Add(time.Minute), time.Hour)) != 1 {
		t.Fatal("older observation replaced newer failure")
	}
	if len(c.unreachable("https://service.example/", now.Add(12*time.Minute), time.Hour)) != 0 {
		t.Fatal("receipt refreshed original observation lifetime")
	}
	recovered := signedCacheObservation(t, id, now.Add(2*time.Minute), false)
	if err := c.Ingest(context.Background(), rawCacheObservation(t, recovered), id.ca, now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-wake:
	default:
		t.Fatal("recovery did not wake subscribers")
	}
	if len(c.unreachable("https://service.example/", now.Add(2*time.Minute), time.Hour)) != 0 {
		t.Fatal("recovery remained pruned")
	}
}

func TestClientObservationCacheRejectsUntrustedOuterStateAndAttachments(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	id := newObservationIdentity(t, "demo-exit")
	for name, mutate := range map[string]func(*observation.Observation){
		"unsigned":     func(o *observation.Observation) { o.Attest = nil },
		"outer target": func(o *observation.Observation) { o.Targets[0].Error = "relay changed failure" },
		"outer edge": func(o *observation.Observation) {
			o.Edges = []observation.Edge{{To: "demo-entry", Samples: 1, RTTMs: 1}}
		},
		"outer timestamp":     func(o *observation.Observation) { o.TS = now.Add(time.Minute).Format(time.RFC3339) },
		"outside candidates":  func(o *observation.Observation) { o.Node = "demo-outside" },
		"own source":          func(o *observation.Observation) { o.Node = "demo-client" },
		"selfcheck signature": func(o *observation.Observation) { o.SelfCheck = &attest.SelfCheckAttest{} },
		"traffic signature":   func(o *observation.Observation) { o.Traffic = &attest.TrafficAttest{} },
		"link signature":      func(o *observation.Observation) { o.LinkMetrics = &attest.LinkMetricAttest{} },
	} {
		t.Run(name, func(t *testing.T) {
			c := newTestObservationCache(t)
			o := signedCacheObservation(t, id, now, true)
			mutate(&o)
			if err := c.Ingest(context.Background(), rawCacheObservation(t, o), id.ca, now); err == nil {
				t.Fatal("invalid evidence accepted")
			}
			if len(c.unreachable("https://service.example/", now, time.Minute)) != 0 {
				t.Fatal("invalid evidence affected a candidate")
			}
		})
	}
	for _, at := range []time.Time{now.Add(-11 * time.Minute), now.Add(3 * time.Minute)} {
		c := newTestObservationCache(t)
		o := signedCacheObservation(t, id, at, true)
		if err := c.Ingest(context.Background(), rawCacheObservation(t, o), id.ca, now); err == nil {
			t.Fatal("stale/future evidence accepted")
		}
	}
	for _, canonical := range []int{0, 4} {
		c := newTestObservationCache(t)
		o := signedCacheObservation(t, id, now, true)
		o.Attest.CanonicalVersion = canonical
		var err error
		o.Attest, err = attest.Sign(o.Attest.Claim, id.key, id.cert)
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Ingest(context.Background(), rawCacheObservation(t, o), id.ca, now); err == nil {
			t.Fatal("legacy signature accepted by client")
		}
	}
}

func TestClientObservationCacheValidAttachmentsAndPartialFailure(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	id := newObservationIdentity(t, "demo-exit")
	o := signedCacheObservation(t, id, now, true)
	var err error
	o.SelfCheck, err = attest.SignSelfCheck(attest.SelfCheckClaim{Version: 1, Node: o.Node, TS: o.TS, Healthy: true}, id.key, id.cert)
	if err != nil {
		t.Fatal(err)
	}
	o.Traffic, err = attest.SignTraffic(attest.TrafficClaim{Version: 1, Node: o.Node, TS: o.TS}, id.key, id.cert)
	if err != nil {
		t.Fatal(err)
	}
	o.LinkMetrics, err = attest.SignLinkMetric(attest.LinkMetricClaim{Version: 1, Node: o.Node, TS: o.TS, Metrics: []attest.LinkMetric{{PeerNode: "demo-entry", Transport: "hysteria2", Scope: "single_hop", Carrier: "public", ObservedAt: o.TS, RTTMS: 12, P50MS: 12, P95MS: 15, Samples: 1, TransferBytes: 65536, TransferDurationMS: 10}}}, id.key, id.cert)
	if err != nil {
		t.Fatal(err)
	}
	c := newTestObservationCache(t)
	if err := c.Ingest(context.Background(), rawCacheObservation(t, o), id.ca, now); err != nil {
		t.Fatal(err)
	}
	for _, attachment := range []string{"selfcheck", "traffic", "link"} {
		t.Run(attachment+" binding", func(t *testing.T) {
			body := rawCacheObservation(t, o)[0]
			var bad observation.Observation
			_ = json.Unmarshal(body, &bad)
			switch attachment {
			case "selfcheck":
				bad.SelfCheck.TS = now.Add(-time.Second).Format(time.RFC3339)
				bad.SelfCheck, err = attest.SignSelfCheck(bad.SelfCheck.SelfCheckClaim, id.key, id.cert)
			case "traffic":
				bad.Traffic.TS = now.Add(-time.Second).Format(time.RFC3339)
				bad.Traffic, err = attest.SignTraffic(bad.Traffic.TrafficClaim, id.key, id.cert)
			case "link":
				bad.LinkMetrics.TS = now.Add(time.Second).Format(time.RFC3339)
				bad.LinkMetrics, err = attest.SignLinkMetric(bad.LinkMetrics.LinkMetricClaim, id.key, id.cert)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := newTestObservationCache(t).Ingest(context.Background(), rawCacheObservation(t, bad), id.ca, now); err == nil {
				t.Fatal("independently signed but detached attachment accepted")
			}
		})
	}
	partial := signedCacheObservation(t, id, now.Add(time.Minute), false)
	partial.Targets[0].Failures = 1
	partial.Attest, err = attest.Sign(attest.Claim{CanonicalVersion: 5, Node: partial.Node, TS: partial.TS, MeasurementsSHA256: observation.MeasurementDigest(&partial)}, id.key, id.cert)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Ingest(context.Background(), rawCacheObservation(t, partial), id.ca, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if len(c.unreachable("https://service.example/", now.Add(time.Minute), time.Minute)) != 0 {
		t.Fatal("partial failures pruned an exit")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := c.Ingest(ctx, rawCacheObservation(t, o), id.ca, now); err == nil {
		t.Fatal("stopped generation accepted observations")
	}
}
