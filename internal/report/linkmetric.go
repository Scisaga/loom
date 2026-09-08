package report

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"time"

	"loom/internal/attest"
	"loom/internal/observation"
)

const (
	linkMetricProbeInterval = 5 * time.Minute
	linkMetricQualityWindow = 15 * time.Minute
	linkMetricProbeTimeout  = 12 * time.Second
)

type linkProbeSample struct {
	at         time.Time
	rttMS      int64
	bytes      int64
	durationMS int64
	err        string
}

func (h *history) linkProbeDue(peer string, now time.Time) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	last := h.linkLast[peer]
	if !last.IsZero() && now.Sub(last) < linkMetricProbeInterval {
		return false
	}
	// Reserve the slot before the network call so two overlapping snapshots do
	// not duplicate a 64 KiB probe. A failed probe is still a real sample.
	h.linkLast[peer] = now
	return true
}

func (h *history) addLinkProbe(peer string, sample linkProbeSample) {
	h.mu.Lock()
	defer h.mu.Unlock()
	xs := append(h.linkBy[peer], sample)
	cut := sample.at.Add(-linkMetricQualityWindow)
	first := 0
	for first < len(xs) && xs[first].at.Before(cut) {
		first++
	}
	h.linkBy[peer] = append([]linkProbeSample(nil), xs[first:]...)
}

func percentileInt64(values []int64, p float64) int64 {
	if len(values) == 0 {
		return 0
	}
	xs := append([]int64(nil), values...)
	sort.Slice(xs, func(i, j int) bool { return xs[i] < xs[j] })
	index := int(float64(len(xs)-1)*p + .999999)
	if index < 0 {
		index = 0
	}
	if index >= len(xs) {
		index = len(xs) - 1
	}
	return xs[index]
}

func (h *history) linkMetric(peer, transport, carrier string, now time.Time) (attest.LinkMetric, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	cut := now.Add(-linkMetricQualityWindow)
	var samples []linkProbeSample
	for _, sample := range h.linkBy[peer] {
		if !sample.at.Before(cut) {
			samples = append(samples, sample)
		}
	}
	if len(samples) == 0 {
		return attest.LinkMetric{}, false
	}
	metric := attest.LinkMetric{
		PeerNode: peer, Transport: transport,
		Scope: attest.LinkMetricScopeSingleHop, Carrier: carrier,
		ObservedAt: samples[len(samples)-1].at.UTC().Format(time.RFC3339),
		Samples:    int64(len(samples)),
	}
	var latencies []int64
	var successful []linkProbeSample
	for _, sample := range samples {
		if sample.err != "" {
			metric.Failures++
			metric.Error = sample.err
			continue
		}
		latencies = append(latencies, sample.rttMS)
		successful = append(successful, sample)
	}
	if len(successful) == 0 {
		return metric, true
	}
	metric.P50MS = percentileInt64(latencies, .50)
	metric.P95MS = percentileInt64(latencies, .95)
	metric.RTTMS = metric.P50MS
	metric.Error = ""
	// Sign one real numerator/denominator pair closest to the median achieved
	// probe rate rather than signing a rounded derived number.
	sort.Slice(successful, func(i, j int) bool {
		a := successful[i].bytes * successful[j].durationMS
		b := successful[j].bytes * successful[i].durationMS
		return a < b
	})
	pick := successful[len(successful)/2]
	metric.TransferBytes, metric.TransferDurationMS = pick.bytes, pick.durationMS
	return metric, true
}

func measureHy2Link(probe LinkProbe, now time.Time) linkProbeSample {
	sample := linkProbeSample{at: now.UTC()}
	proxyURL, err := url.Parse("http://" + probe.ProxyAddr)
	if err != nil {
		sample.err = err.Error()
		return sample
	}
	transport := &http.Transport{
		Proxy: http.ProxyURL(proxyURL), DisableKeepAlives: true,
		DisableCompression: true,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}
	ctx, cancel := context.WithTimeout(context.Background(), linkMetricProbeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"http://"+linkMetricReflectorAddr+linkMetricProbePath, nil)
	if err != nil {
		sample.err = err.Error()
		return sample
	}
	req.Header.Set("Accept-Encoding", "identity")
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		sample.err = err.Error()
		return sample
	}
	firstByte := time.Now()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		sample.err = fmt.Sprintf("reflector HTTP %d", resp.StatusCode)
		return sample
	}
	if got := resp.Header.Get("X-Loom-Node"); got != probe.Peer {
		sample.err = fmt.Sprintf("reflector node=%q, want %q", got, probe.Peer)
		return sample
	}
	if got, err := strconv.Atoi(resp.Header.Get("X-Loom-Probe-Bytes")); err != nil || got != linkMetricProbeBytes {
		sample.err = "reflector payload size header mismatch"
		return sample
	}
	transferStart := time.Now()
	n, err := io.Copy(io.Discard, io.LimitReader(resp.Body, linkMetricProbeBytes+1))
	if err != nil {
		sample.err = err.Error()
		return sample
	}
	if n != linkMetricProbeBytes {
		sample.err = fmt.Sprintf("reflector payload=%d, want %d", n, linkMetricProbeBytes)
		return sample
	}
	sample.rttMS = max(1, firstByte.Sub(start).Milliseconds())
	sample.durationMS = max(1, time.Since(transferStart).Milliseconds())
	sample.bytes = n
	return sample
}

func collectLinkMetricAttestation(cfg *Config, h *history, now time.Time) *attest.LinkMetricAttest {
	if cfg == nil || h == nil || len(cfg.LinkProbes) == 0 {
		return nil
	}
	probes := append([]LinkProbe(nil), cfg.LinkProbes...)
	sort.Slice(probes, func(i, j int) bool { return probes[i].Peer < probes[j].Peer })
	due := make([]bool, len(probes))
	for i := range probes {
		due[i] = h.linkProbeDue(probes[i].Peer, now)
	}
	parallelProbe(len(probes), func(i int) {
		if !due[i] {
			return
		}
		h.addLinkProbe(probes[i].Peer, measureHy2Link(probes[i], now))
	})
	claim := attest.LinkMetricClaim{
		Version: attest.LinkMetricClaimVersion,
		Node:    cfg.Node, TS: now.UTC().Format(time.RFC3339),
	}
	for _, probe := range probes {
		if metric, ok := h.linkMetric(probe.Peer, probe.Transport, probe.Carrier, now); ok {
			claim.Metrics = append(claim.Metrics, metric)
		}
	}
	if len(claim.Metrics) == 0 {
		return nil
	}
	key, err := os.ReadFile(nodeKeyPath)
	if err != nil {
		return nil
	}
	crt, err := os.ReadFile(nodeCertPath)
	if err != nil {
		return nil
	}
	signed, err := attest.SignLinkMetric(claim, key, crt)
	if err != nil {
		return nil
	}
	return signed
}

// verifyLinkMetricAttachment binds the independent claim to its containing
// Observation. A relay cannot attach one node's valid probe to another node or
// refresh its timestamp by changing the outer envelope.
func verifyLinkMetricAttachment(o *Observation, ca []byte, now time.Time, maxAge time.Duration) (*attest.LinkMetricClaim, error) {
	if o == nil {
		return nil, nil
	}
	return observation.VerifyLinkMetricAttachment(&observation.Observation{Node: o.Node, TS: o.TS, LinkMetrics: o.LinkMetrics}, ca, now, maxAge)
}
