package agent

import (
	"time"

	"loom/internal/attest"
)

// §16.1.2：只使用原签名、原方向的 Hy2 单跳与精确目标观测；不混入 WG RTT。
func (c *ObservationCache) clientCost(chain, targets []string, now time.Time) clientCost {
	out := clientCost{known: len(chain) > 0 && len(targets) > 0}
	if c == nil || !out.known {
		return clientCost{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	fresh := func(ts string) bool {
		at, err := time.Parse(time.RFC3339, ts)
		return err == nil && now.Sub(at) <= c.maxAge && !at.After(now.Add(2*time.Minute))
	}
	for i, node := range chain {
		o, ok := c.by[node]
		if !ok || !fresh(o.TS) {
			out.known = false
			continue
		}
		if i+1 < len(chain) {
			found := false
			if o.LinkMetrics != nil {
				for _, m := range o.LinkMetrics.Metrics {
					if m.PeerNode != chain[i+1] || m.Transport != attest.LinkMetricTransportHysteria2 || m.Carrier != attest.LinkMetricCarrierPublic || m.Scope != attest.LinkMetricScopeSingleHop || !fresh(m.ObservedAt) || m.Samples <= 0 {
						continue
					}
					found = true
					out.failed = out.failed || m.Failures == m.Samples
					out.failureRate = max(out.failureRate, float64(m.Failures)/float64(m.Samples))
					out.ms += float64(m.RTTMS)
					break
				}
			}
			out.known = out.known && found
			continue
		}
		var total float64
		for _, target := range targets {
			found := false
			for _, r := range o.Targets {
				if !EquivalentTargetURL(r.Target, target) || r.Samples <= 0 {
					continue
				}
				found = true
				out.failed = out.failed || r.Failures == r.Samples
				out.failureRate = max(out.failureRate, float64(r.Failures)/float64(r.Samples))
				total += float64(r.FirstByteMs)
				break
			}
			out.known = out.known && found
		}
		out.ms += total / float64(len(targets))
	}
	return out
}
