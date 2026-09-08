package agent

import (
	"time"

	"loom/internal/attest"
)

// §16.1.2：按签名数据面的实际承载匹配原方向观测；公网与隧道不可混用。
func (c *ObservationCache) clientCost(chain, targets []string, now time.Time, carriers ...[]string) clientCost {
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
			carrier := "public-hysteria2"
			if len(carriers) > 0 {
				carrier = "unknown"
				if i < len(carriers[0]) {
					carrier = carriers[0][i]
				}
			}
			if carrier == "neighbor" {
				for _, e := range o.Edges {
					if e.To != chain[i+1] || e.Samples <= 0 {
						continue
					}
					found = true
					out.failed = out.failed || e.Failures == e.Samples
					out.failureRate = max(out.failureRate, float64(e.Failures)/float64(e.Samples))
					out.ms += float64(e.RTTMs)
					break
				}
			}
			if carrier == "public-hysteria2" && o.LinkMetrics != nil {
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

// clientTargets 只比较已有测量覆盖的目标；一个全网未测地址不能使其他数据失效。
// §16.1.2：同一声明的所有候选使用相同目标子集，缺失覆盖会写入选择原因。
func (c *ObservationCache) clientTargets(targets []string, now time.Time) []string {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []string
	for _, target := range targets {
		found := false
		for _, o := range c.by {
			at, err := time.Parse(time.RFC3339, o.TS)
			if err != nil || now.Sub(at) > c.maxAge || at.After(now.Add(2*time.Minute)) {
				continue
			}
			for _, r := range o.Targets {
				if r.Samples > 0 && EquivalentTargetURL(r.Target, target) {
					found = true
					break
				}
			}
			if found {
				break
			}
		}
		if found {
			out = append(out, target)
		}
	}
	return out
}
