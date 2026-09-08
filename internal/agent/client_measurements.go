package agent

import (
	"time"

	"loom/internal/attest"
)

// ClientPathMeasurement 是本地拓扑连线的只读数据，不改变服务器签名或报告协议。
// §16.1.2：Hop=0 是入口；最后一段可有多个目标，各自保留身份与原测量时间。
type ClientPathMeasurement struct {
	Hop                               int
	From, To, Kind, ObservedAt, Error string
	DelayMS, VariationMS              *int64
	RateBPS                           *float64
	Samples, Failures                 int64
}

// ClientPathMeasurements 复用当前已验证观测，绝不发请求或累积一套新统计窗口。
func (c *ObservationCache) ClientPathMeasurements(chain, targets, carriers []string, now time.Time) []ClientPathMeasurement {
	if c == nil || len(chain) == 0 {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	fresh := func(ts string) bool {
		at, err := time.Parse(time.RFC3339, ts)
		return err == nil && now.Sub(at) <= c.maxAge && !at.After(now.Add(2*time.Minute))
	}
	var out []ClientPathMeasurement
	for i, node := range chain {
		o, ok := c.by[node]
		valid := ok && fresh(o.TS)
		if i+1 == len(chain) {
			for _, target := range targets {
				m := ClientPathMeasurement{Hop: i + 1, From: node, To: target, Kind: "target"}
				if valid {
					for _, r := range o.Targets {
						if !EquivalentTargetURL(r.Target, target) || r.Samples <= 0 {
							continue
						}
						m.ObservedAt, m.Samples, m.Failures, m.Error = o.TS, int64(r.Samples), int64(r.Failures), r.Error
						if r.Samples > r.Failures {
							ms := int64(r.FirstByteMs)
							m.DelayMS = &ms
						}
						break
					}
				}
				out = append(out, m)
			}
			continue
		}
		m := ClientPathMeasurement{Hop: i + 1, From: node, To: chain[i+1], Kind: "unknown"}
		if i < len(carriers) {
			m.Kind = carriers[i]
		}
		if valid && m.Kind == "neighbor" {
			for _, e := range o.Edges {
				if e.To != m.To || e.Samples <= 0 {
					continue
				}
				m.ObservedAt, m.Samples, m.Failures, m.Error = o.TS, int64(e.Samples), int64(e.Failures), e.Error
				if e.Samples > e.Failures {
					ms := int64(e.RTTMs)
					m.DelayMS = &ms
				}
				// WG 滚动波动和流量速率只在中控历史中，原始观测没有，不伪造。
				break
			}
		}
		if valid && m.Kind == "public-hysteria2" && o.LinkMetrics != nil {
			for _, link := range o.LinkMetrics.Metrics {
				if link.PeerNode != m.To || link.Transport != attest.LinkMetricTransportHysteria2 || link.Carrier != attest.LinkMetricCarrierPublic || link.Scope != attest.LinkMetricScopeSingleHop || !fresh(link.ObservedAt) || link.Samples <= 0 {
					continue
				}
				m.ObservedAt, m.Samples, m.Failures, m.Error = link.ObservedAt, link.Samples, link.Failures, link.Error
				if link.Samples > link.Failures {
					ms := link.RTTMS
					m.DelayMS = &ms
					if link.Samples-link.Failures >= 2 && link.P95MS >= link.P50MS {
						variation := link.P95MS - link.P50MS
						m.VariationMS = &variation
					}
					if link.TransferBytes > 0 && link.TransferDurationMS > 0 {
						rate := float64(link.TransferBytes) * 8000 / float64(link.TransferDurationMS)
						m.RateBPS = &rate
					}
				}
				break
			}
		}
		out = append(out, m)
	}
	return out
}
