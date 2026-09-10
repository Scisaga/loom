// Package clientroute 实现 §5.5.1 的平台无关客户端 selector 决策。
// 它只消费每连接代的一次入口结果和既有签名服务器观测，不执行探测或 selector I/O。
package clientroute

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"loom/internal/attest"
	"loom/internal/observation"
)

type Candidate struct {
	Tag   string
	Chain []string
}

type Declaration struct {
	ID              string
	Selector        string
	Objective       string
	Targets         []string
	SwitchThreshold float64
	Candidates      []Candidate
}

type EntryResult struct {
	RTT time.Duration
	At  time.Time
	Err error
}

type Decision struct {
	Declaration string
	Selector    string
	Candidate   string
	Chain       []string
	Reason      string
}

type Cost struct {
	Known       bool
	Failed      bool
	MS          float64
	FailureRate float64
}

// Evidence 是 §16.1.2 已验证观测的不可变投影。调用方构造前须校验签名、附件、
// 作用域和新鲜度；每次计算仍按原始 TS 检查时效。
type Evidence struct {
	ByNode map[string]observation.Observation
	MaxAge time.Duration
}

func (e Evidence) Targets(targets []string, now time.Time) []string {
	var out []string
	for _, target := range targets {
		found := false
		for _, value := range e.ByNode {
			if !fresh(value.TS, now, e.MaxAge) {
				continue
			}
			for _, reach := range value.Targets {
				if reach.Samples > 0 && EquivalentTargetURL(reach.Target, target) {
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

func (e Evidence) Cost(chain, targets []string, now time.Time, carriers []string) Cost {
	out := Cost{Known: len(chain) > 0 && len(targets) > 0}
	if !out.Known {
		return Cost{}
	}
	for index, node := range chain {
		value, ok := e.ByNode[node]
		if !ok || !fresh(value.TS, now, e.MaxAge) {
			out.Known = false
			continue
		}
		if index+1 < len(chain) {
			found := false
			carrier := "unknown"
			if index < len(carriers) {
				carrier = carriers[index]
			}
			if carrier == "neighbor" {
				for _, edge := range value.Edges {
					if edge.To != chain[index+1] || edge.Samples <= 0 {
						continue
					}
					found = true
					out.Failed = out.Failed || edge.Failures == edge.Samples
					out.FailureRate = combineFailureRate(
						out.FailureRate, float64(edge.Failures)/float64(edge.Samples),
					)
					out.MS += float64(edge.RTTMs)
					break
				}
			}
			if carrier == "public-hysteria2" && value.LinkMetrics != nil {
				for _, metric := range value.LinkMetrics.Metrics {
					if metric.PeerNode != chain[index+1] || metric.Transport != attest.LinkMetricTransportHysteria2 ||
						metric.Carrier != attest.LinkMetricCarrierPublic || metric.Scope != attest.LinkMetricScopeSingleHop ||
						!fresh(metric.ObservedAt, now, e.MaxAge) || metric.Samples <= 0 {
						continue
					}
					found = true
					out.Failed = out.Failed || metric.Failures == metric.Samples
					out.FailureRate = combineFailureRate(
						out.FailureRate, float64(metric.Failures)/float64(metric.Samples),
					)
					out.MS += float64(metric.RTTMS)
					break
				}
			}
			out.Known = out.Known && found
			continue
		}
		var total, targetFailureRate float64
		for _, target := range targets {
			found := false
			for _, reach := range value.Targets {
				if !EquivalentTargetURL(reach.Target, target) || reach.Samples <= 0 {
					continue
				}
				found = true
				out.Failed = out.Failed || reach.Failures == reach.Samples
				targetFailureRate = max(targetFailureRate, float64(reach.Failures)/float64(reach.Samples))
				total += float64(reach.FirstByteMs)
				break
			}
			out.Known = out.Known && found
		}
		out.FailureRate = combineFailureRate(out.FailureRate, targetFailureRate)
		out.MS += total / float64(len(targets))
	}
	return out
}

// combineFailureRate 合并顺序路径各段的失败概率。取 max 会系统性低估多跳路径：
// 两段各失败 6% 时整链成功率是 .94²，失败率应为 11.64%，而不是 6%。
func combineFailureRate(current, next float64) float64 {
	return 1 - (1-current)*(1-next)
}

func Decide(declaration Declaration, actual string, entries map[string]EntryResult, evidence Evidence,
	carriers map[string][]string, now time.Time) (Decision, error) {
	var current *Candidate
	for index := range declaration.Candidates {
		if declaration.Candidates[index].Tag == actual {
			current = &declaration.Candidates[index]
			break
		}
	}
	if current == nil {
		return Decision{}, errors.New("[§5.1] 实际 selector 不在授权候选内")
	}
	chosen := *current
	targets := evidence.Targets(declaration.Targets, now)
	costs := map[string]Cost{}
	for _, candidate := range declaration.Candidates {
		cost := evidence.Cost(candidate.Chain, targets, now, carriers[candidate.Tag])
		entry, ok := entryFor(candidate, entries)
		if !ok {
			cost.Known = false
		} else {
			cost.MS += float64(entry.RTT) / float64(time.Millisecond)
		}
		costs[candidate.Tag] = cost
	}
	best := Cost{}
	if declaration.Objective == "latency" {
		best = costs[actual]
		for _, candidate := range declaration.Candidates {
			cost := costs[candidate.Tag]
			// §5.5.1：先逐个判断能否相对现任切换，再排序可切集合，避免被阈值
			// 拦住的最快候选遮住另一条可立即减少中继的路径。
			if !improves(candidate, cost, *current, costs[actual], declaration.SwitchThreshold) {
				continue
			}
			if !best.Known || best.Failed || cost.FailureRate < best.FailureRate ||
				cost.FailureRate == best.FailureRate &&
					(cost.MS < best.MS || cost.MS == best.MS && len(candidate.Chain) < len(chosen.Chain)) {
				chosen, best = candidate, cost
			}
		}
	}
	// §16.1.2：缺少完整后段证据时保留出口，只比较独立测得且不增加中继的首跳，
	// 不为补全证据追加探测。
	if !best.Known || best.Failed {
		var fastest time.Duration
		found := false
		for _, candidate := range declaration.Candidates {
			if !sameExit(candidate, *current) || len(candidate.Chain) > len(current.Chain) || costs[candidate.Tag].Failed {
				continue
			}
			entry, ok := entryFor(candidate, entries)
			if ok && (!found || entry.RTT < fastest || entry.RTT == fastest &&
				(len(candidate.Chain) < len(chosen.Chain) || len(candidate.Chain) == len(chosen.Chain) && candidate.Tag == actual)) {
				chosen, fastest, found = candidate, entry.RTT, true
			}
		}
	}
	reason := "直连候选；业务可用性未测量"
	if len(chosen.Chain) > 0 {
		entry, ok := entryFor(chosen, entries)
		if ok {
			reason = fmt.Sprintf("入口 %s：单次 ping %d ms（%s）；", chosen.Chain[0], entry.RTT.Milliseconds(), entry.At.UTC().Format(time.RFC3339))
		} else {
			reason = "入口 ping 未获响应，入口可达性未知；"
		}
		cost := costs[chosen.Tag]
		if cost.Known && !cost.Failed && declaration.Objective == "latency" {
			reason += fmt.Sprintf("入口与服务器分段观测估算 %.0f ms；未测整条业务路径", cost.MS)
		} else if cost.Failed {
			reason += "服务器观测显示后段失败；暂无可比较替代路径"
		} else {
			reason += "后段比较证据不足，保留当前出口；未测整条业务路径"
		}
		if declaration.Objective != "latency" {
			reason += "；现有分段观测不能计算配置目标 " + declaration.Objective
		}
		if len(targets) < len(declaration.Targets) {
			reason += fmt.Sprintf("；服务器观测覆盖 %d/%d 个目标，其余未知", len(targets), len(declaration.Targets))
		}
		if chosen.Tag != current.Tag && len(chosen.Chain) < len(current.Chain) && best.Known && !best.Failed && declaration.Objective == "latency" {
			reason += fmt.Sprintf("；减少中继 %d→%d 跳", len(current.Chain), len(chosen.Chain))
		}
	}
	return Decision{Declaration: declaration.ID, Selector: declaration.Selector, Candidate: chosen.Tag,
		Chain: append([]string(nil), chosen.Chain...), Reason: reason}, nil
}

// §5.5.1：失败率相同、估算延迟不增且服务器更少的路径支配现任，阻尼不能保留
// 这个冗余中继；同跳替换和增加中继仍须达到改善阈值，失败率更低则可直接切换。
func improves(next Candidate, cost Cost, current Candidate, old Cost, threshold float64) bool {
	if !cost.Known || cost.Failed {
		return false
	}
	if !old.Known || old.Failed || cost.FailureRate < old.FailureRate {
		return true
	}
	if cost.FailureRate > old.FailureRate {
		return false
	}
	if len(next.Chain) < len(current.Chain) && cost.MS <= old.MS {
		return true
	}
	return cost.MS < old.MS && old.MS > 0 && (old.MS-cost.MS)/old.MS >= threshold
}

func entryFor(candidate Candidate, entries map[string]EntryResult) (EntryResult, bool) {
	if len(candidate.Chain) == 0 {
		return EntryResult{}, false
	}
	result, ok := entries[candidate.Chain[0]]
	return result, ok && result.Err == nil && result.RTT >= 0
}

func sameExit(a, b Candidate) bool {
	return len(a.Chain) > 0 && len(b.Chain) > 0 && a.Chain[len(a.Chain)-1] == b.Chain[len(b.Chain)-1]
}

func fresh(raw string, now time.Time, maxAge time.Duration) bool {
	at, err := time.Parse(time.RFC3339, raw)
	return err == nil && now.Sub(at) <= maxAge && !at.After(now.Add(2*time.Minute))
}

// EquivalentTargetURL 只把 HTTP(S) 空路径与根路径视为等价，保留其余签名 URL 差异。
func EquivalentTargetURL(a, b string) bool {
	key := func(raw string) string {
		parsed, err := url.Parse(raw)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" ||
			parsed.Opaque != "" || parsed.Path != "" {
			return raw
		}
		end := strings.IndexAny(raw, "?#")
		if end < 0 {
			end = len(raw)
		}
		return raw[:end] + "/" + raw[end:]
	}
	return key(a) == key(b)
}
