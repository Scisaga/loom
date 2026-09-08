package agent

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"loom/internal/model"
)

// ClientEntry 是从已验证数据面按候选链提取的入口，不增加配置协议（§5.1）。
type ClientEntry struct{ Node, Address, Source string }
type ClientOptions struct {
	StatePath    string
	Entries      []ClientEntry
	Probe        func(context.Context, ClientEntry) (time.Duration, error)
	Observations *ObservationCache
	HopCarriers  map[string][]string
}
type entryResult struct {
	RTT time.Duration
	At  time.Time
	Err error
}

// RunClient 只在启动时对去重入口各探一次；服务器更新只重算，不调用旧 Run（§5.6）。
func RunClient(ctx context.Context, cfg *Config, opts ClientOptions) (retErr error) {
	defer func() {
		if ctx.Err() != nil {
			retErr = nil
		}
	}()
	if len(cfg.Declarations) == 0 {
		<-ctx.Done()
		return nil
	}
	states, err := newStateStore(ctx, opts.StatePath, cfg.Node, cfg.Declarations, time.Now())
	if err != nil {
		return err
	}
	entries := map[string]entryResult{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	// 同地址的多个授权身份也只发一个包；绝不按声明或完整候选重复测量。
	byAddress := map[string][]ClientEntry{}
	allowed := map[string]bool{}
	for _, d := range cfg.Declarations {
		for _, c := range d.Candidates {
			if len(c.Chain) > 0 {
				allowed[c.Chain[0]] = true
			}
		}
	}
	for _, e := range opts.Entries {
		if !allowed[e.Node] || e.Address == "" {
			return errors.New("[§5.1] 入口探测超出当前授权候选")
		}
		byAddress[e.Address+"\x00"+e.Source] = append(byAddress[e.Address+"\x00"+e.Source], e)
	}
	for _, group := range byAddress {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var r entryResult
			probeCtx, cancel := context.WithTimeout(ctx, time.Second)
			defer cancel()
			if opts.Probe == nil {
				r.Err = errors.New("入口探测不可用")
			} else {
				r.RTT, r.Err = opts.Probe(probeCtx, group[0])
			}
			r.At = time.Now()
			mu.Lock()
			defer mu.Unlock()
			for _, e := range group {
				entries[e.Node] = r
			}
		}()
	}
	wg.Wait()
	k := newClash(cfg.API, cfg.APISecret)
	defer k.c.CloseIdleConnections()
	for {
		if ctx.Err() != nil {
			return nil
		}
		updates := opts.Observations.Updates()
		for _, d := range cfg.Declarations {
			if err := selectClientRoute(ctx, cfg, d, k, states, entries, opts.Observations, opts.HopCarriers, time.Now()); err != nil {
				if ctx.Err() != nil {
					return nil
				}
				return err
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-updates:
		}
	}
}

type clientCost struct {
	known, failed bool
	ms            float64
	failureRate   float64
}

func selectClientRoute(ctx context.Context, cfg *Config, d Decl, k *clash, states *stateStore, entries map[string]entryResult, observations *ObservationCache, carriers map[string][]string, now time.Time) error {
	actual, err := k.Now(ctx, d.Selector)
	if err != nil {
		return err
	}
	var current *Cand
	for i := range d.Candidates {
		if d.Candidates[i].Tag == actual {
			current = &d.Candidates[i]
			break
		}
	}
	if current == nil {
		return errors.New("[§5.1] 实际 selector 不在授权候选内")
	}
	chosen := *current
	best := clientCost{}
	costs := map[string]clientCost{}
	targets := observations.clientTargets(d.Targets, now)
	for _, c := range d.Candidates {
		cost := observations.clientCost(c.Chain, targets, now, carriers[c.Tag])
		entry, ok := entryFor(c, entries)
		if !ok {
			cost.known = false
		} else {
			cost.ms += float64(entry.RTT) / float64(time.Millisecond)
		}
		costs[c.Tag] = cost
	}
	// 只有已覆盖后段的观测才用于跨出口比较，绝不把未知当零延迟。
	if d.Objective == model.Latency {
		best = costs[actual]
		for _, c := range d.Candidates {
			x := costs[c.Tag]
			if !x.known || x.failed {
				continue
			}
			if !best.known || best.failed || x.failureRate < best.failureRate || x.failureRate == best.failureRate && x.ms < best.ms {
				chosen, best = c, x
			}
		}
		old := costs[actual]
		if chosen.Tag != actual && old.known && !old.failed && best.failureRate == old.failureRate && old.ms > 0 && (old.ms-best.ms)/old.ms < d.SwitchThreshold {
			chosen, best = *current, old
		}
	}
	// 尚无后段观测时沿用已配置出口，只根据入口实测改善第一跳；不等待、不补测。
	if !best.known || best.failed {
		var fastest time.Duration
		found := false
		for _, c := range d.Candidates {
			if !sameClientExit(c, *current) || costs[c.Tag].failed {
				continue
			}
			r, ok := entryFor(c, entries)
			if ok && (!found || r.RTT < fastest || r.RTT == fastest && c.Tag == actual) {
				chosen, fastest, found = c, r.RTT, true
			}
		}
	}
	if chosen.Tag != actual {
		if err := k.Select(ctx, d.Selector, chosen.Tag); err != nil {
			return err
		}
		actual, err = k.Now(ctx, d.Selector)
		if err != nil {
			return err
		}
		if actual != chosen.Tag {
			return errors.New("[§7.3.1] selector 未应用本次选择")
		}
	}
	reason := "直连候选；业务可用性未测量"
	if len(chosen.Chain) > 0 {
		r, ok := entryFor(chosen, entries)
		if ok {
			reason = fmt.Sprintf("入口 %s：单次 ping %d ms（%s）；", chosen.Chain[0], r.RTT.Milliseconds(), r.At.UTC().Format(time.RFC3339))
		} else {
			reason = "入口 ping 未获响应，入口可达性未知；"
		}
		x := costs[chosen.Tag]
		if x.known && !x.failed && d.Objective == model.Latency {
			reason += fmt.Sprintf("入口与服务器分段观测估算 %.0f ms；未测整条业务路径", x.ms)
		} else if x.failed {
			reason += "服务器观测显示后段失败；暂无可比较替代路径"
		} else {
			reason += "后段比较证据不足，保留当前出口；未测整条业务路径"
		}
		if d.Objective != model.Latency {
			reason += "；现有分段观测不能计算配置目标 " + string(d.Objective)
		}
		if len(targets) < len(d.Targets) {
			reason += fmt.Sprintf("；服务器观测覆盖 %d/%d 个目标，其余未知", len(targets), len(d.Targets))
		}
	}
	// §16.1：分段估算不是实测健康/分位数。已有线格式保留 unknown，原因承载分工。
	h := &CandidateHealth{Candidates: len(d.Candidates), Unknown: len(d.Candidates), SelectedState: healthUnknown}
	return states.observe(ctx, Selection{Declaration: d.ID, Selector: d.Selector, Candidate: actual, Chain: chosen.Chain, Reason: reason, Health: h}, now)
}

func entryFor(c Cand, entries map[string]entryResult) (entryResult, bool) {
	if len(c.Chain) == 0 {
		return entryResult{}, false
	}
	r, ok := entries[c.Chain[0]]
	return r, ok && r.Err == nil && r.RTT >= 0
}
func sameClientExit(a, b Cand) bool {
	return len(a.Chain) > 0 && len(b.Chain) > 0 && a.Chain[len(a.Chain)-1] == b.Chain[len(b.Chain)-1]
}
