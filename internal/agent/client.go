package agent

import (
	"context"
	"errors"
	"time"

	"loom/internal/clientroute"
)

// ClientEntry 是从已验证数据面按候选链提取的入口，不增加配置协议。
type ClientEntry struct{ Node, Address, Source string }
type ClientOptions struct {
	StatePath              string
	Entries                []ClientEntry
	Probe                  func(context.Context, ClientEntry) (time.Duration, error)
	ProbeRegistry          *EntryProbeRegistry
	UnderlayGeneration     string
	EntryProbesUnavailable bool
	Observations           *ObservationCache
	HopCarriers            map[string][]string
	// 仅供本地界面保留本轮入口结果，不进入报告协议。
	OnEntries func([]ClientPathMeasurement)
}

// ClientEntryResult 是客户端在当前连接代对一个授权入口的单次测量。
// 它不进入 Agent 的窗口样本，也不能冒充完整业务路径健康。
type ClientEntryResult = clientroute.EntryResult

// 保留 Windows 包内测试使用的旧名称；两个客户端宿主实际复用同一表示。
type entryResult = ClientEntryResult

// 兼容既有观测缓存测试；运行时决策统一委托给共享 clientroute。
type clientCost struct {
	known, failed bool
	ms            float64
	failureRate   float64
}

// RunClient 只在启动时对去重入口各探一次；服务器更新只重算，不调用旧 Run。
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
	entries := map[string]ClientEntryResult{}
	measuredNodes := map[string]bool{}
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
			return errors.New("入口探测超出当前授权候选")
		}
	}
	if !opts.EntryProbesUnavailable {
		registry := opts.ProbeRegistry
		if registry == nil {
			registry, err = NewEntryProbeRegistry(ctx)
			if err != nil {
				return err
			}
			if opts.UnderlayGeneration == "" {
				opts.UnderlayGeneration = "activation"
			}
		}
		entries, measuredNodes, err = registry.results(ctx, opts.UnderlayGeneration, opts.Entries, opts.Probe)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
	}
	if opts.OnEntries != nil {
		var measured []ClientPathMeasurement
		seen := map[string]bool{}
		for _, e := range opts.Entries {
			if seen[e.Node] {
				continue
			}
			seen[e.Node] = true
			r, wasMeasured := entries[e.Node]
			m := ClientPathMeasurement{From: cfg.Node, To: e.Node, Kind: "entry"}
			if !wasMeasured || !measuredNodes[e.Node] {
				m.Error = "当前 underlay 代未主动探测此入口"
			} else if r.Err == nil && r.RTT >= 0 {
				m.ObservedAt, m.Samples = r.At.UTC().Format(time.RFC3339), 1
				ms := r.RTT.Milliseconds()
				m.DelayMS = &ms
			} else {
				m.ObservedAt, m.Samples = r.At.UTC().Format(time.RFC3339), 1
				m.Failures = 1
				m.Error = "单次 ping 未获响应"
			}
			measured = append(measured, m)
		}
		opts.OnEntries(measured)
	}
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

func selectClientRoute(ctx context.Context, cfg *Config, d Decl, k *clash, states *stateStore, entries map[string]ClientEntryResult, observations *ObservationCache, carriers map[string][]string, now time.Time) error {
	actual, err := k.Now(ctx, d.Selector)
	if err != nil {
		return err
	}
	selection, err := DecideClientRoute(d, actual, entries, observations, carriers, now)
	if err != nil {
		return err
	}
	if selection.Candidate != actual {
		if err := k.Select(ctx, d.Selector, selection.Candidate); err != nil {
			return err
		}
		actual, err = k.Now(ctx, d.Selector)
		if err != nil {
			return err
		}
		if actual != selection.Candidate {
			return errors.New("selector 未应用本次选择")
		}
	}
	selection.Candidate = actual
	return states.observe(ctx, selection, now)
}

// DecideClientRoute 复用 Windows 与 Android 客户端的窄选路语义。调用方必须
// 先从实际 selector 读取 current，并在返回后自行执行和读回切换；本函数不访问
// 网络、不等待样本，也不会探测入口后的业务路径。
func DecideClientRoute(d Decl, actual string, entries map[string]ClientEntryResult, observations *ObservationCache, carriers map[string][]string, now time.Time) (Selection, error) {
	declaration := clientroute.Declaration{
		ID: d.ID, Selector: d.Selector, Objective: string(d.Objective), Targets: append([]string(nil), d.Targets...),
		SwitchThreshold: d.SwitchThreshold,
	}
	for _, candidate := range d.Candidates {
		declaration.Candidates = append(declaration.Candidates, clientroute.Candidate{Tag: candidate.Tag, Chain: append([]string(nil), candidate.Chain...)})
	}
	decision, err := clientroute.Decide(declaration, actual, entries, observations.clientEvidence(), carriers, now)
	if err != nil {
		return Selection{}, err
	}
	// 分段估算不是实测健康/分位数。已有线格式保留 unknown，原因承载分工。
	h := &CandidateHealth{Candidates: len(d.Candidates), Unknown: len(d.Candidates), SelectedState: healthUnknown}
	return Selection{Declaration: d.ID, Selector: d.Selector, Candidate: decision.Candidate, Chain: decision.Chain, Reason: decision.Reason, Health: h}, nil
}

func entryFor(c Cand, entries map[string]ClientEntryResult) (ClientEntryResult, bool) {
	if len(c.Chain) == 0 {
		return ClientEntryResult{}, false
	}
	r, ok := entries[c.Chain[0]]
	return r, ok && r.Err == nil && r.RTT >= 0
}
