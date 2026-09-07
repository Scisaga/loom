package agent

import (
	"context"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"loom/internal/events"
	"loom/internal/measure"
)

// Options 是 Agent 的运行期参数。它们不进 SSOT —— 都是本机的事(文件放哪、
// 单次探测等多久),换一台机器可以不同,不该让全局声明去描述。
type Options struct {
	MeasurementPath string
	// StatePath 是 selector 当前实际选择的原子快照。
	StatePath    string
	ProbeTimeout time.Duration
	// Retention 是度量文件的保留时长。超出的记录在压实时丢弃 ——
	// 追加日志不压实会无限长大。
	Retention time.Duration
	// EventsPath 非空时,选路切换会记进事件历史。
	EventsPath string

	// Once 为真时,每条声明只跑一轮就返回。给人工执行和自检用。
	Once bool
	// DryRun 为真时照常探测和判断、照常记度量,但不真的切 selector。
	// 上线一个新的排序规则时,先用它看几轮"会怎么切"再放开。
	DryRun bool
	Log    io.Writer
	// Now 由调用方注入,便于测试。渲染与打包不读时钟(§12),但 Agent 是
	// 运行期组件 —— 它**必须**读时钟,只是入口收在这一处。
	Now     func() time.Time
	eventMu *sync.Mutex
}

func (o *Options) fill() {
	if o.MeasurementPath == "" {
		o.MeasurementPath = "/var/lib/loom/measurements.jsonl"
	}
	if o.StatePath == "" {
		o.StatePath = StatePath
	}
	if o.ProbeTimeout == 0 {
		o.ProbeTimeout = 8 * time.Second
	}
	if o.Retention == 0 {
		o.Retention = 24 * time.Hour
	}
	if o.Log == nil {
		o.Log = os.Stderr
	}
	if o.Now == nil {
		o.Now = func() time.Time { return time.Now().UTC() }
	}
}

// Run 跑调参回路,直到 ctx 结束(Once 模式下跑完一轮就返回)。
//
// 每条声明一个 goroutine、各按自己的 tuning_period 走 —— 声明之间的节奏
// 本来就不同,合并成一个全局节拍会让快的那条被慢的拖住。
func Run(ctx context.Context, cfg *Config, opts Options) (retErr error) {
	if ctx == nil {
		return fmt.Errorf("Agent context 不能为空")
	}
	if ctx.Err() != nil {
		return nil
	}
	defer func() {
		if ctx.Err() != nil {
			retErr = nil
		}
	}()
	if err := validateObservationPlatform(cfg); err != nil {
		return err
	}
	opts.fill()
	opts.eventMu = &sync.Mutex{}
	logf := func(f string, a ...any) {
		fmt.Fprintf(opts.Log, "%s "+f+"\n",
			append([]any{opts.Now().Format("15:04:05")}, a...)...)
	}
	if cfg.ObservationDisabledReason != "" {
		logf("⚠️ %s", cfg.ObservationDisabledReason)
	}
	st := &store{path: opts.MeasurementPath, retention: opts.Retention, now: opts.Now}
	selections, err := newStateStore(ctx, opts.StatePath, cfg.Node, cfg.Declarations, opts.Now())
	if err != nil {
		return fmt.Errorf("初始化 Agent 当前选择:%w", err)
	}
	observationMaxAge, err := cfg.ObsStale()
	if err != nil {
		return err
	}
	if err := st.compact(ctx); err != nil {
		return fmt.Errorf("压实度量文件:%w", err)
	}
	var attestationCA []byte
	if len(cfg.Peers) > 0 || cfg.SelfReport != "" {
		attestationCA, err = os.ReadFile(cfg.AttestationCA)
		if err != nil {
			return fmt.Errorf("读取观测签名 CA %s:%w", cfg.AttestationCA, err)
		}
	}

	k := newClash(cfg.API, cfg.APISecret)
	obs := newObserved()
	// 每条声明各自的轮换游标。有界探测靠它保证"每条候选迟早都被试到"。
	rot := map[string]string{}
	var rotMu sync.Mutex
	var wg sync.WaitGroup

	// 拉取对端上报是另一个节奏:它和某一条声明无关,是整台机器的事。
	//
	// **第一轮同步跑完再开始调参。** 并发启动的话,第一次决策会在全网观测
	// 到手之前做出,剪枝失效 —— 而下一次机会要等一整个 tuning_period。
	if len(cfg.Peers) > 0 || cfg.SelfReport != "" {
		pollPeers(ctx, cfg, obs, attestationCA, opts.Now(), observationMaxAge, logf)
		if ctx.Err() != nil {
			return nil
		}
		logf("已收到 %d 个节点的观测", obs.len())
	}
	if (len(cfg.Peers) > 0 || cfg.SelfReport != "") && cfg.PeerPeriod != "" {
		pp, err := dur(cfg.PeerPeriod, "peer_period")
		if err != nil {
			return err
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case <-time.After(pp):
				}
				pollPeers(ctx, cfg, obs, attestationCA, opts.Now(), observationMaxAge, logf)
				if ctx.Err() != nil {
					return
				}
				if opts.Once {
					return
				}
			}
		}()
	}

	for i := range cfg.Declarations {
		d := &cfg.Declarations[i]
		period, err := d.Period()
		if err != nil {
			return err
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				if ctx.Err() != nil {
					return
				}
				if err := tick(ctx, cfg, d, k, st, selections, obs, observationMaxAge, rot, &rotMu, &opts, logf); err != nil {
					if ctx.Err() != nil {
						return
					}
					// 一轮失败不该让回路停掉:控制端点可能只是在重启。
					logf("[%s] 本轮失败:%v", d.ID, err)
				}
				if opts.Once {
					return
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(period):
				}
			}
		}()
	}
	wg.Wait()
	return nil
}

// tick 是一轮:探测全部候选 → 按窗口聚合 → 决定 → 必要时切。
func tick(ctx context.Context, cfg *Config, d *Decl, k *clash, st *store, selections *stateStore,
	obs *observed, observationMaxAge time.Duration, rot map[string]string,
	rotMu *sync.Mutex, opts *Options, logf func(string, ...any)) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	win, err := d.Win()
	if err != nil {
		return err
	}
	scope := decisionScope(cfg.Node, d)
	stale, err := d.Stale()
	if err != nil {
		return err
	}

	// 1. 探测。**逐条串行**,不并发:同一条接入链路上并发打十几个候选,
	//    它们会互相抢上行带宽,把彼此的延迟推高 —— 测出来的是拥塞,不是
	//    这条候选的真实水平。候选按 tag 排序,顺序稳定便于比对日志。
	cands := append([]Cand(nil), d.Candidates...)
	sort.Slice(cands, func(i, j int) bool { return cands[i].Tag < cands[j].Tag })

	// 剪枝:出口已知打不到这个目标的候选,不必再探。
	//
	// **同一个事实不该被反复发现。** "cn-a 到不了 Cloudflare"是关于 cn-a
	// 一台机器的事实,由 cn-a 自己量一次(§16.1.2);而按整条路线去探的话,
	// 它会在每条经过 cn-a 的链上各被发现一次 —— 这里 15 条候选里有 9 条。
	//
	// 剪枝依据每轮都从新的观测重取,不是一次性判定:cn-a 什么时候恢复,
	// 下一轮就自动重新开探。
	// 剪枝按**每个目标**分别算:出口对目标 A 不可达、对目标 B 可达时,
	// 它仍然要为 B 参与竞争。一刀切会把一条对一半目标有效的候选整个砍掉。
	deadFor := map[string]map[string]string{}
	dead := map[string]bool{}
	for _, t := range d.Targets {
		m := obs.unreachable(t, opts.Now(), observationMaxAge)
		deadFor[t] = m
		if len(m) == 0 {
			continue
		}
	}
	// 对**全部**目标都不可达的出口才整条剪掉。
	for exit := range deadFor[d.Targets[0]] {
		all := true
		for _, t := range d.Targets {
			if _, bad := deadFor[t][exit]; !bad {
				all = false
			}
		}
		if all {
			dead[exit] = true
		}
	}
	var probe []Cand
	var pruned []string
	for _, c := range cands {
		if dead[candidateExit(c, cfg.Node)] {
			pruned = append(pruned, c.Tag)
			continue
		}
		probe = append(probe, c)
	}

	// 当前选中的那条**每轮必探**。它变坏了要立刻知道 —— 这正是 D23
	// (停在死候选上不受阻尼保护)依赖的信号。
	current, cerr := k.Now(ctx, d.Selector)
	if cerr != nil {
		return fmt.Errorf("读 selector:%w", cerr)
	}
	currentChain, found := configuredChain(d, current)
	if !found {
		return fmt.Errorf("selector %s 当前值 %q 不在渲染候选中", d.Selector, current)
	}
	// §5.6 此时只有探测前读到的 selector，还没有本轮健康摘要；若先发布，
	// 每轮探测期间都会用 Health=nil 覆盖上一份完整状态，让 report 正确但
	// 反复地产生“证据不完整”漂移。下方各成功路径会把 selector 与本轮健康
	// 一起原子发布。
	var skippedByBudget int
	if d.ProbeBudget > 0 && len(probe) > d.ProbeBudget {
		rotMu.Lock()
		var next string
		probe, next, skippedByBudget = pickProbeCandidates(probe, current, d.ProbeBudget, rot[d.ID])
		rot[d.ID] = next
		rotMu.Unlock()
	}

	ts := opts.Now().Format(time.RFC3339)
	var got []measure.Measurement
	ok := 0

	// 被剪掉的也要如实记一笔失败,而且标成 derived。
	//
	// 不记的话有个洞:当前选中的候选如果正好被剪掉,它在窗口里的**旧数据**
	// 会让 Decide 以为它还健康,于是流量继续停在一条已知不通的路上 ——
	// 正是 Agent 本来要解决的那个问题。
	for _, c := range cands {
		exit := candidateExit(c, cfg.Node)
		if !dead[exit] {
			continue
		}
		for _, t := range d.Targets {
			got = append(got, measure.Measurement{
				TS: ts, Node: cfg.Node, CandidateID: c.Tag, Declaration: d.ID, Target: t,
				DecisionScope: scope,
				Point:         measure.L4Tunnel, Kind: measure.Derived,
				Error: fmt.Sprintf("出口 %s 自己观测到打不到 %s:%s", exit, t, deadFor[t][exit]),
			})
		}
	}
	cands = probe
	for _, c := range cands {
		for _, t := range d.Targets {
			r, perr := ProbeOnce(ctx, cfg.Probe, cfg.ProbeSecret, c.ProbeUser, t, opts.ProbeTimeout)
			if err := ctx.Err(); err != nil {
				return err
			}
			m := measure.Measurement{
				TS: ts, Node: cfg.Node, CandidateID: c.Tag, Declaration: d.ID, Target: t,
				DecisionScope: scope,
				Point:         measure.L4Tunnel, Kind: measure.Active,
			}
			if perr != nil {
				m.Error = perr.Error()
			} else {
				m.FirstByteMs = r.FirstByteMs
				m.KBps = r.KBps()
				ok++
			}
			got = append(got, m)
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := st.append(ctx, got); err != nil {
		return fmt.Errorf("写度量:%w", err)
	}

	// 2. 聚合。窗口之外的不参与;整条候选最新样本超过 stale_after 的当作
	//    没测过 —— 拿半小时前的数据当依据去切换,和瞎猜差不多(§5.8)。
	all, err := st.load()
	if err != nil {
		return fmt.Errorf("读度量:%w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	sums := measure.Summarize(inWindow(all, cfg.Node, d.ID, scope, opts.Now(), win, stale))
	healthFor := func(selected string) *CandidateHealth {
		return summarizeCandidateHealth(d, selected, sums, all, cfg.Node, scope)
	}

	// 3. 决定。
	dec := Decide(d, current, sums)
	selected := current
	reason := dec.Reason
	// 亲自测的和照别人观测判定的必须分开说 —— 混成一个数字,就看不出
	// 这一轮到底有多少是真的测过的。
	line := fmt.Sprintf("探测 %d 条 × %d 个目标(%d 通)", len(cands), len(d.Targets), ok)
	if skippedByBudget > 0 {
		// 少探了多少必须说出来 —— 静默截断会让"这一轮没试到"看起来像
		// "试过了但不行"。
		line += fmt.Sprintf(",预算内轮候 %d 条", skippedByBudget)
	}
	if len(pruned) > 0 {
		line += fmt.Sprintf(",另按全网观测判定 %d 条出口不可用(未探)", len(pruned))
	}
	logf("[%s] %s · %s", d.ID, line, dec.Reason)
	if !dec.Switch {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := selections.observe(ctx, Selection{
			Declaration: d.ID, Selector: d.Selector, Candidate: selected,
			Chain: currentChain, Reason: reason, Health: healthFor(selected),
		}, opts.Now()); err != nil {
			logf("[%s] 写 Agent 当前状态失败:%v", d.ID, err)
		}
		return nil
	}
	if opts.DryRun {
		logf("[%s] (dry-run)本应切 %s → %s", d.ID, current, dec.Choice)
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := selections.observe(ctx, Selection{
			Declaration: d.ID, Selector: d.Selector, Candidate: current,
			Chain: currentChain, Reason: "dry-run，实际未切；" + reason,
			Health: healthFor(current),
		}, opts.Now()); err != nil {
			logf("[%s] 写 Agent 当前状态失败:%v", d.ID, err)
		}
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := k.Select(ctx, d.Selector, dec.Choice); err != nil {
		return fmt.Errorf("切 selector:%w", err)
	}
	actual, err := k.Now(ctx, d.Selector)
	if err != nil {
		return fmt.Errorf("切 selector 后读回实际选择:%w", err)
	}
	if actual != dec.Choice {
		return fmt.Errorf("selector 写入 %s 后读回 %s，拒绝把控制意图冒充实际状态", dec.Choice, actual)
	}
	actualChain, found := configuredChain(d, actual)
	if !found {
		return fmt.Errorf("selector %s 读回值 %q 不在渲染候选中", d.Selector, actual)
	}
	logf("[%s] ✅ %s → %s", d.ID, current, actual)
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := selections.observe(ctx, Selection{
		Declaration: d.ID, Selector: d.Selector, Candidate: actual,
		Chain: actualChain, Reason: reason, Health: healthFor(actual),
	}, opts.Now()); err != nil {
		logf("[%s] 写 Agent 当前状态失败:%v", d.ID, err)
	}
	// 切换是状态变化,该进事件历史 —— 只写 journald 的话,"这条路是什么
	// 时候、因为什么切过去的"事后查不到。
	if opts.EventsPath != "" {
		if err := ctx.Err(); err != nil {
			return err
		}
		ev := events.Event{
			TS: opts.Now().UTC().Format(time.RFC3339), Node: cfg.Node,
			Kind: "route", Subject: d.ID, From: shortChain(currentChain), To: shortChain(actualChain),
			Detail: dec.Reason,
		}
		if opts.eventMu != nil {
			opts.eventMu.Lock()
			defer opts.eventMu.Unlock()
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		_ = events.Append(opts.EventsPath, []events.Event{ev})
	}
	return nil
}

// pickProbeCandidates keeps the current selector member in every bounded
// round, then spends only the remaining slots on a stable ring of other
// candidates. The cursor is the next tag rather than a numeric slice index so
// pruning or candidate-set changes cannot silently shift it onto a different
// part of the ring.
func pickProbeCandidates(candidates []Cand, current string, budget int, nextTag string) ([]Cand, string, int) {
	probe := append([]Cand(nil), candidates...)
	sort.Slice(probe, func(i, j int) bool { return probe[i].Tag < probe[j].Tag })
	if budget <= 0 || len(probe) <= budget {
		return probe, nextTag, 0
	}

	selected := make([]Cand, 0, budget)
	others := make([]Cand, 0, len(probe))
	for _, candidate := range probe {
		if candidate.Tag == current {
			selected = append(selected, candidate)
			continue
		}
		others = append(others, candidate)
	}

	slots := budget - len(selected)
	if slots < 0 {
		slots = 0
	}
	if slots > len(others) {
		slots = len(others)
	}
	start := 0
	if nextTag != "" && len(others) > 0 {
		start = sort.Search(len(others), func(i int) bool { return others[i].Tag >= nextTag })
		if start == len(others) {
			start = 0
		}
	}
	for i := 0; i < slots; i++ {
		selected = append(selected, others[(start+i)%len(others)])
	}
	if slots > 0 {
		nextTag = others[(start+slots)%len(others)].Tag
	}
	return selected, nextTag, len(probe) - len(selected)
}

// configuredChain 按 opaque tag 找 renderer 显式携带的节点链。拓扑不能从
// tag 猜：声明/服务 key 和地址本身都可能含 ':' 或 '@'。
func configuredChain(d *Decl, tag string) ([]string, bool) {
	for _, c := range d.Candidates {
		if c.Tag == tag {
			return append([]string(nil), c.Chain...), true
		}
	}
	return nil, false
}

func shortChain(chain []string) string {
	if len(chain) == 0 {
		return "direct"
	}
	return strings.Join(chain, ">")
}

// inWindow 过滤出这条声明在窗口内的样本。
//
// window 与 stale_after 是两件事:前者决定"用多久的数据算分位数",后者决定
// "多久没新数据就认为这条候选的情况已经不知道了"。一条候选如果最近一次
// 样本已经超过 stale_after,它在本轮里等同没有数据。
func inWindow(ms []measure.Measurement, node, decl, scope string, now time.Time, window, stale time.Duration) []measure.Measurement {
	cut := now.Add(-window)
	staleCut := now.Add(-stale)
	// 节点之间允许少量时钟偏差，但不能让一条来自“未来”的记录在 VM
	// 恢复或时钟回拨后长期占据最新样本。超过两分钟的样本直接丢弃，且
	// 不能参与 newest 计算。
	futureCut := now.Add(2 * time.Minute)

	newest := map[string]time.Time{}
	parsed := make([]time.Time, len(ms))
	for i := range ms {
		t, err := time.Parse(time.RFC3339, ms[i].TS)
		if err != nil || t.After(futureCut) {
			continue
		}
		parsed[i] = t
		if ms[i].Node == node && ms[i].Declaration == decl && ms[i].DecisionScope == scope &&
			t.After(newest[ms[i].CandidateID]) {
			newest[ms[i].CandidateID] = t
		}
	}

	var out []measure.Measurement
	for i := range ms {
		if ms[i].Node != node || ms[i].Declaration != decl || ms[i].DecisionScope != scope ||
			parsed[i].IsZero() || parsed[i].Before(cut) {
			continue
		}
		if newest[ms[i].CandidateID].Before(staleCut) {
			continue
		}
		out = append(out, ms[i])
	}
	return out
}

// candidateExit 取 renderer 显式携带的最后一跳。Tag 是 opaque ID，服务 key
// 与地址都允许 ':'/'@'，不能再从它反解析出口。
func candidateExit(c Cand, self string) string {
	if len(c.Chain) == 0 {
		return self
	}
	return c.Chain[len(c.Chain)-1]
}
