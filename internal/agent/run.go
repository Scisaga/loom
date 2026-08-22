package agent

import (
	"context"
	"fmt"
	"io"
	"os"
	"sort"
	"sync"
	"time"

	"loom/internal/measure"
	"loom/internal/report"
)

// Options 是 Agent 的运行期参数。它们不进 SSOT —— 都是本机的事(文件放哪、
// 单次探测等多久),换一台机器可以不同,不该让全局声明去描述。
type Options struct {
	MeasurementPath string
	ProbeTimeout    time.Duration
	// Retention 是度量文件的保留时长。超出的记录在压实时丢弃 ——
	// 追加日志不压实会无限长大。
	Retention time.Duration
	// Once 为真时,每条声明只跑一轮就返回。给人工执行和自检用。
	Once bool
	// DryRun 为真时照常探测和判断、照常记度量,但不真的切 selector。
	// 上线一个新的排序规则时,先用它看几轮"会怎么切"再放开。
	DryRun bool
	Log    io.Writer
	// Now 由调用方注入,便于测试。渲染与打包不读时钟(§12),但 Agent 是
	// 运行期组件 —— 它**必须**读时钟,只是入口收在这一处。
	Now func() time.Time
}

func (o *Options) fill() {
	if o.MeasurementPath == "" {
		o.MeasurementPath = "/var/lib/loom/measurements.jsonl"
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
func Run(ctx context.Context, cfg *Config, opts Options) error {
	opts.fill()
	st := &store{path: opts.MeasurementPath, retention: opts.Retention, now: opts.Now}
	if err := st.compact(); err != nil {
		return fmt.Errorf("压实度量文件:%w", err)
	}

	k := newClash(cfg.API, cfg.APISecret)
	obs := newObserved()
	logf := func(f string, a ...any) {
		fmt.Fprintf(opts.Log, "%s "+f+"\n",
			append([]any{opts.Now().Format("15:04:05")}, a...)...)
	}

	var wg sync.WaitGroup

	// 拉取对端上报是另一个节奏:它和某一条声明无关,是整台机器的事。
	//
	// **第一轮同步跑完再开始调参。** 并发启动的话,第一次决策会在全网观测
	// 到手之前做出,剪枝失效 —— 而下一次机会要等一整个 tuning_period。
	if len(cfg.Peers) > 0 || cfg.SelfReport != "" {
		pollPeers(cfg, obs, logf)
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
				pollPeers(cfg, obs, logf)
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
				if err := tick(cfg, d, k, st, obs, &opts, logf); err != nil {
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

// pollPeers 拉一遍能够到的节点的自检结果。
//
// 它**不做任何处置** —— 隧道断了要人去看,不是 Agent 能自动修的。价值在于
// 从"完全没有信号"变成"有带时间戳的记录":DDNS 重解析以前是全程静默的,
// IP 变了、隧道断了、脚本修好了,事后连查都没得查。
func pollPeers(cfg *Config, obs *observed, logf func(string, ...any)) {
	peers := append([]Peer(nil), cfg.Peers...)
	sort.Slice(peers, func(i, j int) bool { return peers[i].Node < peers[j].Node })
	// 本机上报者排在最前:它手里已经有转述过来的全网观测,先拿到它,
	// 后面每条声明剪枝就有依据了。
	if cfg.SelfReport != "" {
		peers = append([]Peer{{Node: cfg.Node, Addr: cfg.SelfReport}}, peers...)
	}
	for _, p := range peers {
		st, err := report.Fetch(p.Addr, 5*time.Second)
		if err != nil {
			logf("[对端 %s] ❌ 拉不到 %s:%v", p.Node, p.Addr, err)
			continue
		}
		obs.put(st.Observation)
		for i := range st.Learned {
			obs.put(&st.Learned[i])
		}
		if p.Node == cfg.Node {
			continue // 自己的隧道健康由自己的日志说,不在这里重复
		}
		if st.OK() {
			continue // 正常就不说话,否则日志里全是噪声
		}
		for i := range st.Tunnels {
			t := &st.Tunnels[i]
			switch {
			case t.Down:
				logf("[对端 %s] ❌ 隧道 %s 没起来", p.Node, t.Interface)
			case t.HandshakeAgeSec < 0:
				logf("[对端 %s] ❌ 隧道 %s 从未握手", p.Node, t.Interface)
			case t.Stale:
				logf("[对端 %s] ⚠️ 隧道 %s 握手已 %d 秒前", p.Node, t.Interface, t.HandshakeAgeSec)
			}
		}
		if d := st.Drift; d != nil {
			for _, f := range d.Modified {
				logf("[对端 %s] ⚠️ 配置被改过:%s", p.Node, f)
			}
			for _, f := range d.Missing {
				logf("[对端 %s] ⚠️ 配置缺失:%s", p.Node, f)
			}
			for _, f := range d.Unreadable {
				logf("[对端 %s] ⚠️ 配置读不到:%s", p.Node, f)
			}
		}
		for _, e := range st.Errors {
			logf("[对端 %s] ⚠️ 采集错误:%s", p.Node, e)
		}
	}
}

// tick 是一轮:探测全部候选 → 按窗口聚合 → 决定 → 必要时切。
func tick(cfg *Config, d *Decl, k *clash, st *store, obs *observed, opts *Options, logf func(string, ...any)) error {
	win, err := d.Win()
	if err != nil {
		return err
	}
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
	dead := obs.unreachable(d.ProbeURL, opts.Now(), 15*time.Minute)
	var probe []Cand
	var pruned []string
	for _, c := range cands {
		if why, bad := dead[exitOf(c.Tag, cfg.Node)]; bad {
			pruned = append(pruned, fmt.Sprintf("%s(出口 %s:%s)",
				c.Tag, exitOf(c.Tag, cfg.Node), why))
			continue
		}
		probe = append(probe, c)
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
		if why, bad := dead[exitOf(c.Tag, cfg.Node)]; bad {
			got = append(got, measure.Measurement{
				TS: ts, Node: cfg.Node, CandidateID: c.Tag, Declaration: d.ID,
				Point: measure.L4Tunnel, Kind: measure.Derived,
				Error: fmt.Sprintf("出口 %s 自己观测到打不到目标:%s",
					exitOf(c.Tag, cfg.Node), why),
			})
		}
	}
	cands = probe
	for _, c := range cands {
		ms, perr := ProbeOnce(cfg.Probe, cfg.ProbeSecret, c.ProbeUser, d.ProbeURL, opts.ProbeTimeout)
		m := measure.Measurement{
			TS: ts, Node: cfg.Node, CandidateID: c.Tag, Declaration: d.ID,
			Point: measure.L4Tunnel, Kind: measure.Active,
		}
		if perr != nil {
			m.Error = perr.Error()
		} else {
			m.FirstByteMs = ms
			ok++
		}
		got = append(got, m)
	}
	if err := st.append(got); err != nil {
		return fmt.Errorf("写度量:%w", err)
	}

	// 2. 聚合。窗口之外的不参与;整条候选最新样本超过 stale_after 的当作
	//    没测过 —— 拿半小时前的数据当依据去切换,和瞎猜差不多(§5.8)。
	all, err := st.load()
	if err != nil {
		return fmt.Errorf("读度量:%w", err)
	}
	sums := measure.Summarize(inWindow(all, d.ID, opts.Now(), win, stale))

	// 3. 决定。
	current, err := k.Now(d.Selector)
	if err != nil {
		return fmt.Errorf("读 selector:%w", err)
	}
	dec := Decide(d, current, sums)
	// 亲自测的和照别人观测判定的必须分开说 —— 混成一个数字,就看不出
	// 这一轮到底有多少是真的测过的。
	line := fmt.Sprintf("探测 %d 条(%d 通)", len(cands), ok)
	if len(pruned) > 0 {
		line += fmt.Sprintf(",另按全网观测判定 %d 条出口不可用(未探)", len(pruned))
	}
	logf("[%s] %s · %s", d.ID, line, dec.Reason)
	if !dec.Switch {
		return nil
	}
	if opts.DryRun {
		logf("[%s] (dry-run)本应切 %s → %s", d.ID, current, dec.Choice)
		return nil
	}
	if err := k.Select(d.Selector, dec.Choice); err != nil {
		return fmt.Errorf("切 selector:%w", err)
	}
	logf("[%s] ✅ %s → %s", d.ID, current, dec.Choice)
	return nil
}

// inWindow 过滤出这条声明在窗口内的样本。
//
// window 与 stale_after 是两件事:前者决定"用多久的数据算分位数",后者决定
// "多久没新数据就认为这条候选的情况已经不知道了"。一条候选如果最近一次
// 样本已经超过 stale_after,它在本轮里等同没有数据。
func inWindow(ms []measure.Measurement, decl string, now time.Time, window, stale time.Duration) []measure.Measurement {
	cut := now.Add(-window)
	staleCut := now.Add(-stale)

	newest := map[string]time.Time{}
	parsed := make([]time.Time, len(ms))
	for i := range ms {
		t, err := time.Parse(time.RFC3339, ms[i].TS)
		if err != nil {
			continue
		}
		parsed[i] = t
		if ms[i].Declaration == decl && t.After(newest[ms[i].CandidateID]) {
			newest[ms[i].CandidateID] = t
		}
	}

	var out []measure.Measurement
	for i := range ms {
		if ms[i].Declaration != decl || parsed[i].IsZero() || parsed[i].Before(cut) {
			continue
		}
		if newest[ms[i].CandidateID].Before(staleCut) {
			continue
		}
		out = append(out, ms[i])
	}
	return out
}
