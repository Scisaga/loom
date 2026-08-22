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
	logf := func(f string, a ...any) {
		fmt.Fprintf(opts.Log, "%s "+f+"\n",
			append([]any{opts.Now().Format("15:04:05")}, a...)...)
	}

	var wg sync.WaitGroup
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
				if err := tick(cfg, d, k, st, &opts, logf); err != nil {
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
func tick(cfg *Config, d *Decl, k *clash, st *store, opts *Options, logf func(string, ...any)) error {
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
	ts := opts.Now().Format(time.RFC3339)
	var got []measure.Measurement
	ok := 0
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
	logf("[%s] 探测 %d 条(%d 通)· %s", d.ID, len(got), ok, dec.Reason)
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
