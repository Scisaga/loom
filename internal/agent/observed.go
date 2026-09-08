//go:build !windows

package agent

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"loom/internal/report"
)

// observed 是 Agent 手里的全网观测:观测者 → 它最新那份。
//
// 数据来自上报者的转述网络(§16.1.2)。Agent 只读不产 —— 观测是每台机器
// 量自己那几段的产物,Agent 的活是**用**它。
type observed struct {
	mu sync.Mutex
	by map[string]report.Observation
}

func newObserved() *observed { return &observed{by: map[string]report.Observation{}} }

func (o *observed) put(x *report.Observation) {
	if x == nil || x.Node == "" {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if old, ok := o.by[x.Node]; ok && old.TS >= x.TS {
		return
	}
	o.by[x.Node] = *x
}

// unreachable 返回**已知**打不到这个目标的节点。
//
// 三个状态要分清:已知能到、已知不能到、不知道。只有第二种能用来剪枝 ——
// 把"不知道"当成"不能到",会让一条新加入的、还没被观测过的服务器永远
// 不被尝试。
func (o *observed) unreachable(target string, now time.Time, maxAge time.Duration) map[string]string {
	o.mu.Lock()
	defer o.mu.Unlock()
	out := map[string]string{}
	for id, x := range o.by {
		if x.Age(now) > maxAge {
			continue
		}
		for i := range x.Targets {
			r := &x.Targets[i]
			if EquivalentTargetURL(r.Target, target) && !r.OK() {
				out[id] = r.Error
			}
		}
	}
	return out
}

func (o *observed) len() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.by)
}

// pollPeers 拉一遍能够到的节点的自检结果。
//
// 它**不做任何处置** —— 隧道断了要人去看,不是 Agent 能自动修的。价值在于
// 从"完全没有信号"变成"有带时间戳的记录":DDNS 重解析以前是全程静默的,
// IP 变了、隧道断了、脚本修好了,事后连查都没得查。
func pollPeers(ctx context.Context, cfg *Config, obs *observed, ca []byte, now time.Time,
	maxAge time.Duration, logf func(string, ...any)) {
	peers := append([]Peer(nil), cfg.Peers...)
	sort.Slice(peers, func(i, j int) bool { return peers[i].Node < peers[j].Node })
	// 本机上报者排在最前:它手里已经有转述过来的全网观测,先拿到它,
	// 后面每条声明剪枝就有依据了。
	if cfg.SelfReport != "" {
		peers = append([]Peer{{Node: cfg.Node, Addr: cfg.SelfReport}}, peers...)
	}
	for _, p := range peers {
		if ctx.Err() != nil {
			return
		}
		st, err := report.FetchContext(ctx, p.Addr, 5*time.Second)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			logf("[对端 %s] ❌ 拉不到 %s:%v", p.Node, p.Addr, err)
			continue
		}
		// The loopback report's own observation is local node-owned input, so phase A
		// may accept it unsigned. Phase B closes that exception; every measurement
		// must then carry the configured v5 claim binding Edges/Targets.
		local := p.Node == cfg.Node && p.Addr == cfg.SelfReport
		if err := ingestObservation(obs, st.Observation, cfg.Node, local, ca, now, maxAge,
			cfg.AttestationMinVersion); err != nil {
			logf("[对端 %s] ⚠️ 拒绝观测:%v", p.Node, err)
		}
		for i := range st.Learned {
			if err := ingestObservation(obs, &st.Learned[i], cfg.Node, false, ca, now, maxAge,
				cfg.AttestationMinVersion); err != nil {
				logf("[对端 %s] ⚠️ 拒绝转述观测:%v", p.Node, err)
			}
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

// ingestObservation is the decision boundary between display data and control
// input. Phase A allows an unsigned loopback self-observation because it never
// crossed a relay boundary; phase B deliberately closes that exception so the
// selector cannot keep consuming unsigned measurements after the v5 gate closes.
func ingestObservation(dst *observed, o *report.Observation, self string, local bool,
	ca []byte, now time.Time, maxAge time.Duration, minAttestationVersion int) error {
	if o == nil {
		if local && minAttestationVersion >= 5 {
			return fmt.Errorf("phase-B loopback 上报缺少本机观测")
		}
		return nil
	}
	if local {
		if o.Node != self {
			return fmt.Errorf("loopback 上报声称自己是 %q，不是 %q", o.Node, self)
		}
		if minAttestationVersion < 5 {
			dst.put(o)
			return nil
		}
	}
	trusted, err := report.VerifyObservationAtLeast(o, ca, now, maxAge, minAttestationVersion)
	if err != nil {
		return err
	}
	if !trusted.MeasurementsVerified {
		return fmt.Errorf("节点 %s 的 legacy 签名未覆盖 Edges/Targets", o.Node)
	}
	dst.put(o)
	return nil
}

func validateObservationPlatform(*Config) error { return nil }
