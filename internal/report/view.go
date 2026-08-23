package report

import (
	"sort"
	"time"

	"loom/internal/webui"
)

// buildView 把转述表变成界面要的全网视图。
//
// **界面不自己采集任何东西。** 它显示的就是上报者手里那份数据 —— 于是
// "界面上看到的"和"/status 返回的"永远是同一件事,不会出现两套说法。
func buildView(cfg *Config, self *Status, now time.Time) webui.View {
	v := webui.View{Self: cfg.Node, Applied: self.Applied}

	// 本机那份来自现算的 Status(隧道、漂移都是当场看的);别人的来自转述。
	v.Nodes = append(v.Nodes, nodeView(cfg.Node, true, true, self, self.Observation, now))

	for i := range self.Learned {
		o := &self.Learned[i]
		v.Nodes = append(v.Nodes, nodeView(o.Node, false, false, nil, o, now))
	}
	sort.Slice(v.Nodes, func(i, j int) bool { return v.Nodes[i].ID < v.Nodes[j].ID })

	// 只听到自己,说明转述链断了 —— 而这件事在一张只有一行的表上看不出来。
	if len(v.Nodes) == 1 && len(cfg.Neighbors) > 0 {
		v.Warnings = append(v.Warnings,
			"只听到本机的观测。转述链可能断了,或者邻居的上报者没跑")
	}
	return v
}

func nodeView(id string, self, reached bool, st *Status, o *Observation, now time.Time) webui.NodeView {
	n := webui.NodeView{ID: id, Self: self, Reached: reached}
	if o != nil {
		n.AgeSec = int(o.Age(now).Seconds())
		n.Applied = o.Applied
		for _, e := range o.Edges {
			n.Edges = append(n.Edges, webui.EdgeView{To: e.To, MS: e.RTTMs, Err: e.Error})
		}
		for _, r := range o.Targets {
			n.Targets = append(n.Targets, webui.TargetView{Target: r.Target, MS: r.FirstByteMs, Err: r.Error})
		}
	}
	if st == nil {
		// 转述来的观测里没有隧道健康和漂移 —— 那些是每台机器自己的事,
		// 只有直接问它才拿得到。**不要在界面上假装知道。**
		return n
	}
	if st.Applied != "" {
		n.Applied = st.Applied
	}
	for i := range st.Tunnels {
		t := &st.Tunnels[i]
		tv := webui.TunnelView{
			Interface: t.Interface, State: t.UnitState,
			AgeSec: int(t.HandshakeAgeSec), OK: !t.Down && !t.Stale && t.HandshakeAgeSec >= 0,
		}
		switch {
		case t.Down:
			tv.State = "down"
		case t.HandshakeAgeSec < 0:
			tv.State = "未握手"
		}
		if tv.State != "" && tv.State != "active" && tv.State != "down" && tv.State != "未握手" {
			tv.OK = false // 单元不是 active:现在能用,重启就不回来了
		}
		n.Tunnels = append(n.Tunnels, tv)
	}
	if d := st.Drift; d != nil {
		for _, f := range d.Modified {
			n.Problems = append(n.Problems, "配置被改过:"+f)
		}
		for _, f := range d.Missing {
			n.Problems = append(n.Problems, "配置缺失:"+f)
		}
		for _, f := range d.Unreadable {
			n.Problems = append(n.Problems, "配置读不到:"+f)
		}
	}
	n.Problems = append(n.Problems, st.Errors...)
	return n
}
