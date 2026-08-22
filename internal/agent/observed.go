package agent

import (
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
			if r.Target == target && !r.OK() {
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

// exitOf 取候选链的最后一跳 —— 那台机器就是这次的出口(D12:出口是位置,
// 不是类型)。链为空表示直连,出口就是本机。
func exitOf(tag, self string) string {
	// tag 形如 cand:<声明>:<a>>>b>...[@地址]
	rest := tag
	for i := 0; i < 2; i++ {
		j := indexByte(rest, ':')
		if j < 0 {
			return ""
		}
		rest = rest[j+1:]
	}
	if k := indexByte(rest, '@'); k >= 0 {
		rest = rest[:k]
	}
	last := rest
	for {
		j := indexByte(last, '>')
		if j < 0 {
			break
		}
		last = last[j+1:]
	}
	if last == "direct" {
		return self
	}
	return last
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}
