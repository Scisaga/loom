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

// candidateExit 取 renderer 显式携带的最后一跳。Tag 是 opaque ID，服务 key
// 与地址都允许 ':'/'@'，不能再从它反解析出口。
func candidateExit(c Cand, self string) string {
	if len(c.Chain) == 0 {
		return self
	}
	return c.Chain[len(c.Chain)-1]
}
