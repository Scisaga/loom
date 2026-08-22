package report

import (
	"sort"
	"sync"
	"time"
)

// table 是本节点持有的全网观测:观测者 → 它最新的那份观测。
//
// 为什么要转述别人的:接入节点不一定和每台服务器都有隧道(access-a 就只和
// edge-a、edge-b 有),而上报接口只绑隧道内地址。cn-a 够不到 access-a,但它够得到
// edge-a —— 让 edge-a 转述,access-a 问 edge-a 就拿到了 cn-a 的观测。
//
// **加隧道也能解决,但这里加不了**:access-a 和 cn-a 两端都是 bidirectional,
// §6.3 说这种该交给 Headscale,而 Headscale 还没部署。转述不依赖拓扑变化。
type table struct {
	mu sync.Mutex
	by map[string]*Observation
}

func newTable() *table { return &table{by: map[string]*Observation{}} }

// put 收下一份观测。**同一个观测者只保留最新的一份** —— 转述会让同一份数据
// 从多条路径回来,不去重的话表会无限长大,而且新旧混在一起。
func (t *table) put(o *Observation) {
	if o == nil || o.Node == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if old, ok := t.by[o.Node]; ok && old.TS >= o.TS {
		return // RFC3339 定长,字典序即时间序
	}
	cp := *o
	t.by[o.Node] = &cp
}

// snapshot 返回除 self 之外、还没过期的观测,按观测者排序。
//
// 过期的直接丢掉而不是标记:一份两小时前的"cn-a 能到 Cloudflare"比没有更
// 危险 —— 它看起来是数据,实际是回忆。
func (t *table) snapshot(self string, now time.Time, maxAge time.Duration) []Observation {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []Observation
	for id, o := range t.by {
		if id == self || o.Age(now) > maxAge {
			continue
		}
		out = append(out, *o)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Node < out[j].Node })
	return out
}

// gossip 跑一轮:量自己的,再把邻居知道的收进来。
//
// 只向直接邻居拉,不做全网泛洪 —— 邻居返回的内容里已经包含了**它**听来的
// 那些,所以一跳一跳自然传开。代价是传播延迟随跳数增加,对这个规模无所谓。
func gossip(cfg *Config, t *table, now func() time.Time, maxAge time.Duration) {
	own := observe(cfg, now())
	t.put(own)

	for _, n := range cfg.Neighbors {
		st, err := Fetch(n.Addr, 5*time.Second)
		if err != nil {
			continue // 邻居不可达本身会由隧道健康报出来,这里不重复喊
		}
		t.put(st.Observation)
		for i := range st.Learned {
			t.put(&st.Learned[i])
		}
	}
}

// view 返回本节点自己的观测,以及听来的别人的观测。
func (t *table) view(self string, now time.Time, maxAge time.Duration) (*Observation, []Observation) {
	t.mu.Lock()
	own := t.by[self]
	if own != nil {
		cp := *own
		own = &cp
	}
	t.mu.Unlock()
	if own != nil && own.Age(now) > maxAge {
		own = nil
	}
	return own, t.snapshot(self, now, maxAge)
}

// Once 量一轮并与邻居交换一次,返回结果。给 `loom report` 的一次性模式用。
func Once(cfg *Config, now func() time.Time) (*Observation, []Observation, error) {
	maxAge, err := cfg.ObsStale()
	if err != nil {
		return nil, nil, err
	}
	t := newTable()
	gossip(cfg, t, now, maxAge)
	own, learned := t.view(cfg.Node, now(), maxAge)
	return own, learned, nil
}
