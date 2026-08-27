package report

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// table 是本节点持有的全网观测:观测者 → 它最新的那份观测。
//
// 为什么要转述别人的:接入节点不一定和每台服务器都有隧道(access-a 就只和
// edge-a、edge-b 有),而上报接口只绑隧道内地址。cn-a 够不到 access-a,但它够得到
// edge-a —— 让 edge-a 转述,access-a 问 edge-a 就拿到了 cn-a 的观测。
// 转述不要求为了可观测性额外增加常驻隧道，也不依赖完整图每条边都在线。
type table struct {
	mu sync.Mutex
	by map[string]*Observation
	h  *history

	// errors 是最近一轮拒收的观测。签名/时间异常不能只写 journal：它们
	// 必须进入 /status，影响 OK，并被事件检测器看见。
	errors                []string
	caOnce                sync.Once
	ca                    []byte
	caErr                 error
	verify                func(*Observation, time.Time, time.Duration) error
	minAttestationVersion int
}

func newTable(minVersion ...int) *table {
	t := &table{by: map[string]*Observation{}, h: newHistory()}
	if len(minVersion) > 0 {
		t.minAttestationVersion = minVersion[0]
	}
	return t
}

// put 收下一份观测。先校验时间边界与签名，再允许它参与 Node 最新值竞争。
// 否则一个未来时间的伪观测能占住索引，让随后所有合法观测永远进不来。
func (t *table) put(o *Observation, now time.Time, maxAge time.Duration) error {
	if o == nil {
		return fmt.Errorf("空观测")
	}
	if o.Node == "" {
		return fmt.Errorf("观测缺少 node")
	}
	ts, err := time.Parse(time.RFC3339, o.TS)
	if err != nil {
		return fmt.Errorf("观测 %s 时间无效:%q", o.Node, o.TS)
	}
	age := now.UTC().Sub(ts.UTC())
	if age < -2*time.Minute {
		return fmt.Errorf("观测 %s 时间来自未来:%s", o.Node, o.TS)
	}
	if age > maxAge {
		// 邻居会转述自己表里尚未淘汰、但对本节点阈值已过期的旧格式数据。
		// 正常老化应静默丢弃；只有格式、未来时间和签名错误才是健康问题。
		return nil
	}
	if observationNeedsVerification(o, t.minAttestationVersion) {
		if t.verify != nil {
			if err := t.verify(o, now, maxAge); err != nil {
				return fmt.Errorf("校验观测 %s:%w", o.Node, err)
			}
		} else {
			t.caOnce.Do(func() { t.ca, t.caErr = os.ReadFile(caPath) })
			if t.caErr != nil {
				return fmt.Errorf("校验观测 %s:读签名 CA:%w", o.Node, t.caErr)
			}
			if _, err := VerifyObservationAtLeast(o, t.ca, now, maxAge,
				t.minAttestationVersion); err != nil {
				return fmt.Errorf("校验观测 %s:%w", o.Node, err)
			}
		}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if old, ok := t.by[o.Node]; ok {
		// 已验签观测的身份强度高于 legacy unsigned。较新的 unsigned relay
		// 不能靠刷新 TS 持续把可信状态降级掉；反过来 signed 可替换 unsigned。
		if observationNeedsVerification(old, 0) && !observationNeedsVerification(o, 0) {
			if old.Age(now) <= maxAge {
				return nil
			}
			// 已签名旧值过期后本来就不会再展示；此时允许 fresh legacy
			// 观测恢复 unknown 可见性，不让索引被一条历史 signed 永久占住。
		}
		if !observationNeedsVerification(old, 0) && observationNeedsVerification(o, 0) {
			cp := *o
			t.by[o.Node] = &cp
			return nil
		}
		oldTS, oldErr := time.Parse(time.RFC3339, old.TS)
		if oldErr == nil && !ts.After(oldTS) {
			return nil
		}
	}
	cp := *o
	t.by[o.Node] = &cp
	return nil
}

func (t *table) setRoundErrors(errs []string) {
	t.mu.Lock()
	if len(errs) > 64 {
		errs = errs[:64]
	}
	t.errors = append([]string(nil), errs...)
	t.mu.Unlock()
}

func (t *table) roundErrors() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]string(nil), t.errors...)
}

// putRelayed 收邻居返回的内容。本机 Node 的唯一写者必须是这一轮 observe；
// 否则邻居转述一条较新 unsigned self 观测，就能覆盖本机刚量出的事实。
func (t *table) putRelayed(o *Observation, self string, now time.Time, maxAge time.Duration) error {
	if o == nil || o.Node == self {
		return nil
	}
	return t.put(o, now, maxAge)
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
	var roundErrors []string
	reject := func(err error) {
		if err != nil && len(roundErrors) < 64 {
			roundErrors = append(roundErrors, err.Error())
		}
	}
	roundNow := now()
	own := observe(cfg, t.h, roundNow)
	reject(t.put(own, roundNow, maxAge))

	for _, n := range cfg.Neighbors {
		st, err := Fetch(n.Addr, 5*time.Second)
		if err != nil {
			continue // 邻居不可达本身会由隧道健康报出来,这里不重复喊
		}
		receivedAt := now()
		reject(t.putRelayed(st.Observation, cfg.Node, receivedAt, maxAge))
		for i := range st.Learned {
			reject(t.putRelayed(&st.Learned[i], cfg.Node, receivedAt, maxAge))
		}
	}
	// 整轮完成后再原子替换。抓邻居的几秒里继续保留上一轮错误，避免页面
	// 在 beginRound 与再次遇到同一坏签名之间短暂假绿。
	t.setRoundErrors(roundErrors)
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
	t := newTable(cfg.AttestationMinVersion)
	gossip(cfg, t, now, maxAge)
	own, learned := t.view(cfg.Node, now(), maxAge)
	if errs := t.roundErrors(); len(errs) > 0 {
		return own, learned, fmt.Errorf("拒收观测:%s", strings.Join(errs, "; "))
	}
	return own, learned, nil
}
