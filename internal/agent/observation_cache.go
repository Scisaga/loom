package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"sync"
	"time"

	"loom/internal/observation"
)

// ObservationCache 接收 §16.1.2 既有报告响应中的服务器观测，只影响探测剪枝，
// 不拥有 selector，也不能扩展已激活计划的候选集合。
type ObservationCache struct {
	mu      sync.Mutex
	allowed map[string]bool
	targets []string
	maxAge  time.Duration
	by      map[string]observation.Observation
	changed chan struct{}
}

func NewObservationCache(cfg *Config) (*ObservationCache, error) {
	if cfg == nil {
		return nil, errors.New("[§16.1.2] 缺少当前观测授权计划")
	}
	maxAge, err := cfg.ObsStale()
	if err != nil {
		return nil, err
	}
	c := &ObservationCache{allowed: map[string]bool{}, maxAge: maxAge, by: map[string]observation.Observation{}, changed: make(chan struct{})}
	seen := map[string]bool{}
	for _, d := range cfg.Declarations {
		for _, candidate := range d.Candidates {
			for _, node := range candidate.Chain {
				if node != cfg.Node {
					c.allowed[node] = true
				}
			}
		}
		for _, target := range d.Targets {
			if !seen[target] {
				c.targets = append(c.targets, target)
				seen[target] = true
			}
		}
	}
	return c, nil
}

// Changes 广播有效剪枝事实的变化。相同来源仅刷新原 ts 时不唤醒调参，避免把
// 每分钟上报变成另一套主动探测周期；nil 缓存不会产生通知。
func (c *ObservationCache) Changes() <-chan struct{} {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.changed
}

// Ingest 先验证完整原对象，再按原来源和原时间去重；接收时间不能延长证据寿命。
// §16.1.2：一份坏观测不污染其余合法来源，也不把上报成功变成设备故障。
func (c *ObservationCache) Ingest(ctx context.Context, raw []json.RawMessage, ca []byte, now time.Time) error {
	if c == nil {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	total := 0
	for _, body := range raw {
		total += len(body)
		if total > 1<<20 {
			return errors.New("[§16.1.2] 观测输入超过大小限制")
		}
	}
	var accepted []observation.Observation
	rejected := 0
	for _, body := range raw {
		if err := ctx.Err(); err != nil {
			return err
		}
		var o observation.Observation
		if err := json.Unmarshal(body, &o); err != nil || !c.allowed[o.Node] {
			rejected++
			continue
		}
		trusted, err := observation.VerifyObservationAtLeast(&o, ca, now, c.maxAge, 5)
		if err != nil || !trusted.MeasurementsVerified {
			rejected++
			continue
		}
		if err := observation.VerifyAttachments(&o, ca, now, c.maxAge); err != nil {
			rejected++
			continue
		}
		accepted = append(accepted, o)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	before := c.failuresLocked(now)
	for _, o := range accepted {
		at, _ := time.Parse(time.RFC3339, o.TS)
		if old, ok := c.by[o.Node]; ok {
			previous, _ := time.Parse(time.RFC3339, old.TS)
			if !at.After(previous) {
				continue
			}
		}
		c.by[o.Node] = o
	}
	if !maps.Equal(before, c.failuresLocked(now)) {
		close(c.changed)
		c.changed = make(chan struct{})
	}
	if rejected != 0 {
		return fmt.Errorf("[§16.1.2] 已拒绝 %d 份范围、签名或新鲜度无效的服务器观测", rejected)
	}
	return nil
}

func (c *ObservationCache) failuresLocked(now time.Time) map[string]bool {
	out := map[string]bool{}
	for _, target := range c.targets {
		for node := range c.unreachableLocked(target, now, c.maxAge) {
			out[node+"\x00"+target] = true
		}
	}
	return out
}

func (c *ObservationCache) unreachable(target string, now time.Time, maxAge time.Duration) map[string]string {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.unreachableLocked(target, now, maxAge)
}

func (c *ObservationCache) unreachableLocked(target string, now time.Time, maxAge time.Duration) map[string]string {
	out := map[string]string{}
	maxAge = min(maxAge, c.maxAge)
	for node, o := range c.by {
		at, err := time.Parse(time.RFC3339, o.TS)
		if err != nil || now.Sub(at) > maxAge || at.After(now.Add(2*time.Minute)) {
			continue
		}
		for _, reach := range o.Targets {
			// §16.1.2：缺测或部分失败仍未知/可用，不能被缓存推成出口故障。
			if reach.Samples > 0 && reach.Failures == reach.Samples && reach.Error != "" && EquivalentTargetURL(reach.Target, target) {
				out[node] = reach.Error
			}
		}
	}
	return out
}
