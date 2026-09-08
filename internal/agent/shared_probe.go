package agent

import (
	"context"
	"encoding/json"
	"sync"
	"time"
)

// sharedProbes is only an in-flight/short-lived coalescer. Measurements still
// live in the existing scoped journal; this is not another ranking history.
// 相同完整链路和目标按 key 合并；不同目标不持有网络请求锁，避免一个境外
// 超时拖住国内服务的独立验证。每条声明内部仍按既有顺序串行探测。
type sharedProbes struct {
	mu        sync.Mutex
	targets   map[string]string
	ambiguous map[string]bool
	last      map[string]*sharedProbe
	inflight  map[string]chan struct{}
}

type sharedProbe struct {
	result   Result
	err      error
	at       time.Time
	wallTime time.Time
	maxAge   time.Duration
	used     map[string]bool
}

func newSharedProbes(cfg *Config) *sharedProbes {
	p := &sharedProbes{targets: map[string]string{}, ambiguous: map[string]bool{}, last: map[string]*sharedProbe{}, inflight: map[string]chan struct{}{}}
	for _, d := range cfg.Declarations {
		chains := map[string]int{}
		for _, c := range d.Candidates {
			chains[probeChainKey(c)]++
		}
		for chain, count := range chains {
			if count > 1 {
				// A legacy/ambiguous plan cannot prove that its two members
				// describe the same transport merely from an empty chain.
				p.ambiguous[chain] = true
			}
		}
		for _, target := range d.Targets {
			canonical := target
			for known, value := range p.targets {
				if EquivalentTargetURL(known, target) {
					canonical = value
					break
				}
			}
			p.targets[target] = canonical
		}
	}
	return p
}

func probeChainKey(c Cand) string {
	chain := append([]string{}, c.Chain...)
	encoded, _ := json.Marshal(chain)
	return string(encoded)
}

func (p *sharedProbes) probe(ctx context.Context, cfg *Config, d *Decl, c Cand, target, scope string, opts *Options) (Result, error, time.Time) {
	// Never keep a sample for longer than either consumer's freshness/cadence.
	// One minute is only a coalescing limit, not an extension of evidence age.
	maxAge := time.Minute
	for _, duration := range []string{d.TuningPeriod, d.StaleAfter, d.Window} {
		if parsed, err := time.ParseDuration(duration); err == nil && parsed < maxAge {
			maxAge = parsed
		}
	}
	chain := probeChainKey(c)
	keyParts := []string{chain, p.targets[target]}
	if p.ambiguous[chain] {
		keyParts = append(keyParts, scope, c.Tag)
	}
	encoded, _ := json.Marshal(keyParts)
	key := string(encoded)
	for {
		p.mu.Lock()
		if err := ctx.Err(); err != nil {
			p.mu.Unlock()
			return Result{}, err, opts.Now()
		}
		for key, sample := range p.last {
			if time.Since(sample.wallTime) > time.Minute {
				delete(p.last, key)
			}
		}
		if previous := p.last[key]; previous != nil && !previous.used[scope] && time.Since(previous.wallTime) <= min(maxAge, previous.maxAge) {
			previous.used[scope] = true
			p.mu.Unlock()
			return previous.result, previous.err, previous.at
		}
		if pending := p.inflight[key]; pending != nil {
			p.mu.Unlock()
			select {
			case <-ctx.Done():
				return Result{}, ctx.Err(), opts.Now()
			case <-pending:
				continue
			}
		}
		pending := make(chan struct{})
		p.inflight[key] = pending
		p.mu.Unlock()
		at, wallTime := opts.Now(), time.Now()
		result, err := ProbeOnce(ctx, cfg.Probe, cfg.ProbeSecret, c.ProbeUser, target, opts.ProbeTimeout)
		p.mu.Lock()
		if ctx.Err() == nil {
			p.last[key] = &sharedProbe{result: result, err: err, at: at, wallTime: wallTime, maxAge: maxAge, used: map[string]bool{scope: true}}
		}
		delete(p.inflight, key)
		close(pending)
		p.mu.Unlock()
		return result, err, at
	}
}
