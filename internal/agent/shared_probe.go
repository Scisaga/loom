package agent

import (
	"context"
	"encoding/json"
	"sync"
	"time"
)

// sharedProbes is only an in-flight/short-lived coalescer. Measurements still
// live in the existing scoped journal; this is not another ranking history.
// The mutex also prevents different declarations from competing for the same
// client uplink while measuring it.
type sharedProbes struct {
	mu        sync.Mutex
	targets   map[string]string
	ambiguous map[string]bool
	last      map[string]*sharedProbe
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
	p := &sharedProbes{targets: map[string]string{}, ambiguous: map[string]bool{}, last: map[string]*sharedProbe{}}
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
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return Result{}, err, opts.Now()
	}
	// Never keep a sample for longer than either consumer's freshness/cadence.
	// One minute is only a coalescing limit, not an extension of evidence age.
	maxAge := time.Minute
	for _, duration := range []string{d.TuningPeriod, d.StaleAfter, d.Window} {
		if parsed, err := time.ParseDuration(duration); err == nil && parsed < maxAge {
			maxAge = parsed
		}
	}
	for key, sample := range p.last {
		if time.Since(sample.wallTime) > time.Minute {
			delete(p.last, key)
		}
	}
	chain := probeChainKey(c)
	keyParts := []string{chain, p.targets[target]}
	if p.ambiguous[chain] {
		keyParts = append(keyParts, scope, c.Tag)
	}
	encoded, _ := json.Marshal(keyParts)
	key := string(encoded)
	if previous := p.last[key]; previous != nil && !previous.used[scope] && time.Since(previous.wallTime) <= min(maxAge, previous.maxAge) {
		previous.used[scope] = true
		return previous.result, previous.err, previous.at
	}
	at, wallTime := opts.Now(), time.Now()
	result, err := ProbeOnce(ctx, cfg.Probe, cfg.ProbeSecret, c.ProbeUser, target, opts.ProbeTimeout)
	if ctx.Err() == nil {
		p.last[key] = &sharedProbe{result: result, err: err, at: at, wallTime: wallTime, maxAge: maxAge, used: map[string]bool{scope: true}}
	}
	return result, err, at
}
