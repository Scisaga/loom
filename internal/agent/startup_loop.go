package agent

import (
	"context"
	"sync"
	"time"

	"loom/internal/measure"
)

func runDeclaration(ctx context.Context, cfg *Config, d *Decl, period time.Duration, k *clash, st *store, selections *stateStore,
	obs *observed, observationMaxAge time.Duration, rot map[string]string, rotMu *sync.Mutex, opts Options, logf func(string, ...any)) {
	first := true
	var comparison *startupComparison
	var regularAt time.Time
	for {
		if ctx.Err() != nil {
			return
		}
		var probed []Cand
		opts.probed = &probed
		fullRound := opts.probeSubset == nil
		roundCtx := ctx
		cancel := func() {}
		if !fullRound && comparison != nil {
			roundCtx, cancel = context.WithDeadline(ctx, comparison.deadline)
		}
		err := tick(roundCtx, cfg, d, k, st, selections, obs, observationMaxAge, rot, rotMu, &opts, logf)
		cancel()
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			logf("[%s] 本轮失败:%v", d.ID, err)
		}
		if opts.Once {
			return
		}
		now := time.Now()
		if fullRound {
			regularAt = now.Add(period)
		}
		if first {
			first = false
			if err == nil && opts.StartupProbeInterval > 0 {
				current, summaries, readErr := startupEvidence(ctx, cfg, d, k, st, &opts)
				if readErr == nil {
					comparison = newStartupComparison(d, current, probed, summaries, now, opts.StartupProbeInterval)
				}
			}
		} else if !fullRound && comparison != nil {
			comparison.sampled(now)
			if err != nil {
				comparison = nil
			}
		}
		opts.probeSubset = nil
		opts.probeSampleLimit = nil
		for {
			now = time.Now()
			wakeAt := regularAt
			var changes <-chan struct{}
			if comparison.active(now) {
				if comparison.next.Before(wakeAt) {
					wakeAt = comparison.next
				}
				if comparison.deadline.Before(wakeAt) {
					wakeAt = comparison.deadline
				}
				// Only the bounded initial window reacts to observations.
				// A refresh never starts another maintenance probe round.
				changes = opts.Observations.Changes()
			}
			timer := time.NewTimer(time.Until(wakeAt))
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-changes:
				timer.Stop()
			case <-timer.C:
			}
			now = time.Now()
			if !now.Before(regularAt) {
				comparison = nil
				break
			}
			if !comparison.active(now) {
				comparison = nil
				continue
			}
			current, summaries, readErr := startupEvidence(ctx, cfg, d, k, st, &opts)
			if readErr != nil || startupExitUnavailable(cfg, d, comparison, obs, opts.Now(), observationMaxAge) {
				comparison = nil
				continue
			}
			candidates := comparison.candidates(d, current, summaries, now)
			if len(candidates) == 0 {
				comparison = nil
				continue
			}
			if !now.Before(comparison.next) {
				opts.probeSubset = candidates
				opts.probeSampleLimit = make(map[string]int, len(candidates))
				byTag := startupSummaries(summaries)
				for _, candidate := range candidates {
					opts.probeSampleLimit[candidate.Tag] = d.MinSamples - byTag[candidate.Tag].Samples
				}
				break
			}
		}
	}
}

func startupEvidence(ctx context.Context, cfg *Config, d *Decl, k *clash, st *store, opts *Options) (string, []measure.Summary, error) {
	current, err := k.Now(ctx, d.Selector)
	if err != nil {
		return "", nil, err
	}
	all, err := st.load()
	if err != nil {
		return "", nil, err
	}
	window, _ := d.Win()
	stale, _ := d.Stale()
	samples := inWindow(all, cfg.Node, d.ID, decisionScope(cfg.Node, d), opts.Now(), window, stale)
	return current, measure.Summarize(samples), nil
}

func startupExitUnavailable(cfg *Config, d *Decl, comparison *startupComparison, obs *observed, now time.Time, stale time.Duration) bool {
	for _, candidate := range d.Candidates {
		if candidate.Tag != comparison.current && candidate.Tag != comparison.challenger {
			continue
		}
		allFailed := len(d.Targets) > 0
		for _, target := range d.Targets {
			_, failed := obs.unreachable(target, now, stale)[candidateExit(candidate, cfg.Node)]
			allFailed = allFailed && failed
		}
		if allFailed {
			return true
		}
	}
	return false
}
