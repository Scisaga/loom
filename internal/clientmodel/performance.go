package clientmodel

import (
	"errors"
	"time"
)

// PerformanceRule is local execution policy. Its interval is independent of
// measurement scheduling and sample validity; it grants no network permission.
type PerformanceRule struct {
	MinimumInterval        time.Duration
	MinimumImprovement     time.Duration
	ImprovementBasisPoints int64
	Confirmations          int
}

func (rule PerformanceRule) Validate() error {
	if rule.MinimumInterval < 0 || rule.MinimumImprovement < 0 || rule.ImprovementBasisPoints < 0 || rule.ImprovementBasisPoints > 10000 || rule.Confirmations < 2 || rule.Confirmations > 16 {
		return errors.New("performance switching rule is invalid")
	}
	return nil
}

// These are execution defaults for validation on real devices, not grants.
var DefaultPerformanceRule = PerformanceRule{
	MinimumInterval: 30 * time.Second, MinimumImprovement: 5 * time.Millisecond,
	ImprovementBasisPoints: 1000, Confirmations: 2,
}
