package report

import (
	"encoding/json"
	"errors"
	"os"
	"syscall"
	"time"

	"loom/internal/version"
)

// PublisherHealthPath 与发布器线格式的约定。类型在 report 侧保持中性副本，
// 避免 report → publish → render → report 的包依赖环。
const PublisherHealthPath = "/var/lib/loom/publisher.json"

const PublisherHeartbeatStale = 2 * time.Minute

type PublisherState struct {
	Version version.Coordinate `json:"version"`
	PID     int                `json:"pid"`

	StartedAt string `json:"started_at"`
	UpdatedAt string `json:"updated_at"`
	// IntervalSeconds 与 publish.Health 同一线格式；读者据此按发布器自己的
	// 循环周期判断心跳，而不是另造一个固定阈值。
	IntervalSeconds int64 `json:"interval_seconds,omitempty"`

	LastSuccess        string                       `json:"last_success,omitempty"`
	LastSnapshot       string                       `json:"last_snapshot,omitempty"`
	LastSSOT           string                       `json:"last_ssot,omitempty"`
	LastError          string                       `json:"last_error,omitempty"`
	LastErrorAt        string                       `json:"last_error_at,omitempty"`
	DistributionChecks []PublisherDistributionCheck `json:"distribution_checks,omitempty"`
}

type PublisherDistributionCheck struct {
	URL       string `json:"url"`
	Snapshot  string `json:"snapshot"`
	SSOT      string `json:"ssot"`
	CheckedAt string `json:"checked_at"`
	Success   bool   `json:"success"`
	Error     string `json:"error,omitempty"`
}

func (p *PublisherState) Unhealthy(now time.Time) bool {
	if p == nil {
		return false
	}
	staleAfter := PublisherHeartbeatStale
	if p.IntervalSeconds > 0 {
		if d := 3 * time.Duration(p.IntervalSeconds) * time.Second; d > staleAfter {
			staleAfter = d
		}
	}
	updated, err := time.Parse(time.RFC3339, p.UpdatedAt)
	if err != nil {
		return true
	}
	age := now.UTC().Sub(updated.UTC())
	if age > staleAfter || age < -time.Minute {
		return true
	}
	if p.PID <= 0 || syscall.Kill(p.PID, 0) == syscall.ESRCH {
		return true
	}
	if p.LastSuccess == "" {
		return true
	}
	if p.LastError != "" {
		failedAt, ferr := time.Parse(time.RFC3339, p.LastErrorAt)
		succeededAt, serr := time.Parse(time.RFC3339, p.LastSuccess)
		if ferr != nil || serr != nil || failedAt.After(succeededAt) {
			return true
		}
	}
	return false
}

func readPublisherState(path string) (*PublisherState, error) {
	if path == "" {
		return nil, nil
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var st PublisherState
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, err
	}
	return &st, nil
}
