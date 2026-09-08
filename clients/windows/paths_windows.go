//go:build windows

package main

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"loom/internal/clientcore"
	"loom/internal/clientreport"
)

// §7.3.3：只读显示是实际选路的投影，字符串值避免 GUI 和受限 IPC 共享可变测量对象。
type windowsPathDisplay struct {
	Service         string `json:"service"`
	Candidate       string `json:"candidate,omitempty"`
	Chain           string `json:"chain"`
	Health          string `json:"health"`
	SelectedQuality string `json:"selected_quality"`
	BestQuality     string `json:"best_quality"`
	Reason          string `json:"reason"`
	DecisionScope   string `json:"decision_scope,omitempty"`
	UpdatedAt       string `json:"updated_at,omitempty"`
}

const windowsPathReadInterval = 5 * time.Second

type windowsPathReader struct {
	mu     sync.Mutex
	root   string
	state  clientRuntimeState
	readAt time.Time
	rows   []windowsPathDisplay
	read   func(context.Context, clientRuntimeState, time.Time) (*clientreport.AgentState, error)
}

// §5.5、§7.3.3：后台观测只回填当前连接；停机或出口切换立即隐藏上一代路径。
func (app *portableGUI) watchCurrentPaths(ctx context.Context, sequence uint64) {
	reader := new(windowsPathReader)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		app.mu.RLock()
		ready := app.state == guiConnected && app.runCancel != nil && !app.routeBusy
		root := app.root
		app.mu.RUnlock()
		var rows []windowsPathDisplay
		if ready {
			rows = reader.Read(ctx, root, time.Now())
		} else {
			reader.clear()
		}
		app.mu.Lock()
		if ctx.Err() != nil || sequence != app.runSequence || app.runCancel == nil {
			app.mu.Unlock()
			return
		}
		if app.state != guiConnected || app.routeBusy || !reader.current(root) {
			rows = nil
		}
		changed := !slices.Equal(app.paths, rows)
		if changed {
			app.paths = slices.Clone(rows)
		}
		app.mu.Unlock()
		if changed {
			app.repaint()
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// §16.1：在后台调用；只 GET 当前 selector，不探测、不重跑决策，也不发送报告。
func (reader *windowsPathReader) Read(ctx context.Context, root string, now time.Time) []windowsPathDisplay {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	control, err := activeRouteControl(root)
	if err != nil || ctx.Err() != nil {
		reader.clear()
		return nil
	}
	state := control.snapshot()
	if !state.active() || state.Policy == nil {
		reader.clear()
		return nil
	}
	if root == reader.root && sameWindowsPathGeneration(reader.state, state) && !now.Before(reader.readAt) && now.Sub(reader.readAt) < windowsPathReadInterval {
		return slices.Clone(reader.rows)
	}
	reader.clear()
	read, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if state.Generation != nil {
		stop := context.AfterFunc(state.Generation, cancel)
		defer stop()
	}
	get := reader.read
	if get == nil {
		get = readWindowsPathReport
	}
	report, err := get(read, state, now)
	// §5.5：GET 完成也不能跨过 cancel/join 屏障；重连相同 applied 仍是另一代。
	if ctx.Err() != nil || !state.active() || !sameWindowsPathGeneration(state, control.snapshot()) {
		return nil
	}
	var rows []windowsPathDisplay
	if err != nil || report == nil || len(report.Selections) == 0 {
		for _, declaration := range state.Policy.ObservationDeclarations(state.Preference) {
			rows = append(rows, windowsPathDisplay{Service: declaration, Chain: "未知", Health: "未知", SelectedQuality: "未知", BestQuality: "未知", Reason: "暂无法读取当前实际选路"})
		}
	} else {
		rows = windowsPathsFromReport(report)
	}
	reader.root, reader.state, reader.readAt, reader.rows = root, state, now, rows
	return slices.Clone(rows)
}

func (reader *windowsPathReader) clear() {
	reader.root = ""
	reader.state = clientRuntimeState{}
	reader.readAt = time.Time{}
	reader.rows = nil
}

func (reader *windowsPathReader) current(root string) bool {
	reader.mu.Lock()
	defer reader.mu.Unlock()
	control, err := activeRouteControl(root)
	return err == nil && root == reader.root && reader.state.active() && sameWindowsPathGeneration(reader.state, control.snapshot())
}

func sameWindowsPathGeneration(a, b clientRuntimeState) bool {
	return b.active() && a.Generation == b.Generation && a.Agent == b.Agent && a.Policy == b.Policy && a.Preference == b.Preference && a.Applied == b.Applied && a.Exited == b.Exited
}

func readWindowsPathReport(ctx context.Context, state clientRuntimeState, now time.Time) (*clientreport.AgentState, error) {
	if state.Preference.Mode == clientcore.Direct {
		return state.Policy.ReadDirectPaths(ctx, now)
	}
	return state.Agent.Report(ctx, now)
}

func windowsPathsFromReport(report *clientreport.AgentState) []windowsPathDisplay {
	rows := make([]windowsPathDisplay, 0, len(report.Selections))
	for _, selection := range report.Selections {
		chain := "本机 → 目标（直连）"
		if len(selection.Chain) > 0 {
			chain = "本机 → " + strings.Join(selection.Chain, " → ") + " → 目标"
		}
		reason, scope := splitWindowsPathReason(selection.Reason)
		row := windowsPathDisplay{Service: selection.Declaration, Candidate: selection.Candidate, Chain: chain, Health: "未知", SelectedQuality: "未知", BestQuality: "未知", Reason: reason, DecisionScope: scope, UpdatedAt: selection.UpdatedAt}
		if health := selection.Health; health != nil {
			switch health.SelectedState {
			case "success":
				row.Health = "正常"
			case "degraded":
				row.Health = "不稳定"
			case "failed":
				row.Health = "故障"
			case "stale":
				row.Health = "测量已过期"
			}
			row.SelectedQuality = windowsPathQuality(health.SelectedP50MS, health.SelectedP95MS, health.SelectedKBps)
			row.BestQuality = windowsPathQuality(health.BestP50MS, nil, health.BestKBps)
		}
		if row.Reason == "" {
			row.Reason = "未知"
		}
		rows = append(rows, row)
	}
	return rows
}

func windowsPathQuality(p50, p95, kbps *int) string {
	var metrics []string
	if p50 != nil {
		metrics = append(metrics, fmt.Sprintf("P50 %d ms", *p50))
	}
	if p95 != nil {
		metrics = append(metrics, fmt.Sprintf("P95 %d ms", *p95))
	}
	if kbps != nil {
		metrics = append(metrics, fmt.Sprintf("%d KB/s", *kbps))
	}
	if len(metrics) == 0 {
		return "未知"
	}
	return strings.Join(metrics, " · ")
}

// §16.1：scope 已由 canonical v5 的 reason 保护；只拆开显示，不新定义上报格式。
func splitWindowsPathReason(reason string) (string, string) {
	prefix, scope, ok := strings.Cut(reason, " [decision_scope=")
	if !ok || len(scope) != 65 || scope[64] != ']' {
		return reason, ""
	}
	return prefix, scope[:64]
}

func formatWindowsPaths(rows []windowsPathDisplay, details bool) string {
	if len(rows) == 0 {
		return "未连接"
	}
	var lines []string
	for _, row := range rows {
		line := row.Service + "：" + row.Chain + "（" + row.Health + "）"
		if details {
			line += "\r\n当前质量：" + row.SelectedQuality + "；最佳质量：" + row.BestQuality + "\r\n原因：" + row.Reason
			if row.UpdatedAt != "" {
				line += "\r\n读取时间：" + row.UpdatedAt
			}
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\r\n\r\n")
}
