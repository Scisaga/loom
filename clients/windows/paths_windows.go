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
	Service            string `json:"service"`
	Candidate          string `json:"candidate,omitempty"`
	Chain              string `json:"chain"`
	Health             string `json:"health"`
	MeasurementSummary string `json:"measurement_summary,omitempty"`
	Comparison         string `json:"comparison,omitempty"`
	SelectedQuality    string `json:"selected_quality"`
	BestQuality        string `json:"best_quality"`
	Reason             string `json:"reason"`
	DecisionScope      string `json:"decision_scope,omitempty"`
	UpdatedAt          string `json:"updated_at,omitempty"`
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
				row.Health = "探测可达"
				if health.SelectedSamples == 1 {
					row.Health = "单次可达"
				} else if health.SelectedSamples == 0 {
					row.Health = "样本未知"
				}
			case "degraded":
				row.Health = "部分失败"
			case "failed":
				row.Health = "探测失败"
			case "stale":
				row.Health = "测量过期"
			}
			row.SelectedQuality = windowsSelectedPathQuality(health)
			row.BestQuality = windowsMeasuredPathQuality(health)
			row.MeasurementSummary, row.Comparison = windowsPathEvidence(health)
		}
		if row.Reason == "" {
			row.Reason = "未知"
		}
		// §16.1：客户端原因已有明确分段说明；仅格式化显示，不由文案决定路由。
		if strings.HasPrefix(reason, "入口 ") && strings.Contains(reason, "未测整条业务路径") {
			entry, rest, _ := strings.Cut(reason, "；")
			row.SelectedQuality = entry
			row.MeasurementSummary, _, _ = strings.Cut(entry, "（")
			row.Health = "业务未测"
			row.BestQuality = "不做完整路径比较"
			row.Comparison = rest
		}
		rows = append(rows, row)
	}
	return rows
}

// §16.1：次数、失败和覆盖来自已有测量摘要，不能把读取时间冒充最近探测时间。
func windowsPathEvidence(health *clientreport.AgentCandidateHealth) (string, string) {
	summary := "近期无有效测量"
	if health.SelectedSamples > 0 {
		summary = fmt.Sprintf("近期探测 %d 次 · 失败 %d", health.SelectedSamples, health.SelectedFailures)
	}
	if health.Candidates <= 0 {
		return summary, "候选比较范围未知"
	}
	measured := health.RecentSuccess + health.RecentDegraded + health.RecentFailed
	summary += fmt.Sprintf(" · 已测 %d/%d", measured, health.Candidates)
	comparison := fmt.Sprintf("候选 %d 个有近期样本，%d 个未测，%d 个已过期", measured, health.Unknown, health.Stale)
	if measured < health.Candidates {
		comparison += "；比较尚未覆盖全部候选"
	} else {
		comparison += "；可达状态不代表已选到最优路径"
	}
	return summary, comparison
}

func windowsSelectedPathQuality(health *clientreport.AgentCandidateHealth) string {
	if health.SelectedSamples-health.SelectedFailures == 1 && health.SelectedP50MS != nil {
		quality := fmt.Sprintf("单个成功样本 %d ms", *health.SelectedP50MS)
		if health.SelectedKBps != nil {
			quality += fmt.Sprintf(" · %d KB/s", *health.SelectedKBps)
		}
		return quality
	}
	return windowsPathQuality(health.SelectedP50MS, health.SelectedP95MS, health.SelectedKBps)
}

// §16.1：最低延迟和最高吞吐可能来自不同候选，不将两个独立极值称为“最佳路径”。
func windowsMeasuredPathQuality(health *clientreport.AgentCandidateHealth) string {
	var metrics []string
	if health.BestP50MS != nil {
		metrics = append(metrics, fmt.Sprintf("最低中位延迟 %d ms", *health.BestP50MS))
	}
	if health.BestKBps != nil {
		metrics = append(metrics, fmt.Sprintf("最高吞吐 %d KB/s", *health.BestKBps))
	}
	if len(metrics) == 0 {
		return "未知"
	}
	return strings.Join(metrics, " · ")
}

func windowsPathQuality(p50, p95, kbps *int) string {
	var metrics []string
	if p50 != nil {
		metrics = append(metrics, fmt.Sprintf("P50（中位）%d ms", *p50))
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
			line += "\r\n" + row.MeasurementSummary + "\r\n当前测量：" + row.SelectedQuality + "；已测候选：" + row.BestQuality
			if row.Comparison != "" {
				line += "\r\n" + row.Comparison
			}
			line += "\r\n原因：" + row.Reason
			if row.UpdatedAt != "" {
				line += "\r\n读取时间：" + row.UpdatedAt
			}
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\r\n\r\n")
}
