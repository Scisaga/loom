//go:build windows

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	"loom/internal/deviceclient"
)

// windowsPathDisplay remains the established Misaka presentation DTO. Every
// populated row now comes from selector readback plus real transport/business
// outcomes in the deletable runtime status projection.
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
	LinkLabels         string `json:"link_labels,omitempty"`
	LinkDetails        string `json:"link_details,omitempty"`
}

func windowsObservationDisplay(result string) (health, summary, selected string) {
	switch result {
	case "available":
		return "可用", "TCP/TLS 与 UDP/DNS 已验证", "真实业务成功"
	case "unavailable":
		return "不可用", "TCP/TLS 或 UDP/DNS 失败", "真实业务失败"
	default:
		return "未知", "尚无真实业务结果", "未知"
	}
}

func readWindowsRuntimeStatus(root string) (windowsRuntimeStatus, error) {
	var status windowsRuntimeStatus
	body, err := os.ReadFile(windowsRuntimeStatusPath(root))
	if err != nil {
		return status, err
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&status); err != nil {
		return status, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) || status.Schema != 1 {
		return windowsRuntimeStatus{}, errors.New("Windows runtime status is invalid")
	}
	return status, nil
}

func (app *portableGUI) watchCurrentPaths(ctx context.Context, sequence uint64) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		status, err := readWindowsRuntimeStatus(app.root)
		var rows []windowsPathDisplay
		if err == nil {
			byID := map[string]string{}
			observed := map[string]string{}
			updated := map[string]string{}
			for _, observation := range status.Observations {
				observed[observation.CandidateID] = observation.Result
				updated[observation.CandidateID] = observation.ObservedAt
			}
			store, loadErr := deviceclient.LoadProtected(windowsProfileStatePath(app.root), app.protector())
			if loadErr == nil && store.LKG() != nil {
				for _, route := range store.LKG().View.Routes {
					chain := "本机 → 目标（直连）"
					if len(route.Chain) > 0 {
						chain = "本机 → " + strings.Join(route.Chain, " → ") + " → 目标"
					}
					byID[route.ID] = chain
				}
			}
			for _, selection := range status.Selections {
				result := observed[selection.CandidateID]
				if result == "" {
					result = selection.State
				}
				health, summary, selected := windowsObservationDisplay(result)
				rows = append(rows, windowsPathDisplay{Service: selection.Scope, Candidate: selection.CandidateID,
					Chain: byID[selection.CandidateID], Health: health, MeasurementSummary: summary, SelectedQuality: selected,
					BestQuality: "当前 selector 候选", Reason: "selector 回读为当前候选", UpdatedAt: updated[selection.CandidateID]})
			}
		}
		app.mu.Lock()
		if ctx.Err() != nil || sequence != app.runSequence || app.runCancel == nil {
			app.mu.Unlock()
			return
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

func formatWindowsPaths(rows []windowsPathDisplay, details bool) string {
	if len(rows) == 0 {
		return "未连接"
	}
	var lines []string
	for _, row := range rows {
		line := row.Service + "：" + row.Chain + "（" + row.Health + "）"
		if details {
			line += "\r\n候选：" + row.Candidate + "\r\n依据：" + row.Reason
			if row.UpdatedAt != "" {
				line += "\r\n观测时间：" + row.UpdatedAt
			}
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\r\n\r\n")
}
