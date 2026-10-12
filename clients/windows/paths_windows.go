//go:build windows

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"loom/internal/clientmodel"
	"loom/internal/control"
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
	BusinessDetails    string `json:"business_details,omitempty"`
	SelectorReadAt     string `json:"selector_read_at,omitempty"`
}

// Business text is a one-way projection of the original authorized samples.
// It is never parsed into a decision, report, or persisted client identity.
func windowsBusinessDetails(view control.DeviceView, status windowsRuntimeStatus, scope, selected string, now time.Time) string {
	_, targets := windowsProbeTargets(view, scope)
	allowed := map[string]bool{}
	for _, route := range view.Routes {
		if route.Scope == scope {
			allowed[route.ID] = true
		}
	}
	lines := []string{}
	for _, target := range targets {
		values := []clientmodel.Observation{}
		for _, value := range status.Observations {
			observed, _ := time.Parse(time.RFC3339, value.ObservedAt)
			if value.Scope == scope && value.Target == target && value.NetworkGeneration == status.NetworkGeneration &&
				value.Action == "https_request" && allowed[value.CandidateID] && value.Validate() == nil && !observed.After(now) &&
				value.Result != "unknown" && (selected == "" || value.CandidateID == selected) {
				values = append(values, value)
			}
		}
		var sample clientmodel.Observation
		found, ambiguous := false, false
		for _, value := range values {
			if !found || value.ObservedAt > sample.ObservedAt {
				sample, found, ambiguous = value, true, false
			} else if value.ObservedAt == sample.ObservedAt && value != sample {
				ambiguous = true
			}
		}
		if !found || ambiguous {
			lines = append(lines, "业务目标："+target+" · 未知（没有对应唯一样本）")
			continue
		}
		label, _, _ := windowsObservationDisplay(sample.Result)
		if selected == "" || status.RuntimeState != "running" || !sample.CurrentAt(now) {
			label = "历史" + label + "；当前结果未知"
		}
		lines = append(lines, "业务目标："+target+" · "+label,
			"观测范围："+scope+" · 候选 "+sample.CandidateID+" · 网络 "+sample.NetworkGeneration,
			"业务采样："+windowsDetailTime(sample.ObservedAt)+" · 有效至："+windowsDetailTime(sample.ValidUntil))
	}
	if len(lines) == 0 {
		return "业务目标：未知（没有当前授权探测目标）"
	}
	return strings.Join(lines, "\n")
}

func windowsObservationDisplay(result string) (health, summary, selected string) {
	switch result {
	case "available":
		return "可用", "已配置目标的真实探测成功", "真实业务成功"
	case "unavailable":
		return "不可用", "已配置目标的真实探测失败", "真实业务失败"
	default:
		return "未知", "尚无真实业务结果", "未知"
	}
}

func readWindowsRuntimeStatus(root string) (windowsRuntimeStatus, error) {
	var status windowsRuntimeStatus
	file, err := openWindowsRuntimeStatus(root)
	if err != nil {
		return status, err
	}
	defer file.Close()
	body, err := io.ReadAll(file)
	if err != nil {
		return status, err
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&status); err != nil {
		return status, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) || status.Schema != 3 {
		return windowsRuntimeStatus{}, errors.New("Windows runtime status is invalid")
	}
	return status, nil
}

// The status writer atomically replaces a disposable projection. UI readers
// must keep their opened snapshot without preventing that replace or cleanup.
// This does not relax the separately pinned executable or identity handles.
func openWindowsRuntimeStatus(root string) (*os.File, error) {
	path := windowsRuntimeStatusPath(root)
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(name, windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(handle), path), nil
}

// Root.Rename uses Windows replacement semantics that preserve an opened
// reader's snapshot. Limit this to the disposable status projection; identity
// and profile writes retain their existing durable replacement contract.
func writeWindowsRuntimeStatusFile(path string, body []byte) error {
	return writeWindowsMetadata(path, body, func(temporary, path string) error {
		directory, err := os.OpenRoot(filepath.Dir(path))
		if err != nil {
			return err
		}
		defer directory.Close()
		return directory.Rename(filepath.Base(temporary), filepath.Base(path))
	})
}

func (app *portableGUI) watchCurrentPaths(ctx context.Context, sequence uint64) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		status, err := readWindowsRuntimeStatus(app.root)

		store, loadErr := deviceclient.LoadProtected(windowsProfileStatePath(app.root), app.protector())
		if err == nil && (loadErr != nil || store.LKG() == nil || store.LKG().ViewDigest != status.ViewDigest || store.LKG().View.DeviceID != status.DeviceID) {
			err = errors.New("runtime status does not match accepted View")
		}
		var rows []windowsPathDisplay
		if err == nil {
			now := time.Now()
			byID := map[string]string{}
			if loadErr == nil && store.LKG() != nil {
				for _, route := range store.LKG().View.Routes {
					chain := "本机 → 目标（直连）"
					if route.FinalExit != "direct" && len(route.NodeChain) == 0 {
						chain = "本机（出口 " + route.FinalExit + "）→ 目标"
					} else if len(route.NodeChain) > 0 {
						chain = "本机 → " + strings.Join(route.NodeChain, " → ") + " → 目标"
					}
					byID[route.ID] = chain
				}
			}
			for _, selection := range status.Selections {
				_, targets := windowsProbeTargets(store.LKG().View, selection.Scope)
				result, stateErr := clientmodel.ObservationState(status.Observations, selection.CandidateID, selection.Scope, status.NetworkGeneration, targets, time.Now())
				if stateErr != nil {
					result = "unknown"
				}
				health, summary, selected := windowsObservationDisplay(result)
				details := []string{}
				updated := ""
				for _, target := range targets {
					sample, found, sampleErr := clientmodel.LatestObservation(status.Observations, selection.CandidateID, selection.Scope, status.NetworkGeneration, target)
					targetState := "unknown"
					if found && sampleErr == nil && sample.CurrentAt(time.Now()) {
						targetState = sample.Result
					}
					label, _, _ := windowsObservationDisplay(targetState)
					details = append(details, target+" · "+label+" · "+sample.ObservedAt)
					if sample.ObservedAt > updated {
						updated = sample.ObservedAt
					}
				}
				if len(details) > 0 {
					summary = strings.Join(details, "\n")
				}
				rows = append(rows, windowsPathDisplay{Service: selection.Scope, Candidate: selection.CandidateID,
					Chain: byID[selection.CandidateID], Health: health, MeasurementSummary: summary, SelectedQuality: selected,
					BestQuality: "当前 selector 候选", Reason: "selector 回读为当前候选", UpdatedAt: updated,
					BusinessDetails: windowsBusinessDetails(store.LKG().View, status, selection.Scope, selection.CandidateID, now), SelectorReadAt: status.SelectorReadAt})
			}
			for _, scope := range status.BlockedScopes {
				rows = append(rows, windowsPathDisplay{Service: scope, Chain: "暂无可用路径", Health: "不可用", MeasurementSummary: "当前偏好下没有可用候选", Reason: "该服务 selector 已拒绝；其他服务继续运行",
					BusinessDetails: windowsBusinessDetails(store.LKG().View, status, scope, "", now), SelectorReadAt: status.SelectorReadAt})
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
		ready := err == nil && status.DeviceID != "" && status.ViewDigest != "" && status.RuntimeState == "running"
		becameReady := ready && app.state == guiStarting && !app.stopRequested
		if !ready && app.state == guiConnected && !app.stopRequested {
			app.state = guiStarting
			app.detail = "认证配置已保存；正在等待运行路径回读…"
			changed = true
		}
		app.mu.Unlock()
		if becameReady {
			app.runtimeReady(sequence)
		} else if changed {
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
			if row.BusinessDetails != "" {
				line += "\r\n" + row.BusinessDetails
			}
			if row.SelectorReadAt != "" {
				line += "\r\nselector 回读完成：" + windowsDetailTime(row.SelectorReadAt)
			}
			if row.UpdatedAt != "" {
				line += "\r\n观测时间：" + row.UpdatedAt
			}
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\r\n\r\n")
}
