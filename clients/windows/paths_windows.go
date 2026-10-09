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
		if err == nil && (loadErr != nil || store.LKG() == nil || store.LKG().ViewDigest != status.ViewDigest) {
			err = errors.New("runtime status does not match accepted View")
		}
		var rows []windowsPathDisplay
		if err == nil {
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
					BestQuality: "当前 selector 候选", Reason: "selector 回读为当前候选", UpdatedAt: updated})
			}
			for _, scope := range status.BlockedScopes {
				rows = append(rows, windowsPathDisplay{Service: scope, Chain: "暂无可用路径", Health: "不可用", MeasurementSummary: "当前偏好下没有可用候选", Reason: "该服务 selector 已拒绝；其他服务继续运行"})
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
			if row.UpdatedAt != "" {
				line += "\r\n观测时间：" + row.UpdatedAt
			}
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\r\n\r\n")
}
