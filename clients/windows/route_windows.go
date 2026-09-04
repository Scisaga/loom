//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"loom/internal/clientcore"
	"loom/internal/clientruntime"
)

type portableRouteOption struct {
	Label      string
	Preference clientcore.Preference
}

func (app *portableGUI) watchRoutePreference(ctx context.Context, sequence uint64) {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	lastConfig := ""
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			path, body, err := activePortableRuntimeConfig(app.root)
			if err != nil {
				app.routeFailure(sequence, err)
				continue
			}
			if path == lastConfig {
				continue
			}
			preference, err := clientcore.ReadPreference(filepath.Join(app.root, "state", "preference.json"))
			if err != nil {
				app.routeFailure(sequence, err)
				continue
			}
			plan, err := clientruntime.BuildWindowsSelectorPlan(body, mustRuntimeProfile(app.edition), windowsClientCAPath(app.root, app.edition))
			clear(body)
			if err != nil {
				app.routeFailure(sequence, err)
				continue
			}
			client := &http.Client{Timeout: 3 * time.Second}
			applyCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			err = clientruntime.ApplyWindowsPreference(applyCtx, client, plan, preference)
			cancel()
			if err != nil {
				// The plaintext runtime file is created immediately before sing-box;
				// leave lastConfig unchanged so startup races retry without busy-looping.
				app.routeFailure(sequence, err)
				continue
			}
			lastConfig = path
			app.routeReady(sequence, plan, preference)
		}
	}
}

func mustRuntimeProfile(edition clientEdition) clientruntime.WindowsRuntimeProfile {
	profile, err := runtimeProfile(edition)
	if err != nil {
		panic(err)
	}
	return profile
}

func activePortableRuntimeConfig(root string) (string, []byte, error) {
	paths, err := filepath.Glob(filepath.Join(root, "runtime", ".sing-box-active-*.json"))
	if err != nil || len(paths) != 1 {
		return "", nil, errors.New("本地数据面尚未提供出口控制")
	}
	info, err := os.Lstat(paths[0])
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > 16<<20 {
		return "", nil, errors.New("本地出口控制配置无效")
	}
	body, err := os.ReadFile(paths[0])
	if err != nil || int64(len(body)) != info.Size() {
		clear(body)
		return "", nil, errors.New("读取本地出口控制配置失败")
	}
	return paths[0], body, nil
}

func portableRouteOptions(plan *clientruntime.WindowsSelectorPlan) ([]portableRouteOption, error) {
	policy := plan.Policy()
	exits, err := clientcore.SortedExits(policy)
	if err != nil {
		return nil, err
	}
	options := []portableRouteOption{{
		Label: "自动选择", Preference: clientcore.Preference{Schema: clientcore.PreferenceSchema, Mode: clientcore.Auto},
	}}
	if plan.DirectAvailable() {
		options = append(options, portableRouteOption{
			Label: "直连", Preference: clientcore.Preference{Schema: clientcore.PreferenceSchema, Mode: clientcore.Direct},
		})
	}
	for _, exit := range exits {
		label := exit.ID
		if exit.Name != "" {
			label = exit.Name + " (" + exit.ID + ")"
		}
		options = append(options, portableRouteOption{
			Label:      "固定出口 · " + label,
			Preference: clientcore.Preference{Schema: clientcore.PreferenceSchema, Mode: clientcore.FixedExit, Exit: exit.ID},
		})
	}
	return options, nil
}

func routeOptionIndex(options []portableRouteOption, preference clientcore.Preference) int {
	for index, option := range options {
		if option.Preference == preference {
			return index
		}
	}
	return -1
}

func (app *portableGUI) routeReady(sequence uint64, plan *clientruntime.WindowsSelectorPlan, preference clientcore.Preference) {
	options, err := portableRouteOptions(plan)
	if err != nil {
		app.routeFailure(sequence, err)
		return
	}
	index := routeOptionIndex(options, preference)
	app.mu.Lock()
	if sequence == app.runSequence && app.runCancel != nil {
		app.routeOptions = options
		app.routeSelected = index
		app.routeBusy = false
		app.routeDetail = ""
	}
	app.mu.Unlock()
	app.repaint()
}

func (app *portableGUI) routeFailure(sequence uint64, err error) {
	app.mu.Lock()
	if sequence == app.runSequence && app.runCancel != nil {
		app.routeBusy = false
		app.routeDetail = err.Error()
	}
	app.mu.Unlock()
	app.repaint()
}

func (app *portableGUI) routeSelectionChanged() {
	selection, _, _ := procSendMessage.Call(app.controls.routeCombo, portableCBGetCurSel, 0, 0)
	if selection == ^uintptr(0) {
		if app.routeFiltering {
			app.cancelRouteFilter(app.snapshot())
		}
		return
	}
	visibleIndex := int(selection)
	if visibleIndex < 0 || visibleIndex >= len(app.routeVisible) {
		if app.routeFiltering {
			app.cancelRouteFilter(app.snapshot())
		}
		return
	}
	index := app.routeVisible[visibleIndex]
	wasFiltering := app.routeFiltering
	app.mu.Lock()
	online := app.state == guiConnected && app.runCancel != nil
	offline := app.state == guiStopped || app.state == guiError || app.state == guiNeedsElevation
	if (!online && !offline) || app.routeBusy || index < 0 || index >= len(app.routeOptions) || index == app.routeSelected {
		app.mu.Unlock()
		if wasFiltering {
			app.cancelRouteFilter(app.snapshot())
		}
		return
	}
	preference := app.routeOptions[index].Preference
	previous := app.routeSelected
	sequence := app.runSequence
	app.routeBusy = true
	if online {
		app.routeDetail = "正在切换出口…"
	} else {
		app.routeDetail = "正在保存出口选择…"
	}
	app.mu.Unlock()
	if wasFiltering {
		app.routeFiltering = false
		app.routeFilter = ""
		app.routeUpdating = true
		procSendMessage.Call(app.controls.routeCombo, portableCBShowDropDown, 0, 0)
		app.routeUpdating = false
	}
	app.repaint()

	app.workers.Add(1)
	go func() {
		defer app.workers.Done()
		var err error
		if online {
			_, body, loadErr := activePortableRuntimeConfig(app.root)
			err = loadErr
			if err == nil {
				var plan *clientruntime.WindowsSelectorPlan
				plan, err = clientruntime.BuildWindowsSelectorPlan(body, mustRuntimeProfile(app.edition), windowsClientCAPath(app.root, app.edition))
				clear(body)
				if err == nil {
					applyCtx, cancel := context.WithTimeout(app.ctx, 5*time.Second)
					err = clientruntime.ApplyWindowsPreference(applyCtx, &http.Client{Timeout: 3 * time.Second}, plan, preference)
					cancel()
				}
			}
		}
		if err == nil {
			err = clientcore.WritePreference(filepath.Join(app.root, "state", "preference.json"), preference)
		}
		app.mu.Lock()
		if sequence == app.runSequence {
			app.routeBusy = false
			if err == nil {
				app.routeSelected = index
				if online {
					app.routeDetail = "出口已切换为“" + app.routeOptions[index].Label + "”。"
				} else {
					app.routeDetail = "出口已设为“" + app.routeOptions[index].Label + "”，下次连接生效。"
				}
			} else {
				app.routeSelected = previous
				app.routeDetail = fmt.Sprintf("出口切换失败：%v", err)
			}
		}
		app.mu.Unlock()
		app.repaint()
	}()
}
