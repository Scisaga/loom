//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
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
			path, err := app.refreshRoutePreference(ctx, sequence, lastConfig)
			if err != nil {
				app.routeFailure(sequence, err)
			} else {
				lastConfig = path
			}
		}
	}
}

// §7.2：配置切换时恢复偏好与用户切换串行，避免旧偏好覆盖新选择。
func (app *portableGUI) refreshRoutePreference(ctx context.Context, sequence uint64, lastConfig string) (string, error) {
	app.routeMu.Lock()
	defer app.routeMu.Unlock()
	control, err := activeRouteControl(app.root)
	if err != nil {
		return lastConfig, err
	}
	state := control.snapshot()
	if !state.active() || state.Policy == nil {
		return lastConfig, errors.New("本地数据面正在切换")
	}
	if err := ctx.Err(); err != nil {
		return lastConfig, err
	}
	app.routeReady(sequence, state.Policy, state.Preference)
	return state.Applied, nil
}

func mustRuntimeProfile(edition clientEdition) clientruntime.WindowsRuntimeProfile {
	profile, err := runtimeProfile(edition)
	if err != nil {
		panic(err)
	}
	return profile
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
	if snapshot := app.snapshot(); snapshot.profilesReady {
		if index < 0 || index >= len(snapshot.routeOptions) || index == snapshot.routeSelected || snapshot.routeBusy {
			return
		}
		preference := snapshot.routeOptions[index].Preference
		if app.routeFiltering {
			app.cancelRouteFilter(snapshot)
		}
		app.profileCommand(brokerRequest{Operation: "preference", ProfileID: snapshot.selectedProfile, Preference: &preference})
		return
	}
	wasFiltering := app.routeFiltering
	app.mu.Lock()
	online := app.state == guiConnected && (app.runCancel != nil || app.brokerClient)
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
		if app.brokerClient {
			app.exchangeInstalledBroker(brokerRequest{Operation: "preference", Preference: &preference})
			return
		}
		err = app.setRoutePreference(preference)
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

// §7.2：IPC 与本地 GUI 共用签名出口授权；只接受现有三态偏好。
func (app *portableGUI) setRoutePreference(preference clientcore.Preference) error {
	app.routeMu.Lock()
	defer app.routeMu.Unlock()
	app.mu.RLock()
	index := routeOptionIndex(app.routeOptions, preference)
	online := app.state == guiConnected && app.runCancel != nil
	offline := app.joined && (app.state == guiStopped || app.state == guiError || app.state == guiNeedsElevation)
	app.mu.RUnlock()
	if index < 0 || (!online && !offline) {
		return errors.New("出口未获当前签名配置授权，或数据面正在切换")
	}
	app.mu.Lock()
	app.routeBusy = true
	app.paths = nil
	app.mu.Unlock()
	app.repaint()
	defer func() { app.mu.Lock(); app.routeBusy = false; app.mu.Unlock(); app.repaint() }()
	path := filepath.Join(app.root, "state", "preference.json")
	if online {
		control, err := activeRouteControl(app.root)
		if err != nil {
			return err
		}
		if err := control.apply(app.ctx, preference); err != nil {
			return err
		}
	} else {
		if err := clientcore.WritePreference(path, preference); err != nil {
			return err
		}
	}

	app.mu.Lock()
	app.routeSelected = index
	app.routeDetail = ""
	app.mu.Unlock()
	return nil
}
