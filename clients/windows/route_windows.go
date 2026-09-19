//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"loom/internal/clientadapter"
	"loom/internal/clientmodel"
	"loom/internal/deviceclient"
)

type portableRouteOption struct {
	Label      string
	Preference clientmodel.Preference
}

func routeOptions(routes []clientmodel.RouteCandidate) ([]portableRouteOption, error) {
	exits := map[string]bool{}
	direct := false
	for _, route := range routes {
		if err := route.Validate(); err != nil {
			return nil, err
		}
		if len(route.Chain) == 0 {
			direct = true
		} else {
			exits[route.FinalExit] = true
		}
	}
	options := []portableRouteOption{{Label: "自动选择", Preference: clientmodel.Preference{Schema: 1, Mode: clientmodel.ModeAuto}}}
	if direct {
		options = append(options, portableRouteOption{Label: "直连", Preference: clientmodel.Preference{Schema: 1, Mode: clientmodel.ModeDirect}})
	}
	ids := make([]string, 0, len(exits))
	for id := range exits {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		options = append(options, portableRouteOption{Label: "固定出口 · " + id,
			Preference: clientmodel.Preference{Schema: 1, Mode: clientmodel.ModeFixed, Exit: id}})
	}
	return options, nil
}

func routeOptionIndex(options []portableRouteOption, preference clientmodel.Preference) int {
	for index, option := range options {
		if option.Preference == preference {
			return index
		}
	}
	return -1
}

func (app *portableGUI) watchRoutePreference(ctx context.Context, sequence uint64) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := app.refreshRoutePreference(ctx, sequence); err != nil {
			app.routeFailure(sequence, err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (app *portableGUI) refreshRoutePreference(ctx context.Context, sequence uint64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	store, err := deviceclient.LoadProtected(windowsProfileStatePath(app.root), app.protector())
	if err != nil || store.LKG() == nil {
		return errors.New("DPAPI profile 暂不可读")
	}
	options, err := routeOptions(store.LKG().View.Routes)
	if err != nil {
		return err
	}
	app.mu.Lock()
	if sequence == app.runSequence && app.runCancel != nil {
		app.routeOptions = options
		app.routeSelected = routeOptionIndex(options, store.Preference())
		app.routeBusy = false
		app.routeDetail = ""
	}
	app.mu.Unlock()
	app.repaint()
	return nil
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
	if app.skin != nil {
		app.commitMisakaRouteSelection()
		return
	}
	selection, _, _ := procSendMessage.Call(app.controls.routeCombo, portableCBGetCurSel, 0, 0)
	if selection == ^uintptr(0) {
		return
	}
	visibleIndex := int(selection)
	if visibleIndex < 0 || visibleIndex >= len(app.routeVisible) {
		return
	}
	index := app.routeVisible[visibleIndex]
	snapshot := app.snapshot()
	if index < 0 || index >= len(snapshot.routeOptions) || index == snapshot.routeSelected || snapshot.routeBusy {
		return
	}
	preference := snapshot.routeOptions[index].Preference
	if snapshot.profilesReady {
		app.profileCommand(brokerRequest{Operation: "preference", ProfileID: snapshot.selectedProfile, Preference: &preference})
		return
	}
	app.workers.Add(1)
	go func() {
		defer app.workers.Done()
		if err := app.setRoutePreference(preference); err != nil {
			app.routeFailure(app.runSequence, fmt.Errorf("出口切换失败: %w", err))
		}
	}()
}

func (app *portableGUI) setRoutePreference(preference clientmodel.Preference) error {
	app.routeMu.Lock()
	defer app.routeMu.Unlock()
	store, err := deviceclient.LoadProtected(windowsProfileStatePath(app.root), app.protector())
	if err != nil || store.LKG() == nil {
		return errors.New("无法读取 DPAPI profile")
	}
	options, err := routeOptions(store.LKG().View.Routes)
	if err != nil || routeOptionIndex(options, preference) < 0 {
		return errors.New("出口未获当前 LKG 授权")
	}
	previous := store.Preference()
	if err := store.SetPreference(preference); err != nil {
		return err
	}
	app.mu.RLock()
	online := app.state == guiConnected && app.runCancel != nil
	app.mu.RUnlock()
	if online {
		lkg := store.LKG()
		selector, selectErr := clientadapter.NewHTTPSelector(lkg.View.Runtime.Config)
		if selectErr == nil {
			scopes, byScope, scopeErr := clientadapter.Scopes(lkg.View.Routes)
			if scopeErr != nil {
				selectErr = scopeErr
			} else {
				desired := map[string]string{}
				for _, scope := range scopes {
					current, readErr := selector.Read(app.ctx, scope)
					if readErr != nil {
						selectErr = readErr
						break
					}
					choice, chooseErr := clientmodel.Select(byScope[scope], nil, preference, current, "windows-live", time.Now())
					if chooseErr != nil {
						selectErr = chooseErr
						break
					}
					desired[scope] = choice.CandidateID
				}
				if selectErr == nil {
					_, selectErr = clientadapter.ApplySelections(app.ctx, selector, desired)
				}
			}
		}
		if selectErr != nil {
			_ = store.SetPreference(previous)
			return selectErr
		}
	}
	app.mu.Lock()
	app.routeOptions = options
	app.routeSelected = routeOptionIndex(options, preference)
	app.routeBusy = false
	app.routeDetail = ""
	app.paths = nil
	app.mu.Unlock()
	app.repaint()
	return nil
}
