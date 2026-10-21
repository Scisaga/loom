//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"loom/internal/control"
	"os"
	"path/filepath"
	"sort"
	"time"

	"loom/internal/clientadapter"
	"loom/internal/clientmodel"
	"loom/internal/deviceclient"
)

type portableRouteOption struct {
	Label      string
	ServiceID  string
	PolicyID   string
	Selected   bool
	Preference clientmodel.Preference
}

func equalRouteOptions(left, right []portableRouteOption) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		a, b := left[i], right[i]
		if a.Label != b.Label || a.ServiceID != b.ServiceID || a.PolicyID != b.PolicyID || a.Selected != b.Selected || !a.Preference.Equal(b.Preference) {
			return false
		}
	}
	return true
}

func windowsRouteOptions(view control.DeviceView, preferences ...clientmodel.Preference) ([]portableRouteOption, error) {
	if err := view.Validate(); err != nil {
		return nil, err
	}
	preference := clientmodel.EmptyPreference()
	if len(preferences) == 1 {
		preference = preferences[0]
	}
	preference, err := clientmodel.ReconcilePreference(preference, view)
	if err != nil {
		return nil, err
	}
	options := []portableRouteOption{}
	for _, service := range view.Services {
		for _, policy := range view.Policies {
			if policy.ServiceID != service.ID || policy.Action != "allow" {
				continue
			}
			next, err := clientmodel.ChoosePolicy(preference, view, service.ID, policy.ID)
			if err != nil {
				continue
			}
			selected := preference.Policy(service.ID) == policy.ID
			label := service.Name + " / " + policy.Name
			if selected {
				label += " ✓"
			}
			options = append(options, portableRouteOption{Label: label, ServiceID: service.ID, PolicyID: policy.ID, Selected: selected, Preference: next})
		}
	}
	sort.Slice(options, func(i, j int) bool {
		a, b := options[i], options[j]
		if a.ServiceID != b.ServiceID {
			return a.ServiceID < b.ServiceID
		}
		return a.PolicyID < b.PolicyID
	})
	return options, nil
}
func windowsRuntimeSelector(root, viewDigest string) (*clientadapter.HTTPSelector, error) {
	status, err := readWindowsRuntimeStatus(root)
	if err != nil || status.ViewDigest != viewDigest || status.RuntimeState != "running" {
		return nil, errors.New("accepted View is not the running generation")
	}
	paths, err := filepath.Glob(filepath.Join(root, "runtime", ".sing-box-active-*.json"))
	if err != nil || len(paths) != 1 {
		return nil, errors.New("runtime configuration is unavailable")
	}
	info, err := os.Lstat(paths[0])
	if err != nil || !info.Mode().IsRegular() || info.Size() > 16<<20 {
		return nil, errors.New("runtime configuration is not a bounded regular file")
	}
	body, err := os.ReadFile(paths[0])
	if err != nil {
		return nil, err
	}
	defer clear(body)
	return clientadapter.NewHTTPSelector(string(body))
}

func routeOptionIndex(options []portableRouteOption, preference clientmodel.Preference) int {
	for index, option := range options {
		if option.Preference.Equal(preference) {
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
	options, err := windowsRouteOptions(store.LKG().View, store.Preference())
	if err != nil {
		return err
	}
	app.mu.Lock()
	if sequence == app.runSequence && app.runCancel != nil {
		app.possiblePermissionRestoration = store.PossiblePermissionRestoration()
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
			app.routeFailure(app.runSequence, fmt.Errorf("服务策略切换失败: %w", err))
		}
	}()
}

func (app *portableGUI) setRoutePreference(preference clientmodel.Preference) (resultErr error) {
	app.routeMu.Lock()
	defer app.routeMu.Unlock()
	store, err := deviceclient.LoadProtected(windowsProfileStatePath(app.root), app.protector())
	if err != nil || store.LKG() == nil {
		return errors.New("无法读取 DPAPI profile")
	}
	options, err := windowsRouteOptions(store.LKG().View, store.Preference())
	if err != nil || routeOptionIndex(options, preference) < 0 {
		return errors.New("策略未获当前签名配置授权")
	}
	previous := store.Preference()
	changedScopes := map[string]bool{}
	for _, choice := range preference.Services {
		if previous.Policy(choice.ServiceID) != choice.PolicyID {
			for _, service := range store.LKG().View.Services {
				if service.ID == choice.ServiceID {
					changedScopes[service.Scope()] = true
				}
			}
		}
	}
	if err := store.SetPreference(preference); err != nil {
		return err
	}
	defer func() {
		app.mu.Lock()
		app.routeOptions, _ = windowsRouteOptions(store.LKG().View, preference)
		app.routeSelected = routeOptionIndex(app.routeOptions, preference)
		app.routeBusy = false
		app.routeDetail = ""
		if resultErr != nil {
			app.routeDetail = "服务策略已保存；应用未确认：" + resultErr.Error()
		}
		paths := app.paths[:0]
		for _, path := range app.paths {
			if !changedScopes[path.Service] {
				paths = append(paths, path)
			}
		}
		app.paths = paths
		app.mu.Unlock()
		app.repaint()
	}()
	app.mu.RLock()
	online := app.state == guiConnected && app.runCancel != nil
	app.mu.RUnlock()
	if online && len(changedScopes) > 0 {
		lkg := store.LKG()
		selector, selectErr := windowsRuntimeSelector(app.root, lkg.ViewDigest)
		if selectErr == nil {
			selectErr = func() error {
				routes, _, err := clientadapter.AccessProjection(lkg.View)
				if err != nil {
					return err
				}
				scopes, byScope, err := clientadapter.Scopes(routes, clientmodel.ServiceScopes(lkg.View)...)
				if err != nil {
					return err
				}
				status, err := readWindowsRuntimeStatus(app.root)
				if err != nil || status.ViewDigest != lkg.ViewDigest || status.DeviceID != lkg.View.DeviceID || status.RuntimeState != "running" {
					return errors.New("runtime evidence does not match the accepted profile")
				}
				generation, err := windowsNetworkGeneration()
				if err != nil {
					return err
				}
				if status.NetworkGeneration != generation {
					status.Observations, status.ResourceObservations = nil, nil
				}
				linkState := clientadapter.State{}
				refreshWindowsLinkObservations(app.ctx, store, lkg, &linkState)
				desired := map[string]string{}
				for _, scope := range scopes {
					if !changedScopes[scope] {
						continue
					}
					current, readErr := selector.Read(app.ctx, scope)
					if readErr != nil {
						return readErr
					}
					_, targets := windowsProbeTargets(lkg.View, scope)
					choice, chooseErr := clientmodel.SelectWithLinks(byScope[scope], status.Observations, status.ResourceObservations, linkState.LinkObservations, preference, current, generation, time.Now(), targets...)
					if errors.Is(chooseErr, clientmodel.ErrNoUsableCandidate) {
						desired[scope] = clientadapter.BlockedSelection
						continue
					}
					if chooseErr != nil {
						return chooseErr
					}
					desired[scope] = choice.CandidateID
				}
				_, err = clientadapter.ApplySelections(app.ctx, selector, desired)
				return err
			}()
		}
		if selectErr != nil {
			confirmed := false
			if selector != nil {
				scopes := []string{}
				for scope := range changedScopes {
					scopes = append(scopes, scope)
				}
				sort.Strings(scopes)
				blocked, rejectErr := clientadapter.RejectSelections(app.ctx, selector, scopes)
				confirmed = rejectErr == nil && len(blocked) == len(scopes)
				selectErr = errors.Join(selectErr, rejectErr)
			}
			if !confirmed {
				app.mu.RLock()
				cancel := app.runCancel
				app.mu.RUnlock()
				if cancel != nil {
					cancel()
				}
			}
			return selectErr
		}
	}
	return nil
}
