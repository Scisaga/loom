package clientruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"loom/internal/clientcore"
	"loom/internal/model"
)

// WindowsSelectorPlan is the bounded local-control projection of one already
// verified runtime configuration. Its credentials are intentionally private:
// callers can apply a preference, but cannot accidentally render the API
// bearer into a UI or diagnostic.
type WindowsSelectorPlan struct {
	controller string
	secret     string
	selectors  []windowsSelector
	policy     clientcore.Policy
	direct     bool
}

type windowsSelector struct {
	tag       string
	defaults  string
	direct    string
	fixedExit map[string]string
}

// BuildWindowsSelectorPlan derives the client-writable choice set only from a
// configuration which passes the normal signed-runtime validation boundary.
func BuildWindowsSelectorPlan(body []byte, profile WindowsRuntimeProfile, caPath string) (*WindowsSelectorPlan, error) {
	if err := ValidateWindowsRuntimeConfig(body, profile, caPath); err != nil {
		return nil, err
	}
	var config singBoxConfig
	if err := json.Unmarshal(body, &config); err != nil {
		return nil, err
	}
	return windowsSelectorPlanFromConfig(config)
}

func windowsSelectorPlanFromConfig(config singBoxConfig) (*WindowsSelectorPlan, error) {
	if config.Experimental == nil || config.Experimental.ClashAPI == nil ||
		config.Experimental.ClashAPI.ExternalController != "127.0.0.1:61800" ||
		strings.TrimSpace(config.Experimental.ClashAPI.Secret) == "" {
		return nil, errors.New("Windows selector API is unavailable")
	}
	plan := &WindowsSelectorPlan{
		controller: "http://" + config.Experimental.ClashAPI.ExternalController,
		secret:     config.Experimental.ClashAPI.Secret,
		policy:     clientcore.Policy{Schema: clientcore.PolicySchema},
	}
	var common map[string]bool
	plan.direct = true
	for _, outbound := range config.Outbounds {
		if outbound.Type != "selector" {
			continue
		}
		selector, exits, err := parseWindowsSelector(outbound)
		if err != nil {
			return nil, err
		}
		plan.selectors = append(plan.selectors, selector)
		plan.direct = plan.direct && selector.direct != ""
		if common == nil {
			common = exits
		} else {
			for exit := range common {
				if !exits[exit] {
					delete(common, exit)
				}
			}
		}
	}
	if len(plan.selectors) == 0 {
		return nil, errors.New("Windows runtime has no controllable selectors")
	}
	for exit := range common {
		plan.policy.Exits = append(plan.policy.Exits, clientcore.Exit{ID: exit})
	}
	sort.Slice(plan.policy.Exits, func(i, j int) bool { return plan.policy.Exits[i].ID < plan.policy.Exits[j].ID })
	if err := plan.policy.Validate(); err != nil {
		return nil, err
	}
	return plan, nil
}

func parseWindowsSelector(outbound singBoxOutbound) (windowsSelector, map[string]bool, error) {
	selector := windowsSelector{tag: outbound.Tag, defaults: outbound.Default, fixedExit: map[string]string{}}
	kind, id, ok := strings.Cut(outbound.Tag, ":")
	if !ok || (kind != "decl" && kind != "svc") || !model.ValidNodeID(id) {
		return selector, nil, fmt.Errorf("unsupported managed selector %q", outbound.Tag)
	}
	prefix := "cand:" + id + ":"
	exits := map[string]bool{}
	for _, member := range outbound.Outbounds {
		if member == prefix+"direct" {
			selector.direct = member
			continue
		}
		if !strings.HasPrefix(member, prefix) {
			return selector, nil, fmt.Errorf("selector %q has an unrelated candidate %q", outbound.Tag, member)
		}
		path := strings.TrimPrefix(member, prefix)
		exit := path
		if index := strings.LastIndexByte(path, '>'); index >= 0 {
			exit = path[index+1:]
		}
		if !model.ValidNodeID(exit) {
			return selector, nil, fmt.Errorf("selector %q has an invalid exit candidate", outbound.Tag)
		}
		exits[exit] = true
		// Renderer order is the deterministic path preference. A direct hop is
		// emitted before a multi-hop path to the same final exit.
		if selector.fixedExit[exit] == "" {
			selector.fixedExit[exit] = member
		}
	}
	return selector, exits, nil
}

func (plan *WindowsSelectorPlan) Policy() clientcore.Policy {
	if plan == nil {
		return clientcore.Policy{}
	}
	return clientcore.Policy{Schema: plan.policy.Schema, Exits: append([]clientcore.Exit(nil), plan.policy.Exits...)}
}

func (plan *WindowsSelectorPlan) DirectAvailable() bool { return plan != nil && plan.direct }

// ApplyWindowsPreference changes only selector state on the authenticated
// loopback API. It first snapshots current choices and rolls back a partial
// update, so a failed UI action cannot leave Service selectors in mixed modes.
func ApplyWindowsPreference(ctx context.Context, client *http.Client, plan *WindowsSelectorPlan, preference clientcore.Preference) error {
	if ctx == nil || client == nil || plan == nil {
		return errors.New("Windows selector dependencies are incomplete")
	}
	if err := clientcore.AuthorizeChange(preference, plan.policy); err != nil {
		return err
	}
	targets := make(map[string]string, len(plan.selectors))
	for _, selector := range plan.selectors {
		switch preference.Mode {
		case clientcore.Auto:
			targets[selector.tag] = selector.defaults
		case clientcore.Direct:
			if selector.direct == "" {
				return fmt.Errorf("selector %q has no authorized direct candidate", selector.tag)
			}
			targets[selector.tag] = selector.direct
		case clientcore.FixedExit:
			targets[selector.tag] = selector.fixedExit[preference.Exit]
		}
		if targets[selector.tag] == "" {
			return fmt.Errorf("selector %q cannot apply route preference", selector.tag)
		}
	}
	return applySelectorTargets(ctx, client, plan.controller, plan.secret, targets)
}

func applySelectorTargets(ctx context.Context, client *http.Client, controller, secret string, targets map[string]string) error {
	current := make(map[string]string, len(targets))
	tags := make([]string, 0, len(targets))
	for tag := range targets {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	for _, tag := range tags {
		var state struct {
			Now string `json:"now"`
		}
		if err := selectorRequest(ctx, client, http.MethodGet, controller, secret, tag, "", &state); err != nil {
			return err
		}
		if strings.TrimSpace(state.Now) == "" {
			return fmt.Errorf("selector %q returned no current choice", tag)
		}
		current[tag] = state.Now
	}
	changed := make([]string, 0, len(tags))
	rollback := func() {
		for index := len(changed) - 1; index >= 0; index-- {
			tag := changed[index]
			_ = selectorRequest(context.Background(), client, http.MethodPut, controller, secret, tag, current[tag], nil)
		}
	}
	for _, tag := range tags {
		if current[tag] == targets[tag] {
			continue
		}
		if err := selectorRequest(ctx, client, http.MethodPut, controller, secret, tag, targets[tag], nil); err != nil {
			rollback()
			return err
		}
		changed = append(changed, tag)
	}
	if len(changed) > 0 {
		if err := closeSelectorConnections(ctx, client, controller, secret); err != nil {
			rollback()
			return err
		}
	}
	return nil
}

func closeSelectorConnections(ctx context.Context, client *http.Client, controller, secret string) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodDelete, controller+"/connections/", nil)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+secret)
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("关闭旧出口连接: %w", err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("关闭旧出口连接返回 HTTP %d", response.StatusCode)
	}
	return nil
}

func selectorRequest(ctx context.Context, client *http.Client, method, controller, secret, tag, target string, output any) error {
	var body io.Reader
	if method == http.MethodPut {
		encoded, err := json.Marshal(struct {
			Name string `json:"name"`
		}{Name: target})
		if err != nil {
			return err
		}
		body = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, controller+"/proxies/"+url.PathEscape(tag), body)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+secret)
	if method == http.MethodPut {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("访问本地出口控制接口: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return fmt.Errorf("本地出口控制接口返回 HTTP %d", response.StatusCode)
	}
	if output == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return nil
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 4097))
	if err := decoder.Decode(output); err != nil {
		return errors.New("本地出口控制接口返回无效状态")
	}
	return nil
}
