// Package clientadapter contains selector and real-outcome I/O shared by host
// adapters. Route choice itself remains in the I/O-free clientmodel package.
package clientadapter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"loom/internal/clientmodel"
	"loom/protocol"
	"maps"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync/atomic"
	"time"
)

type profileControl struct {
	Experimental struct {
		ClashAPI struct {
			ExternalController string `json:"external_controller"`
			Secret             string `json:"secret"`
		} `json:"clash_api"`
	} `json:"experimental"`
}

type Selector interface {
	Read(context.Context, string) (string, error)
	Set(context.Context, string, string) error
	ReadSelection(context.Context, string) (clientmodel.Selection, error)
	ApplySelection(context.Context, clientmodel.Selection, clientmodel.Selection) (clientmodel.Selection, error)
	ElapsedMillis() int64
}

var ErrSelectionSuperseded = errors.New("selector changed before application")

type HTTPSelector struct {
	resourceSource atomic.Pointer[runtimeResourceSource]
	secret         string
	client         *http.Client
	started        time.Time
}

// SelectorReadbackLimit bounds metadata that includes all authorized candidates.
const SelectorReadbackLimit = 1 << 20

func NewHTTPSelector(config string) (*HTTPSelector, error) {
	var control profileControl
	if err := json.Unmarshal([]byte(config), &control); err != nil {
		return nil, err
	}
	if control.Experimental.ClashAPI.ExternalController != "127.0.0.1:61800" ||
		len(control.Experimental.ClashAPI.Secret) == 0 || len(control.Experimental.ClashAPI.Secret) > 4<<10 {
		return nil, errors.New("selector control is invalid")
	}
	for _, character := range control.Experimental.ClashAPI.Secret {
		if character < 0x21 || character > 0x7e {
			return nil, errors.New("selector secret is invalid")
		}
	}
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	selector := &HTTPSelector{secret: control.Experimental.ClashAPI.Secret, started: time.Now(),
		client: &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: nil,
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return dialer.DialContext(ctx, "tcp", "127.0.0.1:61800")
			}}}}
	var document map[string]any
	if json.Unmarshal([]byte(config), &document) == nil && document["outbounds"] != nil {
		if err := selector.SetResourceSource(config); err != nil {
			return nil, err
		}
	}
	return selector, nil
}

func (selector *HTTPSelector) request(ctx context.Context, method, path string, body []byte) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, method, "http://127.0.0.1:61800"+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+selector.secret)
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	client := selector.client
	if method == http.MethodPost && strings.HasSuffix(path, "/tcp-connect") || method == http.MethodPut && path == "/loom/resources" {
		// The existing measurement context owns the complete bounded attempt;
		// the ordinary metadata client's 3s timeout must not truncate it.
		copy := *client
		copy.Timeout = 0
		client = &copy
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	maximum := int64(SelectorReadbackLimit)
	if path == "/connections/" {
		maximum = 8 << 20
	} else if path == "/loom/tcp-observations" {
		maximum = NativeObservationReadbackLimit
	}
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, maximum+1))
	if err != nil {
		return nil, err
	}
	if response.StatusCode == http.StatusConflict {
		return nil, ErrSelectionSuperseded
	}
	if response.StatusCode == http.StatusServiceUnavailable {
		return nil, ErrResourcesNotReady
	}
	if int64(len(responseBody)) > maximum || response.StatusCode < 200 || response.StatusCode > 299 {
		return nil, fmt.Errorf("selector API returned HTTP %d", response.StatusCode)
	}
	return responseBody, nil
}

func (selector *HTTPSelector) Read(ctx context.Context, scope string) (string, error) {
	value, err := selector.ReadSelection(ctx, scope)
	return value.CandidateID, err
}

func (selector *HTTPSelector) ReadSelection(ctx context.Context, scope string) (clientmodel.Selection, error) {
	body, err := selector.request(ctx, http.MethodGet, "/proxies/"+url.PathEscape(scope), nil)
	if err != nil {
		return clientmodel.Selection{}, err
	}
	return decodeSelectionSnapshot(scope, body)
}

func decodeSelectionSnapshot(scope string, body []byte) (clientmodel.Selection, error) {
	var response struct {
		PolicyID string                          `json:"policy_id"`
		Choices  map[string]protocol.RouteChoice `json:"choices"`
		Revision string                          `json:"revision"`
		Now      string                          `json:"now"`
		Targets  map[string]string               `json:"targets"`
	}
	if json.Unmarshal(body, &response) != nil || !validSnapshotRevision(response.Revision) || response.Now == "" || len(response.Now) > 128 || response.Targets == nil {
		return clientmodel.Selection{}, errors.New("complete selector readback is invalid")
	}
	for target, candidate := range response.Targets {
		if _, _, _, err := protocol.ParseConnectionTargetKey(target); err != nil || candidate == "" || len(candidate) > 128 {
			return clientmodel.Selection{}, errors.New("invalid selector target readback")
		}
	}
	value := clientmodel.Selection{Scope: scope, CandidateID: response.Now, PolicyID: response.PolicyID, Choices: response.Choices, Targets: response.Targets, Revision: response.Revision}
	return value, clientmodel.ValidateAccessSelection(value)
}

func validSnapshotRevision(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, character := range []byte(value) {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	return true
}

func (selector *HTTPSelector) Set(ctx context.Context, scope, candidate string) error {
	expected, err := selector.ReadSelection(ctx, scope)
	if err != nil {
		return err
	}
	if candidate != "reject" {
		return errors.New("route choice and Policy are required; use ApplySelection")
	}
	_, err = selector.ApplySelection(ctx, expected, clientmodel.Selection{Scope: scope, CandidateID: candidate, Targets: map[string]string{}, Choices: map[string]protocol.RouteChoice{}})
	return err
}

func (selector *HTTPSelector) ApplySelection(ctx context.Context, expected, desired clientmodel.Selection) (clientmodel.Selection, error) {
	if expected.Scope != desired.Scope || !clientmodel.ValidSelectorScope(desired.Scope) || !validSnapshotRevision(expected.Revision) || expected.CandidateID == "" || desired.CandidateID == "" || desired.Targets == nil || expected.Targets == nil {
		return clientmodel.Selection{}, errors.New("incomplete selector update")
	}
	if err := clientmodel.ValidateAccessSelection(expected); err != nil {
		return clientmodel.Selection{}, err
	}
	if err := clientmodel.ValidateAccessSelection(desired); err != nil {
		return clientmodel.Selection{}, err
	}
	for target, candidate := range desired.Targets {
		if _, _, _, err := protocol.ParseConnectionTargetKey(target); err != nil || candidate == "" {
			return clientmodel.Selection{}, errors.New("invalid selector target update")
		}
	}
	body, err := json.Marshal(map[string]any{
		"expected_revision": expected.Revision, "name": desired.CandidateID, "targets": desired.Targets,
		"expected_name": expected.CandidateID, "expected_targets": expected.Targets,
		"policy_id": desired.PolicyID, "choices": desired.Choices,
		"expected_policy_id": expected.PolicyID, "expected_choices": expected.Choices,
	})
	if err != nil {
		return clientmodel.Selection{}, err
	}
	response, err := selector.request(ctx, http.MethodPut, "/proxies/"+url.PathEscape(desired.Scope), body)
	if err != nil {
		return clientmodel.Selection{}, err
	}
	applied, err := decodeSelectionSnapshot(desired.Scope, response)
	if err != nil {
		return clientmodel.Selection{}, err
	}
	if !SameSelection(applied, desired) || applied.Revision == expected.Revision {
		return clientmodel.Selection{}, ErrSelectionSuperseded
	}
	return applied, nil
}

func SameSelection(a, b clientmodel.Selection) bool {
	return a.Scope == b.Scope && a.PolicyID == b.PolicyID && a.CandidateID == b.CandidateID && maps.Equal(a.Targets, b.Targets) && maps.Equal(a.Choices, b.Choices)
}
func (selector *HTTPSelector) ElapsedMillis() int64 {
	return time.Since(selector.started).Milliseconds()
}

// The adapter supplies the existing isolated namespace's dialer before use.
// Requests remain pinned to the one loopback controller and bypass HTTP_PROXY.
func (selector *HTTPSelector) SetDialer(dial func(context.Context, string, string) (net.Conn, error)) {
	selector.client.Transport.(*http.Transport).DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) { return dial(ctx, "tcp", "127.0.0.1:61800") }
}

func (selector *HTTPSelector) CloseServiceConnections(ctx context.Context, serviceID, scope string) error {
	body, err := selector.request(ctx, http.MethodGet, "/connections/", nil)
	if err != nil {
		return err
	}
	ids, err := ServiceConnectionIDs(body, serviceID, scope)
	if err != nil {
		return err
	}
	for _, id := range ids {
		if _, err := selector.request(ctx, http.MethodDelete, "/connections/"+id, nil); err != nil {
			return err
		}
	}
	return nil
}

func WaitSelector(ctx context.Context, selector Selector, scopes []string) error {
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	var last error
	for {
		ready := true
		if len(scopes) == 0 {
			health, ok := selector.(interface{ Health(context.Context) error })
			if !ok {
				return errors.New("empty selection requires actual runtime API readback")
			}
			if err := health.Health(ctx); err != nil {
				last, ready = err, false
			}
		}
		for _, scope := range scopes {
			if _, err := selector.Read(ctx, scope); err != nil {
				last, ready = err, false
				break
			}
		}
		if ready {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return fmt.Errorf("selector API did not become ready: %w", last)
		case <-ticker.C:
		}
	}
}

// RejectSelections blocks new connections in the affected scopes. Existing
// connections retain their pinned paths and current authorization checks;
// explicit rebuilding closes them separately. Cleanup outlives a cancelled
// request but is bounded; a failed readback is never reported applied.
func RejectSelections(ctx context.Context, selector Selector, scopes []string) (map[string]string, error) {
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	readback := map[string]string{}
	var failures []error
	for _, scope := range scopes {
		if err := selector.Set(cleanup, scope, BlockedSelection); err != nil {
			failures = append(failures, fmt.Errorf("reject %s: %w", scope, err))
		}
	}
	for _, scope := range scopes {
		actual, err := selector.Read(cleanup, scope)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		if actual != BlockedSelection {
			failures = append(failures, fmt.Errorf("Service %s rejection was not applied", scope))
			continue
		}
		readback[scope] = actual
	}
	return readback, errors.Join(failures...)
}

func ApplySelections(ctx context.Context, selector Selector, desired map[string]string) (map[string]string, error) {
	scopes := make([]string, 0, len(desired))
	for scope := range desired {
		scopes = append(scopes, scope)
	}
	sort.Strings(scopes)
	readback := make(map[string]string, len(scopes))
	var failures []error
	for _, scope := range scopes {
		apply := func() error {
			current, err := selector.Read(ctx, scope)
			if err != nil {
				return err
			}
			if current != desired[scope] {
				if err := selector.Set(ctx, scope, desired[scope]); err != nil {
					return err
				}
			}
			actual, err := selector.Read(ctx, scope)
			if err != nil {
				return fmt.Errorf("selector %s readback failed: %w", scope, err)
			}
			if actual != desired[scope] {
				return fmt.Errorf("selector %s readback does not match applied candidate", scope)
			}
			readback[scope] = actual
			return nil
		}
		if err := apply(); err != nil {
			if errors.Is(err, ErrSelectionSuperseded) {
				return readback, err
			}
			blocked, rejectErr := RejectSelections(ctx, selector, []string{scope})
			for key, value := range blocked {
				readback[key] = value
			}
			failures = append(failures, errors.Join(err, rejectErr))
		}
	}
	return readback, errors.Join(failures...)
}

func (selector *HTTPSelector) Health(ctx context.Context) error {
	body, err := selector.request(ctx, http.MethodGet, "/version", nil)
	if err != nil {
		return err
	}
	var result struct {
		Version string `json:"version"`
	}
	if json.Unmarshal(body, &result) != nil || result.Version == "" {
		return errors.New("runtime API readback is invalid")
	}
	return nil
}
