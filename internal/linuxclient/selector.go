package linuxclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
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
	CloseConnections(context.Context) error
}

type HTTPSelector struct {
	secret string
	client *http.Client
}

func NewHTTPSelector(config string) (*HTTPSelector, error) {
	var control profileControl
	if err := json.Unmarshal([]byte(config), &control); err != nil {
		return nil, err
	}
	if control.Experimental.ClashAPI.ExternalController != "127.0.0.1:61800" ||
		len(control.Experimental.ClashAPI.Secret) == 0 || len(control.Experimental.ClashAPI.Secret) > 4<<10 {
		return nil, errors.New("Linux selector control is invalid")
	}
	for _, character := range control.Experimental.ClashAPI.Secret {
		if character < 0x21 || character > 0x7e {
			return nil, errors.New("Linux selector secret is invalid")
		}
	}
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	return &HTTPSelector{secret: control.Experimental.ClashAPI.Secret,
		client: &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: nil,
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return dialer.DialContext(ctx, "tcp", "127.0.0.1:61800")
			}}}}, nil
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
	response, err := selector.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(response.Body, 4<<10+1))
	if err != nil {
		return nil, err
	}
	if len(responseBody) > 4<<10 || response.StatusCode < 200 || response.StatusCode > 299 {
		return nil, fmt.Errorf("selector API returned HTTP %d", response.StatusCode)
	}
	return responseBody, nil
}

func (selector *HTTPSelector) Read(ctx context.Context, scope string) (string, error) {
	body, err := selector.request(ctx, http.MethodGet, "/proxies/"+url.PathEscape(scope), nil)
	if err != nil {
		return "", err
	}
	var response struct {
		Now string `json:"now"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(&response); err != nil || response.Now == "" {
		return "", errors.New("selector readback is invalid")
	}
	return response.Now, nil
}

func (selector *HTTPSelector) Set(ctx context.Context, scope, candidate string) error {
	body, _ := json.Marshal(struct {
		Name string `json:"name"`
	}{candidate})
	_, err := selector.request(ctx, http.MethodPut, "/proxies/"+url.PathEscape(scope), body)
	return err
}

func (selector *HTTPSelector) CloseConnections(ctx context.Context) error {
	_, err := selector.request(ctx, http.MethodDelete, "/connections/", nil)
	return err
}

func waitSelector(ctx context.Context, selector Selector, scopes []string) error {
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	var last error
	for {
		ready := true
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

func applySelections(ctx context.Context, selector Selector, desired map[string]string) (map[string]string, error) {
	scopes := make([]string, 0, len(desired))
	for scope := range desired {
		scopes = append(scopes, scope)
	}
	sort.Strings(scopes)
	before := make(map[string]string, len(scopes))
	for _, scope := range scopes {
		current, err := selector.Read(ctx, scope)
		if err != nil {
			return nil, err
		}
		before[scope] = current
	}
	changed := []string{}
	rollback := func(cause error) error {
		var failures []error
		for index := len(changed) - 1; index >= 0; index-- {
			if err := selector.Set(ctx, changed[index], before[changed[index]]); err != nil {
				failures = append(failures, err)
			}
		}
		if len(changed) > 0 {
			if err := selector.CloseConnections(ctx); err != nil {
				failures = append(failures, err)
			}
		}
		return errors.Join(append([]error{cause}, failures...)...)
	}
	for _, scope := range scopes {
		if before[scope] == desired[scope] {
			continue
		}
		if err := selector.Set(ctx, scope, desired[scope]); err != nil {
			return nil, rollback(err)
		}
		changed = append(changed, scope)
	}
	if len(changed) > 0 {
		if err := selector.CloseConnections(ctx); err != nil {
			return nil, rollback(err)
		}
	}
	readback := make(map[string]string, len(scopes))
	for _, scope := range scopes {
		actual, err := selector.Read(ctx, scope)
		if err != nil {
			return nil, rollback(fmt.Errorf("selector %s readback failed: %w", scope, err))
		}
		if actual != desired[scope] {
			return nil, rollback(fmt.Errorf("selector %s readback does not match applied candidate", scope))
		}
		readback[scope] = actual
	}
	return readback, nil
}
