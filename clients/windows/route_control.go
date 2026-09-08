package main

import (
	"context"
	"errors"
	"sync"

	"loom/internal/clientcore"
)

type routeRequest struct {
	preference clientcore.Preference
	done       chan error
}
type routeControl struct {
	requests chan routeRequest
	done     chan struct{}
	mu       sync.RWMutex
	state    clientRuntimeState
	persist  func(clientcore.Preference) error
}

var routeControls sync.Map

func (c *routeControl) update(state clientRuntimeState) { c.mu.Lock(); c.state = state; c.mu.Unlock() }
func (c *routeControl) snapshot() clientRuntimeState {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.state
}
func (c *routeControl) apply(ctx context.Context, p clientcore.Preference) error {
	req := routeRequest{preference: p, done: make(chan error, 1)}
	select {
	case c.requests <- req:
	case <-ctx.Done():
		return ctx.Err()
	case <-c.done:
		return errors.New("[§7.2] 数据面已停止")
	}
	// §7.2：请求一旦入队，就等待激活事务的实际结果，不能把超时冒充回滚。
	select {
	case err := <-req.done:
		return err
	case <-c.done:
		return errors.New("[§7.2] 数据面已停止")
	}
}
func activeRouteControl(root string) (*routeControl, error) {
	c, ok := routeControls.Load(root)
	if !ok {
		return nil, errors.New("本地数据面尚未提供出口控制")
	}
	return c.(*routeControl), nil
}

func (a *clientActivation) withPreference(p clientcore.Preference) (*clientActivation, error) {
	if a.Policy == nil {
		return nil, errors.New("[§5.1] 缺少当前签名 Agent plan")
	}
	body, cfg, err := a.Policy.Derive(a.BaseConfig, p)
	if err != nil {
		return nil, err
	}
	next := *a
	next.Config = body
	next.BaseConfig = append([]byte(nil), a.BaseConfig...)
	next.AgentConfig = cfg
	next.AgentRuntime = nil
	next.Preference = p
	return &next, nil
}

func applyRouteRequest(ctx context.Context, manager *activationManager, control *routeControl, req routeRequest) error {
	if manager.active == nil {
		return errors.New("[§7.2] 数据面未激活")
	}
	old := manager.active.spec
	next, err := old.withPreference(req.preference)
	if err != nil {
		return err
	}
	// §12：持久偏好失败也回滚完整配置与 Agent，不能只把 GUI 文案改回去。
	restore, err := old.withPreference(old.Preference)
	if err != nil {
		next.clear()
		return err
	}
	defer restore.clear()
	if _, err := manager.Replace(ctx, next); err != nil {
		return err
	}
	if err := control.persist(req.preference); err != nil {
		rollback, copyErr := restore.withPreference(restore.Preference)
		if copyErr != nil {
			return errors.Join(err, copyErr)
		}
		_, rollbackErr := manager.Replace(ctx, rollback)
		return errors.Join(err, rollbackErr)
	}
	return nil
}
