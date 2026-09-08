package clientruntime

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestWindowsDirectPathsRequireActualReadback(t *testing.T) {
	body, agentBody := pathPlanFixture(t)
	plan, err := validateWindowsAgentPair(body, agentBody, "")
	if err != nil {
		t.Fatal(err)
	}
	actual := ""
	for _, candidate := range plan.config.Declarations[0].Candidates {
		if len(candidate.Chain) == 0 {
			actual = candidate.Tag
		}
	}
	if actual == "" {
		t.Fatal("缺少直连测试候选")
	}
	var current atomic.Value
	current.Store(actual)
	var gets, puts atomic.Int32
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			puts.Add(1)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+plan.config.APISecret {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		gets.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]string{"type": "Selector", "now": current.Load().(string)})
	}))
	defer api.Close()
	plan.config.API = strings.TrimPrefix(api.URL, "http://")
	now := time.Now().UTC()
	state, err := plan.ReadDirectPaths(context.Background(), now)
	if err != nil || len(state.Selections) != len(plan.config.Declarations) {
		t.Fatalf("直连读回失败: %+v %v", state, err)
	}
	for _, selection := range state.Selections {
		if selection.Candidate != actual || len(selection.Chain) != 0 || selection.Health != nil || selection.UpdatedAt != now.Format(time.RFC3339) {
			t.Fatalf("直连不能伪造 Agent 测量: %+v", selection)
		}
	}
	current.Store("demo-unauthorized-path")
	if state, err = plan.ReadDirectPaths(context.Background(), now); err == nil || state != nil {
		t.Fatalf("偏好直连但实际并非授权零跳候选，应返回未知: %+v %v", state, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	before := gets.Load()
	if state, err = plan.ReadDirectPaths(ctx, now); err == nil || state != nil || gets.Load() != before || puts.Load() != 0 {
		t.Fatalf("取消后不得继续 GET，也不能 PUT: %+v %v gets=%d puts=%d", state, err, gets.Load(), puts.Load())
	}
}

func TestWindowsDirectPathsCancellationInterruptsRead(t *testing.T) {
	body, agentBody := pathPlanFixture(t)
	plan, err := validateWindowsAgentPair(body, agentBody, "")
	if err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{})
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		<-r.Context().Done()
	}))
	defer api.Close()
	plan.config.API = strings.TrimPrefix(api.URL, "http://")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		state, err := plan.ReadDirectPaths(ctx, time.Now())
		if state != nil {
			t.Error("取消的读回不得返回路径")
		}
		done <- err
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("测试 GET 未开始")
	}
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("取消必须拒绝本轮观测")
		}
	case <-time.After(time.Second):
		t.Fatal("取消未中断 GET")
	}
}
