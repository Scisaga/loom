//go:build windows

package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"loom/internal/clientreport"
	"loom/internal/clientruntime"
)

func TestWindowsReportRetainsPathsWhenHealthUsesDeadline(t *testing.T) {
	r, path, _ := healthReporterFixture(t)
	want := &clientreport.AgentState{Node: "demo-client", Selections: []clientreport.AgentSelection{{Declaration: "demo-service"}}}
	r.readPaths = func(ctx context.Context, _ *clientruntime.WindowsAgent, _ time.Time) (*clientreport.AgentState, error) {
		if err := ctx.Err(); err != nil {
			t.Fatal("读取路径前健康探测已耗尽预算")
		}
		return want, nil
	}
	r.check = func(ctx context.Context, _ *clientruntime.WindowsHealthPlan) []string {
		<-ctx.Done()
		return []string{"端到端探测超时"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, problems, got, ok := r.sampleReport(ctx, path, time.Now())
	if !ok || got != want || len(problems) != 1 || problems[0] != "端到端探测超时" {
		t.Fatalf("健康超时丢失路径或引入虚假路径故障：%v %v %v", ok, got, problems)
	}
}

func TestWindowsReportSeparatesUnknownSamplesFromFailure(t *testing.T) {
	r, path, _ := healthReporterFixture(t)
	r.check = func(context.Context, *clientruntime.WindowsHealthPlan) []string { return nil }
	for _, selected := range []string{"unknown", "stale", "success", "degraded", "failed"} {
		t.Run(selected, func(t *testing.T) {
			r.readPaths = func(context.Context, *clientruntime.WindowsAgent, time.Time) (*clientreport.AgentState, error) {
				return &clientreport.AgentState{Selections: []clientreport.AgentSelection{{Declaration: "demo-service", Health: &clientreport.AgentCandidateHealth{SelectedState: selected, SelectedSamples: 2, SelectedFailures: 1}}}}, nil
			}
			_, problems, _, ok := r.sampleReport(context.Background(), path, time.Now())
			failed := selected == "degraded" || selected == "failed"
			if !ok || (len(problems) != 0) != failed {
				t.Fatalf("样本状态与失败事实混淆：%s %v", selected, problems)
			}
			if failed && (!strings.Contains(problems[0], "demo-service") || !strings.Contains(problems[0], "1/2")) {
				t.Fatalf("缺少具体失败范围：%v", problems)
			}
		})
	}
}

func TestWindowsReportDiscardsPathsAcrossActivation(t *testing.T) {
	r, path, state := healthReporterFixture(t)
	r.check = func(context.Context, *clientruntime.WindowsHealthPlan) []string { return nil }
	r.readPaths = func(context.Context, *clientruntime.WindowsAgent, time.Time) (*clientreport.AgentState, error) {
		state.Applied = "abcdef012345"
		r.update(state)
		return &clientreport.AgentState{Node: "demo-client"}, nil
	}
	if _, _, _, ok := r.sampleReport(context.Background(), path, time.Now()); ok {
		t.Fatal("上一代路径与下一代健康结果混入同一报告")
	}
}
