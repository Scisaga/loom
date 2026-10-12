//go:build windows

package main

import (
	"slices"
	"strings"
	"testing"
	"time"

	"loom/internal/clientmodel"
	"loom/internal/control"
)

func TestWindowsBusinessDisplayKeepsTargetsTimesAndFailureScope(t *testing.T) {
	now := time.Date(2030, 1, 1, 0, 0, 20, 0, time.UTC)
	view := control.DeviceView{Routes: []control.RouteCandidate{{ID: "demo-a", Scope: "service:demo-a"}, {ID: "demo-b", Scope: "service:demo-b"}},
		BusinessProbeTargets: []control.ServiceProbeTargets{{ServiceID: "demo-a", Targets: []string{"https://web.example/", "https://web.example/extra"}}, {ServiceID: "demo-b", Targets: []string{"https://api.example/"}}}}
	sample := func(candidate, target, result string) clientmodel.Observation {
		return clientmodel.Observation{CandidateID: candidate, Scope: "service:" + candidate, NetworkGeneration: "demo-network", Action: "https_request", Target: target, Result: result, ObservedAt: "2030-01-01T00:00:00Z", ValidUntil: "2030-01-01T00:00:30Z"}
	}
	status := windowsRuntimeStatus{RuntimeState: "running", NetworkGeneration: "demo-network", Observations: []clientmodel.Observation{
		sample("demo-a", "https://web.example/", "available"), sample("demo-a", "https://web.example/extra", "available"), sample("demo-b", "https://api.example/", "unavailable")}}
	a := windowsBusinessDetails(view, status, "service:demo-a", "demo-a", now)
	b := windowsBusinessDetails(view, status, "service:demo-b", "", now)
	for _, value := range []string{"https://web.example/ · 可用", "https://web.example/extra · 可用", "业务采样：2030-01-01 00:00:00 UTC", "有效至：2030-01-01 00:00:30 UTC", "候选 demo-a", "网络 demo-network"} {
		if !strings.Contains(a, value) {
			t.Fatal("missing original business detail", value, a)
		}
	}
	if !strings.Contains(b, "历史不可用；当前结果未知") || strings.Contains(a, "api.example") || strings.Contains(b, "web.example") {
		t.Fatal("Service outcomes or sources were combined", a, b)
	}
	copy := status
	copy.Observations = slices.Clone(status.Observations)
	slices.Reverse(copy.Observations)
	if windowsBusinessDetails(view, copy, "service:demo-a", "demo-a", now) != a {
		t.Fatal("input order changed UI evidence")
	}
	expired := windowsBusinessDetails(view, status, "service:demo-a", "demo-a", now.Add(10*time.Second))
	if !strings.Contains(expired, "历史可用；当前结果未知") {
		t.Fatal("expiry refreshed an original sample", expired)
	}
	for _, change := range []func(*clientmodel.Observation){
		func(o *clientmodel.Observation) { o.NetworkGeneration = "demo-other" },
		func(o *clientmodel.Observation) { o.Target = "https://other.example/" },
		func(o *clientmodel.Observation) { o.CandidateID = "demo-revoked" },
		func(o *clientmodel.Observation) { o.Scope = "service:demo-b" },
		func(o *clientmodel.Observation) { o.ObservedAt = "2030-01-01T00:00:21Z" },
	} {
		other := status
		value := status.Observations[0]
		change(&value)
		other.Observations = []clientmodel.Observation{value}
		text := windowsBusinessDetails(view, other, "service:demo-a", "demo-a", now)
		if strings.Contains(text, " · 可用") || strings.Contains(text, "业务采样") {
			t.Fatal("foreign or future sample created business evidence", text)
		}
	}
	conflict := status.Observations[0]
	conflict.Result = "unavailable"
	other := status
	other.Observations = append(slices.Clone(status.Observations), conflict)
	if strings.Contains(windowsBusinessDetails(view, other, "service:demo-a", "demo-a", now), "https://web.example/ · 可用") {
		t.Fatal("same-time conflict chose a winner")
	}
}
