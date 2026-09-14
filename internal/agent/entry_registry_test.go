package agent

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestEntryProbeRegistryFreezesFirstSnapshotPerUnderlayGeneration(t *testing.T) {
	serviceContext, cancel := context.WithCancel(context.Background())
	defer cancel()
	registry, err := NewEntryProbeRegistry(serviceContext)
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int64
	probe := func(context.Context, ClientEntry) (time.Duration, error) {
		calls.Add(1)
		return 7 * time.Millisecond, nil
	}
	first := []ClientEntry{
		{Node: "entry-a", Address: "192.0.2.1", Source: "192.0.2.2"},
		{Node: "entry-b", Address: "192.0.2.1", Source: "192.0.2.2"},
	}
	results, measured, err := registry.results(context.Background(), "underlay-a", first, probe)
	if err != nil || calls.Load() != 1 || len(results) != 2 || !measured["entry-a"] || !measured["entry-b"] {
		t.Fatalf("first results=%+v measured=%+v calls=%d err=%v", results, measured, calls.Load(), err)
	}
	second := []ClientEntry{
		first[0],
		{Node: "entry-c", Address: "192.0.2.3", Source: "192.0.2.2"},
	}
	results, measured, err = registry.results(context.Background(), "underlay-a", second, probe)
	if err != nil || calls.Load() != 1 || len(results) != 1 || !measured["entry-a"] || measured["entry-c"] {
		t.Fatalf("reused results=%+v measured=%+v calls=%d err=%v", results, measured, calls.Load(), err)
	}
	results, measured, err = registry.results(context.Background(), "underlay-b", second, probe)
	if err != nil || calls.Load() != 3 || len(results) != 2 || !measured["entry-c"] {
		t.Fatalf("next generation results=%+v measured=%+v calls=%d err=%v", results, measured, calls.Load(), err)
	}
}

func TestEntryProbeRegistryRejectsForkedNodeCoordinates(t *testing.T) {
	registry, err := NewEntryProbeRegistry(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = registry.results(context.Background(), "underlay-a", []ClientEntry{
		{Node: "entry-a", Address: "192.0.2.1"},
		{Node: "entry-a", Address: "192.0.2.2"},
	}, nil)
	if err == nil {
		t.Fatal("接受了同一入口 identity 的分叉坐标")
	}
}
