package clientmodel

import (
	"reflect"
	"testing"
	"time"
)

func TestDirectedPathEstimatesDoNotTreatUnknownAsZero(t *testing.T) {
	edges := []PathEdge{
		{ID: "demo-ab", From: "demo-a", To: "demo-b", RTT: duration(10 * time.Millisecond)},
		{ID: "demo-bx", From: "demo-b", To: "demo-exit", RTT: duration(20 * time.Millisecond)},
		{ID: "demo-ax", From: "demo-a", To: "demo-exit"},
		{ID: "demo-cycle", From: "demo-b", To: "demo-a", RTT: duration(0)},
	}
	for _, order := range [][]PathEdge{edges, {edges[3], edges[2], edges[1], edges[0]}} {
		paths, err := ShortestMeasuredPaths(order, map[string]time.Duration{"demo-exit": 5 * time.Millisecond}, 0)
		if err != nil {
			t.Fatal(err)
		}
		got := paths["demo-a"]
		if got.RTT != 35*time.Millisecond || !reflect.DeepEqual(got.EdgeIDs, []string{"demo-ab", "demo-bx"}) {
			t.Fatalf("unknown edge displaced measured path: %+v", got)
		}
		if _, found := paths["demo-unmeasured"]; found {
			t.Fatal("invented a reachable vertex")
		}
	}
	paths, err := ShortestMeasuredPaths(edges, map[string]time.Duration{"demo-a": 0}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, found := paths["demo-exit"]; found {
		t.Fatal("reversed a directed edge")
	}
}

func TestDirectedPathEstimatesRespectExitCostsLimitsAndStableTies(t *testing.T) {
	edges := []PathEdge{
		{ID: "demo-ac", From: "demo-a", To: "demo-c", RTT: duration(10 * time.Millisecond)},
		{ID: "demo-cx", From: "demo-c", To: "demo-x", RTT: duration(10 * time.Millisecond)},
		{ID: "demo-ay", From: "demo-a", To: "demo-y", RTT: duration(25 * time.Millisecond)},
	}
	paths, err := ShortestMeasuredPaths(edges, map[string]time.Duration{"demo-x": 20 * time.Millisecond, "demo-y": 0}, 0)
	if err != nil || paths["demo-a"].Exit != "demo-y" {
		t.Fatal("ignored exit-to-target cost", paths, err)
	}
	paths, err = ShortestMeasuredPaths(edges, map[string]time.Duration{"demo-x": 0}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, found := paths["demo-a"]; found {
		t.Fatal("exceeded explicit edge limit")
	}
	if _, err := ShortestMeasuredPaths(append(edges, edges[0]), map[string]time.Duration{"demo-x": 0}, 0); err == nil {
		t.Fatal("accepted duplicated edge identity")
	}
	if _, err := ShortestMeasuredPaths([]PathEdge{{ID: "demo-negative", From: "demo-a", To: "demo-x", RTT: duration(-1)}}, map[string]time.Duration{"demo-x": 0}, 0); err == nil {
		t.Fatal("accepted negative RTT")
	}
}

func duration(value time.Duration) *time.Duration { return &value }

func TestHopBoundKeepsMoreExpensiveShortSuffixWhenRequired(t *testing.T) {
	edges := []PathEdge{{ID: "demo-source-a", From: "demo-source", To: "demo-a", RTT: duration(time.Millisecond)}, {ID: "demo-a-b", From: "demo-a", To: "demo-b", RTT: duration(time.Millisecond)}, {ID: "demo-b-c", From: "demo-b", To: "demo-c", RTT: duration(time.Millisecond)}, {ID: "demo-c-exit", From: "demo-c", To: "demo-exit", RTT: duration(time.Millisecond)}, {ID: "demo-b-exit", From: "demo-b", To: "demo-exit", RTT: duration(8 * time.Millisecond)}}
	paths, err := ShortestMeasuredPaths(edges, map[string]time.Duration{"demo-exit": 0}, 3)
	if err != nil || paths["demo-source"].RTT != 10*time.Millisecond || len(paths["demo-source"].EdgeIDs) != 3 {
		t.Fatal("cheaper long suffix hid the usable bounded path", paths["demo-source"], err)
	}
}
