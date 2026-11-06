package clientmodel

import (
	"container/heap"
	"errors"
	"math"
	"slices"
	"time"
)

// PathEdge is a filtered, authorized directed segment. Unknown RTTs are kept
// by callers for exploration and never contribute zero to measured estimates.
type PathEdge struct {
	ID, From, To string
	RTT          *time.Duration
}
type PathEstimate struct {
	Exit           string
	RTT            time.Duration
	Nodes, EdgeIDs []string
}
type pathLabel struct {
	node string
	path PathEstimate
}
type pathQueue []pathLabel

func (q pathQueue) Len() int { return len(q) }
func (q pathQueue) Less(i, j int) bool {
	if estimateLess(q[i].path, q[j].path) {
		return true
	}
	if estimateLess(q[j].path, q[i].path) {
		return false
	}
	return q[i].node < q[j].node
}
func (q pathQueue) Swap(i, j int)   { q[i], q[j] = q[j], q[i] }
func (q *pathQueue) Push(value any) { *q = append(*q, value.(pathLabel)) }
func (q *pathQueue) Pop() any {
	old := *q
	value := old[len(old)-1]
	*q = old[:len(old)-1]
	return value
}

type pathState struct {
	node  string
	steps int
}

// ShortestMeasuredPaths runs reverse Dijkstra once for all entries sharing an
// exit/constraint set. Unlimited hops use O((V+E) log V) queue work. An explicit
// hop constraint keeps separate step labels; a cheaper long suffix cannot erase
// the shorter suffix needed by a predecessor's remaining hop allowance.
func ShortestMeasuredPaths(edges []PathEdge, exitCosts map[string]time.Duration, maxEdges int) (map[string]PathEstimate, error) {
	if len(exitCosts) == 0 || maxEdges < 0 {
		return nil, errors.New("path computation requires exits and a valid edge limit")
	}
	vertices, identities := map[string]bool{}, map[string]bool{}
	reverse := map[string][]PathEdge{}
	for _, edge := range edges {
		if !validName(edge.ID) || !validName(edge.From) || !validName(edge.To) || edge.From == edge.To || identities[edge.ID] || edge.RTT != nil && *edge.RTT < 0 {
			return nil, errors.New("directed edges are invalid or duplicated")
		}
		identities[edge.ID], vertices[edge.From], vertices[edge.To] = true, true, true
		if edge.RTT != nil {
			reverse[edge.To] = append(reverse[edge.To], edge)
		}
	}
	queue := &pathQueue{}
	heap.Init(queue)
	best := map[pathState]PathEstimate{}
	result := map[string]PathEstimate{}
	state := func(node string, path PathEstimate) pathState {
		steps := 0
		if maxEdges > 0 {
			steps = len(path.EdgeIDs)
		}
		return pathState{node, steps}
	}
	for exit, cost := range exitCosts {
		if !validName(exit) || cost < 0 {
			return nil, errors.New("exit cost is invalid")
		}
		vertices[exit] = true
		path := PathEstimate{Exit: exit, RTT: cost, Nodes: []string{exit}, EdgeIDs: []string{}}
		best[state(exit, path)] = path
		heap.Push(queue, pathLabel{exit, path})
	}
	limit := len(vertices) - 1
	if maxEdges > 0 && maxEdges < limit {
		limit = maxEdges
	}
	for queue.Len() > 0 {
		label := heap.Pop(queue).(pathLabel)
		path := label.path
		key := state(label.node, path)
		if current, found := best[key]; !found || estimateLess(current, path) {
			continue
		}
		if previous, found := result[label.node]; !found || estimateLess(path, previous) {
			result[label.node] = path
		}
		if len(path.EdgeIDs) >= limit {
			continue
		}
		for _, edge := range reverse[label.node] {
			if slices.Contains(path.Nodes, edge.From) || int64(*edge.RTT) > math.MaxInt64-int64(path.RTT) {
				continue
			}
			next := PathEstimate{Exit: path.Exit, RTT: *edge.RTT + path.RTT, Nodes: append([]string{edge.From}, path.Nodes...), EdgeIDs: append([]string{edge.ID}, path.EdgeIDs...)}
			key := state(edge.From, next)
			if previous, found := best[key]; found && !estimateLess(next, previous) {
				continue
			}
			best[key] = next
			heap.Push(queue, pathLabel{edge.From, next})
		}
	}
	return result, nil
}
func estimateLess(left, right PathEstimate) bool {
	if left.RTT != right.RTT {
		return left.RTT < right.RTT
	}
	if len(left.EdgeIDs) != len(right.EdgeIDs) {
		return len(left.EdgeIDs) < len(right.EdgeIDs)
	}
	if left.Exit != right.Exit {
		return left.Exit < right.Exit
	}
	return slices.Compare(left.EdgeIDs, right.EdgeIDs) < 0
}
