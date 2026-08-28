package webui

import (
	"sort"
	"strconv"
	"time"
)

func trafficExport(view View) TrafficExportView {
	out := TrafficExportView{
		SchemaVersion: 1, Scope: "node-local", Node: view.Self,
		GeneratedAt: view.ObservedAt, HistoryStatus: view.TrafficHistoryStatus,
		HistoryError: view.TrafficHistoryError, History: trafficHistoryExport(view.TrafficHistory),
		Current: make([]TrafficCurrentCounterView, 0),
	}
	if view.IntentSource == "current SSOT" {
		out.Scope = "control"
	}
	if out.HistoryStatus == "" {
		if view.TrafficHistory != nil {
			out.HistoryStatus = "available"
		} else {
			out.HistoryStatus = "not_supported"
		}
	}
	for _, node := range view.Nodes {
		if node.ID != view.Self && !node.Self {
			continue
		}
		for _, tunnel := range node.Tunnels {
			if !tunnel.CounterPresent {
				continue
			}
			if out.CurrentObservedAt == "" {
				out.CurrentObservedAt = node.TrafficObservedAt
			}
			if laterTimestamp(tunnel.CounterObservedAt, out.CurrentObservedAt) {
				out.CurrentObservedAt = tunnel.CounterObservedAt
			}
			out.Current = append(out.Current, TrafficCurrentCounterView{
				Interface: tunnel.Interface, PeerNode: tunnel.PeerNode, LinkID: tunnel.LinkID,
				RXBytes: decimalBytes(tunnel.RxBytes), TXBytes: decimalBytes(tunnel.TxBytes), Epoch: tunnel.CounterEpoch,
				ObservedAt: tunnel.CounterObservedAt, Source: tunnel.CounterSource,
				Trusted: tunnel.TrafficTrusted, Verified: tunnel.TrafficVerified,
			})
		}
		// Legacy/direct status payloads may have trustworthy current counters
		// without the newer traffic attachment timestamp. Keep the export useful
		// while making the evidence boundary explicit in each counter's Trusted /
		// Verified fields.
		if out.CurrentObservedAt == "" && len(out.Current) > 0 {
			out.CurrentObservedAt = node.ObservedAt
		}
		break
	}
	if out.CurrentObservedAt == "" && len(out.Current) > 0 {
		out.CurrentObservedAt = view.ObservedAt
	}
	sort.Slice(out.Current, func(i, j int) bool {
		if out.Current[i].Interface != out.Current[j].Interface {
			return out.Current[i].Interface < out.Current[j].Interface
		}
		return out.Current[i].PeerNode < out.Current[j].PeerNode
	})
	return out
}

func trafficHistoryExport(history *TrafficHistoryView) *TrafficHistoryExportView {
	if history == nil {
		return nil
	}
	out := &TrafficHistoryExportView{
		WindowStart: history.WindowStart, WindowEnd: history.WindowEnd,
		BucketWidth: history.BucketWidth, Source: history.Source,
		Buckets: make([]TrafficBucketExportView, 0, len(history.Buckets)),
	}
	for _, bucket := range history.Buckets {
		item := TrafficBucketExportView{
			Start: bucket.Start, End: bucket.End, Samples: bucket.Samples,
			Resets: bucket.Resets, Gaps: bucket.Gaps,
		}
		for _, node := range bucket.Nodes {
			item.Nodes = append(item.Nodes, TrafficNodeTotalsExportView{
				Node: node.Node, RXBytes: decimalBytes(node.RXBytes), TXBytes: decimalBytes(node.TXBytes),
				Bytes: decimalBytes(node.Bytes), Samples: node.Samples, Resets: node.Resets, Gaps: node.Gaps,
			})
		}
		for _, link := range bucket.Links {
			item.Links = append(item.Links, TrafficLinkTotalsExportView{
				From: link.From, To: link.To, TXBytes: decimalBytes(link.TXBytes),
				ReportingEndpoints: link.ReportingEndpoints, Samples: link.Samples,
				Resets: link.Resets, Gaps: link.Gaps,
			})
		}
		out.Buckets = append(out.Buckets, item)
	}
	return out
}

func decimalBytes(value int64) string {
	if value < 0 {
		value = 0
	}
	return strconv.FormatInt(value, 10)
}

func laterTimestamp(candidate, current string) bool {
	if candidate == "" {
		return false
	}
	if current == "" {
		return true
	}
	candidateAt, candidateErr := time.Parse(time.RFC3339, candidate)
	currentAt, currentErr := time.Parse(time.RFC3339, current)
	if candidateErr != nil {
		return false
	}
	return currentErr != nil || candidateAt.After(currentAt)
}
