package report

import (
	"sort"
	"time"

	trafficstore "loom/internal/traffic"
	"loom/internal/webui"
)

// TrafficPath is control-node state, not SSOT. It contains independently
// signed runtime observations and can be rebuilt by observing the network
// again; publishing it would turn transient evidence into desired state.
const TrafficPath = "/var/lib/loom/traffic.jsonl"

const (
	trafficRetention   = 30 * 24 * time.Hour
	trafficViewWindow  = 24 * time.Hour
	trafficBucketWidth = time.Hour
	// Traffic sampling is a protocol cadence, not an operator-tunable policy.
	// Report renders one-minute gossip rounds; three missed rounds are the fixed
	// conservative transition boundary persisted with every new frame.
	trafficMaximumGap = 3 * time.Minute
)

// trafficFrameFromView crosses the final storage trust boundary. buildView has
// already verified loom-traffic-v1 and bound its node and timestamp to the
// containing observation. Requiring TrafficVerified (rather than merely a
// direct/current counter) makes it impossible to turn an unsigned /status
// sample or a legacy relay into retained history.
func trafficFrameFromView(v webui.View, collectedAt time.Time) trafficstore.Frame {
	frame := trafficstore.Frame{CollectedAt: collectedAt.UTC().Format(time.RFC3339)}
	for _, node := range v.Nodes {
		if node.ID == "" || !node.TrafficVerified {
			continue
		}
		for _, counter := range node.VerifiedTraffic {
			if counter.Interface == "" || counter.PeerNode == "" ||
				counter.CounterEpoch == "" || counter.ObservedAt == "" {
				continue
			}
			frame.Counters = append(frame.Counters, trafficstore.Counter{
				Node: node.ID, Peer: counter.PeerNode, Interface: counter.Interface,
				PeerPublicKey: counter.PeerPublicKey, Epoch: counter.CounterEpoch,
				TS: counter.ObservedAt, RXBytes: counter.RXBytes, TXBytes: counter.TXBytes,
			})
		}
	}
	return frame
}

func trafficHistoryFromStore(store *trafficstore.Store, at time.Time) (*webui.TrafficHistoryView, error) {
	if store == nil {
		return nil, nil
	}
	end := at.UTC()
	start := end.Add(-trafficViewWindow)
	buckets, err := store.Query(start, end, trafficBucketWidth)
	if err != nil {
		return nil, err
	}
	history := &webui.TrafficHistoryView{
		WindowStart: start.Format(time.RFC3339),
		WindowEnd:   end.Format(time.RFC3339),
		BucketWidth: trafficBucketWidth.String(),
		Source:      "independently signed loom-traffic-v1 · control retention 30d",
		Buckets:     make([]webui.TrafficBucketView, 0, len(buckets)),
	}
	for _, bucket := range buckets {
		item := webui.TrafficBucketView{
			Start: bucket.Start, End: bucket.End, Samples: bucket.Samples,
			Resets: bucket.Resets, Gaps: bucket.Gaps,
		}
		nodeIDs := make([]string, 0, len(bucket.Nodes))
		for nodeID := range bucket.Nodes {
			nodeIDs = append(nodeIDs, nodeID)
		}
		sort.Strings(nodeIDs)
		for _, nodeID := range nodeIDs {
			totals := bucket.Nodes[nodeID]
			item.Nodes = append(item.Nodes, webui.TrafficNodeTotalsView{
				Node: nodeID, RXBytes: totals.RXBytes, TXBytes: totals.TXBytes,
				Bytes: totals.Bytes, Samples: totals.Samples,
				Resets: totals.Resets, Gaps: totals.Gaps,
			})
		}
		linkIDs := make([]string, 0, len(bucket.Links))
		for linkID := range bucket.Links {
			linkIDs = append(linkIDs, linkID)
		}
		sort.Strings(linkIDs)
		for _, linkID := range linkIDs {
			totals := bucket.Links[linkID]
			item.Links = append(item.Links, webui.TrafficLinkTotalsView{
				From: totals.From, To: totals.To, TXBytes: totals.TXBytes,
				ReportingEndpoints: totals.ReportingEndpoints, Samples: totals.Samples,
				Resets: totals.Resets, Gaps: totals.Gaps,
			})
		}
		history.Buckets = append(history.Buckets, item)
	}
	return history, nil
}
