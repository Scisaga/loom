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
	topologyRateWindow = 5 * time.Minute
	topologyRTTWindow  = 15 * time.Minute
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
		// Node.Edges reaches this point only after buildView has accepted direct
		// local evidence or verified the relayed measurement digest. Retaining the
		// signed summary locally avoids a new cross-version observation field.
		for _, edge := range node.Edges {
			if node.ID == "" || edge.To == "" || edge.ObservedAt == "" || edge.Samples <= 0 {
				continue
			}
			frame.Edges = append(frame.Edges, trafficstore.EdgeSample{
				Node: node.ID, Peer: edge.To, TS: edge.ObservedAt, RTTMS: edge.MS,
				Samples: edge.Samples, Failures: edge.Failures,
			})
		}
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

// enrichTopologyLinkMetrics attaches two deliberately different windows:
// five-minute observed WG throughput and fifteen-minute variation of signed
// one-minute RTT medians. Missing samples remain missing rather than becoming
// zero traffic or zero jitter.
func enrichTopologyLinkMetrics(store *trafficstore.Store, at time.Time, links []webui.LinkView) error {
	if store == nil || len(links) == 0 {
		return nil
	}
	rateStart := at.UTC().Add(-topologyRateWindow)
	buckets, err := store.Query(rateStart, at.UTC(), topologyRateWindow)
	if err != nil {
		return err
	}
	quality, err := store.QueryLinkQuality(at.UTC().Add(-topologyRTTWindow), at.UTC())
	if err != nil {
		return err
	}
	byKey := map[string]*webui.LinkView{}
	for i := range links {
		if links[i].Kind != "tunnel" {
			continue
		}
		byKey[trafficstore.LinkID(links[i].From, links[i].To)] = &links[i]
	}
	for _, bucket := range buckets {
		for _, totals := range bucket.Links {
			link := byKey[trafficstore.LinkID(totals.From, totals.To)]
			if link == nil {
				continue
			}
			link.RecentTXBytes = totals.TXBytes
			link.RateWindowSeconds = int64(topologyRateWindow / time.Second)
			link.RateSamples = totals.Samples
			link.RateReportingEndpoints = totals.ReportingEndpoints
		}
	}
	for _, item := range quality {
		link := byKey[trafficstore.LinkID(item.From, item.To)]
		if link == nil {
			continue
		}
		link.QualityP50MS = item.P50MS
		link.QualityP95MS = item.P95MS
		link.QualityObservations = item.Observations
		link.QualityFailed = item.FailedObservations
		link.MetricsObservedAt = item.LastObservedAt
	}
	for _, link := range byKey {
		link.MetricsWindow = "WG 5m throughput · RTT 15m variation"
		link.MetricsSource = "signed report.neighbors + independently signed loom-traffic-v1"
	}
	return nil
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
