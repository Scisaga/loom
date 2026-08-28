package webui

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// trafficBucketPoint is a presentation-only time bucket. Present distinguishes
// a sampled zero-byte interval from a missing interval; drawing a zero-height
// bar for the latter would turn missing evidence into a traffic claim.
type trafficBucketPoint struct {
	Start, End               string
	RXBytes, TXBytes         int64
	Present                  bool
	Samples                  int
	Resets, Gaps             int
	BucketResets, BucketGaps int
}

func writeFleetTrafficHistory(b *strings.Builder, view View) {
	b.WriteString(`<div class=section><div class=sectionhead><h3>Fleet forwarding · last 24 hours</h3><span class="sp tiny dim">retained counter deltas · time-bucket bars</span></div>`)
	history := view.TrafficHistory
	if history == nil {
		writeMissingTrafficHistory(b, view, "fleet")
		b.WriteString(`</div>`)
		return
	}
	if len(history.Buckets) == 0 {
		fmt.Fprintf(b, `<div class="callout warnline"><b>The retained window returned no buckets</b><br><span class=small>%s · no chart is drawn.</span></div></div>`, esc(historyWindowLabel(history)))
		return
	}

	points := make([]trafficBucketPoint, 0, len(history.Buckets))
	var total int64
	covered, resets, gaps := 0, 0, 0
	for _, bucket := range history.Buckets {
		point := trafficBucketPoint{
			Start: bucket.Start, End: bucket.End, Samples: bucket.Samples,
			Resets: bucket.Resets, Gaps: bucket.Gaps,
		}
		for _, node := range bucket.Nodes {
			// A reset/gap-only node entry carries useful quality evidence but no
			// accepted traffic delta. Only Samples proves that zero bytes really
			// means a sampled idle interval rather than missing evidence.
			if node.Samples > 0 {
				point.Present = true
			}
			point.RXBytes = saturatingCounterAdd(point.RXBytes, node.RXBytes)
			point.TXBytes = saturatingCounterAdd(point.TXBytes, node.TXBytes)
			value := trafficNodeBytes(node)
			total = saturatingCounterAdd(total, value)
		}
		// A sampler may retain an accepted zero-byte transition. Samples makes
		// that evidence visible even if an adapter omitted a zero-valued node.
		if bucket.Samples > 0 {
			point.Present = true
		}
		if point.Present {
			covered++
		}
		resets += bucket.Resets
		gaps += bucket.Gaps
		points = append(points, point)
	}
	if covered == 0 {
		fmt.Fprintf(b, `<div class="callout warnline"><b>No accepted fleet delta in this window</b><br><span class=small>%s · %d reset transition(s) · %d long gap(s). Missing buckets are not rendered as zero traffic.</span></div></div>`, esc(historyWindowLabel(history)), resets, gaps)
		return
	}

	fmt.Fprintf(b, `<div class=grid><div class=span3><div class=label>Node-interface delta total</div><div class=metric>%s</div></div><div class=span3><div class=label>Buckets with samples</div><div class=metric>%d <small>/ %d</small></div></div><div class=span3><div class=label>Rejected resets</div><div class=metric>%d</div></div><div class=span3><div class=label>Long gaps</div><div class=metric>%d</div></div></div>`, esc(byteSize(total)), covered, len(points), resets, gaps)
	writeTrafficBucketChart(b, points, false, "Fleet node-interface WireGuard byte deltas by retained time bucket")
	fmt.Fprintf(b, `<div class=barlabel><span>%s</span><span>%s · bucket %s</span></div>`, esc(historyTimeLabel(history.WindowStart)), esc(historyTimeLabel(history.WindowEnd)), esc(orDash(history.BucketWidth)))
	b.WriteString(`<p class="tiny dim">Fleet node-interface total sums RX+TX deltas on every reporting Loom WireGuard interface. It is hop-weighted (and normally represented at both endpoints), so it is not unique application payload volume. A bucket with samples does not prove that every expected interface reported. Resets and long gaps contribute no bytes.</p>`)
	if history.Source != "" {
		fmt.Fprintf(b, `<p class="tiny dim">Source: %s</p>`, esc(history.Source))
	}
	b.WriteString(`</div>`)
}

func writeNodeTrafficHistory(b *strings.Builder, view View, nodeID string) {
	b.WriteString(`<div class=section><div class=sectionhead><h3>Retained forwarding history</h3><span class="sp tiny dim">RX / TX deltas by time bucket</span></div>`)
	history := view.TrafficHistory
	if history == nil {
		writeMissingTrafficHistory(b, view, "node")
		b.WriteString(`</div>`)
		return
	}
	if len(history.Buckets) == 0 {
		fmt.Fprintf(b, `<div class="callout warnline"><b>The retained window returned no buckets for %s</b><br><span class=small>%s · no chart is drawn.</span></div></div>`, esc(nodeID), esc(historyWindowLabel(history)))
		return
	}

	points := make([]trafficBucketPoint, 0, len(history.Buckets))
	var total, rxTotal, txTotal int64
	covered, nodeResets, nodeGaps := 0, 0, 0
	windowResets, windowGaps := 0, 0
	for _, bucket := range history.Buckets {
		point := trafficBucketPoint{Start: bucket.Start, End: bucket.End,
			BucketResets: bucket.Resets, BucketGaps: bucket.Gaps}
		for _, node := range bucket.Nodes {
			if node.Node != nodeID {
				continue
			}
			if node.Samples > 0 {
				point.Present = true
			}
			point.RXBytes = saturatingCounterAdd(point.RXBytes, node.RXBytes)
			point.TXBytes = saturatingCounterAdd(point.TXBytes, node.TXBytes)
			point.Samples += node.Samples
			point.Resets += node.Resets
			point.Gaps += node.Gaps
			total = saturatingCounterAdd(total, trafficNodeBytes(node))
			rxTotal = saturatingCounterAdd(rxTotal, node.RXBytes)
			txTotal = saturatingCounterAdd(txTotal, node.TXBytes)
		}
		if point.Present {
			covered++
		}
		nodeResets += point.Resets
		nodeGaps += point.Gaps
		windowResets += bucket.Resets
		windowGaps += bucket.Gaps
		points = append(points, point)
	}
	if covered == 0 {
		fmt.Fprintf(b, `<div class="callout warnline"><b>No accepted historical delta for %s</b><br><span class=small>The fleet window exists, but this node has accepted samples in 0 / %d buckets. Window-wide quality flags: %d reset transition(s), %d long gap(s); they are not attributed to this node by this view. No chart is drawn.</span></div></div>`, esc(nodeID), len(points), windowResets, windowGaps)
		return
	}

	fmt.Fprintf(b, `<div class=grid><div class=span3><div class=label>Historical RX</div><div class=metric>%s</div></div><div class=span3><div class=label>Historical TX</div><div class=metric>%s</div></div><div class=span3><div class=label>Buckets with samples</div><div class=metric>%d <small>/ %d</small></div></div><div class=span3><div class=label>Accepted delta total</div><div class=metric>%s</div></div></div>`, esc(byteSize(rxTotal)), esc(byteSize(txTotal)), covered, len(points), esc(byteSize(total)))
	writeTrafficBucketChart(b, points, true, "WireGuard receive and transmit byte deltas for node "+nodeID+" by retained time bucket")
	fmt.Fprintf(b, `<div class=barlabel><span>%s</span><span>%s · bucket %s</span></div><div class=legend><span><i class="counterkey rx"></i>RX delta</span><span><i class="counterkey tx"></i>TX delta</span><span>Missing bucket ≠ zero traffic</span></div>`, esc(historyTimeLabel(history.WindowStart)), esc(historyTimeLabel(history.WindowEnd)), esc(orDash(history.BucketWidth)))
	fmt.Fprintf(b, `<p class="tiny dim">Node-attributed quality: %d reset transition(s) · %d long gap(s). Window-wide bucket flags: %d reset transition(s) · %d long gap(s). Rejected transitions contribute no bytes; window-wide flags are not silently attributed to %s.</p>`, nodeResets, nodeGaps, windowResets, windowGaps, esc(nodeID))
	if history.Source != "" {
		fmt.Fprintf(b, `<p class="tiny dim">Source: %s</p>`, esc(history.Source))
	}
	b.WriteString(`</div>`)
}

type trafficLinkAggregate struct {
	From, To                           string
	TXBytes                            int64
	SampleBuckets, BothEndpointBuckets int
	Resets, Gaps                       int
	Declared                           bool
}

func writeTopologyTraffic(b *strings.Builder, view View) {
	intentSource := intentSourceLabel(view)
	b.WriteString(`<div class=section><section class=card><div class=sectionhead><h2>WireGuard link forwarding · last 24 hours</h2><span class="sp tiny dim">sum of endpoint TX deltas · bar comparison</span></div>`)
	history := view.TrafficHistory
	if history == nil {
		writeMissingTrafficHistory(b, view, "link")
		b.WriteString(`</section></div>`)
		return
	}
	if len(history.Buckets) == 0 {
		fmt.Fprintf(b, `<div class="callout warnline"><b>The retained window returned no link buckets</b><br><span class=small>%s · no comparison chart is drawn.</span></div></section></div>`, esc(historyWindowLabel(history)))
		return
	}

	aggregates := map[string]*trafficLinkAggregate{}
	for _, link := range view.Links {
		if link.Kind != "tunnel" || link.From == "" || link.To == "" {
			continue
		}
		from, to, key := canonicalTrafficLink(link.From, link.To)
		agg := aggregates[key]
		if agg == nil {
			agg = &trafficLinkAggregate{From: from, To: to}
			aggregates[key] = agg
		}
		agg.Declared = true
	}
	for _, bucket := range history.Buckets {
		// Collapse duplicate presentation entries inside one bucket before
		// counting sample buckets. A bucket is counted once, never once per endpoint.
		bucketLinks := map[string]TrafficLinkTotalsView{}
		for _, link := range bucket.Links {
			if link.From == "" || link.To == "" || link.From == link.To {
				continue
			}
			from, to, key := canonicalTrafficLink(link.From, link.To)
			item := bucketLinks[key]
			item.From, item.To = from, to
			item.TXBytes = saturatingCounterAdd(item.TXBytes, link.TXBytes)
			item.Samples += link.Samples
			item.Resets += link.Resets
			item.Gaps += link.Gaps
			if link.ReportingEndpoints > item.ReportingEndpoints {
				item.ReportingEndpoints = link.ReportingEndpoints
			}
			bucketLinks[key] = item
		}
		for key, link := range bucketLinks {
			agg := aggregates[key]
			if agg == nil {
				agg = &trafficLinkAggregate{From: link.From, To: link.To}
				aggregates[key] = agg
			}
			agg.TXBytes = saturatingCounterAdd(agg.TXBytes, link.TXBytes)
			agg.Resets += link.Resets
			agg.Gaps += link.Gaps
			// Quality-only link entries attribute a reset/gap without claiming a
			// sampled zero-byte bucket. Older adapters did not expose Samples, so
			// ReportingEndpoints remains a compatible positive sample signal.
			if link.Samples > 0 || link.ReportingEndpoints > 0 {
				agg.SampleBuckets++
				if link.ReportingEndpoints >= 2 {
					agg.BothEndpointBuckets++
				}
			}
		}
	}

	links := make([]*trafficLinkAggregate, 0, len(aggregates))
	var maxBytes, totalBytes int64
	sampledLinks := 0
	for _, aggregate := range aggregates {
		links = append(links, aggregate)
		if aggregate.SampleBuckets > 0 {
			sampledLinks++
		}
		if aggregate.TXBytes > maxBytes {
			maxBytes = aggregate.TXBytes
		}
		totalBytes = saturatingCounterAdd(totalBytes, aggregate.TXBytes)
	}
	sort.Slice(links, func(i, j int) bool {
		if links[i].TXBytes != links[j].TXBytes {
			return links[i].TXBytes > links[j].TXBytes
		}
		return links[i].From+"\x00"+links[i].To < links[j].From+"\x00"+links[j].To
	})
	if sampledLinks == 0 {
		fmt.Fprintf(b, `<div class="callout warnline"><b>No link bucket contains an accepted TX delta</b><br><span class=small>%s · %d WireGuard link(s) from %s remain listed as missing evidence; quality-only reset/gap attribution is retained below.</span></div>`, esc(historyWindowLabel(history)), len(links), esc(intentSource))
	}

	fmt.Fprintf(b, `<div class=grid><div class=span3><div class=label>Link TX delta total</div><div class=metric>%s</div></div><div class=span3><div class=label>Links with samples</div><div class=metric>%d <small>/ %d</small></div></div><div class=span6><div class=label>Accounting boundary</div><p class=small>Each endpoint contributes TX only. Sender TX is not added again as receiver RX; a multi-hop flow still contributes once on every WG hop it crosses.</p></div></div>`, esc(byteSize(totalBytes)), sampledLinks, len(links))
	b.WriteString(`<div class=linkchart role=img aria-label="WireGuard link transmit byte totals for the retained window"><div class=linkcharthead><span>Inventory edge</span><span>TX-direction total</span><span>Sample buckets / reporting endpoints</span></div>`)
	for _, link := range links {
		label := link.From + " ↔ " + link.To
		declared := "retained history"
		if link.Declared {
			declared = intentSource + " WG"
		}
		fmt.Fprintf(b, `<div class=linkchartrow><span><b class=mono>%s</b><br><small class=dim>%s</small></span>`, esc(label), declared)
		if link.SampleBuckets == 0 {
			fmt.Fprintf(b, `<span class="dim small">No retained TX delta · no bar</span><span class="warn small">0 sample buckets<br><small>R%d · G%d</small></span></div>`, link.Resets, link.Gaps)
			continue
		}
		width := trafficBarHeight(link.TXBytes, maxBytes)
		fmt.Fprintf(b, `<span><span class=linkbartrack><i class=linkbarfill style="width:%d%%"></i></span><small class=mono>%s</small></span><span class=small>%d / %d buckets<br><small class=dim>%d both endpoints · %d one endpoint · R%d · G%d</small></span></div>`, width, esc(byteSize(link.TXBytes)), link.SampleBuckets, len(history.Buckets), link.BothEndpointBuckets, link.SampleBuckets-link.BothEndpointBuckets, link.Resets, link.Gaps)
	}
	b.WriteString(`</div>`)
	fmt.Fprintf(b, `<p class="tiny dim">%s · bucket %s. The sample count includes buckets containing an accepted zero-byte link delta; it is not a claim that every expected reporter was present. Missing evidence is not rendered as zero.</p>`, esc(historyWindowLabel(history)), esc(orDash(history.BucketWidth)))
	b.WriteString(`</section></div>`)
}

func writeMissingTrafficHistory(b *strings.Builder, view View, scope string) {
	subject := map[string]string{
		"fleet": "fleet forwarding history",
		"node":  "node forwarding history",
		"link":  "link history",
	}[scope]
	if subject == "" {
		subject = "forwarding history"
	}
	switch view.TrafficHistoryStatus {
	case "unavailable":
		detail := brief(view.TrafficHistoryError)
		if detail == "" {
			detail = "the control-plane retained store could not be read"
		}
		fmt.Fprintf(b, `<div class="callout warnline"><b>Retained traffic store unavailable</b><br><span class=small>%s is unavailable: %s. Current counters remain point-in-time evidence and are not converted into synthetic history.</span></div>`, esc(subject), esc(detail))
	case "not_supported":
		fmt.Fprintf(b, `<div class="callout warnline"><b>History is not retained on this node</b><br><span class=small>%s is a control-node capability. Current counters remain available, but this node does not fabricate or replicate central time buckets.</span></div>`, esc(subject))
	default:
		fmt.Fprintf(b, `<div class="callout warnline"><b>No centrally retained %s in this view</b><br><span class=small>Retained history was not attached. Current counters remain point-in-time evidence and are not converted into synthetic history.</span></div>`, esc(subject))
	}
}

func writeTrafficBucketChart(b *strings.Builder, points []trafficBucketPoint, paired bool, ariaLabel string) {
	var maxValue int64
	for _, point := range points {
		value := saturatingCounterAdd(point.RXBytes, point.TXBytes)
		if paired {
			if point.RXBytes > maxValue {
				maxValue = point.RXBytes
			}
			if point.TXBytes > maxValue {
				maxValue = point.TXBytes
			}
		} else if value > maxValue {
			maxValue = value
		}
	}
	if maxValue <= 0 {
		maxValue = 1 // accepted zero-byte buckets still get a one-pixel baseline
	}
	fmt.Fprintf(b, `<div class=historychart role=img aria-label="%s">`, esc(ariaLabel))
	for _, point := range points {
		qualityResets, qualityGaps := point.Resets, point.Gaps
		qualityScope, qualityPrefix := "node", ""
		if qualityResets == 0 && qualityGaps == 0 && (point.BucketResets > 0 || point.BucketGaps > 0) {
			qualityResets, qualityGaps = point.BucketResets, point.BucketGaps
			qualityScope = "fleet bucket"
			qualityPrefix = "B "
		}
		title := fmt.Sprintf("%s – %s", historyTimeLabel(point.Start), historyTimeLabel(point.End))
		if !point.Present {
			title += ": missing accepted delta"
		} else {
			title += ": RX " + byteSize(point.RXBytes) + ", TX " + byteSize(point.TXBytes)
		}
		if qualityResets > 0 || qualityGaps > 0 {
			title += fmt.Sprintf("; %s resets %d, gaps %d", qualityScope, qualityResets, qualityGaps)
		}
		fmt.Fprintf(b, `<span class=historybucket title="%s"><span class=historybars>`, esc(title))
		if !point.Present {
			b.WriteString(`<i class=historymissing aria-hidden=true></i>`)
		} else if paired {
			fmt.Fprintf(b, `<i class=historyrx style="height:%d%%"></i><i class=historytx style="height:%d%%"></i>`, trafficBarHeight(point.RXBytes, maxValue), trafficBarHeight(point.TXBytes, maxValue))
		} else {
			fmt.Fprintf(b, `<i class=historytotal style="height:%d%%"></i>`, trafficBarHeight(saturatingCounterAdd(point.RXBytes, point.TXBytes), maxValue))
		}
		b.WriteString(`</span>`)
		if qualityResets > 0 || qualityGaps > 0 {
			fmt.Fprintf(b, `<small class=historyflag>%sR%d G%d</small>`, qualityPrefix, qualityResets, qualityGaps)
		} else {
			b.WriteString(`<small class=historyflag>&nbsp;</small>`)
		}
		b.WriteString(`</span>`)
	}
	b.WriteString(`</div>`)
}

func trafficNodeBytes(node TrafficNodeTotalsView) int64 {
	if node.Bytes > 0 {
		return node.Bytes
	}
	return saturatingCounterAdd(node.RXBytes, node.TXBytes)
}

func nonNegative(value int64) int64 {
	if value < 0 {
		return 0
	}
	return value
}

func trafficBarHeight(value, maxValue int64) int {
	if value <= 0 || maxValue <= 0 {
		return 1
	}
	// Convert before scaling: cumulative WireGuard counters can approach int64
	// limits, where value*100 would overflow and emit a negative CSS height.
	height := int(float64(value) * 100 / float64(maxValue))
	if height < 3 {
		return 3
	}
	return height
}

func canonicalTrafficLink(a, b string) (string, string, string) {
	if b < a {
		a, b = b, a
	}
	return a, b, a + "\x00" + b
}

func historyWindowLabel(history *TrafficHistoryView) string {
	if history == nil {
		return "history unavailable"
	}
	start, end := historyTimeLabel(history.WindowStart), historyTimeLabel(history.WindowEnd)
	if start == "—" && len(history.Buckets) > 0 {
		start = historyTimeLabel(history.Buckets[0].Start)
	}
	if end == "—" && len(history.Buckets) > 0 {
		end = historyTimeLabel(history.Buckets[len(history.Buckets)-1].End)
	}
	return start + " → " + end
}

func historyTimeLabel(raw string) string {
	if raw == "" {
		return "—"
	}
	if parsed, err := time.Parse(time.RFC3339, raw); err == nil {
		return parsed.UTC().Format("2006-01-02 15:04Z")
	}
	return raw
}
