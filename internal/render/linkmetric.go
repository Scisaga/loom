package render

import (
	"fmt"
	"sort"

	"loom/internal/model"
)

// LinkMetricReflectorPort is the isolated report reflector.  Unlike 61802 it
// serves no status/UI route and is reachable through telemetry auth only.
const LinkMetricReflectorPort = 61804

// Hy2LinkProbePortBase is a loopback-only mixed-listener range.  It is outside
// the public UDP allocation range and the existing 61800..61804 control ports.
const Hy2LinkProbePortBase = 61820

type hy2LinkProbePlan struct {
	From, To string
	Port     int
}

func (p hy2LinkProbePlan) inboundTag() string  { return "hy2-link-in-" + p.To }
func (p hy2LinkProbePlan) outboundTag() string { return "hy2-link-" + p.To }
func (p hy2LinkProbePlan) user() string        { return "telemetry-" + p.From }
func (p hy2LinkProbePlan) secretRef() string   { return "telemetry/" + p.From }
func (p hy2LinkProbePlan) proxyAddr() string {
	return fmt.Sprintf("127.0.0.1:%d", p.Port)
}

// hy2LinkProbePlans derives one actual dial direction for every pair on the
// directly reachable inner ring.  A node with no public Hysteria2 inbound
// (currently jm24) can still be the source but can never be invented as the
// target.  When both ends accept inbound, lexical order picks a stable single
// direction; the UI renders the pair as one undirected curve and discloses the
// measured direction in its detail text.
func hy2LinkProbePlans(s *model.SSOT) []hy2LinkProbePlan {
	if s == nil {
		return nil
	}
	var inner []*model.Node
	for i := range s.Nodes {
		n := &s.Nodes[i]
		if n.Decommission || !n.MeshEligible() || !runsSingBox(n) {
			continue
		}
		inner = append(inner, n)
	}
	sort.Slice(inner, func(i, j int) bool { return inner[i].ID < inner[j].ID })

	var out []hy2LinkProbePlan
	for i := 0; i < len(inner); i++ {
		for j := i + 1; j < len(inner); j++ {
			a, b := inner[i], inner[j]
			from, to := a, b
			switch {
			case b.PubliclyDialable() && b.Server.InboundProtocol.Or() == model.Hysteria2:
				// Stable default: lexical a -> b.
			case a.PubliclyDialable() && a.Server.InboundProtocol.Or() == model.Hysteria2:
				from, to = b, a
			default:
				continue
			}
			out = append(out, hy2LinkProbePlan{From: from.ID, To: to.ID})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].From+"\x00"+out[i].To < out[j].From+"\x00"+out[j].To
	})
	for i := range out {
		out[i].Port = Hy2LinkProbePortBase + i
	}
	return out
}
