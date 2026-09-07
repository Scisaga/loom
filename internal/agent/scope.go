package agent

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"slices"
	"sort"
	"strconv"
	"time"
)

// decisionScope identifies the complete set of semantics under which a sample
// may influence a selector decision. Candidate tags alone are not enough: the
// same tag can survive a target, route, or access-node change while describing
// a different end-to-end path.
//
// Slice order is not decision semantics, so targets and candidates are sorted
// before hashing. Every field is length-prefixed to keep the encoding
// unambiguous without creating another wire format.
func decisionScope(node string, d *Decl) string {
	h := sha256.New()
	field := func(v string) {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(v)))
		_, _ = h.Write(size[:])
		_, _ = h.Write([]byte(v))
	}
	duration := func(raw string) string {
		if parsed, err := time.ParseDuration(raw); err == nil {
			return parsed.String()
		}
		return raw
	}

	field("loom-agent-decision-scope-v1")
	field(node)
	field(d.ID)
	field(d.Selector)
	field(string(d.Objective))
	field(duration(d.TuningPeriod))
	field(strconv.FormatFloat(d.SwitchThreshold, 'g', -1, 64))
	field(duration(d.Window))
	field(strconv.Itoa(d.MinSamples))
	field(duration(d.StaleAfter))
	field(strconv.Itoa(d.ProbeBudget))

	targets := append([]string(nil), d.Targets...)
	sort.Strings(targets)
	field(strconv.Itoa(len(targets)))
	for _, target := range targets {
		field(target)
	}

	candidates := append([]Cand(nil), d.Candidates...)
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].Tag != candidates[j].Tag {
			return candidates[i].Tag < candidates[j].Tag
		}
		if n := slices.Compare(candidates[i].Chain, candidates[j].Chain); n != 0 {
			return n < 0
		}
		return candidates[i].ProbeUser < candidates[j].ProbeUser
	})
	field(strconv.Itoa(len(candidates)))
	for _, candidate := range candidates {
		field(candidate.Tag)
		field(strconv.Itoa(len(candidate.Chain)))
		for _, hop := range candidate.Chain {
			field(hop)
		}
		field(candidate.ProbeUser)
	}
	return hex.EncodeToString(h.Sum(nil))
}
