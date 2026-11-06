package control

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"math"
	"os"
	"reflect"
	"testing"
	"time"
)

func measurementWindowFixture(t *testing.T, count int) (Projection, DeviceView, func(string) (DeviceView, string, error)) {
	t.Helper()
	p := hy2ProjectionFixture(t)
	targets := []string{}
	for i := 0; i < count; i++ {
		targets = append(targets, fmt.Sprintf("https://demo-%03d.example/health", i))
	}
	p.NetworkIntent.Services[0].ProbeURLs = targets
	viewFor := deviceLinkViewFor(func(id string) (DeviceView, error) { return ProjectDeviceView(p, id) })
	view, _, err := viewFor("demo-access")
	if err != nil {
		t.Fatal(err)
	}
	return p, view, viewFor
}
func measurementWindowRows(t *testing.T, page measurementQueryPage) []DeviceLinkObservation {
	t.Helper()
	at := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	rows := []DeviceLinkObservation{}
	for _, item := range page.queries {
		sample := item.query.spec
		sample.NetworkGeneration = "demo-network"
		sample.Result = "available"
		sample.ObservedAt = at.UnixMilli()
		sample.ValidUntil = at.Add(time.Minute).UnixMilli()
		sample.DurationMS = new(int64(1))
		rows = append(rows, DeviceLinkObservation{DeviceID: item.query.source, ReportSequence: 1, ReportDigest: ReleaseDigest([]byte("demo-original")), CurrentUntil: sample.ValidUntil, Observation: sample})
	}
	return rows
}
func measurementWindowFull(view DeviceView) DeviceLinkObservations {
	digest, _ := DeviceViewDigest(view)
	return DeviceLinkObservations{Schema: 3, NetworkID: view.NetworkID, DeviceID: view.DeviceID, ViewDigest: digest, Cursor: measurementCursorSizeValue(0), Reset: true, Removed: []string{}, Observations: []DeviceLinkObservation{}}
}

func TestMeasurementWindowUnknownPagesAdvanceAcrossEveryCacheMiss(t *testing.T) {
	p, view, viewFor := measurementWindowFixture(t, 7)
	bounds := defaultMeasurementDeliveryBounds
	bounds.Scans, bounds.Queries, bounds.Sources = 2, 2, 1
	cursor := ""
	seen := map[string]bool{}
	for round := 0; round < 8; round++ {
		calls := 0
		page, err := deviceMeasurementQueryPage(context.Background(), p, view, func(id string) (DeviceView, string, error) { calls++; return viewFor(id) }, measurementPosition(cursor), bounds)
		if err != nil || len(page.queries) > 2 || calls > 1 {
			t.Fatal("query work escaped its page", len(page.queries), calls, err)
		}
		for _, item := range page.queries {
			seen[item.query.spec.Target] = true
		}
		full, next, err := selectMeasurementWindow(measurementWindowFull(view), page, nil, bounds)
		if err != nil {
			t.Fatal(err)
		}
		// Each request deliberately reaches another empty control/cache.
		server := &Server{}
		reply, err := server.issueMeasurementDelivery(full, cursor, measurementDeliveryOptions{next, bounds})
		if err != nil || !reply.Reset || reply.Cursor == cursor {
			t.Fatal("unknown cache-miss page did not advance", err)
		}
		cursor = reply.Cursor
	}
	if len(seen) != 7 {
		t.Fatal("stable queries were starved by repeated cache loss", len(seen))
	}
	page, err := deviceMeasurementQueryPage(context.Background(), p, view, viewFor, math.MaxUint64, bounds)
	if err != nil || len(page.queries) == 0 {
		t.Fatal("untrusted position was not safely normalized", err)
	}
}

func TestMeasurementBytePageRetriesTheFirstItemThatDoesNotFit(t *testing.T) {
	p, view, viewFor := measurementWindowFixture(t, 2)
	bounds := defaultMeasurementDeliveryBounds
	page, err := deviceMeasurementQueryPage(context.Background(), p, view, viewFor, 0, bounds)
	if err != nil || len(page.queries) != 2 {
		t.Fatal(err)
	}
	rows := measurementWindowRows(t, page)
	base, _ := CanonicalEncode(measurementWindowFull(view))
	first, _ := CanonicalEncode(rows[0])
	bounds.Bytes = len(base) + len(first) + 1
	full, next, err := selectMeasurementWindow(measurementWindowFull(view), page, rows, bounds)
	if err != nil || len(full.Observations) != 1 || next != page.queries[1].position {
		t.Fatal("page tail was advanced past a valid item", next, err)
	}
	nextPage, err := deviceMeasurementQueryPage(context.Background(), p, view, viewFor, next, bounds)
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := selectMeasurementWindow(measurementWindowFull(view), nextPage, measurementWindowRows(t, nextPage), bounds)
	if err != nil || len(second.Observations) != 1 || second.Observations[0].Observation.Target != rows[1].Observation.Target {
		t.Fatal("valid tail item never entered the next page", err)
	}
}

func TestMeasurementDeltaFallsBackToResetAndMergedOverflowPreservesBase(t *testing.T) {
	p, view, viewFor := measurementWindowFixture(t, 4)
	bounds := defaultMeasurementDeliveryBounds
	page, err := deviceMeasurementQueryPage(context.Background(), p, view, viewFor, 0, bounds)
	if err != nil {
		t.Fatal(err)
	}
	rows := measurementWindowRows(t, page)
	old, next := measurementWindowFull(view), measurementWindowFull(view)
	old.Observations = rows[:2]
	next.Observations = rows[2:]
	oldBytes, _ := CanonicalEncode(old)
	nextBytes, _ := CanonicalEncode(next)
	bounds.Bytes = max(len(oldBytes), len(nextBytes)) + 1
	server := &Server{}
	initial, err := server.issueMeasurementDelivery(old, "", measurementDeliveryOptions{0, bounds})
	if err != nil {
		t.Fatal(err)
	}
	base, err := MergeMeasurementDelivery(nil, initial, view)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := CanonicalEncode(base)
	delta := next
	delta.Reset = false
	delta.Cursor = measurementCursorSizeValue(2)
	if _, err := mergeMeasurementDelivery(&base, delta, view, bounds.Bytes); err == nil {
		t.Fatal("small delta grew cumulative snapshot beyond its budget")
	}
	after, _ := CanonicalEncode(base)
	if !bytes.Equal(before, after) {
		t.Fatal("rejected union modified its exact base")
	}
	reply, err := server.issueMeasurementDelivery(next, initial.Cursor, measurementDeliveryOptions{2, bounds})
	if err != nil || !reply.Reset || len(reply.Removed) != 0 {
		t.Fatal("oversized delta+Removed was not replaced by bounded reset", err)
	}
	if len(server.measurements) == 0 || server.measurements[len(server.measurements)-1].token != reply.Cursor {
		t.Fatal("new cursor immediately evicted its own working set")
	}
	merged, err := mergeMeasurementDelivery(&base, reply, view, bounds.Bytes)
	if err != nil || !reflect.DeepEqual(merged.Observations, next.Observations) {
		t.Fatal("bounded reset did not replace the old exact base", err)
	}
}

func TestSingleMeasurementSpecsRetainTheFormerCanonicalMeaning(t *testing.T) {
	p := relayProjectionFixture(t)
	view, err := ProjectDeviceView(p, "demo-access")
	if err != nil {
		t.Fatal(err)
	}
	inventory := newMeasurementInventory(view)
	links, err := DerivedViewLinks(view)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range links {
		got, allowed, err := inventory.link(want.FromNodeID, want.ResourceID)
		if err != nil || !allowed || !sameContractValue(got, want) {
			t.Fatal("single link changed the published topology", err)
		}
		legacy, err := digestContractValue("loom-directed-link-spec-v3\x00", map[string]any{"network_id": view.NetworkID, "link": want, "receiver_resource": inventory.byResource[want.ResourceID], "source_node_id": want.FromNodeID, "source_wireguard_public_key": inventory.nodes[want.FromNodeID].WireGuardPublicKey, "dns_servers": append([]string{}, inventory.nodes[want.FromNodeID].DNSServers...)})
		current, nowErr := directedLinkSpec(view.NetworkID, got, inventory.nodes[got.FromNodeID], inventory.byResource[got.ResourceID])
		if err != nil || nowErr != nil || current != legacy {
			t.Fatal("single link rewrote the original specification", err, nowErr)
		}
	}
	exit, err := ProjectDeviceView(p, "demo-exit")
	if err != nil {
		t.Fatal(err)
	}
	for _, service := range finalInternetServices(exit) {
		for _, target := range service.ProbeURLs {
			legacy, err := digestContractValue("loom-egress-probe-v3\x00", map[string]any{"network_id": exit.NetworkID, "source": exit.DeviceID, "target": target, "action": "https_request", "method": "GET", "redirect": "none", "body_limit": 4096, "tls_minimum": "TLS1.2", "timeout_ms": 8000, "dns_servers": exit.DNSServers, "public_internet": service.IsPublicInternet()})
			current, nowErr := egressProbeSpec(exit.NetworkID, exit.DeviceID, target, exit.DNSServers, service.IsPublicInternet())
			if err != nil || nowErr != nil || legacy != current {
				t.Fatal("single request rewrote its original specification", err, nowErr)
			}
		}
	}
}

func TestMeasurementWorkingSetCombinesPagesAndAdmitsColdFreshRowsFirst(t *testing.T) {
	p := relayProjectionFixture(t)
	p.NetworkIntent.Services[0].ProbeURLs = []string{"https://demo-service.example/health"}
	viewFor := deviceLinkViewFor(func(id string) (DeviceView, error) { return ProjectDeviceView(p, id) })
	view, _, err := viewFor("demo-access")
	if err != nil {
		t.Fatal(err)
	}
	bounds := defaultMeasurementDeliveryBounds
	all, err := deviceMeasurementQueryPage(context.Background(), p, view, viewFor, 0, bounds)
	if err != nil {
		t.Fatal(err)
	}
	var link, exit positionedMeasurementQuery
	for _, item := range all.queries {
		if item.query.spec.Level == "link" && item.query.source == "demo-entry" {
			link = item
		}
		if item.query.spec.Level == "egress" {
			exit = item
		}
	}
	if link.query.source == "" || exit.query.source == "" {
		t.Fatal("fixture has no independently reusable segment and egress")
	}
	now := time.Date(2030, 1, 2, 3, 4, 6, 0, time.UTC)
	first := measurementWindowRows(t, measurementQueryPage{queries: []positionedMeasurementQuery{link}})
	secondPage := measurementQueryPage{queries: []positionedMeasurementQuery{exit}, next: 1}
	secondRows := measurementWindowRows(t, secondPage)
	fresh, _, err := selectMeasurementWindow(measurementWindowFull(view), secondPage, secondRows, bounds)
	if err != nil {
		t.Fatal(err)
	}
	combined, err := retainMeasurementWorkingSet(fresh, first, secondPage, nil, view, now, bounds)
	if err != nil || len(combined.Observations) != 2 || combined.ValidateForView(view) != nil {
		t.Fatal("link and egress could never coexist across pages", err)
	}
	// A head-only generation change invalidates the old source even without a
	// new matching sample. Another source's original remains unchanged.
	empty := measurementWindowFull(view)
	retained, err := retainMeasurementWorkingSet(empty, combined.Observations, measurementQueryPage{}, map[string]string{link.query.source: "demo-next-network"}, view, now, bounds)
	if err != nil || len(retained.Observations) != 1 || retained.Observations[0].DeviceID != exit.query.source {
		t.Fatal("head-only network change left old-generation health", err)
	}
	// With capacity for one row, this page's old-but-valid original gets admitted
	// before a hotter retained row. Delivery age is never measurement age.
	rowBytes, _ := CanonicalEncode(secondRows[0])
	baseBytes, _ := CanonicalEncode(empty)
	bounds.Bytes = len(rowBytes) + len(baseBytes) + 1
	fresh.Observations[0].Observation.ObservedAt -= 1000
	fresh.Observations[0].Observation.ValidUntil -= 1000
	fresh.Observations[0].CurrentUntil -= 1000
	bounded, err := retainMeasurementWorkingSet(fresh, first, secondPage, nil, view, now, bounds)
	if err != nil || len(bounded.Observations) != 1 || !reflect.DeepEqual(bounded.Observations[0], fresh.Observations[0]) {
		t.Fatal("capacity immediately evicted the page's original", err)
	}
}

func TestMeasurementOriginalByteBudgetRetriesItsUnreadQueryAndReturnsHeadGeneration(t *testing.T) {
	store, _, at, first, query, sign := sharedMeasurementFixture(t)
	second := first
	second.Target = "https://demo-other.example/health"
	second.SpecDigest = ReleaseDigest([]byte("demo-other-spec"))
	one, two := sign(1, first.NetworkGeneration, "running", []Observation{first}), sign(2, first.NetworkGeneration, "running", []Observation{second})
	for _, report := range []DeviceReport{one, two, sign(3, first.NetworkGeneration, "running", nil)} {
		if err := store.Put(report, query.publicKey); err != nil {
			t.Fatal(err)
		}
	}
	a, _ := CanonicalEncode(one)
	b, _ := CanonicalEncode(two)
	limit := max(len(a), len(b)) + 1
	queries := []reportMeasurementQuery{query, {source: query.source, publicKey: query.publicKey, spec: second}}
	rows, checked, generations, err := store.latestMeasurementWindow(context.Background(), "demo-network", queries, at.Add(10*time.Second), limit)
	if err != nil || checked != 1 || len(rows) != 1 || generations[query.source] != first.NetworkGeneration {
		t.Fatal("original budget advanced past an unread report", checked, len(rows), err)
	}
	tail, count, _, err := store.latestMeasurementWindow(context.Background(), "demo-network", queries[checked:], at.Add(10*time.Second), limit)
	if err != nil || count != 1 || len(tail) != 1 || tail[0].Observation.Target != second.Target {
		t.Fatal("deferred original could never be read", err)
	}
	if err := store.Put(sign(4, "demo-network-b", "running", nil), query.publicKey); err != nil {
		t.Fatal(err)
	}
	rows, checked, generations, err = store.latestMeasurementWindow(context.Background(), "demo-network", queries, at.Add(10*time.Second), limit)
	if err != nil || checked != 2 || len(rows) != 0 || generations[query.source] != "demo-network-b" {
		t.Fatal("new head generation depended on finding a sample", err)
	}
}

func TestOwnReportLinkSpecificationsUseOnlyTheReportingNode(t *testing.T) {
	p := relayProjectionFixture(t)
	for _, id := range []string{"demo-access", "demo-entry", "demo-exit"} {
		view, err := ProjectDeviceView(p, id)
		if err != nil {
			t.Fatal(err)
		}
		report := DeviceReport{}
		if containsString(view.Responsibilities, "access") {
			report.PolicyID = "demo-policy"
		}
		queries, err := ownMeasurementQueries(view, report)
		if err != nil {
			t.Fatal(err)
		}
		whole, err := LinkSpecifications(view)
		if err != nil {
			t.Fatal(err)
		}
		links, err := DerivedViewLinks(view)
		if err != nil {
			t.Fatal(err)
		}
		expected := map[string]string{}
		for _, link := range links {
			if link.FromNodeID == id {
				expected[link.ID] = whole[link.ID]
			}
		}
		actual := map[string]string{}
		for _, query := range queries {
			if query.spec.Level == "link" {
				if query.source != id {
					t.Fatal("foreign report query was added")
				}
				actual[query.spec.LinkID] = query.spec.SpecDigest
			}
		}
		if !reflect.DeepEqual(expected, actual) {
			t.Fatal("reporting node lost the previous exact link specifications", id)
		}
	}
}

func TestMeasurementPageMarksKnownUnusableHeadsWithoutRevivingCachedFacts(t *testing.T) {
	for _, scenario := range []string{"stopped", "fork"} {
		t.Run(scenario, func(t *testing.T) {
			store, _, at, sample, query, sign := sharedMeasurementFixture(t)
			if err := store.Put(sign(1, sample.NetworkGeneration, "running", []Observation{sample}), query.publicKey); err != nil {
				t.Fatal(err)
			}
			state := "running"
			if scenario == "stopped" {
				state = "stopped"
			}
			head := sign(3, sample.NetworkGeneration, state, nil)
			if err := store.Put(head, query.publicKey); err != nil {
				t.Fatal(err)
			}
			if scenario == "fork" {
				if err := store.Put(sign(3, sample.NetworkGeneration, "stopped", nil), query.publicKey); err != ErrReportEquivocation {
					t.Fatal("fork evidence was not retained", err)
				}
			}
			now := at.Add(40 * time.Second)
			rows, checked, generations, err := store.latestMeasurementWindow(context.Background(), "demo-network", []reportMeasurementQuery{query}, now, MeasurementDeliveryLimit)
			generation, known := generations[query.source]
			if err != nil || checked != 1 || len(rows) != 0 || !known || generation != "" {
				t.Fatal("an unusable head retained current source health", err)
			}
		})
	}
}

func TestMeasurementCarryUsesOriginalDeadlineAcrossReportSilence(t *testing.T) {
	p, _, _ := measurementWindowFixture(t, 1)
	key := testKey(t)
	public := base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
	for i := range p.DeviceAuthorizations {
		if p.DeviceAuthorizations[i].ID == "demo-exit" {
			p.DeviceAuthorizations[i].DevicePublicKey = public
		}
	}
	viewFor := deviceLinkViewFor(func(id string) (DeviceView, error) { return ProjectDeviceView(p, id) })
	view, _, err := viewFor("demo-access")
	if err != nil {
		t.Fatal(err)
	}
	source, digest, err := viewFor("demo-exit")
	if err != nil {
		t.Fatal(err)
	}
	page, err := deviceMeasurementQueryPage(context.Background(), p, view, viewFor, 0, defaultMeasurementDeliveryBounds)
	if err != nil || len(page.queries) != 1 {
		t.Fatal(err)
	}
	at := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	sample := measurementWindowRows(t, page)[0].Observation
	sample.ValidUntil = at.Add(10 * time.Minute).UnixMilli()
	report, err := SignDeviceReport(DeviceReport{Schema: 3, NetworkID: source.NetworkID, DeviceID: source.DeviceID, ReportSequence: 1, ViewDigest: digest, NetworkGeneration: sample.NetworkGeneration, ReportedAt: at.UnixMilli(), Runtime: RuntimeReadback{State: "running", AppliedViewDigest: digest}, Selections: []ReportSelection{}, Observations: []Observation{sample}, Components: []ComponentReadback{}}, key)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	store, err := testOpenObservationStore(t, root)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put(report, public); err != nil {
		t.Fatal(err)
	}
	rows, _, _, err := store.latestMeasurementWindow(context.Background(), source.NetworkID, []reportMeasurementQuery{page.queries[0].query}, at.Add(time.Second), MeasurementDeliveryLimit)
	if err != nil || len(rows) != 1 || rows[0].CurrentUntil != sample.ValidUntil || rows[0].Observation.ValidUntil != sample.ValidUntil {
		t.Fatal("report age replaced the original routing measurement deadline", err)
	}
	for _, elapsed := range []time.Duration{4 * time.Minute, 10 * time.Minute} {
		read, _, _, err := store.latestMeasurementWindow(context.Background(), source.NetworkID, []reportMeasurementQuery{page.queries[0].query}, at.Add(elapsed), MeasurementDeliveryLimit)
		retained, retainErr := retainMeasurementWorkingSet(measurementWindowFull(view), rows, measurementQueryPage{}, nil, view, at.Add(elapsed), defaultMeasurementDeliveryBounds)
		want := 0
		if elapsed < 10*time.Minute {
			want = 1
		}
		if err != nil || retainErr != nil || len(read) != want || len(retained.Observations) != want {
			t.Fatal("report silence changed an original measurement deadline", elapsed, err, retainErr)
		}
	}
}

func TestMeasurementKnownSemanticSlotClearsItsOldSpecificationWithoutASample(t *testing.T) {
	p, view, viewFor := measurementWindowFixture(t, 2)
	page, err := deviceMeasurementQueryPage(context.Background(), p, view, viewFor, 0, defaultMeasurementDeliveryBounds)
	if err != nil || len(page.queries) != 2 {
		t.Fatal(err)
	}
	old := measurementWindowRows(t, page)
	changed := page.queries[0]
	changed.query.spec.SpecDigest, err = egressProbeSpec(view.NetworkID, changed.query.source, changed.query.spec.Target, []string{"192.0.2.54"}, p.NetworkIntent.Services[0].IsPublicInternet())
	if err != nil {
		t.Fatal(err)
	}
	if changed.query.spec.SpecDigest == page.queries[0].query.spec.SpecDigest {
		t.Fatal("fixture did not change the measured resolver")
	}
	now := time.Date(2030, 1, 2, 3, 4, 6, 0, time.UTC)
	result, err := retainMeasurementWorkingSet(measurementWindowFull(view), old, measurementQueryPage{queries: []positionedMeasurementQuery{changed}}, nil, view, now, defaultMeasurementDeliveryBounds)
	if err != nil || len(result.Observations) != 1 || !reflect.DeepEqual(result.Observations[0], old[1]) {
		t.Fatal("a known new spec without a sample revived its old slot or changed an unqueried slot", err)
	}
	fullKey, _ := measurementQueryKey(page.queries[0].query)
	newKey, _ := measurementQueryKey(changed.query)
	if fullKey == newKey {
		t.Fatal("semantic invalidation weakened exact query identity")
	}
}

func TestRoutingMeasurementDeadlineIsIndependentOfReportAge(t *testing.T) {
	at := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	digest := ReleaseDigest([]byte("demo-view"))
	report := DeviceReport{ReportedAt: at.UnixMilli(), NetworkGeneration: "demo-network", ViewDigest: digest, Runtime: RuntimeReadback{State: "running", AppliedViewDigest: digest}}
	sample := Observation{Result: "available", NetworkGeneration: "demo-network", ObservedAt: at.UnixMilli(), ValidUntil: at.Add(10 * time.Minute).UnixMilli()}
	if !measurementHeadReady(report, at.Add(4*time.Minute)) || measurementObservationUntil(report, sample, at.Add(4*time.Minute)) != sample.ValidUntil {
		t.Fatal("report silence shortened the original measurement lifetime")
	}
	for _, scenario := range []string{"expired", "future sample", "future head", "source network", "stopped", "unapplied", "success lifetime", "failure lifetime"} {
		current, value, now := report, sample, at
		switch scenario {
		case "expired":
			now = at.Add(10 * time.Minute)
		case "future sample":
			value.ObservedAt++
		case "future head":
			current.ReportedAt = at.Add(6 * time.Second).UnixMilli()
		case "source network":
			value.NetworkGeneration = "demo-other"
		case "stopped":
			current.Runtime.State = "stopped"
		case "unapplied":
			current.Runtime.AppliedViewDigest = ReleaseDigest([]byte("demo-other-view"))
		case "success lifetime":
			value.ValidUntil++
		case "failure lifetime":
			value.Result = "unavailable"
		}
		if measurementObservationUntil(current, value, now) != 0 {
			t.Fatal("invalid routing measurement became usable", scenario)
		}
	}
}
