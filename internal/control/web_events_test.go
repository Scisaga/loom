//go:build linux

package control

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"
	"golang.org/x/sys/unix"
)

func eventTestServer(t *testing.T) (*Server, time.Time) {
	t.Helper()
	root, config, genesis := authorityFixture(t)
	if _, err := InitializeAuthority(root, config, genesis); err != nil {
		t.Fatal(err)
	}
	runtime, err := OpenRuntime(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	now := time.Now().UTC().Add(time.Second)
	return &Server{Runtime: runtime, Config: config, Now: func() time.Time { return now }}, now
}
func eventTestReport(t *testing.T, server *Server, sequence int, state string, received time.Time) DeviceReport {
	t.Helper()
	key, err := server.Config.PrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	report := DeviceReport{Schema: 3, NetworkID: server.Config.NetworkID, DeviceID: server.Config.NodeID, ReportSequence: U64(sequence), ReportedAt: received.UnixMilli(), ViewDigest: "sha256:" + strings.Repeat("a", 64), NetworkGeneration: "demo-network", Selections: []ReportSelection{}, Observations: []Observation{}, Components: []ComponentReadback{}, Runtime: RuntimeReadback{State: state, AppliedViewDigest: "sha256:" + strings.Repeat("a", 64)}}
	report, err = SignDeviceReport(report, key)
	if err != nil {
		t.Fatal(err)
	}
	server.Runtime.Reports.now = func() time.Time { return received }
	public, _ := server.Config.PublicKey()
	err = server.Runtime.Reports.Put(report, base64.RawURLEncoding.EncodeToString(public))
	if err != nil {
		t.Fatal(err)
	}
	return report
}
func eventTestQuery(t *testing.T, server *Server, values url.Values) WebEvents {
	t.Helper()
	response := httptest.NewRecorder()
	server.events(response, httptest.NewRequest(http.MethodGet, "/api/control/ui/events?"+values.Encode(), nil))
	if response.Code != http.StatusOK {
		t.Fatalf("event query %d: %s", response.Code, response.Body.String())
	}
	var result WebEvents
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	return result
}
func eventTestValues(q WebEventQuery) url.Values {
	return url.Values{"from": {q.From}, "until": {q.Until}, "kind": {q.Kind}, "source": {q.Source}, "object": {q.Subject}, "q": {q.Search}, "interval": {fmt.Sprint(q.Interval)}, "result": {q.ResultDigest}}
}

func TestWebEventsCachedPredecessorStillReadsActualOriginal(t *testing.T) {
	server, now := eventTestServer(t)
	prior := eventTestReport(t, server, 1, "running", now.Add(-2*time.Minute))
	eventTestReport(t, server, 2, "stopped", now.Add(-time.Minute))
	values := url.Values{"from": {now.Add(-90 * time.Second).Format(time.RFC3339Nano)}, "until": {now.Format(time.RFC3339Nano)}, "kind": {"runtime"}}
	result := eventTestQuery(t, server, values)
	if result.Total != 1 || result.Events[0].From != "running" || result.Events[0].To != "stopped" {
		t.Fatal("query lost its verified predecessor outside the window")
	}
	if err := server.Runtime.Reports.withDatabase(context.Background(), true, func(tx *bolt.Tx) error {
		raw, _ := CanonicalEncode(prior)
		return tx.Bucket(observationBucket).Put(referenceOf(prior).key(ReleaseDigest(raw)), []byte("corrupt"))
	}); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	server.events(response, httptest.NewRequest(http.MethodGet, "/api/control/ui/events?"+values.Encode(), nil))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatal("cached signature replaced a damaged predecessor original")
	}
}

func TestEventRuntimeProjectionKeepsExactBytesKeyAndDisposableCache(t *testing.T) {
	server, now := eventTestServer(t)
	report := eventTestReport(t, server, 1, "running", now.Add(-time.Minute))
	raw, err := CanonicalEncode(report)
	if err != nil {
		t.Fatal(err)
	}
	public, _ := server.Config.PublicKey()
	key := base64.RawURLEncoding.EncodeToString(public)
	ref, runtime, err := server.Runtime.Reports.originalRuntime(raw, key)
	if err != nil || !bytes.Equal(ref.key(ReleaseDigest(raw)), referenceOf(report).key(ReleaseDigest(raw))) || runtime.State != report.Runtime.State || runtime.Resources != nil {
		t.Fatal("runtime projection lost the authenticated identity or retained listener state", err)
	}
	runtime.State = "stopped"
	_, again, err := server.Runtime.Reports.originalRuntime(raw, key)
	if err != nil || again.State != "running" {
		t.Fatal("caller changed the immutable runtime projection", err)
	}
	other := testKey(t)
	otherKey := base64.RawURLEncoding.EncodeToString(other.Public().(ed25519.PublicKey))
	if _, _, err := server.Runtime.Reports.originalRuntime(raw, otherKey); err == nil {
		t.Fatal("a cached runtime accepted a different public key")
	}
	changed := report
	changed.Runtime.State = "stopped"
	changedRaw, _ := CanonicalEncode(changed)
	if _, _, err := server.Runtime.Reports.originalRuntime(changedRaw, key); err == nil {
		t.Fatal("cached runtime replaced verification of changed original bytes")
	}
	values := url.Values{"from": {now.Add(-90 * time.Second).Format(time.RFC3339Nano)}, "until": {now.Format(time.RFC3339Nano)}}
	before := eventTestQuery(t, server, values)
	server.Runtime.Reports.cache.clear()
	after := eventTestQuery(t, server, values)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("deleting the runtime cache changed the complete event result")
	}
}
func TestWebEventsCompleteWindowPaginationExportAndRestart(t *testing.T) {
	server, now := eventTestServer(t)
	start := now.Add(-72 * time.Hour)
	root := server.Runtime.Authority.root
	if err := unix.Setxattr(root, coverageAttribute, binary.BigEndian.AppendUint64(nil, uint64(start.Add(time.Hour).UnixNano())), 0); err != nil {
		t.Fatal(err)
	}
	if err := server.Runtime.Reports.withDatabase(context.Background(), true, func(tx *bolt.Tx) error {
		return tx.Bucket(reportReceptionBucket).Put(receptionSinceKey, binary.BigEndian.AppendUint64(nil, uint64(start.Add(time.Hour).UnixNano())))
	}); err != nil {
		t.Fatal(err)
	}
	var last DeviceReport
	for i := 1; i <= 125; i++ {
		state := "running"
		if i%2 == 0 {
			state = "stopped"
		}
		last = eventTestReport(t, server, i, state, start.Add(2*time.Hour+time.Duration(i)*time.Second))
	}
	// Repeated delivery and an unchanged new report are not new events.
	public, _ := server.Config.PublicKey()
	if err := server.Runtime.Reports.Put(last, base64.RawURLEncoding.EncodeToString(public)); err != nil {
		t.Fatal(err)
	}
	eventTestReport(t, server, 126, last.Runtime.State, now.Add(-time.Minute))
	values := url.Values{"from": {start.Format(time.RFC3339Nano)}, "until": {now.Format(time.RFC3339Nano)}, "kind": {"runtime"}, "object": {server.Config.NodeID}}
	first := eventTestQuery(t, server, values)
	if first.Total != 125 || len(first.Events) != 100 || first.NextCursor == "" || len(first.Buckets) != 432 {
		t.Fatal("complete query was limited to visible rows", first.Total, len(first.Events), len(first.Buckets))
	}
	sum := 0
	for _, bucket := range first.Buckets {
		sum += bucket.Total
	}
	if sum != first.Total || first.Buckets[0].Covered || !first.Buckets[6].Covered || first.Buckets[6].Total != 0 {
		t.Fatal("coverage or complete buckets fabricated events")
	}
	values = eventTestValues(first.Query)
	values.Set("cursor", first.NextCursor)
	second := eventTestQuery(t, server, values)
	if len(second.Events) != 25 || second.NextCursor != "" || second.Total != first.Total || !reflect.DeepEqual(first.Buckets, second.Buckets) {
		t.Fatal("continuation changed window or aggregation")
	}
	ids := map[string]bool{}
	for _, event := range append(first.Events, second.Events...) {
		if ids[event.ID] {
			t.Fatal("duplicate original event")
		}
		ids[event.ID] = true
	}
	values.Del("cursor")
	values.Set("format", "csv")
	response := httptest.NewRecorder()
	server.events(response, httptest.NewRequest(http.MethodGet, "/api/control/ui/events?"+values.Encode(), nil))
	rows, err := csv.NewReader(response.Body).ReadAll()
	if err != nil || len(rows) != 126 || response.Header().Get("X-Loom-Events-Total") != "125" {
		t.Fatal("export did not use the full identical filter", err, len(rows))
	}
	for _, row := range rows[1:] {
		if !ids[row[0]] {
			t.Fatal("export changed record scope")
		}
	}
	values.Del("format")
	// A new report beyond the frozen cutoff belongs only to a refreshed query.
	eventTestReport(t, server, 127, "stopped", now.Add(time.Second))
	after := eventTestQuery(t, server, values)
	if !reflect.DeepEqual(first, after) {
		t.Fatal("new report drifted the fixed window")
	}
	before := testObservationBytes(t, server.Runtime.Reports)
	if err := server.Runtime.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenRuntime(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	server.Runtime = reopened
	after = eventTestQuery(t, server, values)
	if !reflect.DeepEqual(first, after) || !bytes.Equal(before, testObservationBytes(t, reopened.Reports)) {
		t.Fatal("restart changed original bytes or reception history")
	}
	// A rebuildable index never substitutes for reception annotations or originals.
	if err := reopened.Reports.withDatabase(context.Background(), true, func(tx *bolt.Tx) error {
		if err := tx.DeleteBucket(reportIndexBucket); err != nil {
			return err
		}
		if err := ensureReportIndexes(tx); err != nil {
			return err
		}
		return ensureReportReceptions(tx, now)
	}); err != nil {
		t.Fatal(err)
	}
	if got := eventTestQuery(t, server, values); !reflect.DeepEqual(first, got) {
		t.Fatal("index rebuild changed events")
	}
	values.Set("cursor", first.NextCursor)
	values.Set("object", "demo-other")
	response = httptest.NewRecorder()
	server.events(response, httptest.NewRequest(http.MethodGet, "/api/control/ui/events?"+values.Encode(), nil))
	if response.Code != http.StatusBadRequest {
		t.Fatal("cursor accepted another filter")
	}
}

func TestWebEventsOriginalReceptionBoundariesAndAuthorityWrite(t *testing.T) {
	server, now := eventTestServer(t)
	start := now.Add(-time.Hour)
	eventTestReport(t, server, 1, "running", start)
	eventTestReport(t, server, 2, "stopped", now)
	values := url.Values{"from": {start.Format(time.RFC3339Nano)}, "until": {now.Format(time.RFC3339Nano)}, "kind": {"runtime"}}
	result := eventTestQuery(t, server, values)
	if result.Total != 1 || result.Events[0].At != values.Get("from") {
		t.Fatal("event window is not left closed and right open")
	}
	operation, err := EncodeOperation(authorityService("demo-web", "demo-write"))
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	server.AdminHandler().ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/control/operations", bytes.NewReader(operation)))
	if response.Code != http.StatusOK {
		t.Fatal(response.Code, response.Body.String())
	}
	result = eventTestQuery(t, server, url.Values{"kind": {"authority"}, "object": {"demo-web"}, "source": {server.Config.ControlID}})
	if result.Total != 1 || !strings.Contains(result.Events[0].Detail, "service.put") {
		t.Fatal("formal signed write did not reach event query")
	}
	id := result.Events[0].ID
	raw, err := server.Runtime.Authority.Material(id)
	if err != nil {
		t.Fatal(err)
	}
	path, _ := server.Runtime.Authority.materialPath(id)
	received, err := fileReception(path, receptionAttribute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.Runtime.Authority.PutMaterial(raw); err != nil {
		t.Fatal(err)
	}
	retried, err := fileReception(path, receptionAttribute)
	if err != nil || !retried.Equal(received) {
		t.Fatal("redelivery rewrote original reception")
	}
	// Legacy files have no asserted reception. mtime never fills the gap.
	if err := unix.Removexattr(path, receptionAttribute); err != nil {
		t.Fatal(err)
	}
	result = eventTestQuery(t, server, url.Values{"kind": {"authority"}, "object": {"demo-web"}})
	if result.Total != 0 {
		t.Fatal("legacy original was backdated from filesystem time")
	}
	if got, err := os.ReadFile(path); err != nil || !bytes.Equal(got, raw) {
		t.Fatal("event projection rewrote signed bytes")
	}
}

func TestWebEventsRejectAmbiguousQueriesAndChangedOriginalSet(t *testing.T) {
	server, now := eventTestServer(t)
	for _, query := range []string{"unknown=1", "kind=runtime&kind=authority", "interval=010", "interval=1", "kind=made-up", "until=2026-01-01T00:00:00%2B00:00", "from=2026-01-01T00:00:00Z&until=2026-03-01T00:00:00Z", "cursor=abc", "format=json", "result=abc"} {
		response := httptest.NewRecorder()
		server.events(response, httptest.NewRequest(http.MethodGet, "/api/control/ui/events?"+query, nil))
		if response.Code != http.StatusBadRequest {
			t.Fatal("ambiguous query accepted", query, response.Code)
		}
	}
	eventTestReport(t, server, 1, "running", now.Add(-time.Minute))
	first := eventTestQuery(t, server, url.Values{"kind": {"runtime"}})
	// A local clock regression or newly recovered old dependency must produce an
	// explicit refresh conflict, never silently change the original query result.
	eventTestReport(t, server, 2, "stopped", now.Add(-30*time.Second))
	response := httptest.NewRecorder()
	server.events(response, httptest.NewRequest(http.MethodGet, "/api/control/ui/events?"+eventTestValues(first.Query).Encode(), nil))
	if response.Code != http.StatusConflict {
		t.Fatal("changed originals silently drifted a fixed query")
	}
	// No public or unauthenticated entry is created for the new query route.
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/control/ui/events", nil))
	if response.Code == http.StatusOK {
		t.Fatal("unauthenticated event source exposed")
	}
}

func TestWebEventsForkGapAndCorruptionDoNotInventChanges(t *testing.T) {
	server, now := eventTestServer(t)
	original := eventTestReport(t, server, 1, "running", now.Add(-time.Minute))
	eventTestReport(t, server, 3, "stopped", now.Add(-30*time.Second))
	result := eventTestQuery(t, server, url.Values{"kind": {"runtime"}})
	if result.Total != 1 {
		t.Fatal("sequence gap invented a transition")
	}
	key, _ := server.Config.PrivateKey()
	fork := original
	fork.Runtime.State = "stopped"
	fork, _ = SignDeviceReport(fork, key)
	server.Runtime.Reports.now = func() time.Time { return now.Add(-20 * time.Second) }
	public, _ := server.Config.PublicKey()
	if err := server.Runtime.Reports.Put(fork, base64.RawURLEncoding.EncodeToString(public)); !errors.Is(err, ErrReportEquivocation) {
		t.Fatal("fork evidence was not retained", err)
	}
	if result := eventTestQuery(t, server, url.Values{"kind": {"runtime"}}); result.Total != 0 {
		t.Fatal("fork selected a winner or made a new baseline")
	}
	if err := server.Runtime.Reports.withDatabase(context.Background(), true, func(tx *bolt.Tx) error {
		raw, _ := CanonicalEncode(original)
		return tx.Bucket(observationBucket).Put(referenceOf(original).key(ReleaseDigest(raw)), []byte("corrupt"))
	}); err != nil {
		t.Fatal(err)
	}
	// Query a window whose original position was pinned before its fork arrived.
	values := url.Values{"from": {now.Add(-2 * time.Minute).Format(time.RFC3339Nano)}, "until": {now.Add(-40 * time.Second).Format(time.RFC3339Nano)}, "kind": {"runtime"}}
	response := httptest.NewRecorder()
	server.events(response, httptest.NewRequest(http.MethodGet, "/api/control/ui/events?"+values.Encode(), nil))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatal("corrupt original was restored from cache")
	}
}

func TestWebEventsConflictAndMemberCertificateComeFromSignedOriginals(t *testing.T) {
	f := newMaterialFixture(t)
	authorities, locals := materialAuthorities(t, f)
	first := f.sign(t, 0, 1, nil, "demo-first", "service.put", "service", "demo-service", materialTestService("demo-service"))
	second := f.sign(t, 1, 1, nil, "demo-second", "service.put", "service", "demo-service", materialTestService("demo-service"))
	for _, material := range []Material{first, second} {
		raw, _, _ := EncodeMaterial(material)
		if _, err := authorities[0].PutMaterial(raw); err != nil {
			t.Fatal(err)
		}
	}
	at := time.Now().UTC().Add(time.Second)
	values, _, _, err := authorities[0].authorityEvents(context.Background(), at.Add(-time.Hour), at)
	if err != nil {
		t.Fatal(err)
	}
	conflicts := 0
	for _, event := range values {
		if event.Kind == "conflict" {
			conflicts++
			if event.ID != materialTestID(t, second) || !strings.Contains(event.Detail, materialTestID(t, first)) {
				t.Fatal("conflict history lost its immutable sources")
			}
		}
	}
	if conflicts != 1 {
		t.Fatal("conflict was not projected once on original receipt")
	}
	// A later explicit withdrawal does not erase the original conflict.
	op := Operation{Schema: 3, RequestID: "demo-withdraw", Operation: "service.delete", TargetKind: "service", TargetID: "demo-service", Payload: DeleteTarget{ID: "demo-service"}}
	op.Dependencies = []string{materialTestID(t, first), materialTestID(t, second)}
	sort.Strings(op.Dependencies)
	if _, err := authorities[0].Submit(context.Background(), op, locals[0]); err != nil {
		t.Fatal(err)
	}
	values, _, _, err = authorities[0].authorityEvents(context.Background(), at.Add(-time.Hour), at)
	if err != nil {
		t.Fatal(err)
	}
	conflicts = 0
	for _, event := range values {
		if event.Kind == "conflict" {
			conflicts++
		}
	}
	if conflicts != 1 {
		t.Fatal("current resolution rewrote conflict history")
	}
	// Member certificates use the existing majority path, without an event log.
	f = newMaterialFixture(t)
	authorities, locals = materialAuthorities(t, f)
	ctx := context.Background()
	a, err := authorities[0].BeginControlRound(ctx, locals[0])
	if err != nil {
		t.Fatal(err)
	}
	b, err := authorities[1].PrepareControl(ctx, f.configID, a.Round, locals[1])
	if err != nil {
		t.Fatal(err)
	}
	promises := []ControlPromise{a, b}
	proposal := emptyRemoval(f, promises, 1)
	votes := []ControlVote{}
	for i := range authorities {
		vote, err := authorities[i].VoteControl(ctx, proposal, a.Round, promises, locals[i], time.Now())
		if err != nil {
			t.Fatal(err)
		}
		votes = append(votes, vote)
	}
	certificate := ControlCertificate{Config: proposal, Round: a.Round, Promises: promises, Votes: votes}
	raw, err := CanonicalEncode(certificate)
	if err != nil {
		t.Fatal(err)
	}
	if err := authorities[0].AcceptControlCertificate(ctx, raw, locals[0]); err != nil {
		t.Fatal(err)
	}
	values, _, _, err = authorities[0].authorityEvents(ctx, time.Now().Add(-time.Hour), time.Now().Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	members := 0
	for _, event := range values {
		if event.Kind == "membership" {
			members++
			if event.ID != ReleaseDigest(raw) || event.Source != a.Round.ProposerControlID {
				t.Fatal("member event did not name its original")
			}
		}
	}
	if members != 1 {
		t.Fatal("majority certificate was not projected")
	}
}

func TestWebEventsFixedCutoffExcludesLaterSignatureFork(t *testing.T) {
	f := newMaterialFixture(t)
	authorities, locals := materialAuthorities(t, f)
	first := f.sign(t, 0, 1, nil, "demo-first", "service.put", "service", "demo-service", materialTestService("demo-service"))
	raw, _, _ := EncodeMaterial(first)
	if _, err := authorities[0].PutMaterial(raw); err != nil {
		t.Fatal(err)
	}
	runtime, err := OpenRuntime(authorities[0].root, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.Close()
	server := &Server{Runtime: runtime, Config: locals[0]}
	before := eventTestQuery(t, server, url.Values{"object": {"demo-service"}})
	fork := f.sign(t, 0, 1, nil, "demo-fork", "service.put", "service", "demo-service", materialTestService("demo-service"))
	raw, _, _ = EncodeMaterial(fork)
	if _, err := runtime.Authority.PutMaterial(raw); !errors.Is(err, ErrMaterialEquivocation) {
		t.Fatal("late fork evidence was not accepted", err)
	}
	after := eventTestQuery(t, server, eventTestValues(before.Query))
	if !reflect.DeepEqual(before, after) {
		t.Fatal("post-cutoff original changed the historical query")
	}
}
