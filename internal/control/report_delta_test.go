package control

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

type reportTransferCapture struct {
	mu       sync.Mutex
	calls    int
	failCall int
	sent     map[string]int
}

func (capture *reportTransferCapture) handler(t *testing.T, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/internal/reports" {
			next.ServeHTTP(w, r)
			return
		}
		capture.mu.Lock()
		capture.calls++
		fail := capture.calls == capture.failCall
		capture.mu.Unlock()
		if fail {
			http.Error(w, "demo interrupted member transfer", http.StatusServiceUnavailable)
			return
		}
		recorded := httptest.NewRecorder()
		next.ServeHTTP(recorded, r)
		if recorded.Code == http.StatusOK {
			var batch reportBatch
			if err := DecodeCanonical(recorded.Body.Bytes(), &batch, ContractDecodeLimits{MaxBytes: reportBatchBytes, MaxDepth: 128, MaxItems: recorded.Body.Len()}); err != nil {
				t.Error(err)
			} else {
				capture.mu.Lock()
				for _, report := range batch.Reports {
					body, _ := CanonicalEncode(report)
					capture.sent[ReleaseDigest(body)]++
				}
				capture.mu.Unlock()
			}
		}
		for key, values := range recorded.Header() {
			w.Header()[key] = values
		}
		w.WriteHeader(recorded.Code)
		_, _ = w.Write(recorded.Body.Bytes())
	})
}

type reportTestPeer struct {
	server  *Server
	channel *PrivateChannel
	http    *http.Server
}

func (peer reportTestPeer) close() {
	peer.http.Close()
	peer.channel.Close()
	peer.server.Runtime.Close()
}

func TestReportMemberDeltaFillsOldHolesAndForksThroughPrivateTLS(t *testing.T) {
	parent := t.TempDir()
	ca := testTransportCA(t, parent)
	firstRoot, firstConfig, genesis := authorityFixture(t)
	firstKey, err := firstConfig.PrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	keys := []ed25519.PrivateKey{firstKey, testKey(t)}
	initial := genesis.Payload.(Genesis)
	initial.ControlConfig.Members = append(initial.ControlConfig.Members, Member{ControlID: "demo-control-b", NodeID: "demo-node-b", PublicKey: base64.RawURLEncoding.EncodeToString(keys[1].Public().(ed25519.PublicKey))})
	genesis.Payload, genesis.Signature = initial, ""
	genesis, err = SignMaterial(genesis, firstKey)
	if err != nil {
		t.Fatal(err)
	}
	genesisID, _ := MaterialID(genesis)
	members := initial.ControlConfig.Members
	roots := []string{firstRoot, filepath.Join(parent, "demo-second-authority")}
	addresses := []string{testLoopbackAddress(t), testLoopbackAddress(t)}
	configs := []NodeConfig{}
	for i, member := range members {
		files, _, _ := testTransportIdentity(t, parent, member.ControlID, int64(i+10), keys[i], ca, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth})
		browser, _, _ := testTransportIdentity(t, parent, member.ControlID+"-browser", int64(i+20), testKey(t), ca, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
		config := NodeConfig{Schema: 3, NetworkID: firstConfig.NetworkID, ControlID: member.ControlID, NodeID: member.NodeID, GenesisID: genesisID, SigningKeyFile: files.KeyFile, PeerTLS: &files, BrowserTLS: &browser}
		configs = append(configs, config)
		if _, err := InitializeAuthority(roots[i], config, genesis); err != nil {
			t.Fatal(err)
		}
	}
	capture := &reportTransferCapture{failCall: 2, sent: map[string]int{}}
	start := func(i int) reportTestPeer {
		t.Helper()
		// Drive the same reconciliation function explicitly to make partition
		// and interruption ordering deterministic; transport is actual TLS.
		runtime, err := OpenRuntime(roots[i], nil)
		if err != nil {
			t.Fatal(err)
		}
		channel, err := OpenPrivateChannel(PrivateChannelConfig{Schema: 3, Node: members[i].NodeID, Listen: []string{addresses[i]}, Peers: []PrivatePeer{{Node: members[1-i].NodeID, Addresses: []string{addresses[1-i]}}}}, configs[i])
		if err != nil {
			t.Fatal(err)
		}
		channel.AttachAuthority(runtime.Authority)
		runtime.Channel = channel
		server := &Server{Runtime: runtime, Channel: channel, Config: configs[i], Now: func() time.Time { return time.Unix(2000000000, 0).UTC() }}
		httpServer := &http.Server{Handler: capture.handler(t, server.Handler()), ConnContext: controlConnContext, ReadHeaderTimeout: time.Second}
		go httpServer.Serve(channel.ControlListener())
		return reportTestPeer{server, channel, httpServer}
	}
	peers := []reportTestPeer{start(0), start(1)}
	t.Cleanup(func() {
		for _, peer := range peers {
			peer.close()
		}
	})
	syncPeer := func(to, from int) error {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return peers[to].server.Runtime.reconcilePeer(ctx, members[from])
	}
	joining, invite, _, claim, deviceKey, _ := enrollmentFixtureWithRuntime(t, peers[0].server.Runtime)
	submitAuthority(t, joining.Runtime, Operation{Schema: 3, RequestID: "demo-report-target", Operation: "probe_target.put", TargetKind: "probe_target", TargetID: "demo-probe", Dependencies: []string{}, Payload: BusinessProbeTarget{ID: "demo-probe", URL: "https://demo-service.example/probe"}})
	if response := enrollmentHTTP(t, joining, "/enrollment/claim", claim, enrollmentTunnel(invite)); response.Code != http.StatusOK {
		t.Fatal("formal enrollment failed", response.Code)
	}
	if err := syncPeer(1, 0); err != nil {
		t.Fatal("ordinary authorization did not precede report exchange", err)
	}
	view, err := joining.deviceEnvelope(invite.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	route := view.View.Routes[0]
	reportFor := func(sequence U64, state string) DeviceReport {
		t.Helper()
		at := joining.now().Add(-time.Duration(1000-sequence) * time.Second).UnixMilli()
		report, err := SignDeviceReport(DeviceReport{Schema: 3, NetworkID: firstConfig.NetworkID, DeviceID: invite.DeviceID, ReportSequence: sequence, ViewDigest: view.ViewDigest, NetworkGeneration: "demo-underlay", ReportedAt: joining.now().UnixMilli(), Selections: []ReportSelection{{ServiceID: route.ServiceID, CandidateID: route.ID}}, Observations: []Observation{{NetworkGeneration: "demo-underlay", Level: "service", ServiceID: route.ServiceID, CandidateID: route.ID, SpecDigest: route.SpecDigest, Target: "https://demo-service.example/probe", Action: "https_request", Result: "available", ObservedAt: at, ValidUntil: at + 60000}}, Runtime: RuntimeReadback{State: state, AppliedViewDigest: view.ViewDigest}, Components: []ComponentReadback{}}, deviceKey)
		if err != nil {
			t.Fatal(err)
		}
		return report
	}
	post := func(node int, report DeviceReport, want int) {
		t.Helper()
		response := enrollmentHTTP(t, peers[node].server, "/device/report", report, tunnelIdentity{Mode: "device", DeviceID: invite.DeviceID})
		if response.Code != want {
			t.Fatalf("device upload status = %d, want %d: %s", response.Code, want, response.Body.String())
		}
	}
	for sequence := U64(1); sequence <= 40; sequence++ {
		post(0, reportFor(sequence, "running"), http.StatusOK)
	}
	latest := reportFor(101, "running")
	post(0, latest, http.StatusOK)
	post(1, latest, http.StatusOK)
	if err := syncPeer(1, 0); err == nil {
		t.Fatal("interrupted range claimed success")
	}
	if got := peers[1].server.Runtime.Reports.History(); len(got) != reportBatchCount+1 {
		t.Fatal("complete prefix was not durable before interruption", len(got))
	}
	// Both controls already have the same highest sequence. Restart and retry
	// must still request only the missing historical IDs, including old slots.
	peers[1].close()
	peers[1] = start(1)
	if err := syncPeer(1, 0); err != nil {
		t.Fatal("restart could not fill an equal-height historical gap", err)
	}
	capture.mu.Lock()
	for _, times := range capture.sent {
		if times != 1 {
			t.Error("already received original report was retransmitted")
		}
	}
	if len(capture.sent) != 40 {
		t.Error("some original reports never crossed the member channel", len(capture.sent))
	}
	calls := capture.calls
	capture.mu.Unlock()
	if err := syncPeer(1, 0); err != nil {
		t.Fatal(err)
	}
	capture.mu.Lock()
	if capture.calls != calls {
		t.Error("equal range digests caused another report body transfer")
	}
	capture.mu.Unlock()
	readHistory := func(node int) []byte {
		t.Helper()
		body, err := os.ReadFile(filepath.Join(roots[node], "observations.json"))
		if err != nil {
			t.Fatal(err)
		}
		return body
	}
	if !bytes.Equal(readHistory(0), readHistory(1)) {
		t.Fatal("member history changed original canonical signed bytes")
	}
	query := url.Values{"device": {invite.DeviceID}, "service": {route.ServiceID}, "candidate": {route.ID}, "target": {"https://demo-service.example/probe"}}
	for _, peer := range peers {
		response := httptest.NewRecorder()
		peer.server.AdminHandler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/control/ui/path-history?"+query.Encode(), nil))
		var history WebPathHistory
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &history) != nil {
			t.Fatal("normal authorized history read failed", response.Code)
		}
		found := false
		for _, bucket := range history.Buckets {
			found = found || bucket.Observation != nil && reflect.DeepEqual(*bucket.Observation, latest.Observations[0])
		}
		if !found {
			t.Fatal("expired original sample was lost instead of shown as scoped history")
		}
	}
	post(1, reportFor(1, "stopped"), http.StatusConflict)
	if err := syncPeer(0, 1); err != nil {
		t.Fatal("old signed fork did not propagate", err)
	}
	if !bytes.Equal(readHistory(0), readHistory(1)) || len(peers[0].server.Runtime.Reports.All()) != 1 {
		t.Fatal("old fork replaced latest or original histories diverged")
	}
	post(1, reportFor(101, "stopped"), http.StatusConflict)
	if err := syncPeer(0, 1); err != nil || len(peers[0].server.Runtime.Reports.All()) != 0 {
		t.Fatal("equal-height signed fork acquired a current winner", err)
	}
	post(0, reportFor(100, "running"), http.StatusConflict)
	for _, path := range []string{
		"/internal/report-ranges?extra=1",
		"/internal/report-ids?device_id=" + url.QueryEscape(invite.DeviceID) + "&first_sequence=01",
		"/internal/report-ids?device_id=" + url.QueryEscape(invite.DeviceID) + "&first_sequence=1&first_sequence=65",
	} {
		if _, err := peers[1].server.Runtime.peerBody(context.Background(), members[0], http.MethodGet, path, nil); err == nil {
			t.Fatal("member entry accepted ambiguous range query")
		}
	}
	encodedLatest, _ := CanonicalEncode(latest)
	wrongRange, _ := CanonicalEncode(reportBatchRequest{3, invite.DeviceID, 1, []string{ReleaseDigest(encodedLatest)}})
	if _, err := peers[1].server.Runtime.peerBody(context.Background(), members[0], http.MethodPost, "/internal/reports", wrongRange); err == nil {
		t.Fatal("member entry returned a report outside the requested range")
	}
	for _, peer := range peers {
		for _, path := range []string{"/internal/report-ranges", "/internal/report-ids?device_id=demo-access&first_sequence=1"} {
			response := httptest.NewRecorder()
			peer.server.AdminHandler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
			if response.Code != http.StatusNotFound {
				t.Fatal("admin entry exposed private member report exchange")
			}
		}
	}
}

func TestReportHistoryMergeRejectsUntrustedBatchWithoutChangingOriginals(t *testing.T) {
	server, invite, _, claim, key, _ := enrollmentAuthorityFixture(t)
	if response := enrollmentHTTP(t, server, "/enrollment/claim", claim, enrollmentTunnel(invite)); response.Code != http.StatusOK {
		t.Fatal(response.Code)
	}
	projection := server.Runtime.Authority.Snapshot()
	view, _ := server.deviceEnvelope(invite.DeviceID)
	base := DeviceReport{Schema: 3, NetworkID: projection.NetworkID, DeviceID: invite.DeviceID, ReportSequence: 5, ViewDigest: view.ViewDigest, NetworkGeneration: "demo-underlay", ReportedAt: 1, Selections: []ReportSelection{}, Observations: []Observation{}, Runtime: RuntimeReadback{State: "stopped", AppliedViewDigest: view.ViewDigest}, Components: []ComponentReadback{}}
	base, err := SignDeviceReport(base, key)
	if err != nil || server.Runtime.Reports.Put(base, claim.DevicePublicKey) != nil {
		t.Fatal("could not persist original report", err)
	}
	path := filepath.Join(server.Runtime.Authority.root, "observations.json")
	before, _ := os.ReadFile(path)
	lower := base
	lower.ReportSequence, lower.Signature = 2, ""
	lower, _ = SignDeviceReport(lower, key)
	wrongNetwork := lower
	wrongNetwork.NetworkID, wrongNetwork.Signature = "demo-other-network", ""
	wrongNetwork, _ = SignDeviceReport(wrongNetwork, key)
	wrongKey, _ := SignDeviceReport(lower, testKey(t))
	for _, invalid := range []DeviceReport{wrongNetwork, wrongKey} {
		if err := server.Runtime.Reports.mergeReportHistory(context.Background(), []DeviceReport{lower, invalid}, projection); err == nil {
			t.Fatal("partially valid peer batch was accepted")
		}
		if after, _ := os.ReadFile(path); !bytes.Equal(before, after) {
			t.Fatal("rejected peer batch changed original history")
		}
	}
	revoked := projection
	revoked.DeviceAuthorizations = nil
	if err := server.Runtime.Reports.mergeReportHistory(context.Background(), []DeviceReport{lower}, revoked); err == nil {
		t.Fatal("member transfer restored a revoked device authorization")
	}
	if after, _ := os.ReadFile(path); !bytes.Equal(before, after) {
		t.Fatal("revoked report transfer changed original history")
	}
	if err := server.Runtime.Reports.Put(lower, claim.DevicePublicKey); !errors.Is(err, ErrReportReplay) {
		t.Fatal("device upload filled an unknown old slot", err)
	}
	if err := server.Runtime.Reports.mergeReportHistory(context.Background(), []DeviceReport{lower}, projection); err != nil {
		t.Fatal("authenticated history could not fill the old slot", err)
	}
	if got := server.Runtime.Reports.All(); len(got) != 1 || got[0].ReportSequence != base.ReportSequence {
		t.Fatal("historical merge lowered the durable high-water mark")
	}
	for _, first := range []U64{1, 65, reportRangeStart(^U64(0))} {
		if !validReportRange("demo-access", first) {
			t.Fatal("valid sparse or final uint64 range was refused")
		}
	}
	for _, first := range []U64{0, 2, 64, ^U64(0)} {
		if validReportRange("demo-access", first) {
			t.Fatal("ambiguous report range was accepted")
		}
	}
	request := reportBatchRequest{3, "demo-access", 1, []string{"sha256:" + strings.Repeat("0", 64)}}
	body, _ := CanonicalEncode(request)
	var decoded reportBatchRequest
	for _, invalid := range [][]byte{append(append([]byte{}, body...), '\n'), []byte(strings.Replace(string(body), `"schema":3`, `"schema":3,"unknown":1`, 1))} {
		if DecodeCanonical(invalid, &decoded, ContractDecodeLimits{MaxBytes: 4096, MaxDepth: 16, MaxItems: 128}) == nil {
			t.Fatal("noncanonical or unknown report request was accepted")
		}
	}
}

func TestReportMemberBatchReturnsBoundedOriginalPrefix(t *testing.T) {
	server, invite, _, claim, key, _ := enrollmentAuthorityFixture(t)
	if response := enrollmentHTTP(t, server, "/enrollment/claim", claim, enrollmentTunnel(invite)); response.Code != http.StatusOK {
		t.Fatal(response.Code)
	}
	projection := server.Runtime.Authority.Snapshot()
	view, _ := server.deviceEnvelope(invite.DeviceID)
	route := view.View.Routes[0]
	// Each original fits the device boundary, while three exceed a member
	// response. A long canonical target exercises bytes rather than item count.
	target := "https://demo-service.example/" + strings.Repeat("a", 6<<20)
	reports := []DeviceReport{}
	originals := map[string][]byte{}
	for sequence := U64(1); sequence <= 3; sequence++ {
		report, err := SignDeviceReport(DeviceReport{Schema: 3, NetworkID: projection.NetworkID, DeviceID: invite.DeviceID, ReportSequence: sequence, ViewDigest: view.ViewDigest, NetworkGeneration: "demo-underlay", ReportedAt: 1, Selections: []ReportSelection{}, Observations: []Observation{{NetworkGeneration: "demo-underlay", Level: "service", ServiceID: route.ServiceID, CandidateID: route.ID, SpecDigest: route.SpecDigest, Target: target, Action: "https_request", Result: "unknown", ObservedAt: 1, ValidUntil: 2}}, Runtime: RuntimeReadback{State: "stopped", AppliedViewDigest: view.ViewDigest}, Components: []ComponentReadback{}}, key)
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := CanonicalEncode(report)
		if len(raw) >= controlHTTPBodyLimit {
			t.Fatal("fixture exceeds individual device report boundary")
		}
		reports = append(reports, report)
		originals[ReleaseDigest(raw)] = raw
	}
	if err := server.Runtime.Reports.mergeReportHistory(context.Background(), reports, projection); err != nil {
		t.Fatal(err)
	}
	missing := sortedReportIDs(originals)
	for _, wantCount := range []int{2, 1} {
		body, _ := CanonicalEncode(reportBatchRequest{3, invite.DeviceID, 1, missing})
		response := httptest.NewRecorder()
		server.internalReports(response, httptest.NewRequest(http.MethodPost, "/internal/reports", bytes.NewReader(body)))
		var batch reportBatch
		if response.Code != http.StatusOK || response.Body.Len() > reportBatchBytes || DecodeCanonical(response.Body.Bytes(), &batch, ContractDecodeLimits{MaxBytes: reportBatchBytes, MaxDepth: 128, MaxItems: response.Body.Len()}) != nil || len(batch.Reports) != wantCount {
			t.Fatal("member response did not provide the fitting original prefix", response.Code, response.Body.Len())
		}
		for i, report := range batch.Reports {
			raw, _ := CanonicalEncode(report)
			if !bytes.Equal(raw, originals[missing[i]]) {
				t.Fatal("bounded response changed or reordered signed originals")
			}
		}
		missing = missing[wantCount:]
	}
	if len(missing) != 0 {
		t.Fatal("bounded responses left requested originals behind")
	}
}
