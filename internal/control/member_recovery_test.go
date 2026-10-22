package control

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func recoveryMemberCall(t *testing.T, runtime *Runtime, member Member) (*memberCall, *sync.WaitGroup) {
	t.Helper()
	clients, err := runtime.memberClients(member)
	if err != nil {
		t.Fatal(err)
	}
	ctx, stop := context.WithCancel(context.Background())
	active := &memberCall{member: member, ctx: ctx, stop: stop, http: clients}
	workers := new(sync.WaitGroup)
	t.Cleanup(func() { stop(); workers.Wait(); active.close() })
	return active, workers
}

func runRecoveryAttempt(t *testing.T, runtime *Runtime, active *memberCall) error {
	t.Helper()
	scope := active.attemptScope()
	ctx := context.WithValue(active.ctx, memberHTTPAttemptKey{}, scope)
	active.result = runtime.reconcilePeerAttempt(ctx, active.member)
	active.finishAttempt(runtime, runtime.currentMember(active.member))
	return active.result
}

func recoveryConnection(t *testing.T, runtime *Runtime, active *memberCall) net.Conn {
	t.Helper()
	var got net.Conn
	ctx := httptrace.WithClientTrace(active.ctx, &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) { got = info.Conn }})
	ctx = context.WithValue(ctx, memberHTTPAttemptKey{}, active.http)
	if _, err := runtime.peerBody(ctx, active.member, http.MethodGet, "/internal/frontier", nil); err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("normal authenticated request did not acquire a connection")
	}
	return got
}

func waitRecoveryCheck(t *testing.T, active *memberCall) {
	t.Helper()
	if active.direct == nil {
		t.Fatal("due relay did not start its direct check")
	}
	select {
	case <-active.direct.done:
	case <-time.After(5 * time.Second):
		t.Fatal("direct check did not finish")
	}
}

func recoveryReportPublisher(t *testing.T, runtime *Runtime) func(U64) []byte {
	t.Helper()
	server, invite, _, claim, key, _ := enrollmentFixtureWithRuntime(t, runtime)
	if response := enrollmentHTTP(t, server, "/enrollment/claim", claim, enrollmentTunnel(invite)); response.Code != http.StatusOK {
		t.Fatal("formal claim failed", response.Code)
	}
	view, err := server.deviceEnvelope(invite.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	return func(sequence U64) []byte {
		t.Helper()
		report, err := SignDeviceReport(DeviceReport{Schema: 3, NetworkID: view.View.NetworkID, DeviceID: invite.DeviceID, ReportSequence: sequence, ViewDigest: view.ViewDigest, NetworkGeneration: "demo-underlay", ReportedAt: server.now().UnixMilli(), Selections: []ReportSelection{}, Observations: []Observation{}, Runtime: RuntimeReadback{State: "running", AppliedViewDigest: view.ViewDigest}, Components: []ComponentReadback{}}, key)
		if err != nil {
			t.Fatal(err)
		}
		if response := enrollmentHTTP(t, server, "/device/report", report, tunnelIdentity{Mode: "device", DeviceID: invite.DeviceID}); response.Code != http.StatusOK {
			t.Fatal("formal report rejected", response.Code)
		}
		body, _ := CanonicalEncode(report)
		return body
	}
}

func requireRecoveryReport(t *testing.T, runtime *Runtime, want []byte) {
	t.Helper()
	values, err := runtime.Reports.Latest(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, report := range values {
		body, _ := CanonicalEncode(report)
		if bytes.Equal(body, want) {
			return
		}
	}
	t.Fatal("normal member synchronization did not persist the expected signed report")
}

func TestMemberRecoveryPrefersSlowerUsableDirectAfterRelayRace(t *testing.T) {
	f := threeSchedulingMembers(t)
	peers := membershipTLSPeers(t, f)
	runtime, channel := peers[0].server.Runtime, peers[0].channel
	direct, relay := peers[1].channel.ListenAddresses()[0], peers[2].channel.ListenAddresses()[0]
	var directDials, relayDials atomic.Int32
	firstRelay := make(chan struct{})
	channel.underlayDial = func(ctx context.Context, network, address string) (net.Conn, error) {
		delay := time.Duration(0)
		if address == direct {
			directDials.Add(1)
			delay = 220 * time.Millisecond
		}
		if address == relay {
			relayDials.Add(1)
			delay = 50 * time.Millisecond
		}
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		// Fix the first race's ordering under race instrumentation and CPU load;
		// later direct checks retain their real delayed TLS establishment.
		if address == direct && directDials.Load() == 1 {
			select {
			case <-firstRelay:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	start := time.Now()
	var offset atomic.Int64
	runtime.now = func() time.Time { return start.Add(time.Duration(offset.Load())) }
	active, workers := recoveryMemberCall(t, runtime, f.members[1])
	var first sync.Once
	active.ctx = httptrace.WithClientTrace(active.ctx, &httptrace.ClientTrace{GotConn: func(httptrace.GotConnInfo) { first.Do(func() { close(firstRelay) }) }})
	initial := recoveryConnection(t, runtime, active)
	if !ordinaryMemberTransport(active.http.client).relayed.Load() {
		t.Fatal("fixture failed to reproduce the healthy direct losing its first race")
	}
	offset.Store(int64(61 * time.Second))
	active.checkDirect(runtime, workers)
	waitRecoveryCheck(t, active)
	if active.direct.err != nil {
		t.Fatal(active.direct.err)
	}
	if recoveryConnection(t, runtime, active) != initial {
		t.Fatal("frontier check replaced the working relay before formal synchronization")
	}
	change := submitAuthority(t, peers[1].server.Runtime, authorityService("demo-recovery-service", "demo-recovery-request"))
	if err := runRecoveryAttempt(t, runtime, active); err != nil {
		t.Fatal(err)
	}
	if _, err := runtime.Authority.Material(change.MaterialID); err != nil {
		t.Fatal("trial did not persist the signed fact", err)
	}
	if active.direct != nil || ordinaryMemberTransport(active.http.client).relayed.Load() {
		t.Fatal("successful formal synchronization did not commit the direct pool")
	}
	second := recoveryConnection(t, runtime, active)
	if second == initial {
		t.Fatal("direct preference retained the old relay")
	}
	_ = initial.SetReadDeadline(time.Now().Add(time.Second))
	_, err := initial.Read(make([]byte, 1))
	var ne net.Error
	if err == nil || errors.As(err, &ne) && ne.Timeout() {
		t.Fatal("committed direct left the old idle relay open", err)
	}
	beforeDirect, beforeRelay := directDials.Load(), relayDials.Load()
	offset.Store(int64(10 * time.Minute))
	active.checkDirect(runtime, workers)
	if active.direct != nil || recoveryConnection(t, runtime, active) != second || directDials.Load() != beforeDirect || relayDials.Load() != beforeRelay {
		t.Fatal("healthy direct generated recovery traffic or rotated")
	}
}

func TestMemberRecoveryKeepsPermanentRelayAndFailedTrialOriginals(t *testing.T) {
	f := threeSchedulingMembers(t)
	var failReports atomic.Bool
	peers, _ := membershipTLSPeersWithHandler(t, f, -1, func(i int, next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if i == 1 && failReports.Load() && r.URL.Path == "/internal/report-ranges" {
				http.Error(w, "demo report exchange unavailable", http.StatusServiceUnavailable)
				return
			}
			next.ServeHTTP(w, r)
		})
	})
	runtime, channel := peers[0].server.Runtime, peers[0].channel
	direct, relay := peers[1].channel.ListenAddresses()[0], peers[2].channel.ListenAddresses()[0]
	var available atomic.Bool
	var directDials, relayDials atomic.Int32
	channel.underlayDial = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address == direct {
			directDials.Add(1)
			if !available.Load() {
				return nil, errors.New("demo direct unreachable")
			}
		}
		if address == relay {
			relayDials.Add(1)
		}
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	start := time.Now()
	var offset atomic.Int64
	runtime.now = func() time.Time { return start.Add(time.Duration(offset.Load())) }
	active, workers := recoveryMemberCall(t, runtime, f.members[1])
	first := recoveryConnection(t, runtime, active)
	post := recoveryReportPublisher(t, peers[1].server.Runtime)
	for _, seconds := range []int64{61, 122} {
		offset.Store(seconds * int64(time.Second))
		active.checkDirect(runtime, workers)
		waitRecoveryCheck(t, active)
		if active.direct.err == nil {
			t.Fatal("unreachable direct passed its check")
		}
		active.checkDirect(runtime, workers)
		id := strconv.FormatInt(seconds, 10)
		change := submitAuthority(t, peers[1].server.Runtime, authorityService("demo-relay-service-"+id, "demo-relay-request-"+id))
		want := post(U64(seconds))
		if err := runRecoveryAttempt(t, runtime, active); err != nil {
			t.Fatal(err)
		}
		if _, err := runtime.Authority.Material(change.MaterialID); err != nil {
			t.Fatal(err)
		}
		requireRecoveryReport(t, runtime, want)
		if recoveryConnection(t, runtime, active) != first || relayDials.Load() != 1 {
			t.Fatal("periodic direct failure rebuilt the working relay")
		}
		active.checkDirect(runtime, workers)
		if active.direct != nil {
			t.Fatal("completed failure busy retried before the next minute")
		}
	}
	if directDials.Load() != 3 {
		t.Fatal("direct checks did not keep their minute budget", directDials.Load())
	}
	available.Store(true)
	offset.Store(int64(183 * time.Second))
	active.checkDirect(runtime, workers)
	waitRecoveryCheck(t, active)
	if active.direct.err != nil {
		t.Fatal(active.direct.err)
	}
	change := submitAuthority(t, peers[1].server.Runtime, authorityService("demo-partial-service", "demo-partial-request"))
	failReports.Store(true)
	if err := runRecoveryAttempt(t, runtime, active); err == nil {
		t.Fatal("failed report exchange committed the candidate")
	}
	if _, err := runtime.Authority.Material(change.MaterialID); err != nil {
		t.Fatal("failed trial rolled back its already persisted fact", err)
	}
	if active.direct != nil || recoveryConnection(t, runtime, active) != first || relayDials.Load() != 1 {
		t.Fatal("failed trial discarded the standby relay")
	}
	failReports.Store(false)
	if err := runRecoveryAttempt(t, runtime, active); err != nil {
		t.Fatal(err)
	}
}

func TestMemberRecoveryDirectTransferFailurePrefersRelay(t *testing.T) {
	f := threeSchedulingMembers(t)
	var broken atomic.Int32
	peers, _ := membershipTLSPeersWithHandler(t, f, -1, func(i int, next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if i == 1 && broken.Load() == 1 && r.URL.Path == "/internal/frontier" {
				http.Error(w, "demo authority temporarily unavailable", http.StatusServiceUnavailable)
				return
			}
			if i == 1 && broken.Load() == 2 && r.URL.Path == "/internal/frontier" {
				connection, _, err := w.(http.Hijacker).Hijack()
				if err == nil {
					connection.Close()
				}
				return
			}
			next.ServeHTTP(w, r)
		})
	})
	runtime, channel := peers[0].server.Runtime, peers[0].channel
	direct, relay := peers[1].channel.ListenAddresses()[0], peers[2].channel.ListenAddresses()[0]
	var directDials, relayDials atomic.Int32
	channel.underlayDial = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address == direct {
			directDials.Add(1)
		}
		if address == relay {
			relayDials.Add(1)
		}
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	active, _ := recoveryMemberCall(t, runtime, f.members[1])
	_ = recoveryConnection(t, runtime, active)
	owned := ordinaryMemberTransport(active.http.client)
	broken.Store(1)
	if err := runRecoveryAttempt(t, runtime, active); err == nil {
		t.Fatal("server rejection was hidden")
	}
	if memberDialPreference(owned.preference.Load()) != memberPreferDirect || owned.networkFailure.Load() {
		t.Fatal("server rejection was treated as a failed direct path")
	}
	broken.Store(2)
	if err := runRecoveryAttempt(t, runtime, active); err == nil {
		t.Fatal("actual direct connection failures were accepted")
	}
	if memberDialPreference(owned.preference.Load()) != memberPreferRelay {
		t.Fatal("failed adopted direct retained cold-start preference")
	}
	broken.Store(0)
	beforeDirect := directDials.Load()
	_ = recoveryConnection(t, runtime, active)
	if !owned.relayed.Load() || relayDials.Load() != 1 || directDials.Load() != beforeDirect {
		t.Fatal("failed direct was selected before the healthy relay", directDials.Load(), relayDials.Load())
	}
}

func TestMemberRecoveryRejectsUnverifiedCandidateWithoutChangingRelay(t *testing.T) {
	f := threeSchedulingMembers(t)
	var mode atomic.Int32
	peers, _ := membershipTLSPeersWithHandler(t, f, -1, func(i int, next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if i != 1 || r.URL.Path != "/internal/frontier" || mode.Load() < 2 {
				next.ServeHTTP(w, r)
				return
			}
			recorder := httptest.NewRecorder()
			next.ServeHTTP(recorder, r)
			for name, values := range recorder.Header() {
				w.Header()[name] = values
			}
			if mode.Load() == 2 {
				w.Header().Set(frontierProofHeader, "\"demo-unconfirmed-proof\"")
				w.WriteHeader(recorder.Code)
				w.Write(recorder.Body.Bytes())
				return
			}
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("[]\n"))
		})
	})
	runtime, channel := peers[0].server.Runtime, peers[0].channel
	direct := peers[1].channel.ListenAddresses()[0]
	var available atomic.Bool
	channel.underlayDial = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address == direct {
			if !available.Load() {
				return nil, errors.New("demo direct unavailable")
			}
			if mode.Load() == 1 {
				address = peers[0].channel.ListenAddresses()[0]
			}
		}
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	start := time.Now()
	var offset atomic.Int64
	runtime.now = func() time.Time { return start.Add(time.Duration(offset.Load())) }
	active, workers := recoveryMemberCall(t, runtime, f.members[1])
	first := recoveryConnection(t, runtime, active)
	available.Store(true)
	for _, fault := range []int32{1, 2, 3} {
		mode.Store(fault)
		offset.Store(int64(time.Duration(fault) * 61 * time.Second))
		active.checkDirect(runtime, workers)
		waitRecoveryCheck(t, active)
		if active.direct.err == nil {
			t.Fatal("unverified candidate passed its actual frontier read", fault)
		}
		active.checkDirect(runtime, workers)
		mode.Store(0)
		if active.direct != nil || recoveryConnection(t, runtime, active) != first {
			t.Fatal("candidate rejection displaced the relay", fault)
		}
	}
	offset.Store(int64(244 * time.Second))
	active.checkDirect(runtime, workers)
	waitRecoveryCheck(t, active)
	if active.direct.err != nil {
		t.Fatal(active.direct.err)
	}
	scope := active.attemptScope()
	ctx := context.WithValue(active.ctx, memberHTTPAttemptKey{}, scope)
	active.result = runtime.reconcilePeerAttempt(ctx, active.member)
	if active.result != nil {
		t.Fatal(active.result)
	}
	active.stop()
	active.finishAttempt(runtime, true)
	if active.direct != nil || !ordinaryMemberTransport(active.http.client).relayed.Load() {
		t.Fatal("late result committed after its member owner stopped")
	}
}

func TestMemberRecoverySchedulerContinuesReportsWhileCheckWaits(t *testing.T) {
	for _, mode := range []string{"deadline", "shutdown"} {
		t.Run(mode, func(t *testing.T) {
			f := threeSchedulingMembers(t)
			peers := membershipTLSPeers(t, f)
			runtime, channel := peers[0].server.Runtime, peers[0].channel
			direct := peers[1].channel.ListenAddresses()[0]
			var checking atomic.Bool
			var checks atomic.Int32
			entered, cancelled := make(chan struct{}, 1), make(chan struct{}, 1)
			channel.underlayDial = func(ctx context.Context, network, address string) (net.Conn, error) {
				if address == direct {
					if checking.Load() {
						checks.Add(1)
						entered <- struct{}{}
						<-ctx.Done()
						cancelled <- struct{}{}
						return nil, ctx.Err()
					}
					return nil, errors.New("demo initial direct unavailable")
				}
				return (&net.Dialer{}).DialContext(ctx, network, address)
			}
			post := recoveryReportPublisher(t, peers[1].server.Runtime)
			first := post(1)
			start := time.Now()
			var offset atomic.Int64
			runtime.now = func() time.Time { return start.Add(time.Duration(offset.Load())) }
			runtime.done = make(chan struct{})
			ticks := make(chan time.Time, 1)
			go runtime.reconcilePeers(ticks)
			t.Cleanup(func() { runtime.Close() })
			waitReport := func(want []byte) {
				t.Helper()
				deadline := time.Now().Add(5 * time.Second)
				for time.Now().Before(deadline) {
					values, err := runtime.Reports.Latest(context.Background())
					if err != nil {
						t.Fatal(err)
					}
					for _, v := range values {
						body, _ := CanonicalEncode(v)
						if bytes.Equal(body, want) {
							return
						}
					}
					select {
					case ticks <- time.Now():
					default:
					}
					time.Sleep(10 * time.Millisecond)
				}
				t.Fatal("pending direct check blocked normal signed report synchronization")
			}
			waitReport(first)
			checking.Store(true)
			offset.Store(int64(61 * time.Second))
			ticks <- time.Now()
			select {
			case <-entered:
			case <-time.After(3 * time.Second):
				t.Fatal("scheduler did not launch direct recovery check")
			}
			waitReport(post(2))
			offset.Store(int64(181 * time.Second))
			waitReport(post(3))
			if checks.Load() != 1 {
				t.Fatal("scheduler overlapped direct checks", checks.Load())
			}
			if mode == "deadline" {
				select {
				case <-cancelled:
				case <-time.After(17 * time.Second):
					t.Fatal("direct check outlived its fifteen-second deadline")
				}
				checking.Store(false)
				waitReport(post(4))
			}
			closed := make(chan struct{})
			go func() { runtime.Close(); close(closed) }()
			select {
			case <-closed:
			case <-time.After(3 * time.Second):
				t.Fatal("shutdown failed to join its pending direct check")
			}
			if mode == "shutdown" {
				select {
				case <-cancelled:
				case <-time.After(time.Second):
					t.Fatal("direct dial did not observe member cancellation")
				}
			}
			reopened, err := testOpenObservationStore(t, runtime.Authority.root)
			if err != nil {
				t.Fatal(err)
			}
			wantCount := 3
			if mode == "deadline" {
				wantCount = 4
			}
			if len(reopened.History()) != wantCount {
				t.Fatal("reports received while checking did not survive reopening")
			}
		})
	}

}

func TestMemberRecoveryDoesNotCommitAcrossCertifiedIdentityReplacement(t *testing.T) {
	for _, operation := range []string{"revoke", "rotate"} {
		t.Run(operation, func(t *testing.T) {
			f := threeSchedulingMembers(t)
			peers := membershipTLSPeers(t, f)
			runtime, channel := peers[0].server.Runtime, peers[0].channel
			direct := peers[1].channel.ListenAddresses()[0]
			var available atomic.Bool
			channel.underlayDial = func(ctx context.Context, network, address string) (net.Conn, error) {
				if address == direct && !available.Load() {
					return nil, errors.New("demo direct unavailable")
				}
				return (&net.Dialer{}).DialContext(ctx, network, address)
			}
			start := time.Now()
			var offset atomic.Int64
			runtime.now = func() time.Time { return start.Add(time.Duration(offset.Load())) }
			active, workers := recoveryMemberCall(t, runtime, f.members[1])
			_ = recoveryConnection(t, runtime, active)
			old := active.http.client
			available.Store(true)
			offset.Store(int64(61 * time.Second))
			active.checkDirect(runtime, workers)
			waitRecoveryCheck(t, active)
			if active.direct.err != nil {
				t.Fatal(active.direct.err)
			}
			scope := active.attemptScope()
			ctx := context.WithValue(active.ctx, memberHTTPAttemptKey{}, scope)
			active.result = runtime.reconcilePeerAttempt(ctx, active.member)
			if active.result != nil {
				t.Fatal(active.result)
			}
			acceptSchedulingReplacement(t, runtime, f, operation)
			active.finishAttempt(runtime, true)
			if active.direct != nil || active.http.client != old {
				t.Fatal("late successful trial committed across authenticated member replacement")
			}
			ctx = context.WithValue(context.Background(), memberHTTPAttemptKey{}, active.http)
			if _, err := runtime.peerBody(ctx, active.member, http.MethodGet, "/internal/frontier", nil); err == nil {
				t.Fatal("standby relay inherited removed ordinary member authorization")
			}
		})
	}
}
