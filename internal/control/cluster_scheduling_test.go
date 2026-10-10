package control

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"net/http"
	"net/http/httptrace"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestMemberConnectionsReuseAcrossAttemptsAndClose(t *testing.T) {
	f := newMaterialFixture(t)
	peers := membershipTLSPeers(t, f)
	runtime, member := peers[0].server.Runtime, f.members[1]
	clients, err := runtime.memberClients(member)
	if err != nil {
		t.Fatal(err)
	}
	defer clients.close()
	ctx := context.WithValue(context.Background(), memberHTTPAttemptKey{}, clients)
	var got []httptrace.GotConnInfo
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) { got = append(got, info) }})
	for round := range 2 {
		got = nil
		if err := runtime.reconcilePeerAttempt(ctx, member); err != nil {
			t.Fatal(err)
		}
		if len(got) < 2 || got[0].Reused != (round > 0) || got[1].Reused != (round > 0) || got[0].Conn == got[1].Conn {
			t.Fatal("attempt did not retain separate proof and ordinary connections", round, got)
		}
		for _, info := range got[2:] {
			if !info.Reused || info.Conn != got[1].Conn {
				t.Fatal("ordinary requests did not share their own transport")
			}
		}
	}
	request, _ := http.NewRequest(http.MethodGet, "https://control.loom/internal/frontier", nil)
	if _, err := clients.proof.Do(request); err == nil {
		t.Fatal("retained proof transport admitted a privileged request")
	}
	retained := append([]httptrace.GotConnInfo(nil), got[:2]...)
	clients.close()
	for _, info := range retained {
		_ = info.Conn.SetReadDeadline(time.Now().Add(time.Second))
		if _, err := info.Conn.Read(make([]byte, 1)); err == nil || !strings.Contains(err.Error(), "closed") {
			t.Fatal("connection remained open after owner closure", err)
		}
	}
}

func threeSchedulingMembers(t *testing.T) materialFixture {
	t.Helper()
	f := newMaterialFixture(t)
	key := testKey(t)
	f.keys = append(f.keys, key)
	f.members = append(f.members, Member{ControlID: "demo-control-c", NodeID: "demo-node-c", PublicKey: base64.RawURLEncoding.EncodeToString(key.Public().(ed25519.PublicKey))})
	genesis := f.genesis.Payload.(Genesis)
	genesis.ControlConfig.Members = f.members
	f.configID, _ = ConfigID(genesis.ControlConfig)
	f.genesis.Payload, f.genesis.Signature = genesis, ""
	var err error
	f.genesis, err = SignMaterial(f.genesis, f.keys[0])
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestMemberSchedulingKeepsReceivingWhileAnotherMemberWaits(t *testing.T) {
	f := threeSchedulingMembers(t)
	entered, cancelled := make(chan struct{}, 4), make(chan struct{}, 4)
	var slowCalls, active, maximum atomic.Int32
	peers, _ := membershipTLSPeersWithHandler(t, f, -1, func(i int, next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if i != 1 {
				next.ServeHTTP(w, r)
				return
			}
			slowCalls.Add(1)
			n := active.Add(1)
			for old := maximum.Load(); n > old && !maximum.CompareAndSwap(old, n); old = maximum.Load() {
			}
			entered <- struct{}{}
			<-r.Context().Done()
			active.Add(-1)
			cancelled <- struct{}{}
		})
	})
	joining, invite, _, claim, key, _ := enrollmentFixtureWithRuntime(t, peers[2].server.Runtime)
	if response := enrollmentHTTP(t, joining, "/enrollment/claim", claim, enrollmentTunnel(invite)); response.Code != http.StatusOK {
		t.Fatal("formal claim failed", response.Code)
	}
	view, err := joining.deviceEnvelope(invite.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	post := func(sequence U64) []byte {
		t.Helper()
		report, err := SignDeviceReport(DeviceReport{Schema: 3, NetworkID: view.View.NetworkID, DeviceID: invite.DeviceID,
			ReportSequence: sequence, ViewDigest: view.ViewDigest, NetworkGeneration: "demo-underlay", ReportedAt: joining.now().UnixMilli(),
			Selections: []ReportSelection{}, Observations: []Observation{}, Runtime: RuntimeReadback{State: "running", AppliedViewDigest: view.ViewDigest}, Components: []ComponentReadback{}}, key)
		if err != nil {
			t.Fatal(err)
		}
		if response := enrollmentHTTP(t, joining, "/device/report", report, tunnelIdentity{Mode: "device", DeviceID: invite.DeviceID}); response.Code != http.StatusOK {
			t.Fatal("formal report failed", response.Code)
		}
		body, _ := CanonicalEncode(report)
		return body
	}
	first := post(1)
	runtime := peers[0].server.Runtime
	// The fixture attaches real TLS without starting the loop; inject only its
	// scheduling ticks. No transport, signature or persistence path is replaced.
	runtime.done = make(chan struct{})
	ticks := make(chan time.Time, 1)
	go runtime.reconcilePeers(ticks)
	t.Cleanup(func() { runtime.Close() })
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("waiting peer was not contacted")
	}
	waitReport := func(want []byte) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			values, err := runtime.Reports.Latest(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if len(values) == 1 {
				body, _ := CanonicalEncode(values[0])
				if bytes.Equal(body, want) {
					return
				}
			}
			select {
			case ticks <- time.Now():
			default:
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatal("waiting member prevented another member's original report from being received")
	}
	waitReport(first)
	second := post(2)
	waitReport(second)
	if slowCalls.Load() != 1 || maximum.Load() != 1 || active.Load() != 1 {
		t.Fatal("same member overlapped or its timeout elapsed before independent progress", slowCalls.Load(), maximum.Load(), active.Load())
	}
	closed := make(chan struct{})
	go func() { runtime.Close(); close(closed) }()
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("closing runtime did not cancel the in-flight TLS request")
	}
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("remote request did not observe cancellation")
	}
	reopened, err := testOpenObservationStore(t, runtime.Authority.root)
	if err != nil {
		t.Fatal(err)
	}
	values := reopened.History()
	if len(values) != 2 {
		t.Fatal("independent original reports did not survive reopening")
	}
	for i, want := range [][]byte{first, second} {
		body, _ := CanonicalEncode(values[i])
		if !bytes.Equal(body, want) {
			t.Fatal("scheduling changed canonical signed report bytes")
		}
	}
}

func TestMemberSchedulingCancelsReplacedMembershipIdentity(t *testing.T) {
	for _, operation := range []string{"revoke", "rotate"} {
		t.Run(operation, func(t *testing.T) {
			f := threeSchedulingMembers(t)
			entered, cancelled := make(chan struct{}, 4), make(chan struct{}, 4)
			var calls, active, maximum atomic.Int32
			peers, _ := membershipTLSPeersWithHandler(t, f, -1, func(i int, next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if i != 1 || r.URL.Path != "/internal/frontier" {
						next.ServeHTTP(w, r)
						return
					}
					calls.Add(1)
					n := active.Add(1)
					for old := maximum.Load(); n > old && !maximum.CompareAndSwap(old, n); old = maximum.Load() {
					}
					entered <- struct{}{}
					<-r.Context().Done()
					active.Add(-1)
					cancelled <- struct{}{}
				})
			})
			runtime := peers[0].server.Runtime
			runtime.done = make(chan struct{})
			ticks := make(chan time.Time, 1)
			go runtime.reconcilePeers(ticks)
			t.Cleanup(func() { runtime.Close() })
			select {
			case <-entered:
			case <-time.After(3 * time.Second):
				t.Fatal("member request did not start")
			}
			// Accept a real majority-signed successor, not a mocked projection.
			s := successorFixture{base: f.genesis.Payload.(Genesis).ControlConfig, keys: f.keys, baseID: f.configID}
			signers := []int{0, 2}
			if operation == "rotate" {
				signers[0] = 1
			}
			promises := []ControlPromise{s.promise(t, signers[0], 1, []ControlVoteHistoryItem{}), s.promise(t, signers[1], 1, []ControlVoteHistoryItem{})}
			if operation == "rotate" {
				for i, signer := range signers {
					promises[i].Round.ProposerControlID = f.members[1].ControlID
					promises[i].Signature, _ = signControlValue("loom-control-promise-v3\x00", unsignedControlPromise(promises[i]), f.keys[signer])
				}
			}
			key, _ := KeyID(f.members[1].PublicKey)
			next := ControlConfig{Schema: 3, NetworkID: s.base.NetworkID, PreviousConfigID: s.baseID, Operation: operation,
				TargetNodeID: f.members[1].NodeID, Members: []Member{f.members[0], f.members[2]},
				SealedKeys: []ControlSealedKey{{KeyID: key, TipMaterialID: emptyMaterialTip()}}, OriginPromises: promises}
			if operation == "rotate" {
				next.Members = append([]Member{}, f.members...)
				next.Members[1].PublicKey = base64.RawURLEncoding.EncodeToString(testKey(t).Public().(ed25519.PublicKey))
			}
			cert := ControlCertificate{Config: next, Round: promises[0].Round, Promises: promises,
				Votes: []ControlVote{s.vote(t, signers[0], 1, next), s.vote(t, signers[1], 1, next)}}
			for i, signer := range signers {
				cert.Votes[i].Round = cert.Round
				cert.Votes[i].Signature, _ = signControlValue("loom-control-vote-v3\x00", unsignedControlVote(cert.Votes[i]), f.keys[signer])
			}
			body, _ := CanonicalEncode(cert)
			if err := runtime.Authority.AcceptControlCertificate(context.Background(), body, runtime.Config); err != nil {
				t.Fatal(err)
			}
			ticks <- time.Now()
			select {
			case <-cancelled:
			case <-time.After(2 * time.Second):
				t.Fatal("old member identity remained in flight after its replacement")
			}
			for range 3 {
				ticks <- time.Now()
				time.Sleep(20 * time.Millisecond)
			}
			if operation == "revoke" && calls.Load() != 1 {
				t.Fatal("a removed member was scheduled again", calls.Load())
			}
			// A rotated identity may still use the existing proof-only TLS
			// recovery path to the historical key. It must not overlap the
			// cancelled attempt or regain ordinary member authorization.
			if maximum.Load() != 1 {
				t.Fatal("old and replacement attempts overlapped", maximum.Load())
			}
		})
	}
}

func TestMemberRequestRechecksCertificateLifetime(t *testing.T) {
	root, config, genesis := authorityFixture(t)
	authority, err := InitializeAuthority(root, config, genesis)
	if err != nil {
		t.Fatal(err)
	}
	member := authority.Snapshot().Config.Members[0]
	key, _ := decodePublicKey(member.PublicKey)
	now := time.Now()
	leaf := &x509.Certificate{Subject: pkix.Name{CommonName: member.ControlID}, PublicKey: key,
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	issuer := &x509.Certificate{NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	// TLS has already verified this connection. Its next HTTP request must
	// still reject an expired leaf or issuer; observation time is unrelated.
	request := &http.Request{TLS: &tls.ConnectionState{NegotiatedProtocol: controlALPN,
		PeerCertificates: []*x509.Certificate{leaf}, VerifiedChains: [][]*x509.Certificate{{leaf, issuer}}}}
	server := &Server{Runtime: &Runtime{Authority: authority}, Now: func() time.Time { return now.Add(24 * time.Hour) }}
	if !server.memberRequest(request) || !server.historicalProofRequest(request) {
		t.Fatal("current TLS identity was rejected using the business observation clock")
	}
	for _, certificate := range []*x509.Certificate{leaf, issuer} {
		certificate.NotAfter = now.Add(-time.Second)
		if server.memberRequest(request) || server.historicalProofRequest(request) {
			t.Fatal("an earlier TLS handshake preserved an expired HTTP request identity")
		}
		certificate.NotAfter = now.Add(time.Hour)
	}
}
