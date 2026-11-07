package clientadapter

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"loom/internal/control"
	"loom/protocol"

	"github.com/sagernet/quic-go/quicvarint"
)

func TestNativeEchoExcludesConnectionAndRequiresMatchingResponse(t *testing.T) {
	public := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("a", 32)))
	resource := control.TransportResource{ID: "demo-wg", Kind: "wireguard", OwnerNodeID: "demo-node", ListenerID: "demo-wg", DialHost: "192.0.2.1", DialPort: 12345, Authentication: control.ResourceAuthentication{PublicKey: &public, LocalAddresses: new([]string{})}}

	for _, mode := range []string{"success", "wrong-response", "cancel", "metric-unknown"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			finished := make(chan error, 1)
			const connectDelay = 150 * time.Millisecond
			const responseDelay = 20 * time.Millisecond
			const diagnosticDelay = 100 * time.Millisecond
			completedAt := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
			var clock atomic.Int64
			clock.Store(completedAt.UnixMilli())
			ctx, captured := captureMeasurementTime(ctx, func() time.Time { return time.UnixMilli(clock.Load()) })
			var diagnosticLines []string
			ctx = WithEchoDiagnosticLog(ctx, func(line string) {
				diagnosticLines = append(diagnosticLines, line)
				clock.Store(completedAt.Add(time.Hour).UnixMilli())
				if mode == "success" && len(diagnosticLines) == 1 {
					time.Sleep(diagnosticDelay)
				}
			})
			go func() {
				finished <- func() error {
					defer server.Close()
					_ = server.SetDeadline(time.Now().Add(3 * time.Second))
					read := func(n int) ([]byte, error) {
						body := make([]byte, n)
						_, err := io.ReadFull(server, body)
						return body, err
					}
					connect, err := http.ReadRequest(bufio.NewReader(server))
					if err != nil {
						return err
					}
					address, _ := control.WireGuardAccessAddress(resource, "")
					key, _ := protocol.ConnectionTargetKey("tcp", address.String(), 53)
					if connect.Method != http.MethodConnect || connect.URL.Path != "/loom/probe" || connect.Header.Get("Authorization") != "Bearer demo-secret" || connect.Header.Get("X-Loom-Target") != key || connect.Header.Get("X-Loom-Scope") != "" {
						return errors.New("probe escaped exact authenticated execution target")
					}
					time.Sleep(connectDelay)
					if _, err = io.WriteString(server, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
						return err
					}
					preface, err := read(len(protocol.WireGuardPreface))
					if err != nil || !bytes.Equal(preface, []byte(protocol.WireGuardPreface)) {
						return errors.New("missing native WG frame")
					}
					body, err := protocol.ReadFrame(server, 1024)
					if err != nil {
						return err
					}
					request, err := protocol.UnmarshalRequest(body, 1)
					if err != nil || request.Operation != protocol.TransportEcho {
						return errors.New("wrong transport echo")
					}
					if connect.Header.Get("X-Loom-Echo-ID") != protocol.EchoDiagnosticID(request.Nonce) {
						return errors.New("CONNECT diagnostic ID did not match the actual echo nonce")
					}
					if mode == "cancel" {
						cancel()
						var extra [1]byte
						if _, err := server.Read(extra[:]); err == nil {
							return errors.New("canceled probe did not close its actual socket")
						}
						return nil
					}
					response := protocol.Response{Nonce: request.Nonce, Status: protocol.Accepted}
					if mode == "wrong-response" {
						response.Nonce[0] ^= 1
					}
					if mode == "metric-unknown" {
						response.ProcessingNanos = ^uint64(0)
					}
					raw, err := response.Marshal()
					if err != nil {
						return err
					}
					time.Sleep(responseDelay)
					return protocol.WriteFrame(server, raw)

				}()
			}()
			diagnostic, err := NativeDiagnosticContext(ctx, "demo-secret", func(_ context.Context, network, address string) (net.Conn, error) {
				if network != "tcp" || address != "127.0.0.1:61800" {
					return nil, errors.New("wrong local execution entry")
				}
				return client, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			started := time.Now()
			roundTrip, err := ProbeWireGuard(diagnostic, "demo-network", resource)
			complete := time.Since(started)
			if serverErr := <-finished; serverErr != nil {
				t.Fatal(serverErr)
			}
			if mode == "success" {
				if err != nil || roundTrip == nil || *roundTrip < responseDelay || complete-*roundTrip < connectDelay+diagnosticDelay {
					t.Fatalf("connection or response timing mixed: complete=%s roundTrip=%s err=%v", complete, roundTrip, err)
				}
				if complete-captured.timing.duration < diagnosticDelay {
					t.Fatal("Debug sink latency entered the original measurement duration", complete, captured.timing.duration)
				}
			} else if mode == "metric-unknown" {
				if err != nil || roundTrip != nil {
					t.Fatal("incomparable processing time became a failure or zero RTT", err)
				}
			} else if err == nil || roundTrip != nil {
				t.Fatal("failed or cancelled response produced RTT", roundTrip, err)
			}
			if mode == "wrong-response" {
				checkDiagnosticStage(t, err, "native echo stage=response-validate")
			}
			if mode != "cancel" && !captured.timing.completed.Equal(completedAt) {
				t.Fatal("Debug sink renewed the actual measurement completion time", captured.timing.completed)
			}
			if len(diagnosticLines) < 6 || !strings.Contains(diagnosticLines[0], "phase=request-start") || !strings.Contains(diagnosticLines[len(diagnosticLines)-1], "phase=request-finish") {
				t.Fatal("actual echo did not flush its ordered diagnostic phases", diagnosticLines)
			}
			if mode == "cancel" && !strings.HasSuffix(diagnosticLines[len(diagnosticLines)-1], "outcome=canceled") {
				t.Fatal("canceled echo lost its final diagnostic outcome")
			}
		})
	}
	if value, err := ProbeWireGuard(context.Background(), "demo-network", resource); err == nil || value != nil {
		t.Fatal("missing native execution produced RTT")
	}
}

func TestExecutionEchoKeepsDeclaredRefusalsDistinct(t *testing.T) {
	request := protocol.Request{Operation: protocol.AdmissionEcho, PolicyID: "demo-policy", Nonce: [16]byte{1}}
	errorsByStatus := map[protocol.Status]error{}
	for _, status := range []protocol.Status{protocol.Accepted, protocol.Denied, protocol.Unavailable} {
		body, err := (protocol.Response{Nonce: request.Nonce, Status: status}).Marshal()
		if err != nil {
			t.Fatal(err)
		}
		_, err = executionEchoResponse(body, request)
		if status == protocol.Accepted && err != nil || status != protocol.Accepted && err == nil {
			t.Fatal("echo changed the declared acceptance or refusal", status, err)
		}
		errorsByStatus[status] = err
	}
	if errorsByStatus[protocol.Denied].Error() == errorsByStatus[protocol.Unavailable].Error() {
		t.Fatal("an explicit denial and remote unavailability became the same failure")
	}
	if !errors.Is(errorsByStatus[protocol.Denied], ErrEchoDenied) || errors.Is(errorsByStatus[protocol.Denied], ErrEchoUnavailable) ||
		!errors.Is(errorsByStatus[protocol.Unavailable], ErrEchoUnavailable) || errors.Is(errorsByStatus[protocol.Unavailable], ErrEchoDenied) ||
		errors.Is(errorsByStatus[protocol.Denied], ErrMeasurementDeferred) || errors.Is(errorsByStatus[protocol.Unavailable], ErrMeasurementDeferred) {
		t.Fatal("declared echo refusals lost their separate types or became local deferral")
	}
	for _, response := range []protocol.Response{{Nonce: [16]byte{2}, Status: protocol.Denied}, {Nonce: request.Nonce, Status: protocol.Accepted, Address: netip.MustParseAddr("fdab::1")}} {
		body, err := response.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		if _, err = executionEchoResponse(body, request); err == nil || errors.Is(err, ErrEchoDenied) || errors.Is(err, ErrEchoUnavailable) {
			t.Fatal("malformed echo confirmation was accepted or treated as a declared refusal", err)
		}
	}
}

type echoFailureReadWriter struct {
	writes, failWrite int
	cause             error
}

func (stream *echoFailureReadWriter) Write(body []byte) (int, error) {
	stream.writes++
	if stream.writes == stream.failWrite {
		return 0, stream.cause
	}
	return len(body), nil
}
func (stream *echoFailureReadWriter) Read([]byte) (int, error) { return 0, stream.cause }

func checkDiagnosticStage(t *testing.T, err error, prefix string) {
	t.Helper()
	if err == nil || !strings.HasPrefix(err.Error(), prefix+" elapsed=") {
		t.Fatal("diagnostic error lost its failing stage", err)
	}
	elapsed := strings.SplitN(strings.TrimPrefix(err.Error(), prefix+" elapsed="), ": ", 2)[0]
	duration, parseErr := time.ParseDuration(elapsed)
	if parseErr != nil || duration < 0 {
		t.Fatal("diagnostic error lost its monotonic stage duration", err)
	}
}

func TestEchoDiagnosticLogUsesSafeOutcomesWithoutErrorText(t *testing.T) {
	id := protocol.EchoDiagnosticID([16]byte{1})
	private := errors.New("demo-private-secret tcp://demo.example:443")
	for _, input := range []struct {
		cause   error
		outcome string
	}{
		{nil, "success"}, {context.Canceled, "canceled"}, {context.DeadlineExceeded, "timeout"},
		{errors.Join(ErrEchoDenied, private), "denied"}, {ErrEchoUnavailable, "unavailable"},
		{ErrResourcesNotReady, "local-pending"}, {ErrSelectionSuperseded, "superseded"}, {private, "failed"},
	} {
		var line string
		ctx := WithEchoDiagnosticLog(context.Background(), func(value string) { line = value })
		emitEchoDiagnostic(ctx, id, "request-finish", 25*time.Nanosecond, input.cause)
		want := "echo_id=" + id + " phase=request-finish elapsed_ns=25 outcome=" + input.outcome
		if line != want {
			t.Fatal("echo diagnostic exposed an error string or changed its safe outcome", line)
		}
	}
}

func TestEchoFailureStagesPreserveCauseForBothTransports(t *testing.T) {
	for kind, prefix := range map[string][]byte{"wireguard": []byte(protocol.WireGuardPreface), "hysteria2": quicvarint.Append(nil, protocol.Hy2FrameType)} {
		for index, stage := range []string{"preface-write", "request-write", "response-read"} {
			t.Run(kind+"/"+stage, func(t *testing.T) {
				cause := &net.OpError{Op: "demo-echo", Net: "tcp", Err: context.DeadlineExceeded}
				stream := &echoFailureReadWriter{cause: cause}
				if index < 2 {
					stream.failWrite = index + 1
				}
				rtt, err := echoRoundTrip(stream, protocol.Request{Operation: protocol.AdmissionEcho, PolicyID: "demo-policy", Nonce: [16]byte{1}}, prefix, nil)
				var restored *net.OpError
				if rtt != nil || !errors.Is(err, cause) || !errors.Is(err, context.DeadlineExceeded) || !errors.As(err, &restored) || restored != cause {
					t.Fatal("failed echo lost its cause or produced a metric", err)
				}
				checkDiagnosticStage(t, err, "native echo stage="+stage)
			})
		}
	}
}

func TestWireGuardEchoLocalConnectPreservesCauseAndStage(t *testing.T) {
	view, _, _ := resourceProbeFixture(t, "wireguard")
	probes, err := control.FirstHopProbes(testDeviceExecution(view))
	if err != nil || len(probes) == 0 {
		t.Fatal("fixture has no WG admission probe", err)
	}
	budget, err := NewMeasurementBudget(MeasurementLimits{Window: time.Minute, Requests: 1, Concurrent: 1, Bytes: 8 << 10, Timeout: time.Second}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	cause := errors.New("demo-local-connect-failure")
	ctx, err := NativeDiagnosticContext(WithMeasurementBudget(context.Background(), budget), "demo-secret", func(context.Context, string, string) (net.Conn, error) {
		return nil, cause
	})
	if err != nil {
		t.Fatal(err)
	}
	rtt, err := ProbeWireGuardAdmission(ctx, probes[0])
	if rtt != nil || !errors.Is(err, cause) {
		t.Fatal("local connection failure lost its cause or produced RTT", err)
	}
	checkDiagnosticStage(t, err, "WG stage=local-connect")
}

func TestWGAdmissionInflightReuseCannotBorrowAnotherPolicyOrSpecification(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	budget, _ := NewMeasurementBudget(MeasurementLimits{Window: time.Minute, Requests: 8, Concurrent: 3, Bytes: 64 << 10, Timeout: 3 * time.Second}, time.Now)
	ctx = WithMeasurementBudget(ctx, budget)
	entered, release := make(chan string, 3), make(chan struct{})
	servers := make(chan error, 3)
	var loggedFlights atomic.Int32
	ctx = WithEchoDiagnosticLog(WithMeasurementNetwork(ctx, "demo-underlay"), func(line string) {
		if strings.Contains(line, "phase=request-start") {
			loggedFlights.Add(1)
		}
	})
	diagnostic, err := NativeDiagnosticContext(ctx, "demo-secret", func(_ context.Context, _, _ string) (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			servers <- func() error {
				defer server.Close()
				_ = server.SetDeadline(time.Now().Add(4 * time.Second))
				read := func(n int) ([]byte, error) {
					body := make([]byte, n)
					_, err := io.ReadFull(server, body)
					return body, err
				}
				connect, err := http.ReadRequest(bufio.NewReader(server))
				if err != nil {
					return err
				}
				if connect.Method != http.MethodConnect || connect.URL.Path != "/loom/probe" || connect.Header.Get("Authorization") != "Bearer demo-secret" {
					return errors.New("diagnostic did not authenticate its local socket")
				}
				if _, err := io.WriteString(server, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
					return err
				}
				prefix, err := read(len(protocol.WireGuardPreface))
				if err != nil || string(prefix) != protocol.WireGuardPreface {
					return errors.New("missing native admission frame")
				}
				body, err := protocol.ReadFrame(server, 1024)
				if err != nil {
					return err
				}
				request, err := protocol.UnmarshalRequest(body, 1)
				if err != nil || request.Operation != protocol.AdmissionEcho {
					return errors.New("wrong admission operation")
				}
				if connect.Header.Get("X-Loom-Echo-ID") != protocol.EchoDiagnosticID(request.Nonce) {
					return errors.New("admission diagnostic ID did not match the actual nonce")
				}
				entered <- request.PolicyID
				select {
				case <-release:
				case <-ctx.Done():
					return ctx.Err()
				}
				status := protocol.Accepted
				if request.PolicyID == "demo-policy-b" {
					status = protocol.Denied
				}
				response, err := (protocol.Response{Nonce: request.Nonce, Status: status}).Marshal()
				if err != nil {
					return err
				}
				return protocol.WriteFrame(server, response)
			}()
		}()
		return client, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	public := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("a", 32)))
	resource := control.TransportResource{ID: "demo-wg", Kind: "wireguard", OwnerNodeID: "demo-node", ListenerID: "demo-wg", DialHost: "192.0.2.1", DialPort: 12345, Authentication: control.ResourceAuthentication{PublicKey: &public, LocalAddresses: new([]string{})}}
	done := make(chan error, 4)
	for _, input := range []struct{ policy, specification string }{{"demo-policy-a", "a"}, {"demo-policy-a", "a"}, {"demo-policy-a", "b"}, {"demo-policy-b", "c"}} {
		go func() {
			probe := control.ResourceProbe{NetworkID: "demo-network", Resource: resource, DiagnosticID: "entry:demo-source", PolicyID: input.policy, SpecDigest: "sha256:" + strings.Repeat(input.specification, 64)}
			_, err := ProbeWireGuardAdmission(diagnostic, probe)
			if input.policy == "demo-policy-b" {
				if !errors.Is(err, ErrEchoDenied) {
					err = errors.New("denied Policy borrowed another admission success or lost the declared refusal")
				} else {
					err = nil
				}
			}
			done <- err
		}()
	}
	counts := map[string]int{}
	for range 3 {
		select {
		case policy := <-entered:
			counts[policy]++
		case <-ctx.Done():
			t.Fatal("different actual measurement specifications coalesced")
		}
	}
	for {
		budget.mu.Lock()
		waiters := 0
		for _, flight := range budget.flights {
			waiters += flight.waiters
		}
		budget.mu.Unlock()
		if waiters == 4 {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("identical admission consumers did not join their actual flight")
		case <-time.After(time.Millisecond):
		}
	}
	close(release)
	for range 4 {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	for range 3 {
		if err := <-servers; err != nil {
			t.Fatal("real diagnostic exchange failed", err)
		}
	}
	if counts["demo-policy-a"] != 2 || counts["demo-policy-b"] != 1 || loggedFlights.Load() != 3 {
		t.Fatal("native admission lost the Policy or specification boundary")
	}
}
