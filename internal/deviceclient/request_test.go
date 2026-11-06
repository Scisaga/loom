package deviceclient

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"loom/internal/control"
)

type deviceRequestFixture struct {
	store     *Store
	view      func(uint64) control.DeviceViewEnvelope
	addresses map[string]string
}

func newDeviceRequestFixture(t *testing.T, handlers ...http.HandlerFunc) deviceRequestFixture {
	t.Helper()
	invite, makeView := schema3Fixture(t, "linux")
	store, err := OpenForPlatform(filepath.Join(t.TempDir(), "identity"), invite, "linux")
	if err != nil {
		t.Fatal(err)
	}
	fixture := deviceRequestFixture{store: store, addresses: map[string]string{}}
	endpoints := []control.EndpointGeneration{}
	for i, handler := range handlers {
		endpoint, address := testDeviceTunnel(t, store.PublicKey(), handler)
		endpoint.ID, endpoint.Host = fmt.Sprintf("demo-entry-%d", i), fmt.Sprintf("192.0.2.%d", i+1)
		endpoints = append(endpoints, endpoint)
		fixture.addresses[net.JoinHostPort(endpoint.Host, "443")] = address
	}
	fixture.view = func(sequence uint64) control.DeviceViewEnvelope {
		return makeView(store.PublicKey(), sequence, func(view *control.DeviceView) { view.Endpoints = endpoints })
	}
	if err := store.SaveLKG(fixture.view(7)); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func (fixture deviceRequestFixture) dial(ctx context.Context, network, address string) (net.Conn, error) {
	local, ok := fixture.addresses[address]
	if !ok {
		return nil, errors.New("unexpected demo endpoint")
	}
	return (&net.Dialer{}).DialContext(ctx, network, local)
}

func (fixture deviceRequestFixture) context(ctx context.Context) context.Context {
	return control.WithEndpointDialer(ctx, fixture.dial)
}

func writeDeviceResponse(t *testing.T, w http.ResponseWriter, value any) {
	t.Helper()
	body, err := control.CanonicalEncode(value)
	if err != nil {
		t.Error(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	_, _ = w.Write(body)
}

func TestFetchWaitsForValidatedBusinessResponse(t *testing.T) {
	for _, scenario := range []string{"http-unavailable", "stale-frontier", "wrong-signature", "noncanonical"} {
		t.Run(scenario, func(t *testing.T) {
			firstRequested := make(chan struct{})
			var rejected, accepted atomic.Int32
			var badBody, goodBody []byte
			fixture := newDeviceRequestFixture(t,
				func(w http.ResponseWriter, r *http.Request) {
					rejected.Add(1)
					close(firstRequested)
					if scenario == "http-unavailable" {
						w.WriteHeader(http.StatusServiceUnavailable)
					}
					_, _ = w.Write(badBody)
				},
				func(w http.ResponseWriter, r *http.Request) { accepted.Add(1); _, _ = w.Write(goodBody) })
			good := fixture.view(8)
			goodBody, _ = control.CanonicalEncode(good)
			bad := fixture.view(6)
			if scenario == "wrong-signature" {
				bad = good
				bad.Signature = strings.Repeat("A", 86)
			}
			if scenario != "http-unavailable" {
				badBody, _ = control.CanonicalEncode(bad)
				if scenario == "noncanonical" {
					badBody = append(badBody, '\n')
				}
			}
			before, _ := os.ReadFile(fixture.store.path)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			ctx = control.WithEndpointDialer(ctx, func(ctx context.Context, network, address string) (net.Conn, error) {
				if address == "192.0.2.2:443" {
					select {
					case <-firstRequested:
					case <-ctx.Done():
						return nil, ctx.Err()
					}
				}
				return fixture.dial(ctx, network, address)
			})
			result, err := Fetch(ctx, fixture.store)
			if err != nil || rejected.Load() != 1 || accepted.Load() != 1 || result.FactFrontier[0].Sequence != 8 {
				t.Fatalf("healthy business response was canceled by rejected primary: %v rejected=%d accepted=%d", err, rejected.Load(), accepted.Load())
			}
			after, _ := os.ReadFile(fixture.store.path)
			if !bytes.Equal(before, after) {
				t.Fatal("read-only candidate fetch changed identity, LKG or progress")
			}
		})
	}
}

func TestAllRejectedFetchesPreserveAcceptedState(t *testing.T) {
	fixture := newDeviceRequestFixture(t,
		func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) },
		func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{"schema":4}`)) })
	before, _ := os.ReadFile(fixture.store.path)
	if _, err := Fetch(fixture.context(context.Background()), fixture.store); err == nil {
		t.Fatal("accepted invalid responses")
	}
	after, _ := os.ReadFile(fixture.store.path)
	if !bytes.Equal(before, after) {
		t.Fatal("rejected candidates changed accepted state")
	}
}

func TestJoinedResumeValidatesAlternativeBeforePersistingOnce(t *testing.T) {
	var fixture deviceRequestFixture
	requested := make(chan struct{})
	handler := func(primary bool) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/enrollment/resume" {
				t.Error("joined resume used a different business handler")
			}
			sequence := uint64(8)
			if primary {
				close(requested)
				sequence = 6
			}
			view := fixture.view(sequence)
			writeDeviceResponse(t, w, control.EnrollmentResponse{Schema: 3, TransactionID: fixture.store.Invite().Material.Payload.(control.Invite).ID, State: "completed", DeviceView: &view})
		}
	}
	fixture = newDeviceRequestFixture(t, handler(true), handler(false))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ctx = control.WithEndpointDialer(ctx, func(ctx context.Context, network, address string) (net.Conn, error) {
		if address == "192.0.2.2:443" {
			select {
			case <-requested:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return fixture.dial(ctx, network, address)
	})
	response, err := Resume(ctx, fixture.store)
	if err != nil || response.DeviceView == nil || response.DeviceView.FactFrontier[0].Sequence != 8 {
		t.Fatal("joined resume stopped at a validly signed stale response", err)
	}
	reloaded, err := Load(fixture.store.path)
	if err != nil || reloaded.LKG().FactFrontier[0].Sequence != 8 || reloaded.state.ReportSequence != 0 {
		t.Fatal("joined resume did not persist the single verified winner", err)
	}
}

type countedReportStore struct {
	IdentityStore
	reservations atomic.Int32
}

func (store *countedReportStore) ReserveReportSequence() (control.U64, error) {
	store.reservations.Add(1)
	return store.IdentityStore.ReserveReportSequence()
}

func TestReportRetriesTheSameOriginalAndReservesOnce(t *testing.T) {
	firstRequested := make(chan struct{})
	var originalsMu sync.Mutex
	var originals [][]byte
	var encodedOriginals [][]byte
	handler := func(primary bool) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			encoded, _ := io.ReadAll(r.Body)
			if r.Header.Get("Content-Encoding") != "gzip" {
				t.Error("large signed report was not compressed")
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			reader, err := gzip.NewReader(bytes.NewReader(encoded))
			if err != nil {
				t.Error(err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			body, err := io.ReadAll(reader)
			reader.Close()
			if err != nil {
				t.Error(err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			originalsMu.Lock()
			originals = append(originals, body)
			encodedOriginals = append(encodedOriginals, encoded)
			originalsMu.Unlock()
			var report control.DeviceReport
			if err := control.DecodeCanonical(body, &report, control.ContractDecodeLimits{MaxBytes: 8 << 20, MaxDepth: 128, MaxItems: 1 << 20}); err != nil {
				t.Error(err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if primary {
				close(firstRequested)
				report.ReportSequence++ // A different report ACK cannot win.
			}
			writeDeviceResponse(t, w, control.DeviceReportResponse{Schema: 3, ReportSequence: report.ReportSequence, Status: "accepted"})
		}
	}
	fixture := newDeviceRequestFixture(t, handler(true), handler(false))
	store := &countedReportStore{IdentityStore: fixture.store}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ctx = control.WithEndpointDialer(ctx, func(ctx context.Context, network, address string) (net.Conn, error) {
		if address == "192.0.2.2:443" {
			select {
			case <-firstRequested:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return fixture.dial(ctx, network, address)
	})
	report := control.DeviceReport{NetworkGeneration: "demo-network-generation", ReportedAt: time.Now().UnixMilli(), Selections: []control.ReportSelection{}, Observations: []control.Observation{}, Runtime: control.RuntimeReadback{State: "stopped"}, Components: []control.ComponentReadback{}}
	for i := 0; i < 20; i++ {
		report.Observations = append(report.Observations, control.Observation{Level: "service", ServiceID: "demo-service", CandidateID: control.ReleaseDigest([]byte("demo-candidate")), SpecDigest: control.ReleaseDigest([]byte("demo-specification")), Target: fmt.Sprintf("https://demo-service.example/probe/%02d", i), Action: "https_request", NetworkGeneration: report.NetworkGeneration, Result: "available", ObservedAt: report.ReportedAt, ValidUntil: report.ReportedAt + time.Minute.Milliseconds()})
	}
	if err := Report(ctx, store, report); err != nil {
		t.Fatal(err)
	}
	if store.reservations.Load() != 1 || fixture.store.state.ReportSequence != 1 {
		t.Fatal("candidate retry reserved another report sequence")
	}
	originalsMu.Lock()
	defer originalsMu.Unlock()
	if len(originals) != 2 || !bytes.Equal(originals[0], originals[1]) {
		t.Fatal("candidate retry altered the signed original")
	}
	if len(encodedOriginals) != 2 || !bytes.Equal(encodedOriginals[0], encodedOriginals[1]) || len(encodedOriginals[0])*2 >= len(originals[0]) {
		t.Fatal("retry recompressed different bytes or failed to reduce repeated report fields")
	}
}

func TestReportOmitsOnlyMeasurementsAcknowledgedByFormalTransport(t *testing.T) {
	var acknowledged atomic.Bool
	var lock sync.Mutex
	sent := map[control.U64][]int{}
	handler := func(w http.ResponseWriter, r *http.Request) {
		var reader io.Reader = r.Body
		if r.Header.Get("Content-Encoding") == "gzip" {
			compressed, err := gzip.NewReader(r.Body)
			if err != nil {
				t.Error(err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			defer compressed.Close()
			reader = compressed
		}
		body, err := io.ReadAll(reader)
		var report control.DeviceReport
		if err != nil || control.DecodeCanonical(body, &report, control.ContractDecodeLimits{MaxBytes: 1 << 20, MaxDepth: 32, MaxItems: 1024}) != nil {
			t.Error("report body was not canonical", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		lock.Lock()
		sent[report.ReportSequence] = append(sent[report.ReportSequence], len(report.Observations))
		lock.Unlock()
		if !acknowledged.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		writeDeviceResponse(t, w, control.DeviceReportResponse{Schema: 3, ReportSequence: report.ReportSequence, Status: "accepted"})
	}
	fixture := newDeviceRequestFixture(t, handler, handler)
	at := time.Now().UnixMilli()
	sample := control.Observation{Level: "service", ServiceID: "demo-service", CandidateID: control.ReleaseDigest([]byte("demo-candidate")), SpecDigest: control.ReleaseDigest([]byte("demo-spec")),
		Target: "https://demo-service.example/delivery-ack", Action: "https_request", NetworkGeneration: "demo-underlay", Result: "available", ObservedAt: at, ValidUntil: at + 60_000}
	report := control.DeviceReport{NetworkGeneration: sample.NetworkGeneration, ReportedAt: at, Selections: []control.ReportSelection{}, Observations: []control.Observation{sample}, Components: []control.ComponentReadback{}, Runtime: control.RuntimeReadback{State: "stopped"}}
	ctx, cancel := context.WithTimeout(fixture.context(context.Background()), 5*time.Second)
	defer cancel()
	if err := Report(ctx, fixture.store, report); err == nil {
		t.Fatal("failed upload was acknowledged")
	}
	acknowledged.Store(true)
	if err := Report(ctx, fixture.store, report); err != nil {
		t.Fatal(err)
	}
	if err := Report(ctx, fixture.store, report); err != nil {
		t.Fatal(err)
	}
	lock.Lock()
	defer lock.Unlock()
	for sequence, want := range map[control.U64]int{1: 1, 2: 1, 3: 0} {
		if len(sent[sequence]) == 0 {
			t.Fatal("report did not cross the authenticated transport", sequence)
		}
		for _, count := range sent[sequence] {
			if count != want {
				t.Fatal("failed upload lost a sample or confirmed upload was repeated", sequence, count, want)
			}
		}
	}
	if fixture.store.state.ReportSequence != 3 {
		t.Fatal("measurement deduplication changed durable report sequence")
	}
}

func TestScopedReadsRejectPrimaryBeforeChoosingAlternative(t *testing.T) {
	for _, operation := range []string{"link-observations", "release"} {
		t.Run(operation, func(t *testing.T) {
			var fixture deviceRequestFixture
			var requests atomic.Int32
			handler := func(primary bool) http.HandlerFunc {
				return func(w http.ResponseWriter, r *http.Request) {
					requests.Add(1)
					view := fixture.store.LKG()
					if operation == "link-observations" {
						result := control.DeviceLinkObservations{Cursor: "projection", Reset: true, Removed: []string{}, Schema: 3, NetworkID: view.NetworkID, DeviceID: view.View.DeviceID, ViewDigest: view.ViewDigest, Observations: []control.DeviceLinkObservation{}}
						if primary {
							result.DeviceID = "demo-other-device"
						}
						writeDeviceResponse(t, w, result)
						return
					}
					result := control.DeviceReleaseDelivery{Schema: 3, Platform: "linux-amd64", ViewDigest: view.ViewDigest, CatalogBody: "demo-accepted", ManifestBody: "demo-manifest", CatalogSignature: strings.Repeat("A", 86), ManifestSignature: strings.Repeat("A", 86)}
					if primary {
						result.CatalogBody = "demo-rejected"
					}
					writeDeviceResponse(t, w, result)
				}
			}
			fixture = newDeviceRequestFixture(t, handler(true), handler(false))
			// Delaying the second dial until the first handler ran proves that
			// HTTP decoding alone does not cancel the semantically valid peer.
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			ctx = control.WithEndpointDialer(ctx, func(ctx context.Context, network, address string) (net.Conn, error) {
				if address == "192.0.2.2:443" {
					for requests.Load() == 0 {
						select {
						case <-ctx.Done():
							return nil, ctx.Err()
						case <-time.After(time.Millisecond):
						}
					}
				}
				return fixture.dial(ctx, network, address)
			})
			var err error
			if operation == "link-observations" {
				_, err = FetchLinkObservations(ctx, fixture.store, nil)
			} else {
				_, err = Release(ctx, fixture.store, "linux-amd64", func(value control.DeviceReleaseDelivery) error {
					if value.CatalogBody != "demo-accepted" {
						return errors.New("demo signature/expectation check rejected original")
					}
					return nil
				})
			}
			if err != nil || requests.Load() != 2 {
				t.Fatalf("scoped primary canceled healthy peer: %v requests=%d", err, requests.Load())
			}
		})
	}
}

func TestDeviceRequestCancellationWaitsForLateConnections(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{}, 2)
	var active, maximum atomic.Int32
	var connections sync.Map
	returned := make(chan error, 1)
	go func() {
		_, err := requestDeviceEndpoints(ctx, []control.EndpointGeneration{{ID: "demo-a"}, {ID: "demo-b"}, {ID: "demo-c"}}, "demo-device", nil, 2, time.Second,
			func(ctx context.Context, _ control.EndpointGeneration, _ control.TunnelHello, _ ed25519.PrivateKey) (net.Conn, error) {
				count := active.Add(1)
				defer active.Add(-1)
				for prior := maximum.Load(); count > prior && !maximum.CompareAndSwap(prior, count); prior = maximum.Load() {
				}
				started <- struct{}{}
				<-ctx.Done()
				client, server := net.Pipe()
				_ = server.Close()
				connection := &trackedDeviceConnection{Conn: client}
				connections.Store(connection, true)
				return connection, nil
			}, func(context.Context, net.Conn) (struct{}, error) {
				t.Error("canceled late connection reached business processing")
				return struct{}{}, nil
			})
		returned <- err
	}()
	<-started
	<-started
	cancel()
	if err := <-returned; !errors.Is(err, context.Canceled) || active.Load() != 0 || maximum.Load() != 2 {
		t.Fatal("cancellation did not wait within concurrency limit", err)
	}
	connections.Range(func(key, _ any) bool {
		if !key.(*trackedDeviceConnection).closed.Load() {
			t.Error("late successful connection was orphaned")
		}
		return true
	})
}

func TestDeviceRequestTimeoutReachesThirdCandidate(t *testing.T) {
	var entered, active, maximum atomic.Int32
	value, err := requestDeviceEndpoints(context.Background(), []control.EndpointGeneration{{ID: "demo-a"}, {ID: "demo-b"}, {ID: "demo-c"}}, "demo-device", nil, 2, 20*time.Millisecond,
		func(context.Context, control.EndpointGeneration, control.TunnelHello, ed25519.PrivateKey) (net.Conn, error) {
			client, server := net.Pipe()
			_ = server.Close()
			return client, nil
		}, func(ctx context.Context, _ net.Conn) (int, error) {
			count := active.Add(1)
			defer active.Add(-1)
			for prior := maximum.Load(); count > prior && !maximum.CompareAndSwap(prior, count); prior = maximum.Load() {
			}
			if entered.Add(1) <= 2 {
				<-ctx.Done()
				return 0, ctx.Err()
			}
			return 7, nil
		})
	if err != nil || value != 7 || entered.Load() != 3 || active.Load() != 0 || maximum.Load() > 2 {
		t.Fatalf("business blackholes starved third candidate: %d %v", value, err)
	}
}
