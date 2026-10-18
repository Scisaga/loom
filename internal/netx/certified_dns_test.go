package netx

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestCertifiedDNSUsesOnlySuppliedUnderlayAndHandlesTruncation(t *testing.T) {
	var transportsMu sync.Mutex
	var transports []string
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != "192.0.2.53:53" {
			return nil, errors.New("unexpected resolver")
		}
		transportsMu.Lock()
		transports = append(transports, network)
		transportsMu.Unlock()
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			query := make([]byte, 512)
			if network == "tcp" {
				var length [2]byte
				if _, err := io.ReadFull(server, length[:]); err != nil {
					return
				}
				query = make([]byte, binary.BigEndian.Uint16(length[:]))
				if _, err := io.ReadFull(server, query); err != nil {
					return
				}
			} else {
				n, err := server.Read(query)
				if err != nil {
					return
				}
				query = query[:n]
			}
			answer := append([]byte(nil), query...)
			binary.BigEndian.PutUint16(answer[2:4], 0x8180)
			kind := binary.BigEndian.Uint16(query[len(query)-4:])
			if kind == 1 && network == "udp" {
				binary.BigEndian.PutUint16(answer[2:4], 0x8380)
			}
			if kind == 1 && network == "tcp" {
				binary.BigEndian.PutUint16(answer[6:8], 1)
				answer = append(answer, 0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 192, 0, 2, 8)
			}
			if network == "tcp" {
				framed := make([]byte, 2)
				binary.BigEndian.PutUint16(framed, uint16(len(answer)))
				answer = append(framed, answer...)
			}
			_, _ = server.Write(answer)
		}()
		return client, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	addresses, err := ResolveCertifiedIPs(ctx, "demo-entry.example", []string{"192.0.2.53"}, dial)
	if err != nil || !reflect.DeepEqual(addresses, []netip.Addr{netip.MustParseAddr("192.0.2.8")}) || len(transports) != 3 || countTransport(transports, "udp") != 2 || countTransport(transports, "tcp") != 1 {
		t.Fatalf("DNS exchange: %v %v %v", addresses, transports, err)
	}
}

func TestCertifiedDNSNeverFallsBackToHostResolution(t *testing.T) {
	var calls atomic.Int32
	dial := func(context.Context, string, string) (net.Conn, error) {
		calls.Add(1)
		return nil, errors.New("demo resolver unavailable")
	}
	for _, servers := range [][]string{nil, {"demo-resolver.example"}, {"192.0.2.53"}} {
		if _, err := ResolveCertifiedIPs(context.Background(), "localhost", servers, dial); err == nil {
			t.Fatal("used host-local resolution")
		}
	}
	if calls.Load() != 2 {
		t.Fatalf("unexpected resolver attempts: %d", calls.Load())
	}
	addresses, err := ResolveCertifiedIPs(context.Background(), "192.0.2.8", nil, dial)
	if err != nil || len(addresses) != 1 || calls.Load() != 2 {
		t.Fatal("literal needed DNS")
	}
}

func TestCertifiedDNSHealthyResolverDoesNotWaitForBlackhole(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var active atomic.Int32
	var blackholes atomic.Int32
	blackholesReady := make(chan struct{})
	dial := func(_ context.Context, network, address string) (net.Conn, error) {
		return certifiedDNSTestPipe(network, &active, func(query []byte) []byte {
			if address == "192.0.2.53:53" {
				if blackholes.Add(1) == 2 {
					close(blackholesReady)
				}
				return nil
			}
			select {
			case <-blackholesReady:
			case <-ctx.Done():
				return nil
			}
			return certifiedDNSTestAnswer(query, "192.0.2.8")
		}), nil
	}
	got, err := ResolveCertifiedIPs(ctx, "demo-entry.example", []string{"192.0.2.53", "192.0.2.54"}, dial)
	if err != nil || !reflect.DeepEqual(got, []netip.Addr{netip.MustParseAddr("192.0.2.8")}) {
		t.Fatalf("healthy second resolver blocked by first: %v, %v", got, err)
	}
	if active.Load() != 0 {
		t.Fatalf("resolver returned with %d sockets still open", active.Load())
	}
}

func TestCertifiedDNSWorkingFamilyRetainsCallerDialBudget(t *testing.T) {
	for _, healthyKind := range []uint16{1, 28} {
		t.Run(map[uint16]string{1: "A", 28: "AAAA"}[healthyKind], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			var active atomic.Int32
			blackholeReady := make(chan struct{})
			dial := func(_ context.Context, network, _ string) (net.Conn, error) {
				return certifiedDNSTestPipe(network, &active, func(query []byte) []byte {
					if binary.BigEndian.Uint16(query[len(query)-4:]) != healthyKind {
						close(blackholeReady)
						return nil
					}
					select {
					case <-blackholeReady:
					case <-ctx.Done():
						return nil
					}
					return certifiedDNSTestAnswer(query, "192.0.2.9", "192.0.2.8", "192.0.2.8", "2001:db8::9", "2001:db8::8", "2001:db8::8")
				}), nil
			}
			want := []netip.Addr{netip.MustParseAddr("192.0.2.8"), netip.MustParseAddr("192.0.2.9")}
			if healthyKind == 28 {
				want = []netip.Addr{netip.MustParseAddr("2001:db8::8"), netip.MustParseAddr("2001:db8::9")}
			}
			got, err := ResolveCertifiedIPs(ctx, "demo-entry.example", []string{"192.0.2.53"}, dial)
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("working family blocked or answer lost: %v, %v", got, err)
			}
			if active.Load() != 0 {
				t.Fatalf("resolver returned with %d sockets still open", active.Load())
			}
			if remaining, ok := ctx.Deadline(); !ok || time.Until(remaining) < 100*time.Millisecond {
				t.Fatal("blackholed family exhausted the caller's connection budget")
			}
		})
	}
}

func TestCertifiedDNSCollectsDelayedAAfterAAAA(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var active atomic.Int32
	firstAnswered := make(chan struct{})
	releaseA := make(chan struct{})
	dial := func(_ context.Context, network, _ string) (net.Conn, error) {
		return certifiedDNSTestPipe(network, &active, func(query []byte) []byte {
			if binary.BigEndian.Uint16(query[len(query)-4:]) == 28 {
				close(firstAnswered)
			} else {
				select {
				case <-releaseA:
				case <-ctx.Done():
					return nil
				}
			}
			return certifiedDNSTestAnswer(query, "192.0.2.8", "2001:db8::8")
		}), nil
	}
	type result struct {
		addresses []netip.Addr
		err       error
	}
	done := make(chan result, 1)
	go func() {
		addresses, err := ResolveCertifiedIPs(ctx, "demo-entry.example", []string{"192.0.2.53"}, dial)
		done <- result{addresses, err}
	}()
	<-firstAnswered
	select {
	case result := <-done:
		t.Fatalf("AAAA discarded the pending IPv4 alternative: %v %v", result.addresses, result.err)
	case <-time.After(20 * time.Millisecond):
	}
	close(releaseA)
	outcome := <-done
	want := []netip.Addr{netip.MustParseAddr("192.0.2.8"), netip.MustParseAddr("2001:db8::8")}
	if outcome.err != nil || !reflect.DeepEqual(outcome.addresses, want) || active.Load() != 0 {
		t.Fatalf("lost delayed IPv4 alternative: %v %v open=%d", outcome.addresses, outcome.err, active.Load())
	}
}

func TestCertifiedDNSBoundsResolversAndAdvancesAfterEmptyAnswers(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var active atomic.Int32
	queries := make(chan string, 6)
	release := make(chan struct{})
	dial := func(_ context.Context, network, address string) (net.Conn, error) {
		return certifiedDNSTestPipe(network, &active, func(query []byte) []byte {
			queries <- address
			if address == "192.0.2.55:53" {
				return certifiedDNSTestAnswer(query, "192.0.2.8")
			}
			select {
			case <-release:
				return certifiedDNSTestAnswer(query)
			case <-ctx.Done():
				return nil
			}
		}), nil
	}
	done := make(chan error, 1)
	go func() {
		got, err := ResolveCertifiedIPs(ctx, "demo-entry.example", []string{"192.0.2.53", "192.0.2.54", "192.0.2.55"}, dial)
		if err == nil && !reflect.DeepEqual(got, []netip.Addr{netip.MustParseAddr("192.0.2.8")}) {
			err = errors.New("next resolver returned the wrong address")
		}
		done <- err
	}()
	for range 4 {
		select {
		case address := <-queries:
			if address == "192.0.2.55:53" {
				t.Fatal("started a third resolver while both attempts were blocked")
			}
		case <-ctx.Done():
			t.Fatal("did not start both families on the first two resolvers")
		}
	}
	select {
	case address := <-queries:
		t.Fatalf("exceeded two active resolver attempts: %s", address)
	default:
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if active.Load() != 0 {
		t.Fatalf("resolver returned with %d sockets still open", active.Load())
	}
}

func TestCertifiedDNSBudgetReachesThirdResolverAfterTwoBlackholes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var active atomic.Int32
	var third atomic.Int32
	dial := func(_ context.Context, network, address string) (net.Conn, error) {
		return certifiedDNSTestPipe(network, &active, func(query []byte) []byte {
			if address != "192.0.2.55:53" {
				return nil
			}
			third.Add(1)
			return certifiedDNSTestAnswer(query, "192.0.2.8")
		}), nil
	}
	got, err := ResolveCertifiedIPs(ctx, "demo-entry.example", []string{"192.0.2.53", "192.0.2.54", "192.0.2.55"}, dial)
	if err != nil || !reflect.DeepEqual(got, []netip.Addr{netip.MustParseAddr("192.0.2.8")}) || third.Load() != 2 || active.Load() != 0 {
		t.Fatalf("first two blackholes starved third resolver: %v %v third=%d open=%d", got, err, third.Load(), active.Load())
	}
	if deadline, _ := ctx.Deadline(); time.Until(deadline) < 400*time.Millisecond {
		t.Fatal("DNS resolver waves consumed the caller's reserved dial budget")
	}
}

func TestCertifiedDNSCancellationClosesAllAttempts(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var active atomic.Int32
	queries := make(chan struct{}, 4)
	dial := func(_ context.Context, network, _ string) (net.Conn, error) {
		return certifiedDNSTestPipe(network, &active, func([]byte) []byte {
			queries <- struct{}{}
			return nil
		}), nil
	}
	done := make(chan error, 1)
	go func() {
		_, err := ResolveCertifiedIPs(ctx, "demo-entry.example", []string{"192.0.2.53", "192.0.2.54"}, dial)
		done <- err
	}()
	for range 4 {
		select {
		case <-queries:
		case <-time.After(time.Second):
			t.Fatal("resolver attempts did not start")
		}
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) || active.Load() != 0 {
			t.Fatalf("cancel failed to join and close attempts: %v, %d open", err, active.Load())
		}
	case <-time.After(time.Second):
		t.Fatal("cancel did not terminate resolver attempts")
	}
}

func countTransport(values []string, want string) int {
	count := 0
	for _, value := range values {
		if value == want {
			count++
		}
	}
	return count
}

type certifiedDNSTestConnection struct {
	net.Conn
	active *atomic.Int32
	once   sync.Once
}

func (c *certifiedDNSTestConnection) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { c.active.Add(-1) })
	return err
}

func certifiedDNSTestPipe(network string, active *atomic.Int32, response func([]byte) []byte) net.Conn {
	client, server := net.Pipe()
	active.Add(1)
	go func() {
		defer server.Close()
		query := make([]byte, 512)
		if network == "tcp" {
			var length [2]byte
			if _, err := io.ReadFull(server, length[:]); err != nil {
				return
			}
			query = make([]byte, binary.BigEndian.Uint16(length[:]))
			if _, err := io.ReadFull(server, query); err != nil {
				return
			}
		} else {
			n, err := server.Read(query)
			if err != nil {
				return
			}
			query = query[:n]
		}
		answer := response(query)
		if answer == nil {
			_, _ = io.Copy(io.Discard, server)
			return
		}
		if network == "tcp" {
			framed := make([]byte, 2)
			binary.BigEndian.PutUint16(framed, uint16(len(answer)))
			answer = append(framed, answer...)
		}
		_, _ = server.Write(answer)
	}()
	return &certifiedDNSTestConnection{Conn: client, active: active}
}

func certifiedDNSTestAnswer(query []byte, addresses ...string) []byte {
	answer := append([]byte(nil), query...)
	binary.BigEndian.PutUint16(answer[2:4], 0x8180)
	kind := binary.BigEndian.Uint16(query[len(query)-4:])
	var count uint16
	for _, address := range addresses {
		ip := netip.MustParseAddr(address)
		if kind == 1 && !ip.Is4() || kind == 28 && !ip.Is6() {
			continue
		}
		data := ip.AsSlice()
		answer = append(answer, 0xc0, 12, byte(kind>>8), byte(kind), 0, 1, 0, 0, 0, 30, 0, byte(len(data)))
		answer = append(answer, data...)
		count++
	}
	binary.BigEndian.PutUint16(answer[6:8], count)
	return answer
}
