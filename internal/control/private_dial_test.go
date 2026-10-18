package control

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"reflect"
	"sync"
	"testing"
	"time"
)

// DNS uses actual wire messages through a disposable underlay connection. TCP
// still reaches the real TLS listener; no host DNS configuration is changed.
type privateDNSFixture struct {
	mu      sync.Mutex
	answers map[string][]netip.Addr
	queries []string
	tcp     []string
	workers sync.WaitGroup
}

func newPrivateDNSFixture(t *testing.T) *privateDNSFixture {
	t.Helper()
	f := &privateDNSFixture{answers: map[string][]netip.Addr{}}
	t.Cleanup(f.workers.Wait)
	return f
}
func (f *privateDNSFixture) set(server, address string) {
	f.setAddresses(server, address)
}
func (f *privateDNSFixture) setAddresses(server string, addresses ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var values []netip.Addr
	for _, address := range addresses {
		values = append(values, netip.MustParseAddr(address))
	}
	f.answers[net.JoinHostPort(server, "53")] = values
}
func (f *privateDNSFixture) dial(ctx context.Context, network, address string) (net.Conn, error) {
	if network == "tcp" {
		f.mu.Lock()
		f.tcp = append(f.tcp, address)
		f.mu.Unlock()
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	if network != "udp" {
		return nil, errors.New("unexpected underlay transport")
	}
	f.mu.Lock()
	answers, ok := f.answers[address]
	f.queries = append(f.queries, address)
	f.mu.Unlock()
	if !ok {
		return nil, errors.New("DNS escaped current authorization")
	}
	client, server := net.Pipe()
	f.workers.Add(1)
	go func() {
		defer f.workers.Done()
		defer server.Close()
		query := make([]byte, 512)
		n, err := server.Read(query)
		if err != nil || n < 17 {
			return
		}
		query = query[:n]
		response := append([]byte(nil), query...)
		binary.BigEndian.PutUint16(response[2:4], 0x8180)
		if binary.BigEndian.Uint16(query[len(query)-4:]) == 1 {
			binary.BigEndian.PutUint16(response[6:8], uint16(len(answers)))
			for _, answer := range answers {
				ip := answer.As4()
				response = append(response, 0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4)
				response = append(response, ip[:]...)
			}
		}
		_, _ = server.Write(response)
	}()
	return client, nil
}
func (f *privateDNSFixture) observations() ([]string, []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.queries...), append([]string(nil), f.tcp...)
}
func setPrivateDNSProjection(authority *Authority, node string, servers []string) {
	authority.mu.Lock()
	defer authority.mu.Unlock()
	authority.projection.DeviceAuthorizations = []DeviceAuthorization{{ID: node, DNSServers: servers}}
}

func TestPrivateHostnameUsesCurrentDNSAndActualMemberTLS(t *testing.T) {
	f := newMaterialFixture(t)
	authorities, nodes := materialAuthorities(t, f)
	root := t.TempDir()
	ca := testTransportCA(t, root)
	channels := make([]*PrivateChannel, 2)
	first := testLoopbackAddress(t)
	_, port, _ := net.SplitHostPort(first)
	second := net.JoinHostPort("127.0.0.2", port)
	for i := range nodes {
		files, _, _ := testTransportIdentity(t, root, nodes[i].ControlID, int64(100+i), f.keys[i], ca, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth})
		nodes[i].PeerTLS = &files
		listen := []string{first, second}
		peers := []PrivatePeer{}
		if i == 1 {
			listen = []string{testLoopbackAddress(t)}
			peers = []PrivatePeer{{Node: nodes[0].NodeID, Addresses: []string{net.JoinHostPort("demo.example", port)}}}
		}
		var err error
		channels[i], err = OpenPrivateChannel(PrivateChannelConfig{Schema: 3, Node: nodes[i].NodeID, Listen: listen, Peers: peers}, nodes[i])
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { channels[i].Close() })
		channels[i].AttachAuthority(authorities[i])
	}
	runtime, err := OpenRuntime(authorities[0].root, channels[0])
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { runtime.Close() })
	server := &http.Server{Handler: (&Server{Runtime: runtime, Channel: channels[0], Config: nodes[0]}).Handler(), ConnContext: controlConnContext}
	t.Cleanup(func() { server.Close() })
	go server.Serve(channels[0].ControlListener())
	dns := newPrivateDNSFixture(t)
	dns.set("192.0.2.53", "127.0.0.1")
	dns.set("192.0.2.54", "127.0.0.1")
	channels[1].underlayDial = dns.dial
	setPrivateDNSProjection(authorities[1], nodes[1].NodeID, []string{"192.0.2.53"})
	request := func() {
		t.Helper()
		client, err := channels[1].peerClient(nodes[0].NodeID)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
		defer cancel()
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://control.loom/internal/frontier", nil)
		response, err := client.Do(req)
		if err != nil {
			t.Fatal("current member request through domain failed", err)
		}
		defer response.Body.Close()
		io.Copy(io.Discard, response.Body)
		if response.StatusCode != http.StatusOK {
			t.Fatal("current member request rejected", response.StatusCode)
		}
	}
	request()
	_, calls := dns.observations()
	if !reflect.DeepEqual(calls, []string{first}) {
		t.Fatal("first answer was not consumed", calls)
	}
	// Same supplied name and resolver, changed answer: no cached IP survives.
	dns.set("192.0.2.53", "127.0.0.2")
	request()
	_, calls = dns.observations()
	if !reflect.DeepEqual(calls, []string{first, second}) {
		t.Fatal("DNS answer was persisted", calls)
	}
	// The next dial also uses the current signed projection's resolver value.
	setPrivateDNSProjection(authorities[1], nodes[1].NodeID, []string{"192.0.2.54"})
	request()
	queries, calls := dns.observations()
	if len(queries) < 3 || queries[len(queries)-1] != "192.0.2.54:53" || !reflect.DeepEqual(calls, []string{first, second, first}) {
		t.Fatal("current DNS authorization was not consumed", queries, calls)
	}
	// The first address accepts TCP and presents a CA-issued leaf for the
	// correct ControlID but a noncurrent key. Only the second authenticates.
	channels[0].transportM.Lock()
	old := channels[0].listeners[first]
	channels[0].transportM.Unlock()
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	wrongFiles, wrongPair, _ := testTransportIdentity(t, t.TempDir(), nodes[0].ControlID, 200, testKey(t), ca, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	_, roots, err := LoadTLSIdentity(wrongFiles)
	if err != nil {
		t.Fatal(err)
	}
	wrong, err := tls.Listen("tcp", first, &tls.Config{Certificates: []tls.Certificate{wrongPair}, ClientCAs: roots, ClientAuth: tls.RequireAndVerifyClientCert, MinVersion: tls.VersionTLS13, NextProtos: []string{controlALPN}})
	if err != nil {
		t.Fatal(err)
	}
	defer wrong.Close()
	rejected := make(chan struct{})
	go func() {
		defer close(rejected)
		connection, err := wrong.Accept()
		if err == nil {
			connection.SetDeadline(time.Now().Add(time.Second))
			connection.(*tls.Conn).Handshake()
			connection.Close()
		}
	}()
	channels[1].underlayDial = func(ctx context.Context, network, address string) (net.Conn, error) {
		if network == "tcp" && address == second {
			select {
			case <-rejected:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		return dns.dial(ctx, network, address)
	}
	dns.setAddresses("192.0.2.54", "127.0.0.1", "127.0.0.2")
	request()
	_, calls = dns.observations()
	if calls[len(calls)-1] != second {
		t.Fatal("reachable wrong TLS identity prevented the next authenticated address", calls)
	}
}

func TestPrivateHostnameRejectsMissingAuthorizationWithoutBlockingLiteral(t *testing.T) {
	channel := &PrivateChannel{config: PrivateChannelConfig{Node: "demo-local"}, done: make(chan struct{}), control: newConnectionListener()}
	defer channel.Close()
	authority := &Authority{}
	dialed := 0
	connect := func(context.Context, string) (net.Conn, error) {
		dialed++
		a, b := net.Pipe()
		b.Close()
		return a, nil
	}
	for _, test := range []struct {
		name           string
		authority      *Authority
		authorizations []DeviceAuthorization
	}{
		{name: "no-authority"},
		{name: "missing", authority: authority},
		{name: "another-device", authority: authority, authorizations: []DeviceAuthorization{{ID: "demo-another", DNSServers: []string{"192.0.2.53"}}}},
		{name: "no-resolvers", authority: authority, authorizations: []DeviceAuthorization{{ID: "demo-local"}}},
		{name: "ambiguous", authority: authority, authorizations: []DeviceAuthorization{{ID: "demo-local", DNSServers: []string{"192.0.2.53"}}, {ID: "demo-local", DNSServers: []string{"192.0.2.54"}}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			authority.mu.Lock()
			authority.projection.DeviceAuthorizations = test.authorizations
			authority.mu.Unlock()
			channel.AttachAuthority(test.authority)
			before := dialed
			if c, err := channel.dialPrivateEndpoint(context.Background(), "demo.example:443", connect); err == nil {
				c.Close()
				t.Fatal("hostname escaped missing or ambiguous authorization")
			}
			if dialed != before {
				t.Fatal("hostname reached an uncertified dialer")
			}
			c, err := channel.dialPrivateEndpoint(context.Background(), "127.0.0.1:443", connect)
			if err != nil {
				t.Fatal("literal coordinate acquired a DNS dependency", err)
			}
			c.Close()
		})
	}
}

func TestPrivateHostnameCancellationJoinsDNSAndDoesNotBlockLiteral(t *testing.T) {
	authority := &Authority{}
	setPrivateDNSProjection(authority, "demo-local", []string{"192.0.2.53"})
	channel := &PrivateChannel{config: PrivateChannelConfig{Node: "demo-local"}, done: make(chan struct{}), control: newConnectionListener()}
	channel.AttachAuthority(authority)
	var dnsWorkers sync.WaitGroup
	started := make(chan struct{}, 2)
	channel.underlayDial = func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "udp" || address != "192.0.2.53:53" {
			return nil, errors.New("unexpected resolution")
		}
		client, server := net.Pipe()
		dnsWorkers.Add(1)
		go func() {
			defer dnsWorkers.Done()
			defer server.Close()
			query := make([]byte, 512)
			if _, err := server.Read(query); err == nil {
				started <- struct{}{}
				io.Copy(io.Discard, server)
			}
		}()
		return client, nil
	}
	done := make(chan error, 1)
	go func() {
		_, err := channel.dialPrivateEndpoint(context.Background(), "demo.example:443", channel.dialPrivateTCP)
		done <- err
	}()
	<-started
	// A literal candidate can proceed while DNS remains silent.
	c, err := channel.dialPrivateEndpoint(context.Background(), "127.0.0.1:443", func(context.Context, string) (net.Conn, error) { a, b := net.Pipe(); b.Close(); return a, nil })
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	closed := make(chan error, 1)
	go func() { closed <- channel.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("channel shutdown retained a DNS attempt")
	}
	if err := <-done; err == nil {
		t.Fatal("cancelled DNS attempt succeeded")
	}
	dnsWorkers.Wait()
}
