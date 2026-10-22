package control

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

const (
	controlALPN      = "loom-control/3"
	controlRelayALPN = "loom-control-relay/1"
)

// PrivateChannelConfig contains protected local dialing inputs. Membership
// and target identity are always obtained from the signed ControlConfig.
type PrivateChannelConfig struct {
	Schema int           `json:"schema"`
	Node   string        `json:"node"`
	Listen []string      `json:"listen"`
	Peers  []PrivatePeer `json:"peers"`
}
type PrivatePeer struct {
	Node      string   `json:"node"`
	Addresses []string `json:"addresses"`
}

func privateAddress(address string) bool {
	return parsePrivateChannelAddress(address, true)
}

func parsePrivateChannelAddress(address string, local bool) bool {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		if local || !contractDNSName(host) || net.JoinHostPort(host, port) != address {
			return false
		}
	} else if ip.Zone() != "" || ip.String() != host {
		return false
	} else if local && !ip.IsPrivate() && !ip.IsLoopback() {
		return false
	} else if !local && !ip.IsPrivate() && !ip.IsLoopback() && (ip.Is4In6() || !ip.IsGlobalUnicast()) {
		return false
	}
	n, err := strconv.Atoi(port)
	return err == nil && n > 0 && n <= 65535 && strconv.Itoa(n) == port
}
func (config PrivateChannelConfig) Validate() error {
	if config.Schema != 3 || ValidateID(config.Node) != nil || len(config.Listen) == 0 || config.Peers == nil {
		return errors.New("private channel inputs are incomplete")
	}
	check := func(addresses []string, local bool) bool {
		if len(addresses) == 0 {
			return false
		}
		for i, address := range addresses {
			if !parsePrivateChannelAddress(address, local) || i > 0 && addresses[i-1] >= address {
				return false
			}
		}
		return true
	}
	if !check(config.Listen, true) {
		return errors.New("private listeners must be uniquely sorted canonical private IP addresses")
	}
	for i, peer := range config.Peers {
		if ValidateID(peer.Node) != nil || peer.Node == config.Node || !check(peer.Addresses, false) || i > 0 && config.Peers[i-1].Node >= peer.Node {
			return errors.New("private peer inputs are invalid or not uniquely sorted")
		}
	}
	return nil
}
func LoadPrivateChannelConfig(path string) (PrivateChannelConfig, error) {
	body, err := readProtectedControlFile(path)
	if err != nil {
		return PrivateChannelConfig{}, err
	}
	var config PrivateChannelConfig
	err = DecodeCanonical(body, &config, ContractDecodeLimits{MaxBytes: 8 << 20, MaxDepth: 16, MaxItems: 1 << 20})
	return config, err
}

type PrivateChannel struct {
	config       PrivateChannelConfig
	tlsConfig    *tls.Config
	peerTLS      *tls.Config
	control      *connectionListener
	listeners    map[string]net.Listener
	connections  map[*privateConnection]struct{}
	transportM   sync.Mutex
	workers      sync.WaitGroup
	done         chan struct{}
	closeOnce    sync.Once
	authorityM   sync.RWMutex
	authority    *Authority
	relayOnly    bool
	underlayDial func(context.Context, string, string) (net.Conn, error)
}

func OpenPrivateChannel(config PrivateChannelConfig, node NodeConfig) (*PrivateChannel, error) {
	return openPrivateChannel(config, node, net.Listen, 5*time.Second)
}

func openPrivateChannel(config PrivateChannelConfig, node NodeConfig, listen func(string, string) (net.Listener, error), retry time.Duration) (*PrivateChannel, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if err := node.Validate(); err != nil {
		return nil, err
	}
	if node.NodeID != config.Node {
		return nil, errors.New("control identity does not match private channel node")
	}
	browserConfig, browserErr := browserTLSConfig(node)
	peerConfig, peerErr := peerTLSConfig(node)
	if browserErr != nil {
		log.Print("control: private browser TLS unavailable; local administration remains available")
	}
	if peerErr != nil {
		log.Print("control: private member TLS unavailable; local administration remains available")
	} else {
		peerConfig.NextProtos = []string{controlALPN, controlRelayALPN}
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
	tlsConfig.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		for _, protocol := range hello.SupportedProtos {
			if protocol == controlALPN || protocol == controlRelayALPN {
				if peerConfig == nil {
					return nil, errors.New("private member TLS unavailable")
				}
				return peerConfig, nil
			}
		}
		if browserConfig == nil {
			return nil, errors.New("private browser TLS unavailable")
		}
		return browserConfig, nil
	}
	channel := &PrivateChannel{config: config, tlsConfig: tlsConfig, peerTLS: peerConfig, control: newConnectionListener(),
		done: make(chan struct{}), listeners: map[string]net.Listener{}, connections: map[*privateConnection]struct{}{}}
	channel.startPrivateListeners(listen, retry)
	return channel, nil
}

func (channel *PrivateChannel) AttachAuthority(authority *Authority) { // runtime-only connection
	channel.authorityM.Lock()
	channel.authority = authority
	channel.authorityM.Unlock()
}

func (channel *PrivateChannel) authorizeMember(certificates []*x509.Certificate) bool {
	return channel.authorizeMemberFor(certificates, false)
}

func (channel *PrivateChannel) authorizeMemberFor(certificates []*x509.Certificate, history bool) bool {
	channel.authorityM.RLock()
	authority := channel.authority
	channel.authorityM.RUnlock()
	if authority == nil || channel.peerTLS == nil || len(certificates) == 0 {
		return false
	}
	certificate := certificates[0]
	intermediates := x509.NewCertPool()
	for _, intermediate := range certificates[1:] {
		intermediates.AddCert(intermediate)
	}
	if _, err := certificate.Verify(x509.VerifyOptions{Roots: channel.peerTLS.ClientCAs, Intermediates: intermediates,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return false
	}
	public, ok := certificate.PublicKey.(ed25519.PublicKey)
	if !ok {
		return false
	}
	if history {
		return authority.historicalMember(certificate.Subject.CommonName, base64.RawURLEncoding.EncodeToString(public))
	}
	projection := authority.Snapshot()
	for _, member := range projection.Config.Members {
		key, _ := decodePublicKey(member.PublicKey)
		if member.ControlID == certificate.Subject.CommonName && key != nil && key.Equal(public) {
			return true
		}
	}
	return false
}

func decodePublicKey(value string) (ed25519.PublicKey, error) {
	key, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return nil, errors.New("control member key is invalid")
	}
	return ed25519.PublicKey(key), nil
}

func (channel *PrivateChannel) accept(listener net.Listener) {
	for {
		connection, err := listener.Accept()
		if err != nil {
			select {
			case <-channel.done:
				return
			default:
				return
			}
		}
		tracked := channel.trackPrivateConnection(connection)
		if tracked == nil {
			return
		}
		channel.workers.Add(1)
		go func() {
			defer channel.workers.Done()
			channel.classify(tracked)
		}()
	}
}

func (channel *PrivateChannel) classify(connection net.Conn) {
	reader := bufio.NewReader(connection)
	_ = connection.SetReadDeadline(time.Now().Add(10 * time.Second))
	first, err := reader.Peek(1)
	if err != nil {
		_ = connection.Close()
		return
	}
	_ = connection.SetReadDeadline(time.Time{})
	buffered := &bufferedConnection{Conn: connection, reader: reader}
	if first[0] != 0x16 {
		_ = connection.Close()
		return
	}
	tlsConnection := tls.Server(buffered, channel.tlsConfig.Clone())
	_ = tlsConnection.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tlsConnection.Handshake(); err != nil {
		_ = tlsConnection.Close()
		return
	}
	_ = tlsConnection.SetDeadline(time.Time{})
	state := tlsConnection.ConnectionState()
	if state.NegotiatedProtocol == controlRelayALPN {
		if !channel.relayOnly && !channel.authorizeMember(state.PeerCertificates) {
			_ = tlsConnection.Close()
			return
		}
		channel.relayPrivate(tlsConnection)
		return
	}
	if channel.relayOnly {
		_ = tlsConnection.Close()
		return
	}
	if state.NegotiatedProtocol == controlALPN && !channel.authorizeMemberFor(state.PeerCertificates, true) {
		_ = tlsConnection.Close()
		return
	}
	if state.NegotiatedProtocol == controlALPN {
		if !channel.control.deliver(&memberHTTPConnection{Conn: tlsConnection, state: state}) {
			_ = tlsConnection.Close()
		}
		return
	}
	if state.NegotiatedProtocol != "" && state.NegotiatedProtocol != "http/1.1" && state.NegotiatedProtocol != controlALPN || !channel.control.deliver(tlsConnection) {
		_ = tlsConnection.Close()
	}
}

func (channel *PrivateChannel) memberForNode(node string) (Member, bool) {
	channel.authorityM.RLock()
	authority := channel.authority
	channel.authorityM.RUnlock()
	if authority == nil {
		return Member{}, false
	}
	projection := authority.Snapshot()
	for _, member := range projection.Config.Members {
		if member.NodeID == node {
			return member, true
		}
	}
	return Member{}, false
}

func (channel *PrivateChannel) relayPrivate(connection *tls.Conn) {
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(10 * time.Second))
	var length uint16
	if err := binary.Read(connection, binary.BigEndian, &length); err != nil || length == 0 || length > 1024 {
		return
	}
	body := make([]byte, int(length))
	if _, err := io.ReadFull(connection, body); err != nil {
		return
	}
	target := string(body)
	if channel.relayOnly && len(channel.endpoints(target)) == 0 {
		_, _ = connection.Write([]byte{1})
		return
	}
	if !channel.relayOnly {
		if _, ok := channel.memberForNode(target); !ok {
			_, _ = connection.Write([]byte{1})
			return
		}
	}
	var targetConnection net.Conn
	for _, endpoint := range channel.endpoints(target) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		candidate, err := channel.dialPrivateEndpoint(ctx, endpoint, channel.dialPrivateTCP)
		cancel()
		if err == nil {
			targetConnection = candidate
			break
		}
	}
	if targetConnection == nil {
		_, _ = connection.Write([]byte{1})
		return
	}
	targetConnection = channel.trackPrivateConnection(targetConnection)
	if targetConnection == nil {
		return
	}
	defer targetConnection.Close()
	if _, err := connection.Write([]byte{0}); err != nil {
		return
	}
	_ = connection.SetDeadline(time.Time{})
	_ = targetConnection.SetDeadline(time.Time{})
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(targetConnection, connection)
		if tcp, ok := targetConnection.(interface{ CloseWrite() error }); ok {
			_ = tcp.CloseWrite()
		}
		close(done)
	}()
	_, _ = io.Copy(connection, targetConnection)
	_ = connection.Close()
	<-done
}

func (channel *PrivateChannel) ControlListener() net.Listener { return channel.control }
func (channel *PrivateChannel) ListenAddresses() []string {
	return append([]string(nil), channel.config.Listen...)
}

func (channel *PrivateChannel) endpoints(node string) []string {
	for _, peer := range channel.config.Peers {
		if peer.Node == node {
			return append([]string(nil), peer.Addresses...)
		}
	}
	return nil
}

func (channel *PrivateChannel) peerClient(node string) (*http.Client, error) {
	return channel.peerClientFor(node, false)
}

type controlProofRoundTripper struct{ transport http.RoundTripper }

func (t controlProofRoundTripper) CloseIdleConnections() {
	if closer, ok := t.transport.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}

func (t controlProofRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Method != http.MethodGet || r.URL.Path != "/internal/control-proof" || r.URL.RawPath != "" || r.URL.RawQuery != "" {
		return nil, errors.New("member proof transport cannot carry privileged requests")
	}
	return t.transport.RoundTrip(r)
}

func (channel *PrivateChannel) peerClientFor(node string, proofOnly bool) (*http.Client, error) {
	if _, ok := channel.memberForNode(node); !ok {
		return nil, errors.New("control HTTP target is not a configured member")
	}
	transport := &http.Transport{Proxy: nil, ForceAttemptHTTP2: false, DisableKeepAlives: true, DisableCompression: true,
		MaxIdleConns: 1, MaxIdleConnsPerHost: 1, MaxConnsPerHost: 1, IdleConnTimeout: 30 * time.Second}
	transport.DialTLSContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		return channel.dialMemberTLSFor(ctx, node, controlALPN, controlRelayALPN, 15*time.Second, proofOnly)
	}
	client := &http.Client{Timeout: 15 * time.Second, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("member request redirect is forbidden") }}
	if proofOnly {
		client.Transport = controlProofRoundTripper{transport}
	}
	return client, nil
}

func (channel *PrivateChannel) Close() error {
	var result error
	channel.closeOnce.Do(func() {
		close(channel.done)
		channel.control.Close()
		channel.transportM.Lock()
		for _, listener := range channel.listeners {
			if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) && result == nil {
				result = err
			}
		}
		connections := make([]*privateConnection, 0, len(channel.connections))
		for connection := range channel.connections {
			connections = append(connections, connection)
		}
		channel.transportM.Unlock()
		for _, connection := range connections {
			_ = connection.Close()
		}
		channel.workers.Wait()
	})
	return result
}

type bufferedConnection struct {
	net.Conn
	reader *bufio.Reader
}

// The member ALPN selects the member TLS identity while the payload remains
// HTTP/1.1. net/http would otherwise hand a custom ALPN to TLSNextProto instead
// of parsing HTTP. Preserve the verified handshake in the connection context.
type memberHTTPConnection struct {
	net.Conn
	state tls.ConnectionState
}

type memberTLSContextKey struct{}

func controlConnContext(ctx context.Context, connection net.Conn) context.Context {
	if member, ok := connection.(*memberHTTPConnection); ok {
		return context.WithValue(ctx, memberTLSContextKey{}, member.state)
	}
	return ctx
}

func (connection *bufferedConnection) Read(body []byte) (int, error) {
	return connection.reader.Read(body)
}

type connectionListener struct {
	connections chan net.Conn
	done        chan struct{}
	once        sync.Once
}

func newConnectionListener() *connectionListener {
	return &connectionListener{connections: make(chan net.Conn), done: make(chan struct{})}
}

func (listener *connectionListener) deliver(connection net.Conn) bool {
	select {
	case listener.connections <- connection:
		return true
	case <-listener.done:
		return false
	}
}

func (listener *connectionListener) Accept() (net.Conn, error) {
	select {
	case connection := <-listener.connections:
		return connection, nil
	case <-listener.done:
		return nil, net.ErrClosed
	}
}
func (listener *connectionListener) Close() error {
	listener.once.Do(func() { close(listener.done) })
	return nil
}
func (listener *connectionListener) Addr() net.Addr { return channelAddress("private-channel") }

type channelAddress string

func (address channelAddress) Network() string { return "loom-private" }
func (address channelAddress) String() string  { return string(address) }

func (channel *PrivateChannel) dialMemberTLS(ctx context.Context, target, protocol, relayProtocol string, timeout time.Duration) (net.Conn, error) {
	return channel.dialMemberTLSFor(ctx, target, protocol, relayProtocol, timeout, false)
}

func (channel *PrivateChannel) dialMemberTLSFor(ctx context.Context, target, protocol, relayProtocol string, timeout time.Duration, proofOnly bool) (net.Conn, error) {
	if _, ok := channel.memberForNode(target); !ok {
		return nil, errors.New("private control target is not a current member")
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	type route struct {
		endpoint  string
		relayNode string
	}
	var routes []route
	for _, endpoint := range channel.endpoints(target) {
		routes = append(routes, route{endpoint: endpoint})
	}
	for _, peer := range channel.config.Peers {
		if peer.Node != target {
			for _, endpoint := range peer.Addresses {
				routes = append(routes, route{endpoint: endpoint, relayNode: peer.Node})
			}
		}
	}
	if len(routes) == 0 {
		return nil, fmt.Errorf("private control node %s has no private route", target)
	}
	type result struct {
		connection net.Conn
		err        error
	}
	results := make(chan result)
	start := func(candidate route) {
		go func(candidate route) {
			connection, err := channel.dialMemberRoute(ctx, target, candidate.endpoint, protocol, relayProtocol, candidate.relayNode, proofOnly)
			select {
			case results <- result{connection, err}:
			case <-ctx.Done():
				if connection != nil {
					_ = connection.Close()
				}
			}
		}(candidate)
	}
	// A fast authenticated direct route avoids paying for an extra relay hop
	// throughout the retained member connection. Slow direct authentication
	// cannot consume the whole request before independent relays get a chance.
	var waiting []route
	pending := 0
	for _, candidate := range routes {
		if candidate.relayNode != "" {
			waiting = append(waiting, candidate)
		} else {
			start(candidate)
			pending++
		}
	}
	var release <-chan time.Time
	var timer *time.Timer
	if pending > 0 && len(waiting) > 0 {
		timer = time.NewTimer(150 * time.Millisecond)
		release = timer.C
		defer timer.Stop()
	}
	startRelays := func() {
		if timer != nil {
			timer.Stop()
		}
		release = nil
		for _, candidate := range waiting {
			start(candidate)
			pending++
		}
		waiting = nil
	}
	if pending == 0 {
		startRelays()
	}
	var failures []error
	for pending > 0 {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-channel.done:
			return nil, net.ErrClosed
		case <-release:
			startRelays()
		case result := <-results:
			pending--
			if result.err == nil {
				return result.connection, nil
			}
			failures = append(failures, result.err)
			if pending == 0 {
				startRelays()
			}
		}
	}
	return nil, errors.Join(failures...)
}

// All establishment steps share one deadline and cancellation, including the
// relay's target response. The losing attempts cannot outlive the request.
func (channel *PrivateChannel) dialMemberRoute(ctx context.Context, target, endpoint, protocol, relayProtocol, relayNode string, proofOnly bool) (net.Conn, error) {
	if channel.peerTLS == nil {
		return nil, errors.New("private member TLS unavailable")
	}
	return channel.dialPrivateEndpoint(ctx, endpoint, func(ctx context.Context, address string) (net.Conn, error) {
		return channel.dialMemberAddress(ctx, target, endpoint, address, protocol, relayProtocol, relayNode, proofOnly)
	})
}

func (channel *PrivateChannel) dialMemberAddress(ctx context.Context, target, endpoint, address, protocol, relayProtocol, relayNode string, proofOnly bool) (net.Conn, error) {
	raw, err := channel.dialPrivateTCP(ctx, address)
	if err != nil {
		return nil, err
	}
	raw = channel.trackPrivateConnection(raw)
	if raw == nil {
		return nil, net.ErrClosed
	}
	stop := context.AfterFunc(ctx, func() { _ = raw.Close() })
	success := false
	defer func() {
		stop()
		if !success {
			_ = raw.Close()
		}
	}()
	if deadline, ok := ctx.Deadline(); ok {
		_ = raw.SetDeadline(deadline)
	}
	var transport net.Conn = raw
	if relayNode != "" {
		host, _, _ := net.SplitHostPort(endpoint)
		config := channel.peerTLS.Clone()
		config.ServerName = host
		config.NextProtos = []string{relayProtocol}
		if _, currentMember := channel.memberForNode(relayNode); currentMember {
			// Member identity is independent of its supplied underlay coordinate.
			// The outer hop always needs the current relay key, including when
			// the inner request is only retrieving a historical control proof.
			config = channel.relayTargetTLS(relayNode, relayProtocol, false)
		}
		outer := tls.Client(raw, config)
		if err := outer.HandshakeContext(ctx); err != nil {
			return nil, err
		}
		targetBytes := []byte(target)
		if len(targetBytes) > 1024 {
			return nil, errors.New("private relay target is too long")
		}
		if err := binary.Write(outer, binary.BigEndian, uint16(len(targetBytes))); err != nil {
			return nil, err
		}
		if _, err := outer.Write(targetBytes); err != nil {
			return nil, err
		}
		var status [1]byte
		if _, err := io.ReadFull(outer, status[:]); err != nil {
			return nil, err
		}
		if status[0] != 0 {
			return nil, errors.New("private relay rejected target")
		}
		transport = outer
	}
	connection := tls.Client(transport, channel.relayTargetTLS(target, protocol, proofOnly))
	if err := connection.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	if !stop() || ctx.Err() != nil {
		return nil, ctx.Err()
	}
	_ = connection.SetDeadline(time.Time{})
	success = true
	return connection, nil
}

func (channel *PrivateChannel) relayTargetTLS(node, protocol string, proofOnly bool) *tls.Config {
	member, _ := channel.memberForNode(node)
	want, _ := decodePublicKey(member.PublicKey)
	config := channel.peerTLS.Clone()
	config.NextProtos = []string{protocol}
	config.ServerName = ""
	config.InsecureSkipVerify = true // VerifyConnection binds the CA and ID; ordinary requests also require the current member key.
	config.VerifyConnection = func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) == 0 {
			return errors.New("private relay target certificate is missing")
		}
		leaf := state.PeerCertificates[0]
		intermediates := x509.NewCertPool()
		for _, certificate := range state.PeerCertificates[1:] {
			intermediates.AddCert(certificate)
		}
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: config.RootCAs, Intermediates: intermediates,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
			return err
		}
		if leaf.Subject.CommonName != member.ControlID {
			return errors.New("private relay target is not the configured member")
		}
		public, ok := leaf.PublicKey.(ed25519.PublicKey)
		if !ok || want == nil || !proofOnly && !want.Equal(public) {
			return errors.New("private target key is not the current member key")
		}
		return nil
	}
	return config
}
