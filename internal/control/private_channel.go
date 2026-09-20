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
	"net"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/hashicorp/raft"
)

const (
	raftALPN      = "loom-raft/1"
	raftRelayALPN = "loom-raft-relay/1"
)

// PrivateChannelConfig is local transport input derived from the already
// deployed private report listener. It does not grant control membership.
type PrivateChannelConfig struct {
	Node   string
	Listen []string
	Peers  map[string][]string
}

func (config PrivateChannelConfig) Validate() error {
	if config.Node == "" || len(config.Listen) == 0 {
		return errors.New("private channel node or listeners are missing")
	}
	validateAddress := func(address string) error {
		host, port, err := net.SplitHostPort(address)
		if err != nil || port == "" {
			return errors.New("private channel address is not host:port")
		}
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsPrivate() && !ip.IsLoopback() {
			return errors.New("private channel address is not private")
		}
		return nil
	}
	seen := map[string]bool{}
	for _, address := range config.Listen {
		if err := validateAddress(address); err != nil || seen[address] {
			return errors.New("private channel listeners are invalid or duplicated")
		}
		seen[address] = true
	}
	for node, addresses := range config.Peers {
		if node == "" || node == config.Node || len(addresses) == 0 {
			return errors.New("private channel peer is invalid")
		}
		seen = map[string]bool{}
		for _, address := range addresses {
			if err := validateAddress(address); err != nil || seen[address] {
				return errors.New("private channel peer addresses are invalid or duplicated")
			}
			seen[address] = true
		}
	}
	return nil
}

type PrivateChannel struct {
	config     PrivateChannelConfig
	tlsConfig  *tls.Config
	peerTLS    *tls.Config
	nodeTLS    TLSIdentity
	control    *connectionListener
	report     *connectionListener
	raft       *raftStreamLayer
	listeners  []net.Listener
	done       chan struct{}
	closeOnce  sync.Once
	authorityM sync.RWMutex
	authority  *Authority
}

func OpenPrivateChannel(config PrivateChannelConfig, node NodeConfig) (*PrivateChannel, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if err := node.Validate(); err != nil {
		return nil, err
	}
	if node.Node != config.Node {
		return nil, errors.New("control identity does not match private channel node")
	}
	tlsConfig, err := browserTLSConfig(node)
	if err != nil {
		return nil, err
	}
	peerConfig, err := peerTLSConfig(node)
	if err != nil {
		return nil, err
	}
	tlsConfig.NextProtos = []string{raftALPN, raftRelayALPN, "http/1.1"}
	peerConfig.NextProtos = []string{raftALPN, raftRelayALPN, "http/1.1"}
	tlsConfig.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		for _, protocol := range hello.SupportedProtos {
			if protocol == raftALPN || protocol == raftRelayALPN {
				return peerConfig, nil
			}
		}
		return nil, nil
	}
	channel := &PrivateChannel{config: config, tlsConfig: tlsConfig, peerTLS: peerConfig, nodeTLS: node.PeerTLS, control: newConnectionListener(),
		report: newConnectionListener(), done: make(chan struct{})}
	channel.raft = &raftStreamLayer{channel: channel, incoming: newConnectionListener()}
	for _, address := range config.Listen {
		listener, listenErr := net.Listen("tcp", address)
		if listenErr != nil {
			channel.Close()
			return nil, fmt.Errorf("listen on existing private channel %s: %w", address, listenErr)
		}
		channel.listeners = append(channel.listeners, listener)
		go channel.accept(listener)
	}
	return channel, nil
}

func (channel *PrivateChannel) AttachAuthority(authority *Authority) { // runtime-only connection
	channel.authorityM.Lock()
	channel.authority = authority
	channel.authorityM.Unlock()
}

func (channel *PrivateChannel) authorizeRaft(certificates []*x509.Certificate) bool {
	channel.authorityM.RLock()
	authority := channel.authority
	channel.authorityM.RUnlock()
	if authority == nil || len(certificates) == 0 {
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
	_, projection, _ := authority.Snapshot()
	for _, member := range uniqueMembers(projection.Config) {
		key, _ := decodePublicKey(member.PublicKey)
		if member.ID == certificate.Subject.CommonName && key != nil && key.Equal(public) {
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
		go channel.classify(connection)
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
		if !channel.report.deliver(buffered) {
			_ = connection.Close()
		}
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
	if state.NegotiatedProtocol == raftRelayALPN {
		if !channel.authorizeRaft(state.PeerCertificates) {
			_ = tlsConnection.Close()
			return
		}
		channel.relayRaft(tlsConnection)
		return
	}
	if state.NegotiatedProtocol == raftALPN {
		if !channel.authorizeRaft(state.PeerCertificates) || !channel.raft.incoming.deliver(tlsConnection) {
			_ = tlsConnection.Close()
		}
		return
	}
	if state.NegotiatedProtocol != "" && state.NegotiatedProtocol != "http/1.1" || !channel.control.deliver(tlsConnection) {
		_ = tlsConnection.Close()
	}
}

func (channel *PrivateChannel) raftMember(node string) (Member, bool) {
	channel.authorityM.RLock()
	authority := channel.authority
	channel.authorityM.RUnlock()
	if authority == nil {
		return Member{}, false
	}
	_, projection, _ := authority.Snapshot()
	for _, member := range uniqueMembers(projection.Config) {
		if member.Node == node {
			return member, true
		}
	}
	return Member{}, false
}

func (channel *PrivateChannel) relayRaft(connection *tls.Conn) {
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
	if _, ok := channel.raftMember(target); !ok {
		_, _ = connection.Write([]byte{1})
		return
	}
	var targetConnection net.Conn
	for _, endpoint := range channel.endpoints(target) {
		dialer := &net.Dialer{Timeout: 5 * time.Second}
		candidate, err := dialer.Dial("tcp", endpoint)
		if err == nil {
			targetConnection = candidate
			break
		}
	}
	if targetConnection == nil {
		_, _ = connection.Write([]byte{1})
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
		if tcp, ok := targetConnection.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		close(done)
	}()
	_, _ = io.Copy(connection, targetConnection)
	_ = connection.Close()
	<-done
}

func (channel *PrivateChannel) ControlListener() net.Listener { return channel.control }
func (channel *PrivateChannel) ReportListener() net.Listener  { return channel.report }
func (channel *PrivateChannel) RaftStream() raft.StreamLayer  { return channel.raft }
func (channel *PrivateChannel) ListenAddresses() []string {
	return append([]string(nil), channel.config.Listen...)
}

func (channel *PrivateChannel) endpoints(node string) []string {
	values := append([]string(nil), channel.config.Peers[node]...)
	sort.Strings(values)
	return values
}

func (channel *PrivateChannel) peerClient(endpoint string) (*http.Client, error) {
	certificate, err := tls.X509KeyPair([]byte(channel.nodeTLS.CertificateChainPEM), []byte(channel.nodeTLS.PrivateKeyPKCS8PEM))
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(channel.nodeTLS.CertificateChainPEM)) {
		return nil, errors.New("control TLS trust chain is invalid")
	}
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		return nil, err
	}
	return &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, Certificates: []tls.Certificate{certificate},
		RootCAs: pool, ServerName: host, NextProtos: []string{"http/1.1"},
	}}}, nil
}

func (channel *PrivateChannel) Close() error {
	var result error
	channel.closeOnce.Do(func() {
		close(channel.done)
		channel.control.Close()
		channel.report.Close()
		channel.raft.incoming.Close()
		for _, listener := range channel.listeners {
			if err := listener.Close(); result == nil {
				result = err
			}
		}
	})
	return result
}

type bufferedConnection struct {
	net.Conn
	reader *bufio.Reader
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

type raftStreamLayer struct {
	channel  *PrivateChannel
	incoming *connectionListener
}

func (stream *raftStreamLayer) Accept() (net.Conn, error) { return stream.incoming.Accept() }
func (stream *raftStreamLayer) Close() error              { return stream.incoming.Close() }
func (stream *raftStreamLayer) Addr() net.Addr            { return channelAddress(stream.channel.config.Node) }
func (stream *raftStreamLayer) Dial(address raft.ServerAddress, timeout time.Duration) (net.Conn, error) {
	var failures []error
	for _, endpoint := range stream.channel.endpoints(string(address)) {
		connection, err := stream.channel.dialTLS(endpoint, raftALPN, timeout)
		if err == nil {
			return connection, nil
		}
		failures = append(failures, err)
	}
	if _, ok := stream.channel.raftMember(string(address)); ok {
		relayNodes := make([]string, 0, len(stream.channel.config.Peers))
		for relayNode := range stream.channel.config.Peers {
			relayNodes = append(relayNodes, relayNode)
		}
		sort.Strings(relayNodes)
		for _, relayNode := range relayNodes {
			if relayNode == string(address) {
				continue
			}
			endpoints := stream.channel.endpoints(relayNode)
			for _, endpoint := range endpoints {
				outer, err := stream.channel.dialTLS(endpoint, raftRelayALPN, timeout)
				if err != nil {
					failures = append(failures, err)
					continue
				}
				target := []byte(address)
				if len(target) > 1024 || binary.Write(outer, binary.BigEndian, uint16(len(target))) != nil {
					_ = outer.Close()
					continue
				}
				if _, err := outer.Write(target); err != nil {
					_ = outer.Close()
					failures = append(failures, err)
					continue
				}
				var status [1]byte
				if _, err := io.ReadFull(outer, status[:]); err != nil || status[0] != 0 {
					_ = outer.Close()
					failures = append(failures, errors.New("raft relay rejected target"))
					continue
				}
				connection := tls.Client(outer, stream.channel.relayTargetTLS(string(address)))
				_ = connection.SetDeadline(time.Now().Add(timeout))
				if err := connection.HandshakeContext(context.Background()); err != nil {
					_ = connection.Close()
					failures = append(failures, err)
					continue
				}
				_ = connection.SetDeadline(time.Time{})
				return connection, nil
			}
		}
	}
	if len(failures) == 0 {
		return nil, fmt.Errorf("private control node %s has no private route", address)
	}
	return nil, errors.Join(failures...)
}

func (channel *PrivateChannel) dialTLS(endpoint, protocol string, timeout time.Duration) (*tls.Conn, error) {
	dialer := &net.Dialer{Timeout: timeout}
	raw, err := dialer.Dial("tcp", endpoint)
	if err != nil {
		return nil, err
	}
	host, _, _ := net.SplitHostPort(endpoint)
	config := channel.peerTLS.Clone()
	config.ServerName = host
	config.NextProtos = []string{protocol}
	connection := tls.Client(raw, config)
	_ = connection.SetDeadline(time.Now().Add(timeout))
	if err := connection.HandshakeContext(context.Background()); err != nil {
		_ = raw.Close()
		return nil, err
	}
	_ = connection.SetDeadline(time.Time{})
	return connection, nil
}

func (channel *PrivateChannel) relayTargetTLS(node string) *tls.Config {
	member, _ := channel.raftMember(node)
	want, _ := decodePublicKey(member.PublicKey)
	config := channel.peerTLS.Clone()
	config.NextProtos = []string{raftALPN}
	config.ServerName = ""
	config.InsecureSkipVerify = true // VerifyConnection binds CA, member ID, and member key below.
	config.VerifyConnection = func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) == 0 {
			return errors.New("raft relay target certificate is missing")
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
		public, ok := leaf.PublicKey.(ed25519.PublicKey)
		if !ok || leaf.Subject.CommonName != member.ID || want == nil || !want.Equal(public) {
			return errors.New("raft relay target is not the configured member")
		}
		return nil
	}
	return config
}
