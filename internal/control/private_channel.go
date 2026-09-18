package control

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/hashicorp/raft"
)

const raftALPN = "loom-raft/1"

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
	nodeTLS    BrowserTLS
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
	tlsConfig, err := TLSConfig(node)
	if err != nil {
		return nil, err
	}
	tlsConfig.NextProtos = []string{raftALPN, "http/1.1"}
	channel := &PrivateChannel{config: config, tlsConfig: tlsConfig, nodeTLS: node.BrowserTLS, control: newConnectionListener(),
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
	if _, err := certificate.Verify(x509.VerifyOptions{Roots: channel.tlsConfig.ClientCAs, Intermediates: intermediates,
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
		dialer := &net.Dialer{Timeout: timeout}
		raw, err := dialer.Dial("tcp", endpoint)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		host, _, _ := net.SplitHostPort(endpoint)
		config := stream.channel.tlsConfig.Clone()
		config.ServerName = host
		config.NextProtos = []string{raftALPN}
		connection := tls.Client(raw, config)
		_ = connection.SetDeadline(time.Now().Add(timeout))
		if err := connection.HandshakeContext(context.Background()); err != nil {
			_ = raw.Close()
			failures = append(failures, err)
			continue
		}
		_ = connection.SetDeadline(time.Time{})
		return connection, nil
	}
	if len(failures) == 0 {
		return nil, fmt.Errorf("private control node %s is not a direct neighbor", address)
	}
	return nil, errors.Join(failures...)
}
