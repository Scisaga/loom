package control

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"sync"
	"time"
)

const (
	tunnelALPN         = "loom-tunnel/1"
	tunnelProofDomain  = "loom-device-tunnel-proof-v1\n"
	maximumTunnelFrame = 64 << 10
)

type TunnelHello struct {
	Schema     int                  `json:"schema"`
	Mode       string               `json:"mode"`
	EndpointID string               `json:"endpoint_id"`
	Generation uint64               `json:"generation"`
	Capability *BootstrapCapability `json:"capability,omitempty"`
	DeviceID   string               `json:"device_id,omitempty"`
}

type tunnelChallenge struct {
	Schema int    `json:"schema"`
	Nonce  string `json:"nonce"`
}

type TunnelProof struct {
	Schema    int    `json:"schema"`
	Signature string `json:"signature"`
}

type tunnelReady struct {
	Schema int    `json:"schema"`
	Status string `json:"status"`
}

type endpointCounters struct {
	Active    int
	Successes uint64
}

type endpointSocket struct {
	generation EndpointGeneration
	listener   net.Listener
	done       chan struct{}
}

type EndpointRuntime struct {
	authority *Authority
	node      string
	now       func() time.Time
	incoming  *authenticatedListener
	stop      chan struct{}
	done      chan struct{}
	mu        sync.RWMutex
	sockets   map[string]*endpointSocket
	ready     map[string]bool
	counters  map[string]*endpointCounters
	closeOnce sync.Once
}

func endpointKey(endpointID string, generation uint64) string {
	return fmt.Sprintf("%s/%d", endpointID, generation)
}

func NewEndpointRuntime(authority *Authority, node string, now func() time.Time) (*EndpointRuntime, error) {
	if authority == nil || node == "" {
		return nil, errors.New("endpoint runtime authority and node are required")
	}
	if now == nil {
		now = time.Now
	}
	runtime := &EndpointRuntime{authority: authority, node: node, now: now, incoming: newAuthenticatedListener(),
		stop: make(chan struct{}), done: make(chan struct{}), sockets: map[string]*endpointSocket{},
		ready: map[string]bool{}, counters: map[string]*endpointCounters{}}
	runtime.reconcile()
	go runtime.loop()
	return runtime, nil
}

func (runtime *EndpointRuntime) loop() {
	defer close(runtime.done)
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-runtime.stop:
			runtime.closeSockets()
			return
		case <-ticker.C:
			runtime.reconcile()
		}
	}
}

func (runtime *EndpointRuntime) reconcile() {
	_, projection, _ := runtime.authority.Snapshot()
	wanted := map[string]EndpointGeneration{}
	conflict := map[string]bool{}
	for _, generation := range projection.EndpointGenerations {
		if generation.Node != runtime.node || generation.State == "retired" {
			continue
		}
		if current, found := wanted[generation.Listen]; found {
			if current.TLSCertificateFile != generation.TLSCertificateFile || current.TLSPrivateKeyFile != generation.TLSPrivateKeyFile ||
				current.SPKISHA256 != generation.SPKISHA256 {
				conflict[generation.Listen] = true
			}
			continue
		}
		wanted[generation.Listen] = generation
	}
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	for address, socket := range runtime.sockets {
		if _, found := wanted[address]; !found || conflict[address] {
			_ = socket.listener.Close()
			delete(runtime.sockets, address)
		}
	}
	runtime.ready = map[string]bool{}
	for address, generation := range wanted {
		if conflict[address] {
			continue
		}
		socket := runtime.sockets[address]
		if socket == nil {
			created, err := runtime.openSocket(generation)
			if err != nil {
				continue
			}
			runtime.sockets[address] = created
			socket = created
			go runtime.accept(socket)
		}
		for _, candidate := range projection.EndpointGenerations {
			if candidate.Node == runtime.node && candidate.Listen == address && candidate.State != "retired" &&
				candidate.TLSCertificateFile == socket.generation.TLSCertificateFile &&
				candidate.TLSPrivateKeyFile == socket.generation.TLSPrivateKeyFile && candidate.SPKISHA256 == socket.generation.SPKISHA256 {
				runtime.ready[endpointKey(candidate.EndpointID, candidate.Generation)] = true
			}
		}
	}
}

func (runtime *EndpointRuntime) openSocket(generation EndpointGeneration) (*endpointSocket, error) {
	certificate, err := tls.LoadX509KeyPair(generation.TLSCertificateFile, generation.TLSPrivateKeyFile)
	if err != nil || len(certificate.Certificate) == 0 {
		return nil, errors.New("load endpoint TLS identity")
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return nil, err
	}
	now := runtime.now().UTC()
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return nil, errors.New("endpoint TLS identity is outside its validity period")
	}
	spki := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	if hex.EncodeToString(spki[:]) != generation.SPKISHA256 {
		return nil, errors.New("endpoint TLS identity does not match certified SPKI")
	}
	listener, err := net.Listen("tcp", generation.Listen)
	if err != nil {
		return nil, err
	}
	config := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{certificate}, NextProtos: []string{tunnelALPN}}
	return &endpointSocket{generation: generation, listener: tls.NewListener(listener, config), done: make(chan struct{})}, nil
}

func (runtime *EndpointRuntime) accept(socket *endpointSocket) {
	for {
		connection, err := socket.listener.Accept()
		if err != nil {
			return
		}
		go runtime.authenticate(connection, socket.generation.Listen)
	}
}

func readFrame(reader *bufio.Reader, value any) error {
	header := make([]byte, 4)
	if _, err := io.ReadFull(reader, header); err != nil {
		return err
	}
	size := binary.BigEndian.Uint32(header)
	if size == 0 || size > maximumTunnelFrame {
		return errors.New("tunnel frame exceeds boundary")
	}
	body := make([]byte, int(size))
	if _, err := io.ReadFull(reader, body); err != nil {
		return err
	}
	return decodeCanonicalValue(body, value)
}

func writeFrame(writer io.Writer, value any) error {
	body, err := canonical(value)
	if err != nil || len(body) == 0 || len(body) > maximumTunnelFrame {
		return errors.New("tunnel frame is invalid")
	}
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(len(body)))
	if _, err := writer.Write(header); err != nil {
		return err
	}
	_, err = writer.Write(body)
	return err
}

func (runtime *EndpointRuntime) authenticate(connection net.Conn, listen string) {
	defer func() {
		if connection != nil {
			_ = connection.Close()
		}
	}()
	_ = connection.SetDeadline(time.Now().Add(15 * time.Second))
	reader := bufio.NewReader(connection)
	var hello TunnelHello
	if err := readFrame(reader, &hello); err != nil || hello.Schema != 1 || !validName(hello.EndpointID) || hello.Generation == 0 {
		return
	}
	_, projection, _ := runtime.authority.Snapshot()
	var generation *EndpointGeneration
	for index := range projection.EndpointGenerations {
		candidate := &projection.EndpointGenerations[index]
		if candidate.EndpointID == hello.EndpointID && candidate.Generation == hello.Generation && candidate.Node == runtime.node &&
			candidate.Listen == listen && candidate.State == "serving" {
			generation = candidate
			break
		}
	}
	if generation == nil {
		return
	}
	identity := tunnelIdentity{Mode: hello.Mode, EndpointID: hello.EndpointID, Generation: hello.Generation}
	switch hello.Mode {
	case "bootstrap":
		if hello.Capability == nil || hello.DeviceID != "" || runtime.authorizeBootstrap(*hello.Capability, *generation, projection) != nil {
			return
		}
		identity.TransactionID = hello.Capability.TransactionID
	case "device":
		if hello.Capability != nil || !validName(hello.DeviceID) {
			return
		}
		authorization, found := authorizationFor(projection, hello.DeviceID)
		if !found {
			return
		}
		nonce := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			return
		}
		challenge := tunnelChallenge{Schema: 1, Nonce: base64.RawURLEncoding.EncodeToString(nonce)}
		if err := writeFrame(connection, challenge); err != nil {
			return
		}
		var proof TunnelProof
		if err := readFrame(reader, &proof); err != nil || proof.Schema != 1 {
			return
		}
		message, _ := tunnelProofBytes(hello, challenge)
		key, _ := base64.RawURLEncoding.DecodeString(authorization.DevicePublicKey)
		signature, err := base64.RawURLEncoding.DecodeString(proof.Signature)
		if err != nil || !ed25519.Verify(key, message, signature) {
			return
		}
		identity.DeviceID = hello.DeviceID
	default:
		return
	}
	if err := writeFrame(connection, tunnelReady{Schema: 1, Status: "ready"}); err != nil {
		return
	}
	_ = connection.SetDeadline(time.Time{})
	key := endpointKey(generation.EndpointID, generation.Generation)
	runtime.mu.Lock()
	counters := runtime.counters[key]
	if counters == nil {
		counters = &endpointCounters{}
		runtime.counters[key] = counters
	}
	counters.Active++
	counters.Successes++
	runtime.mu.Unlock()
	wrapped := &authenticatedConn{Conn: connection, reader: reader, identity: identity, closed: func() {
		runtime.mu.Lock()
		if current := runtime.counters[key]; current != nil && current.Active > 0 {
			current.Active--
		}
		runtime.mu.Unlock()
	}}
	connection = nil
	if !runtime.incoming.deliver(wrapped) {
		_ = wrapped.Close()
	}
}

func (runtime *EndpointRuntime) authorizeBootstrap(capability BootstrapCapability, generation EndpointGeneration, projection Projection) error {
	if capability.Validate() != nil || capability.ConfigMaterial != projection.ConfigMaterial ||
		!sameControlConfig(capability.ControlConfig, projection.Config) {
		return errors.New("bootstrap capability is not current")
	}
	allowed := false
	for _, endpoint := range capability.Endpoints {
		if endpoint.EndpointID == generation.EndpointID && endpoint.Generation == generation.Generation {
			allowed = true
		}
	}
	_, transaction := findEnrollment(&projection, capability.TransactionID)
	digest, _ := capabilityDigest(capability)
	if !allowed || transaction == nil || transaction.CapabilityDigest != digest || transaction.State == "rejected" || transaction.State == "expired" ||
		transaction.State == "cancelled" || transaction.State == "open" && !runtime.now().UTC().Before(mustTime(capability.ExpiresAt)) {
		return errors.New("bootstrap capability is not authorized")
	}
	return nil
}

func authorizationFor(projection Projection, deviceID string) (DeviceAuthorization, bool) {
	index := sort.Search(len(projection.DeviceAuthorizations), func(index int) bool {
		return projection.DeviceAuthorizations[index].DeviceID >= deviceID
	})
	if index == len(projection.DeviceAuthorizations) || projection.DeviceAuthorizations[index].DeviceID != deviceID {
		return DeviceAuthorization{}, false
	}
	return projection.DeviceAuthorizations[index], true
}

func tunnelProofBytes(hello TunnelHello, challenge tunnelChallenge) ([]byte, error) {
	body, err := canonical(struct {
		Hello     TunnelHello     `json:"hello"`
		Challenge tunnelChallenge `json:"challenge"`
	}{hello, challenge})
	if err != nil {
		return nil, err
	}
	return append([]byte(tunnelProofDomain), body...), nil
}

func (runtime *EndpointRuntime) Ready(generation EndpointGeneration) bool {
	runtime.mu.RLock()
	defer runtime.mu.RUnlock()
	return runtime.ready[endpointKey(generation.EndpointID, generation.Generation)]
}

func (runtime *EndpointRuntime) Successes(generation EndpointGeneration) uint64 {
	runtime.mu.RLock()
	defer runtime.mu.RUnlock()
	if counters := runtime.counters[endpointKey(generation.EndpointID, generation.Generation)]; counters != nil {
		return counters.Successes
	}
	return 0
}

func (runtime *EndpointRuntime) Active(generation EndpointGeneration) int {
	runtime.mu.RLock()
	defer runtime.mu.RUnlock()
	if counters := runtime.counters[endpointKey(generation.EndpointID, generation.Generation)]; counters != nil {
		return counters.Active
	}
	return 0
}

func (runtime *EndpointRuntime) closeSockets() {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	for address, socket := range runtime.sockets {
		_ = socket.listener.Close()
		delete(runtime.sockets, address)
	}
	runtime.incoming.Close()
}

func (runtime *EndpointRuntime) Close() error {
	runtime.closeOnce.Do(func() { close(runtime.stop) })
	<-runtime.done
	return nil
}

func (runtime *EndpointRuntime) Accept() (net.Conn, error) { return runtime.incoming.Accept() }
func (runtime *EndpointRuntime) Addr() net.Addr            { return channelAddress("device-channel") }

type authenticatedConn struct {
	net.Conn
	reader   *bufio.Reader
	identity tunnelIdentity
	closed   func()
	once     sync.Once
}

func (connection *authenticatedConn) Read(body []byte) (int, error) {
	return connection.reader.Read(body)
}
func (connection *authenticatedConn) Close() error {
	connection.once.Do(connection.closed)
	return connection.Conn.Close()
}

type authenticatedListener struct {
	connections chan net.Conn
	done        chan struct{}
	once        sync.Once
}

func newAuthenticatedListener() *authenticatedListener {
	return &authenticatedListener{connections: make(chan net.Conn), done: make(chan struct{})}
}
func (listener *authenticatedListener) deliver(connection net.Conn) bool {
	select {
	case listener.connections <- connection:
		return true
	case <-listener.done:
		return false
	}
}
func (listener *authenticatedListener) Accept() (net.Conn, error) {
	select {
	case connection := <-listener.connections:
		return connection, nil
	case <-listener.done:
		return nil, net.ErrClosed
	}
}
func (listener *authenticatedListener) Close() error {
	listener.once.Do(func() { close(listener.done) })
	return nil
}
func (listener *authenticatedListener) Addr() net.Addr { return channelAddress("authenticated-device") }

func endpointConnContext(ctx context.Context, connection net.Conn) context.Context {
	if authenticated, ok := connection.(*authenticatedConn); ok {
		return context.WithValue(ctx, tunnelIdentityKey{}, authenticated.identity)
	}
	return ctx
}

func DialEndpoint(ctx context.Context, endpoint EndpointReference, hello TunnelHello, private ed25519.PrivateKey) (net.Conn, error) {
	if endpoint.State != "serving" || hello.EndpointID != endpoint.EndpointID || hello.Generation != endpoint.Generation {
		return nil, errors.New("endpoint generation is not serving")
	}
	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", endpoint.Address)
	if err != nil {
		return nil, err
	}
	failed := true
	defer func() {
		if failed {
			_ = raw.Close()
		}
	}()
	config := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, ServerName: endpoint.ServerName,
		NextProtos: []string{tunnelALPN}, InsecureSkipVerify: true, VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return errors.New("endpoint TLS certificate is missing")
			}
			sum := sha256.Sum256(state.PeerCertificates[0].RawSubjectPublicKeyInfo)
			if hex.EncodeToString(sum[:]) != endpoint.SPKISHA256 {
				return errors.New("endpoint TLS SPKI does not match certified generation")
			}
			return nil
		}}
	connection := tls.Client(raw, config)
	if deadline, ok := ctx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	}
	if err := connection.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	if err := writeFrame(connection, hello); err != nil {
		return nil, err
	}
	reader := bufio.NewReader(connection)
	if hello.Mode == "device" {
		if len(private) != ed25519.PrivateKeySize {
			return nil, errors.New("device tunnel private key is invalid")
		}
		var challenge tunnelChallenge
		if err := readFrame(reader, &challenge); err != nil || challenge.Schema != 1 {
			return nil, errors.New("device tunnel challenge is invalid")
		}
		message, _ := tunnelProofBytes(hello, challenge)
		proof := TunnelProof{Schema: 1, Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, message))}
		if err := writeFrame(connection, proof); err != nil {
			return nil, err
		}
	}
	var ready tunnelReady
	if err := readFrame(reader, &ready); err != nil || ready.Schema != 1 || ready.Status != "ready" {
		return nil, errors.New("endpoint tunnel was not accepted")
	}
	_ = connection.SetDeadline(time.Time{})
	failed = false
	return &bufferedConnection{Conn: connection, reader: reader}, nil
}

func certificateSPKI(path string) (string, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(body)
	if block == nil || block.Type != "CERTIFICATE" {
		return "", errors.New("certificate PEM is invalid")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(certificate.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:]), nil
}
