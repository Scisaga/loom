package control

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

const (
	tunnelALPN         = "loom-tunnel/3"
	tunnelProofDomain  = "loom-device-tunnel-proof-v3\x00"
	maximumTunnelFrame = 8 << 20
)

// EndpointLocalInputs locates execution material. It never grants an endpoint
// identity, changes a signed stage, or supplies device authorization.
type EndpointLocalInputs struct {
	Listen          string `json:"listen"`
	CertificateFile string `json:"certificate_file"`
	KeyFile         string `json:"key_file"`
}

func (inputs EndpointLocalInputs) Validate() error {
	host, port, err := net.SplitHostPort(inputs.Listen)
	number, numberErr := strconv.Atoi(port)
	if err != nil || numberErr != nil || number < 1 || number > 65535 || strconv.Itoa(number) != port || net.ParseIP(host) == nil || !absoluteControlPath(inputs.CertificateFile) || !absoluteControlPath(inputs.KeyFile) {
		return errors.New("endpoint inputs require an IP listener and canonical absolute file references")
	}
	return nil
}
func endpointInputPath(root, id string, generation U64) string {
	body, _ := CanonicalEncode(struct {
		ID         string `json:"id"`
		Generation U64    `json:"generation"`
	}{id, generation})
	digest := sha256.Sum256(body)
	return filepath.Join(root, "endpoint-inputs", hex.EncodeToString(digest[:])+".json")
}
func InstallEndpointInputs(root string, endpoint EndpointGeneration, inputs EndpointLocalInputs) error {
	return installEndpointInputsAt(root, endpoint, inputs, time.Now())
}

func installEndpointInputsAt(root string, endpoint EndpointGeneration, inputs EndpointLocalInputs, now time.Time) error {
	if endpoint.Validate() != nil || inputs.Validate() != nil {
		return errors.New("invalid endpoint execution inputs")
	}
	config, err := LoadNodeConfig(root)
	if err != nil {
		return err
	}
	if config.ControlID != endpoint.OwnerControlID {
		return errors.New("endpoint is owned by another control")
	}
	authority, err := OpenAuthority(root)
	if err != nil {
		return err
	}
	if _, err := loadAuthorizedEndpointCertificate(authority.Snapshot(), endpoint, inputs, now); err != nil {
		return err
	}
	if endpoint.WebsiteTrustID != "" {
		if err := verifyLocalWebsiteRequest(root, authority.Snapshot(), endpoint, inputs, now); err != nil {
			return err
		}
	}
	body, err := CanonicalEncode(inputs)
	if err != nil {
		return err
	}
	path := endpointInputPath(root, endpoint.ID, endpoint.Generation)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(filepath.Dir(path))
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return errors.New("endpoint inputs require an owner-only directory")
	}
	if err := putControlBytes(path, body); err != nil {
		return err
	}
	return syncControlDirectory(root)
}
func loadEndpointInputs(root string, endpoint EndpointGeneration) (EndpointLocalInputs, error) {
	body, err := readProtectedControlFile(endpointInputPath(root, endpoint.ID, endpoint.Generation))
	if err != nil {
		return EndpointLocalInputs{}, err
	}
	var inputs EndpointLocalInputs
	err = DecodeCanonical(body, &inputs, ContractDecodeLimits{MaxBytes: 1 << 20, MaxDepth: 8, MaxItems: 32})
	return inputs, err
}
func endpointByteDigest(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}
func validateEndpointCertificate(leaf *x509.Certificate, endpoint EndpointGeneration, now time.Time) error {
	if leaf == nil || leaf.IsCA || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) || leaf.VerifyHostname(endpoint.ServerName) != nil || endpointByteDigest(leaf.RawSubjectPublicKeyInfo) != endpoint.SPKISHA256 || endpointByteDigest(leaf.Raw) != endpoint.CertificateDigest {
		return errors.New("endpoint TLS certificate does not match its signed identity, name, or validity")
	}
	for _, usage := range leaf.ExtKeyUsage {
		if usage == x509.ExtKeyUsageServerAuth {
			return nil
		}
	}
	return errors.New("endpoint TLS certificate is missing serverAuth")
}
func loadEndpointCertificate(endpoint EndpointGeneration, inputs EndpointLocalInputs, now time.Time) (tls.Certificate, error) {
	certPEM, err := readControlPublicFile(inputs.CertificateFile)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM, err := readProtectedControlFile(inputs.KeyFile)
	if err != nil {
		return tls.Certificate{}, err
	}
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil || len(certificate.Certificate) == 0 {
		return tls.Certificate{}, errors.New("endpoint TLS certificate and key do not match")
	}
	certificate.Leaf, err = x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return tls.Certificate{}, err
	}
	if err := validateEndpointCertificate(certificate.Leaf, endpoint, now); err != nil {
		return tls.Certificate{}, err
	}
	return certificate, nil
}

type TunnelHello struct {
	Schema     int              `json:"schema"`
	Mode       string           `json:"mode"`
	EndpointID string           `json:"endpoint_id"`
	Generation U64              `json:"generation"`
	Invite     *BootstrapInvite `json:"invite,omitempty"`
	DeviceID   string           `json:"device_id,omitempty"`
}

func (hello TunnelHello) Validate() error {
	if hello.Schema != 3 || ValidateID(hello.EndpointID) != nil || hello.Generation == 0 {
		return errors.New("invalid tunnel identity")
	}
	switch hello.Mode {
	case "bootstrap":
		if hello.Invite == nil || hello.DeviceID != "" {
			return errors.New("bootstrap tunnel requires one complete invite")
		}
		return hello.Invite.Validate()
	case "device":
		if hello.Invite != nil || ValidateID(hello.DeviceID) != nil {
			return errors.New("device tunnel requires a device identity")
		}
		return nil
	}
	return errors.New("invalid tunnel mode")
}

type tunnelChallenge struct {
	Schema int    `json:"schema"`
	Nonce  string `json:"nonce"`
}

func (challenge tunnelChallenge) Validate() error {
	nonce, err := base64.RawURLEncoding.DecodeString(challenge.Nonce)
	if challenge.Schema != 3 || err != nil || len(nonce) != 32 || base64.RawURLEncoding.EncodeToString(nonce) != challenge.Nonce {
		return errors.New("invalid tunnel challenge")
	}
	return nil
}

type TunnelProof struct {
	Schema    int    `json:"schema"`
	Signature string `json:"signature"`
}

func (proof TunnelProof) Validate() error {
	signature, err := base64.RawURLEncoding.DecodeString(proof.Signature)
	if proof.Schema != 3 || err != nil || len(signature) != ed25519.SignatureSize || base64.RawURLEncoding.EncodeToString(signature) != proof.Signature {
		return errors.New("invalid tunnel proof")
	}
	return nil
}

type tunnelReady struct {
	Schema int    `json:"schema"`
	Status string `json:"status"`
}

func (ready tunnelReady) Validate() error {
	if ready.Schema != 3 || ready.Status != "ready" {
		return errors.New("invalid tunnel acceptance")
	}
	return nil
}

type endpointCounters struct {
	Active    int
	Successes uint64
}
type endpointTLSBinding struct {
	certificateDigest string
	serverName        string
	config            *tls.Config
}
type endpointSocket struct {
	listen   string
	listener net.Listener
	bindings map[string]*endpointTLSBinding
}
type endpointCandidate struct {
	generation  EndpointGeneration
	certificate tls.Certificate
}
type endpointSession struct {
	generation EndpointGeneration
	identity   tunnelIdentity
}
type EndpointRuntime struct {
	authority  *Authority
	controlID  string
	now        func() time.Time
	incoming   *authenticatedListener
	web        *authenticatedListener
	stop       chan struct{}
	done       chan struct{}
	mu         sync.RWMutex
	sockets    map[string]*endpointSocket
	ready      map[string]bool
	counters   map[string]*endpointCounters
	sessions   map[*authenticatedConn]endpointSession
	handshakes map[net.Conn]struct{}
	workers    sync.WaitGroup
	closed     bool
	closeErr   error
	closeOnce  sync.Once
}

func endpointKey(id string, generation U64) string {
	return fmt.Sprintf("%d:%s:%d", len(id), id, generation)
}
func NewEndpointRuntime(authority *Authority, controlID string, now func() time.Time) (*EndpointRuntime, error) {
	if authority == nil || ValidateID(controlID) != nil {
		return nil, errors.New("endpoint authority and control identity are required")
	}
	if now == nil {
		now = time.Now
	}
	runtime := &EndpointRuntime{authority: authority, controlID: controlID, now: now, incoming: newAuthenticatedListener(), web: newAuthenticatedListener(), stop: make(chan struct{}), done: make(chan struct{}), sockets: map[string]*endpointSocket{}, ready: map[string]bool{}, counters: map[string]*endpointCounters{}, sessions: map[*authenticatedConn]endpointSession{}, handshakes: map[net.Conn]struct{}{}}
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
	runtime.authority.mu.RLock()
	projection := runtime.authority.projection
	now := runtime.now()
	wanted := map[string][]endpointCandidate{}
	current := map[string]EndpointGeneration{}
	for _, endpoint := range projection.EndpointGenerations {
		if !endpointOwnerActive(projection, runtime.controlID) || endpoint.OwnerControlID != runtime.controlID || endpoint.State == "retired" {
			continue
		}
		inputs, err := loadEndpointInputs(runtime.authority.root, endpoint)
		if err != nil {
			continue
		}
		certificate, err := loadAuthorizedEndpointCertificate(projection, endpoint, inputs, now)
		if err != nil {
			continue
		}
		current[endpointKey(endpoint.ID, endpoint.Generation)] = endpoint
		if endpoint.State == "draining" {
			continue
		}
		wanted[inputs.Listen] = append(wanted[inputs.Listen], endpointCandidate{endpoint, certificate})
	}
	runtime.mu.Lock()
	if runtime.closed {
		runtime.mu.Unlock()
		runtime.authority.mu.RUnlock()
		return
	}
	for address, socket := range runtime.sockets {
		if len(wanted[address]) == 0 {
			_ = socket.listener.Close()
			delete(runtime.sockets, address)
		}
	}
	runtime.ready = map[string]bool{}
	for address, candidates := range wanted {
		socket := runtime.sockets[address]
		if socket == nil {
			listener, err := net.Listen("tcp", address)
			if err != nil {
				continue
			}
			socket = &endpointSocket{listen: address, listener: listener}
			runtime.sockets[address] = socket
			runtime.workers.Add(1)
			go runtime.accept(socket)
		}
		socket.bindings = runtime.tlsBindings(candidates, socket.bindings)
		for _, candidate := range candidates {
			binding := socket.bindings[endpointSNI(candidate.generation.ServerName)]
			if binding != nil && binding.serverName == candidate.generation.ServerName && binding.certificateDigest == candidate.generation.CertificateDigest {
				runtime.ready[endpointKey(candidate.generation.ID, candidate.generation.Generation)] = true
			}
		}
	}
	closing := []*authenticatedConn{}
	for connection, session := range runtime.sessions {
		endpoint, found := current[endpointKey(session.generation.ID, session.generation.Generation)]
		closeSession := !found || endpoint.State == "draining" && now.UnixMilli() >= endpoint.DrainUntil
		if !closeSession && session.identity.Mode == "device" {
			_, found := identityFor(projection, session.identity.DeviceID)
			closeSession = !found
		}
		if !closeSession && session.identity.Mode == "bootstrap" {
			closeSession = !runtime.bootstrapSessionValidLocked(session.identity.TransactionID, projection, now)
		}
		if closeSession {
			closing = append(closing, connection)
		}
	}
	runtime.mu.Unlock()
	runtime.authority.mu.RUnlock()
	for _, connection := range closing {
		_ = connection.Close()
	}
}
func endpointSNI(serverName string) string {
	if net.ParseIP(serverName) != nil {
		return ""
	}
	return serverName
}

// This is a disposable TLS projection. It has no authority or lifecycle of its
// own. Preserve an existing serving certificate when names share a socket.
func (runtime *EndpointRuntime) tlsBindings(candidates []endpointCandidate, previous map[string]*endpointTLSBinding) map[string]*endpointTLSBinding {
	selected := map[string]endpointCandidate{}
	for _, candidate := range candidates {
		name := endpointSNI(candidate.generation.ServerName)
		prior, found := selected[name]
		old := previous[name]
		isServing := candidate.generation.State == "serving"
		preserves := isServing && old != nil && old.certificateDigest == candidate.generation.CertificateDigest && old.serverName == candidate.generation.ServerName
		priorPreserves := found && prior.generation.State == "serving" && old != nil && old.certificateDigest == prior.generation.CertificateDigest && old.serverName == prior.generation.ServerName
		if !found || isServing && prior.generation.State != "serving" || preserves && !priorPreserves {
			selected[name] = candidate
		}
	}
	bindings := map[string]*endpointTLSBinding{}
	for name, candidate := range selected {
		endpoint := candidate.generation
		config := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, Certificates: []tls.Certificate{candidate.certificate}, Time: runtime.now}
		var web, tunnel bool
		for _, other := range candidates {
			if other.generation.ServerName != endpoint.ServerName || other.generation.CertificateDigest != endpoint.CertificateDigest {
				continue
			}
			web = web || containsString(other.generation.Modes, "web")
			tunnel = tunnel || containsString(other.generation.Modes, "device") || containsString(other.generation.Modes, "bootstrap")
		}
		if tunnel {
			config.NextProtos = append(config.NextProtos, tunnelALPN)
		}
		if web {
			node, err := LoadNodeConfig(runtime.authority.root)
			if err != nil || node.BrowserTLS == nil {
				continue
			}
			roots, err := loadTLSRoots(node.BrowserTLS.TrustFile)
			if err != nil {
				continue
			}
			config.ClientAuth = tls.VerifyClientCertIfGiven
			config.ClientCAs = roots
			config.NextProtos = append(config.NextProtos, "http/1.1")
		}
		bindings[name] = &endpointTLSBinding{endpoint.CertificateDigest, endpoint.ServerName, config}
	}
	return bindings
}
func (runtime *EndpointRuntime) accept(socket *endpointSocket) {
	defer runtime.workers.Done()
	for {
		connection, err := socket.listener.Accept()
		if err != nil {
			return
		}
		runtime.mu.Lock()
		if runtime.closed {
			runtime.mu.Unlock()
			_ = connection.Close()
			return
		}
		runtime.handshakes[connection] = struct{}{}
		runtime.workers.Add(1)
		runtime.mu.Unlock()
		go func() {
			defer runtime.workers.Done()
			defer func() { runtime.mu.Lock(); delete(runtime.handshakes, connection); runtime.mu.Unlock() }()
			runtime.authenticate(connection, socket)
		}()
	}
}
func endpointOwnerActive(projection Projection, controlID string) bool {
	for _, member := range projection.Config.Members {
		if member.ControlID == controlID {
			return true
		}
	}
	return false
}

// The caller holds the Authority read lock, so transaction state and device
// authorization come from exactly the same immutable fact set.
func (runtime *EndpointRuntime) bootstrapSessionValidLocked(transactionID string, projection Projection, now time.Time) bool {
	origin, err := runtime.authority.inviteLocked(transactionID)
	if err != nil {
		return false
	}
	invite := origin.Payload.(Invite)
	if invite.IssuerControlID != runtime.controlID || !endpointOwnerActive(projection, invite.IssuerControlID) {
		return false
	}
	state, err := runtime.authority.enrollmentStateLocked(transactionID)
	if err != nil || state == "cancelled" || state == "expired" || state == "open" && now.UnixMilli() >= invite.ExpiresAt {
		return false
	}
	if state == "completed" {
		authorization, found := identityFor(projection, invite.DeviceID)
		return found && authorization.TransactionID == transactionID
	}
	return state == "open" || state == "bound"
}
func readFrame(reader *bufio.Reader, value any) error {
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || size > maximumTunnelFrame {
		return errors.New("tunnel frame exceeds receiver resource boundary")
	}
	body := make([]byte, int(size))
	if _, err := io.ReadFull(reader, body); err != nil {
		return err
	}
	return DecodeCanonical(body, value, ContractDecodeLimits{MaxBytes: maximumTunnelFrame, MaxDepth: 128, MaxItems: 1 << 20})
}
func writeFrame(writer io.Writer, value any) error {
	body, err := CanonicalEncode(value)
	if err != nil {
		return err
	}
	if len(body) == 0 || len(body) > maximumTunnelFrame {
		return errors.New("tunnel frame exceeds sender resource boundary")
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(body)))
	if _, err := io.Copy(writer, bytes.NewReader(header[:])); err != nil {
		return err
	}
	_, err = io.Copy(writer, bytes.NewReader(body))
	return err
}
func (runtime *EndpointRuntime) socketGeneration(socket *endpointSocket, binding *endpointTLSBinding, id string, generation U64, mode string, prepared bool) (EndpointGeneration, bool) {
	projection := runtime.authority.Snapshot()
	for _, endpoint := range projection.EndpointGenerations {
		if endpoint.OwnerControlID != runtime.controlID || endpoint.CertificateDigest != binding.certificateDigest || endpoint.ServerName != binding.serverName || !containsString(endpoint.Modes, mode) || endpoint.State != "serving" && !(prepared && endpoint.State == "prepared") {
			continue
		}
		if id != "" && (endpoint.ID != id || endpoint.Generation != generation) {
			continue
		}
		inputs, err := loadEndpointInputs(runtime.authority.root, endpoint)
		if err != nil || inputs.Listen != socket.listen {
			continue
		}
		if _, err := loadAuthorizedEndpointCertificate(projection, endpoint, inputs, runtime.now()); err == nil {
			return endpoint, true
		}
	}
	return EndpointGeneration{}, false
}
func (runtime *EndpointRuntime) authenticate(connection net.Conn, socket *endpointSocket) {
	defer func() {
		if connection != nil {
			_ = connection.Close()
		}
	}()
	_ = connection.SetDeadline(time.Now().Add(15 * time.Second))
	var binding *endpointTLSBinding
	tlsConnection := tls.Server(connection, &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			runtime.mu.RLock()
			defer runtime.mu.RUnlock()
			if runtime.closed {
				return nil, errors.New("endpoint runtime is closed")
			}
			binding = socket.bindings[hello.ServerName]
			if binding == nil {
				return nil, errors.New("endpoint has no authorized TLS identity for this server name")
			}
			return binding.config, nil
		}})
	connection = tlsConnection
	if tlsConnection.Handshake() != nil || binding == nil {
		return
	}
	state := tlsConnection.ConnectionState()
	if state.NegotiatedProtocol == "http/1.1" || state.NegotiatedProtocol == "" {
		endpoint, found := runtime.socketGeneration(socket, binding, "", 0, "web", true)
		if !found {
			return
		}
		_ = connection.SetDeadline(time.Time{})
		wrapped, err := runtime.track(connection, bufio.NewReader(connection), endpoint, tunnelIdentity{Mode: "web", EndpointID: endpoint.ID, Generation: endpoint.Generation}, &state, "")
		if err != nil {
			return
		}
		connection = nil
		if !runtime.web.deliver(wrapped) {
			_ = wrapped.Close()
		}
		return
	}
	if state.NegotiatedProtocol != tunnelALPN {
		return
	}
	reader := bufio.NewReader(connection)
	var hello TunnelHello
	if readFrame(reader, &hello) != nil {
		return
	}
	endpoint, found := runtime.socketGeneration(socket, binding, hello.EndpointID, hello.Generation, hello.Mode, false)
	if !found {
		return
	}
	projection := runtime.authority.Snapshot()
	identity := tunnelIdentity{Mode: hello.Mode, EndpointID: hello.EndpointID, Generation: hello.Generation}
	verifiedPublicKey := ""
	switch hello.Mode {
	case "bootstrap":
		if runtime.authorizeBootstrap(*hello.Invite, endpoint) != nil {
			return
		}
		identity.TransactionID = hello.Invite.Material.TargetID
	case "device":
		authorization, found := identityFor(projection, hello.DeviceID)
		if !found {
			return
		}
		nonce := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			return
		}
		challenge := tunnelChallenge{Schema: 3, Nonce: base64.RawURLEncoding.EncodeToString(nonce)}
		if writeFrame(connection, challenge) != nil {
			return
		}
		var proof TunnelProof
		if readFrame(reader, &proof) != nil {
			return
		}
		message, err := tunnelProofBytes(hello, challenge)
		if err != nil {
			return
		}
		key, _ := base64.RawURLEncoding.DecodeString(authorization.DevicePublicKey)
		signature, _ := base64.RawURLEncoding.DecodeString(proof.Signature)
		if !ed25519.Verify(ed25519.PublicKey(key), message, signature) {
			return
		}
		identity.DeviceID = hello.DeviceID
		verifiedPublicKey = authorization.DevicePublicKey
	default:
		return
	}
	wrapped, err := runtime.track(connection, reader, endpoint, identity, nil, verifiedPublicKey)
	if err != nil {
		return
	}
	connection = nil
	if writeFrame(wrapped, tunnelReady{Schema: 3, Status: "ready"}) != nil {
		_ = wrapped.Close()
		return
	}
	_ = wrapped.SetDeadline(time.Time{})
	if !runtime.incoming.deliver(wrapped) {
		_ = wrapped.Close()
	}
}
func (runtime *EndpointRuntime) track(connection net.Conn, reader *bufio.Reader, endpoint EndpointGeneration, identity tunnelIdentity, tlsState *tls.ConnectionState, verifiedPublicKey string) (*authenticatedConn, error) {
	runtime.authority.mu.RLock()
	defer runtime.authority.mu.RUnlock()
	projection := runtime.authority.projection
	if !endpointOwnerActive(projection, runtime.controlID) {
		return nil, errors.New("endpoint owner is no longer a control member")
	}
	found := false
	for _, current := range projection.EndpointGenerations {
		if current.ID == endpoint.ID && current.Generation == endpoint.Generation && current.OwnerControlID == runtime.controlID && current.CertificateDigest == endpoint.CertificateDigest &&
			containsString(current.Modes, identity.Mode) && (current.State == "serving" || identity.Mode == "web" && current.State == "prepared") {
			endpoint, found = current, true
			break
		}
	}
	if !found {
		return nil, errors.New("endpoint no longer accepts new sessions")
	}
	inputs, err := loadEndpointInputs(runtime.authority.root, endpoint)
	if err != nil {
		return nil, err
	}
	if _, err := loadAuthorizedEndpointCertificate(projection, endpoint, inputs, runtime.now()); err != nil {
		return nil, err
	}
	switch identity.Mode {
	case "device":
		authorization, found := identityFor(projection, identity.DeviceID)
		if !found || verifiedPublicKey == "" || authorization.DevicePublicKey != verifiedPublicKey {
			return nil, errors.New("device changed authorization during authentication")
		}
	case "bootstrap":
		if !runtime.bootstrapSessionValidLocked(identity.TransactionID, projection, runtime.now()) {
			return nil, errors.New("bootstrap transaction ended during authentication")
		}
	}
	key := endpointKey(endpoint.ID, endpoint.Generation)
	wrapped := &authenticatedConn{Conn: connection, reader: reader, identity: identity, tlsState: tlsState}
	wrapped.closed = func() {
		runtime.mu.Lock()
		delete(runtime.sessions, wrapped)
		if counters := runtime.counters[key]; counters != nil && counters.Active > 0 {
			counters.Active--
		}
		runtime.mu.Unlock()
	}
	runtime.mu.Lock()
	select {
	case <-runtime.stop:
		runtime.mu.Unlock()
		return nil, net.ErrClosed
	default:
	}
	if runtime.closed {
		runtime.mu.Unlock()
		return nil, net.ErrClosed
	}
	counters := runtime.counters[key]
	if counters == nil {
		counters = &endpointCounters{}
		runtime.counters[key] = counters
	}
	counters.Active++
	counters.Successes++
	runtime.sessions[wrapped] = endpointSession{endpoint, identity}
	runtime.mu.Unlock()
	return wrapped, nil
}
func (runtime *EndpointRuntime) authorizeBootstrap(invite BootstrapInvite, endpoint EndpointGeneration) error {
	if invite.Validate() != nil {
		return errors.New("invalid bootstrap invite")
	}
	payload := invite.Material.Payload.(Invite)
	if payload.IssuerControlID != runtime.controlID || payload.Endpoint.ID != endpoint.ID || payload.Endpoint.Generation != endpoint.Generation {
		return errors.New("invite is bound to another issuer or endpoint")
	}
	stored, err := runtime.authority.Invite(payload.ID)
	if err != nil {
		return err
	}
	want, _, err := EncodeMaterial(stored)
	if err != nil {
		return err
	}
	given, _, err := EncodeMaterial(invite.Material)
	if err != nil || !bytes.Equal(want, given) {
		return errors.New("invite differs from the stored signed material")
	}
	status, err := runtime.authority.EnrollmentState(payload.ID)
	if err != nil {
		return err
	}
	if status == "cancelled" || status == "expired" || status == "open" && runtime.now().UnixMilli() >= payload.ExpiresAt {
		return errors.New("bootstrap invitation is no longer usable")
	}
	return nil
}
func authorizationFor(projection Projection, id string) (DeviceAuthorization, bool) {
	for _, authorization := range projection.DeviceAuthorizations {
		if authorization.ID == id {
			return authorization, true
		}
	}
	return DeviceAuthorization{}, false
}
func tunnelProofBytes(hello TunnelHello, challenge tunnelChallenge) ([]byte, error) {
	body, err := CanonicalEncode(struct {
		Hello     TunnelHello     `json:"hello"`
		Challenge tunnelChallenge `json:"challenge"`
	}{hello, challenge})
	if err != nil {
		return nil, err
	}
	return append([]byte(tunnelProofDomain), body...), nil
}
func (runtime *EndpointRuntime) Ready(endpoint EndpointGeneration) bool {
	runtime.mu.RLock()
	ready := runtime.ready[endpointKey(endpoint.ID, endpoint.Generation)]
	runtime.mu.RUnlock()
	if !ready {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return ProbeEndpoint(ctx, endpoint) == nil
}
func (runtime *EndpointRuntime) ExpiresAt(endpoint EndpointGeneration) (time.Time, error) {
	inputs, err := loadEndpointInputs(runtime.authority.root, endpoint)
	if err != nil {
		return time.Time{}, err
	}
	certificate, err := loadEndpointCertificate(endpoint, inputs, runtime.now())
	if err != nil {
		return time.Time{}, err
	}
	return certificate.Leaf.NotAfter, nil
}
func (runtime *EndpointRuntime) Successes(endpoint EndpointGeneration) uint64 {
	runtime.mu.RLock()
	defer runtime.mu.RUnlock()
	if counters := runtime.counters[endpointKey(endpoint.ID, endpoint.Generation)]; counters != nil {
		return counters.Successes
	}
	return 0
}
func (runtime *EndpointRuntime) Active(endpoint EndpointGeneration) int {
	runtime.mu.RLock()
	defer runtime.mu.RUnlock()
	if counters := runtime.counters[endpointKey(endpoint.ID, endpoint.Generation)]; counters != nil {
		return counters.Active
	}
	return 0
}
func (runtime *EndpointRuntime) closeSockets() {
	runtime.mu.Lock()
	runtime.closed = true
	var closeErr error
	for _, socket := range runtime.sockets {
		if err := socket.listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			closeErr = errors.Join(closeErr, err)
		}
	}
	runtime.sockets = map[string]*endpointSocket{}
	runtime.ready = map[string]bool{}
	connections := []*authenticatedConn{}
	for connection := range runtime.sessions {
		connections = append(connections, connection)
	}
	handshakes := []net.Conn{}
	for connection := range runtime.handshakes {
		handshakes = append(handshakes, connection)
	}
	runtime.mu.Unlock()
	_ = runtime.incoming.Close()
	_ = runtime.web.Close()
	for _, connection := range handshakes {
		if err := closeEndpointTransport(connection); err != nil && !errors.Is(err, net.ErrClosed) {
			closeErr = errors.Join(closeErr, err)
		}
	}
	for _, connection := range connections {
		if err := connection.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			closeErr = errors.Join(closeErr, err)
		}
	}
	runtime.workers.Wait()
	runtime.mu.Lock()
	runtime.closeErr = closeErr
	runtime.mu.Unlock()
}
func (runtime *EndpointRuntime) Close() error {
	runtime.closeOnce.Do(func() { close(runtime.stop) })
	<-runtime.done
	return runtime.closeErr
}
func (runtime *EndpointRuntime) Accept() (net.Conn, error) { return runtime.incoming.Accept() }
func (runtime *EndpointRuntime) Addr() net.Addr            { return channelAddress("device-channel") }
func (runtime *EndpointRuntime) WebListener() net.Listener { return runtime.web }

type authenticatedConn struct {
	net.Conn
	reader   *bufio.Reader
	identity tunnelIdentity
	tlsState *tls.ConnectionState
	closed   func()
	closeErr error
	once     sync.Once
}

func (connection *authenticatedConn) Read(body []byte) (int, error) {
	return connection.reader.Read(body)
}
func (connection *authenticatedConn) Close() error {
	connection.once.Do(func() {
		connection.closeErr = closeEndpointTransport(connection.Conn)
		// An unproven close must retain its active handle, so retirement cannot
		// report zero sessions after a failed cleanup.
		if connection.closeErr == nil || errors.Is(connection.closeErr, net.ErrClosed) {
			connection.closed()
		}
	})
	return connection.closeErr
}

func closeEndpointTransport(connection net.Conn) error {
	err := connection.Close()
	if secure, ok := connection.(*tls.Conn); ok && err != nil {
		// TLS can fail to send close_notify after the peer has gone, while
		// successfully closing TCP. Prove closure on that exact underlying
		// connection; never infer resource cleanup from a TLS write error.
		if closeErr := secure.NetConn().Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
			return errors.Join(err, closeErr)
		}
		return nil
	}
	return err
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
		ctx = context.WithValue(ctx, tunnelIdentityKey{}, authenticated.identity)
		if authenticated.tlsState != nil {
			ctx = context.WithValue(ctx, memberTLSContextKey{}, *authenticated.tlsState)
		}
	}
	return ctx
}

func endpointTLSConfig(endpoint EndpointGeneration, protocol string) *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, ServerName: endpoint.ServerName, NextProtos: []string{protocol}, InsecureSkipVerify: true, VerifyConnection: func(state tls.ConnectionState) error {
		if state.NegotiatedProtocol != protocol || len(state.PeerCertificates) == 0 {
			return errors.New("endpoint TLS protocol or certificate is missing")
		}
		return validateEndpointCertificate(state.PeerCertificates[0], endpoint, time.Now())
	}}
}
func connectEndpoint(ctx context.Context, endpoint EndpointGeneration, protocol string) (*tls.Conn, error) {
	if err := endpoint.Validate(); err != nil {
		return nil, err
	}
	raw, err := EndpointDialer(ctx)(ctx, "tcp", net.JoinHostPort(endpoint.Host, strconv.Itoa(endpoint.Port)))
	if err != nil {
		return nil, err
	}
	connection := tls.Client(raw, endpointTLSConfig(endpoint, protocol))
	if err := connection.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, err
	}
	return connection, nil
}

type endpointDialerKey struct{}

// WithEndpointDialer supplies transport addresses without changing the signed
// endpoint's TLS name, SPKI, certificate or application authentication.
func WithEndpointDialer(ctx context.Context, dial func(context.Context, string, string) (net.Conn, error)) context.Context {
	return context.WithValue(ctx, endpointDialerKey{}, dial)
}

func EndpointDialer(ctx context.Context) func(context.Context, string, string) (net.Conn, error) {
	if dial, ok := ctx.Value(endpointDialerKey{}).(func(context.Context, string, string) (net.Conn, error)); ok && dial != nil {
		return dial
	}
	return (&net.Dialer{}).DialContext
}

// ProbeEndpoint verifies the advertised address without claiming or opening a
// device session. A prepared endpoint may be checked before it is selectable.
func ProbeEndpoint(ctx context.Context, endpoint EndpointGeneration) error {
	protocols := map[string]bool{}
	for _, mode := range endpoint.Modes {
		protocol := tunnelALPN
		if mode == "web" {
			protocol = "http/1.1"
		}
		// Bootstrap and device authentication share one TLS transport. Repeating
		// that handshake consumes the same deadline without testing a new mode;
		// their distinct application authentication is checked by DialEndpoint.
		if protocols[protocol] {
			continue
		}
		protocols[protocol] = true
		connection, err := connectEndpoint(ctx, endpoint, protocol)
		if err != nil {
			return err
		}
		_ = connection.Close()
	}
	return nil
}
func DialEndpoint(ctx context.Context, endpoint EndpointGeneration, hello TunnelHello, private ed25519.PrivateKey) (net.Conn, error) {
	if endpoint.State != "serving" || hello.EndpointID != endpoint.ID || hello.Generation != endpoint.Generation || !containsString(endpoint.Modes, hello.Mode) || hello.Validate() != nil {
		return nil, errors.New("endpoint generation does not authorize this tunnel")
	}
	connection, err := connectEndpoint(ctx, endpoint, tunnelALPN)
	if err != nil {
		return nil, err
	}
	failed := true
	defer func() {
		if failed {
			_ = connection.Close()
		}
	}()
	stop := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	}
	if err := writeFrame(connection, hello); err != nil {
		return nil, err
	}
	reader := bufio.NewReader(connection)
	if hello.Mode == "device" {
		if len(private) != ed25519.PrivateKeySize {
			return nil, errors.New("invalid device tunnel signing key")
		}
		var challenge tunnelChallenge
		if err := readFrame(reader, &challenge); err != nil {
			return nil, err
		}
		message, err := tunnelProofBytes(hello, challenge)
		if err != nil {
			return nil, err
		}
		proof := TunnelProof{Schema: 3, Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, message))}
		if err := writeFrame(connection, proof); err != nil {
			return nil, err
		}
	}
	var ready tunnelReady
	if err := readFrame(reader, &ready); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	_ = connection.SetDeadline(time.Time{})
	failed = false
	return &bufferedConnection{Conn: connection, reader: reader}, nil
}
