package control

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"os"
	"path/filepath"
)

const relayIdentitySchema = 1

// RelayIdentity is a transport-only TLS identity. It deliberately contains no
// control member signing key, browser administrator material, authority store,
// or certified projection.
type RelayIdentity struct {
	Schema int         `json:"schema"`
	Node   string      `json:"node"`
	TLS    TLSIdentity `json:"tls"`
}

func (identity RelayIdentity) Validate(listen []string) error {
	if identity.Schema != relayIdentitySchema || !validName(identity.Node) {
		return errors.New("private relay identity is incomplete")
	}
	certificate, err := tls.X509KeyPair([]byte(identity.TLS.CertificateChainPEM), []byte(identity.TLS.PrivateKeyPKCS8PEM))
	if err != nil || len(certificate.Certificate) < 2 {
		return errors.New("private relay TLS identity is invalid")
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil || leaf.Subject.CommonName != "relay-"+identity.Node {
		return errors.New("private relay TLS leaf is invalid")
	}
	return verifyTLSListeners(identity.TLS.CertificateChainPEM, listen)
}

func PrepareRelayIdentity(root, sourceRoot, node string, listen []string) (RelayIdentity, error) {
	if existing, err := LoadRelayIdentity(root, listen); err == nil {
		if existing.Node != node {
			return RelayIdentity{}, errors.New("existing private relay identity belongs to another node")
		}
		return existing, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return RelayIdentity{}, err
	}
	source, err := LoadNodeConfig(sourceRoot)
	if err != nil {
		return RelayIdentity{}, err
	}
	if source.Node != node {
		return RelayIdentity{}, errors.New("relay source control identity belongs to another node")
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return RelayIdentity{}, err
	}
	transport, err := issuePeerTLS(source.BrowserTLS, "relay-"+node, listen, private)
	if err != nil {
		return RelayIdentity{}, err
	}
	identity := RelayIdentity{Schema: relayIdentitySchema, Node: node, TLS: transport}
	if err := identity.Validate(listen); err != nil {
		return RelayIdentity{}, err
	}
	if err := atomicJSON(filepath.Join(root, "identity.json"), identity); err != nil {
		return RelayIdentity{}, err
	}
	return identity, nil
}

func LoadRelayIdentity(root string, listen []string) (RelayIdentity, error) {
	var identity RelayIdentity
	if err := readStrict(filepath.Join(root, "identity.json"), &identity); err != nil {
		return identity, err
	}
	return identity, identity.Validate(listen)
}

func relayTLSConfig(identity RelayIdentity) (*tls.Config, error) {
	certificate, err := tls.X509KeyPair([]byte(identity.TLS.CertificateChainPEM), []byte(identity.TLS.PrivateKeyPKCS8PEM))
	if err != nil || len(certificate.Certificate) < 2 {
		return nil, errors.New("private relay TLS identity is invalid")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(identity.TLS.CertificateChainPEM)) {
		return nil, errors.New("private relay TLS trust chain is invalid")
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{certificate}, ClientCAs: pool, RootCAs: pool,
		ClientAuth: tls.RequireAndVerifyClientCert, NextProtos: []string{raftRelayALPN, controlRelayALPN}}, nil
}

// OpenPrivateRelay starts only the authenticated byte-forwarding adapter. The
// destination member performs the authoritative end-to-end Raft TLS or signed
// internal control HTTP check.
func OpenPrivateRelay(config PrivateChannelConfig, identity RelayIdentity) (*PrivateChannel, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if identity.Node != config.Node {
		return nil, errors.New("private relay identity does not match transport node")
	}
	if err := identity.Validate(config.Listen); err != nil {
		return nil, err
	}
	tlsConfig, err := relayTLSConfig(identity)
	if err != nil {
		return nil, err
	}
	channel := &PrivateChannel{config: config, tlsConfig: tlsConfig, peerTLS: tlsConfig.Clone(),
		control: newConnectionListener(), report: newConnectionListener(), done: make(chan struct{}), relayOnly: true}
	channel.raft = &raftStreamLayer{channel: channel, incoming: newConnectionListener()}
	for _, address := range config.Listen {
		listener, listenErr := net.Listen("tcp", address)
		if listenErr != nil {
			channel.Close()
			return nil, listenErr
		}
		channel.listeners = append(channel.listeners, listener)
		go channel.accept(listener)
	}
	return channel, nil
}
