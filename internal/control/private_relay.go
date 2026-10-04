package control

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"path/filepath"
)

const relayIdentitySchema = 3

// RelayIdentity is a transport-only TLS identity. It deliberately contains no
// control member signing key, browser administrator material, authority store,
// or certified projection.
type RelayIdentity struct {
	Schema int      `json:"schema"`
	Node   string   `json:"node"`
	TLS    TLSFiles `json:"tls"`
}

func (identity RelayIdentity) Validate(listen []string) error {
	if identity.Schema != relayIdentitySchema || ValidateID(identity.Node) != nil {
		return errors.New("private relay identity is incomplete")
	}
	certificate, _, err := LoadTLSIdentity(identity.TLS)
	if err != nil || len(certificate.Certificate) == 0 {
		return errors.New("private relay TLS identity is invalid")
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil || leaf.Subject.CommonName != "relay-"+identity.Node {
		return errors.New("private relay TLS leaf is invalid")
	}
	for _, address := range listen {
		host, _, err := net.SplitHostPort(address)
		if err != nil || leaf.VerifyHostname(host) != nil {
			return errors.New("private relay TLS identity does not cover its listener")
		}
	}
	return nil
}

func LoadRelayIdentity(root string, listen []string) (RelayIdentity, error) {
	var identity RelayIdentity
	body, err := readProtectedControlFile(filepath.Join(root, "identity.json"))
	if err != nil {
		return identity, err
	}
	if err := DecodeCanonical(body, &identity, ContractDecodeLimits{MaxBytes: 1 << 20, MaxDepth: 8, MaxItems: 32}); err != nil {
		return identity, err
	}
	return identity, identity.Validate(listen)
}

func relayTLSConfig(identity RelayIdentity) (*tls.Config, error) {
	certificate, pool, err := LoadTLSIdentity(identity.TLS)
	if err != nil || len(certificate.Certificate) == 0 {
		return nil, errors.New("private relay TLS identity is invalid")
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{certificate}, ClientCAs: pool, RootCAs: pool,
		ClientAuth: tls.RequireAndVerifyClientCert, NextProtos: []string{controlRelayALPN}}, nil
}

// OpenPrivateRelay starts only the authenticated byte-forwarding adapter. The
// destination member verifies the end-to-end member TLS identity and signed
// facts. The relay has no authority to decode their plaintext.
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
		control: newConnectionListener(), done: make(chan struct{}), relayOnly: true}
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
