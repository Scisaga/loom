package control

import (
	"bytes"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"time"
)

// LoadTLSIdentity consumes only explicit local file references. The trust file
// is public transport trust, not a source of member or administrator authority.
func LoadTLSIdentity(ref TLSFiles) (tls.Certificate, *x509.CertPool, error) {
	if err := ref.Validate(); err != nil {
		return tls.Certificate{}, nil, err
	}
	pair, err := LoadTLSCertificate(ref.CertificateFile, ref.KeyFile)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	roots, err := loadTLSRoots(ref.TrustFile)
	return pair, roots, err
}

func loadTLSRoots(path string) (*x509.CertPool, error) {
	roots, err := readControlPublicFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	count := 0
	for len(bytes.TrimSpace(roots)) != 0 {
		block, rest := pem.Decode(roots)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, errors.New("TLS trust file contains non-certificate bytes")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !cert.IsCA {
			return nil, errors.New("TLS trust file must contain CA certificates")
		}
		pool.AddCert(cert)
		roots = rest
		count++
	}
	if count == 0 {
		return nil, errors.New("TLS trust file is empty")
	}
	return pool, nil
}

// LoadTLSCertificate resolves explicit local identity references without
// supplying trust. Data resources obtain their trust only from the signed View.
func LoadTLSCertificate(certificateFile, keyFile string) (tls.Certificate, error) {
	if !absoluteControlPath(certificateFile) || !absoluteControlPath(keyFile) {
		return tls.Certificate{}, errors.New("TLS identity requires canonical absolute file references")
	}
	certPEM, err := readControlPublicFile(certificateFile)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM, err := readProtectedControlFile(keyFile)
	if err != nil {
		return tls.Certificate{}, err
	}
	block, rest := pem.Decode(keyPEM)
	if block == nil || block.Type != "PRIVATE KEY" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return tls.Certificate{}, errors.New("TLS key must be one PKCS8 PEM value")
	}
	if _, err := x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
		return tls.Certificate{}, errors.New("TLS key is not PKCS8")
	}
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, errors.New("TLS certificate and key do not match")
	}
	pair.Leaf, err = x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return tls.Certificate{}, err
	}
	return pair, nil
}
func readControlPublicFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("TLS certificate input must be a regular file")
	}
	return os.ReadFile(path)
}
func localTLSConfig(ref *TLSFiles, peer bool) (*tls.Config, error) {
	if ref == nil {
		return nil, errors.New("selected TLS listener has no local identity and trust references")
	}
	pair, roots, err := LoadTLSIdentity(*ref)
	if err != nil {
		return nil, err
	}
	leaf := pair.Leaf
	now := time.Now()
	if leaf.IsCA || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return nil, errors.New("TLS leaf is outside its validity or is a CA")
	}
	serverOK, clientOK := false, false
	for _, usage := range leaf.ExtKeyUsage {
		serverOK = serverOK || usage == x509.ExtKeyUsageServerAuth
		clientOK = clientOK || usage == x509.ExtKeyUsageClientAuth
	}
	if !serverOK || peer && !clientOK {
		return nil, errors.New("TLS leaf is missing its required endpoint purposes")
	}
	authentication := tls.VerifyClientCertIfGiven
	if peer {
		authentication = tls.RequireAndVerifyClientCert
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}, RootCAs: roots, ClientCAs: roots, ClientAuth: authentication, NextProtos: []string{"http/1.1"}}, nil
}
func browserTLSConfig(config NodeConfig) (*tls.Config, error) {
	return localTLSConfig(config.BrowserTLS, false)
}
func peerTLSConfig(config NodeConfig) (*tls.Config, error) {
	result, err := localTLSConfig(config.PeerTLS, true)
	if err != nil {
		return nil, err
	}
	leaf := result.Certificates[0].Leaf
	public, ok := leaf.PublicKey.(ed25519.PublicKey)
	local, err := config.PublicKey()
	if err != nil {
		return nil, err
	}
	if !ok || !public.Equal(local) || leaf.Subject.CommonName != config.ControlID {
		return nil, errors.New("member transport leaf does not match the local control identity")
	}
	return result, nil
}
