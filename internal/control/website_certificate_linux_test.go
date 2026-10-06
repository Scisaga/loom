package control

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"math/big"
	"net"
	"testing"
	"time"
)

func TestWebsiteReturnedCertificateUsesIndependentConstrainedRoot(t *testing.T) {
	directory, node, genesis := authorityFixture(t)
	authority, err := InitializeAuthority(directory, node, genesis)
	if err != nil {
		t.Fatal(err)
	}
	request, err := PrepareWebsiteRequest(directory, "demo-website", 1)
	if err != nil {
		t.Fatal(err)
	}
	expected := WebsiteRequestExpectation{node.NetworkID, node.GenesisID, authority.Snapshot().ControlConfigID,
		node.ControlID, node.NodeID, "demo-website", 1}
	csr, err := VerifyWebsiteRequest(request, expected)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	makeChain := func(change func(*x509.Certificate, *x509.Certificate), public any) ([]byte, []byte) {
		t.Helper()
		_, v4, _ := net.ParseCIDR("0.0.0.0/0")
		_, v6, _ := net.ParseCIDR("::/0")
		root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "demo-website-root"},
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour), BasicConstraintsValid: true, IsCA: true,
			KeyUsage: x509.KeyUsageCertSign, PermittedDNSDomainsCritical: true, PermittedDNSDomains: []string{".loom"}, ExcludedIPRanges: []*net.IPNet{v4, v6}}
		leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "demo-website"},
			NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), BasicConstraintsValid: true,
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: []string{"control.loom"}}
		if change != nil {
			change(root, leaf)
		}
		rootDER, err := x509.CreateCertificate(rand.Reader, root, root, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := x509.ParseCertificate(rootDER)
		if err != nil {
			t.Fatal(err)
		}
		leafDER, err := x509.CreateCertificate(rand.Reader, leaf, parsed, public, key)
		if err != nil {
			t.Fatal(err)
		}
		return leafDER, rootDER
	}
	leafDER, rootDER := makeChain(nil, csr.PublicKey)
	if _, err := VerifyWebsiteCertificate(request, expected, leafDER, rootDER, now); err != nil {
		t.Fatal("matching returned certificate rejected", err)
	}
	for name, change := range map[string]func(*x509.Certificate, *x509.Certificate){
		"unconstrained root":     func(root, _ *x509.Certificate) { root.PermittedDNSDomains = nil; root.ExcludedIPRanges = nil },
		"noncritical constraint": func(root, _ *x509.Certificate) { root.PermittedDNSDomainsCritical = false },
		"extra permitted namespace": func(root, _ *x509.Certificate) {
			root.PermittedDNSDomains = append(root.PermittedDNSDomains, ".example")
		},
		"missing IP family":  func(root, _ *x509.Certificate) { root.ExcludedIPRanges = root.ExcludedIPRanges[:1] },
		"additional DNS SAN": func(_, leaf *x509.Certificate) { leaf.DNSNames = append(leaf.DNSNames, "demo-other.loom") },
		"IP SAN":             func(_, leaf *x509.Certificate) { leaf.IPAddresses = []net.IP{net.ParseIP("192.0.2.1")} },
		"unknown SAN": func(_, leaf *x509.Certificate) {
			value, _ := asn1.Marshal([]asn1.RawValue{{Class: 2, Tag: 2, Bytes: []byte("control.loom")}, {Class: 2, Tag: 8, Bytes: []byte{42, 3, 4}}})
			leaf.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: value}}
		},
		"additional purpose": func(_, leaf *x509.Certificate) {
			leaf.ExtKeyUsage = append(leaf.ExtKeyUsage, x509.ExtKeyUsageClientAuth)
		},
		"leaf CA capability": func(_, leaf *x509.Certificate) { leaf.IsCA = true; leaf.KeyUsage |= x509.KeyUsageCertSign },
		"leaf expired":       func(_, leaf *x509.Certificate) { leaf.NotAfter = now },
		"root expired":       func(root, _ *x509.Certificate) { root.NotAfter = now },
		"leaf not yet valid": func(_, leaf *x509.Certificate) { leaf.NotBefore = now.Add(time.Minute) },
	} {
		t.Run(name, func(t *testing.T) {
			leaf, root := makeChain(change, csr.PublicKey)
			if _, err := VerifyWebsiteCertificate(request, expected, leaf, root, now); err == nil {
				t.Fatal("invalid website certificate accepted")
			}
		})
	}
	wrongKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrongLeaf, _ := makeChain(nil, &wrongKey.PublicKey)
	if _, err := VerifyWebsiteCertificate(request, expected, wrongLeaf, rootDER, now); err == nil {
		t.Fatal("returned leaf substituted the original CSR key")
	}
	key = wrongKey
	_, wrongRoot := makeChain(nil, csr.PublicKey)
	if _, err := VerifyWebsiteCertificate(request, expected, leafDER, wrongRoot, now); err == nil {
		t.Fatal("same-name root substituted the independent signing root")
	}
	if _, err := VerifyWebsiteCertificate(request, expected, leafDER, rootDER, now.Add(24*time.Hour)); err == nil {
		t.Fatal("certificate accepted at its expiry boundary")
	}
}

func TestWebsiteRequestRejectsUnprojectedSAN(t *testing.T) {
	directory, node, genesis := authorityFixture(t)
	if _, err := InitializeAuthority(directory, node, genesis); err != nil {
		t.Fatal(err)
	}
	request, err := PrepareWebsiteRequest(directory, "demo-website", 1)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	value, _ := asn1.Marshal([]asn1.RawValue{{Class: 2, Tag: 2, Bytes: []byte("control.loom")}, {Class: 2, Tag: 8, Bytes: []byte{42, 3, 4}}})
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 17}, Value: value}},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil || csr.CheckSignature() != nil || len(csr.DNSNames) != 1 || csr.DNSNames[0] != "control.loom" {
		t.Fatal("fixture must have a valid signature and the one projected DNS name", err)
	}
	request.CSRDER = base64.RawURLEncoding.EncodeToString(der)
	message, err := request.message()
	if err != nil {
		t.Fatal(err)
	}
	private, err := node.PrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	request.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, message))
	if request.Validate() == nil {
		t.Fatal("unprojected GeneralName escaped the exact website CSR template")
	}
}
