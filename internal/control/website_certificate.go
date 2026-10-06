package control

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"time"
)

// Check the complete SAN encoding as well as x509's parsed names: unknown
// GeneralName variants must not disappear during the website template check.
func exactWebsiteSAN(extensions []pkix.Extension) bool {
	wanted, _ := asn1.Marshal([]asn1.RawValue{{Class: 2, Tag: 2, Bytes: []byte("control.loom")}})
	count := 0
	for _, extension := range extensions {
		if extension.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 17}) {
			if !bytes.Equal(extension.Value, wanted) {
				return false
			}
			count++
		}
	}
	return count == 1
}

// ValidateWebsiteRoot checks the public root's fixed constraints without
// consulting a clock, host trust store or external certificate service.
func ValidateWebsiteRoot(der []byte) (*x509.Certificate, error) {
	root, err := x509.ParseCertificate(der)
	if err != nil || len(der) > 32<<10 || !bytes.Equal(root.Raw, der) || !root.IsCA || !root.BasicConstraintsValid ||
		root.KeyUsage&x509.KeyUsageCertSign == 0 || !bytes.Equal(root.RawIssuer, root.RawSubject) || root.CheckSignatureFrom(root) != nil ||
		len(root.UnhandledCriticalExtensions) != 0 || !root.NotAfter.After(root.NotBefore) {
		return nil, errors.New("website trust requires one complete self-signed CA certificate")
	}
	if !root.PermittedDNSDomainsCritical || len(root.PermittedDNSDomains) != 1 || root.PermittedDNSDomains[0] != ".loom" ||
		len(root.ExcludedDNSDomains) != 0 || len(root.PermittedIPRanges) != 0 || len(root.ExcludedIPRanges) != 2 ||
		len(root.PermittedEmailAddresses)+len(root.ExcludedEmailAddresses)+len(root.PermittedURIDomains)+len(root.ExcludedURIDomains) != 0 {
		return nil, errors.New("website root requires critical .loom DNS constraints and complete IP exclusions")
	}
	var ipv4, ipv6 bool
	for _, network := range root.ExcludedIPRanges {
		ones, bits := network.Mask.Size()
		if ones != 0 || !network.IP.IsUnspecified() {
			return nil, errors.New("website root IP exclusions must cover every address")
		}
		switch {
		case bits == 32 && network.IP.To4() != nil && !ipv4:
			ipv4 = true
		case bits == 128 && network.IP.To4() == nil && !ipv6:
			ipv6 = true
		default:
			return nil, errors.New("website root requires distinct IPv4 and IPv6 exclusions")
		}
	}
	if !ipv4 || !ipv6 {
		return nil, errors.New("website root is missing an address-family exclusion")
	}
	return root, nil
}

// VerifyWebsiteCertificate verifies a returned public leaf against the original
// authenticated CSR and an independently selected constrained root. This does
// not install browser trust, load a private key or activate an endpoint.
func VerifyWebsiteCertificate(request WebsiteRequest, expected WebsiteRequestExpectation, leafDER, rootDER []byte, now time.Time) (*x509.Certificate, error) {
	csr, err := VerifyWebsiteRequest(request, expected)
	if err != nil {
		return nil, err
	}
	leaf, err := verifyWebsiteLeaf(leafDER, rootDER, now)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(leaf.RawSubjectPublicKeyInfo, csr.RawSubjectPublicKeyInfo) {
		return nil, errors.New("website leaf does not bind the original CSR")
	}
	return leaf, nil
}

func verifyWebsiteLeaf(leafDER, rootDER []byte, now time.Time) (*x509.Certificate, error) {
	root, err := ValidateWebsiteRoot(rootDER)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil || len(leafDER) > 32<<10 || !bytes.Equal(leaf.Raw, leafDER) ||
		leaf.IsCA || !leaf.BasicConstraintsValid || leaf.KeyUsage != x509.KeyUsageDigitalSignature ||
		len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth || len(leaf.UnknownExtKeyUsage) != 0 ||
		!exactWebsiteSAN(leaf.Extensions) || !leaf.NotAfter.After(leaf.NotBefore) {
		return nil, errors.New("website leaf must bind the original CSR and contain only control.loom, serverAuth and digitalSignature")
	}
	for _, certificate := range []*x509.Certificate{leaf, root} {
		if now.Before(certificate.NotBefore) || !now.Before(certificate.NotAfter) {
			return nil, errors.New("website certificate is outside its validity")
		}
	}
	if !bytes.Equal(leaf.RawIssuer, root.RawSubject) || leaf.CheckSignatureFrom(root) != nil {
		return nil, errors.New("website leaf was not signed by the independently selected root")
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	chains, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "control.loom", CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	if err != nil || len(chains) != 1 || len(chains[0]) != 2 || !bytes.Equal(chains[0][1].Raw, rootDER) {
		return nil, errors.New("website leaf chain does not verify against the selected constrained root")
	}
	return leaf, nil
}
