package control

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"time"
)

func (AdminCertificate) materialPayload() {}

// AdminCertificateID identifies the complete leaf, never a name or public key.
func AdminCertificateID(der []byte) string {
	sum := sha256.Sum256(der)
	return "admin-" + hex.EncodeToString(sum[:])
}

// ValidateAdminLeaf applies to new grants. Genesis retains its original codec
// and certificate acceptance rules, including already authenticated identities.
func ValidateAdminLeaf(value AdminCertificate) (*x509.Certificate, error) {
	der, err := base64.RawURLEncoding.DecodeString(value.CertificateDER)
	if ValidateID(value.ID) != nil || err != nil || len(der) > 32<<10 || base64.RawURLEncoding.EncodeToString(der) != value.CertificateDER {
		return nil, errors.New("administrator certificate is not canonical")
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil || !bytes.Equal(leaf.Raw, der) {
		return nil, errors.New("administrator value must contain one complete DER certificate")
	}
	key, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() || leaf.IsCA || !leaf.BasicConstraintsValid || leaf.KeyUsage != x509.KeyUsageDigitalSignature ||
		len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth || len(leaf.UnknownExtKeyUsage) != 0 ||
		!leaf.NotAfter.After(leaf.NotBefore) {
		return nil, errors.New("administrator leaf must be P-256 with only clientAuth and digitalSignature")
	}
	return leaf, nil
}

func (graph *materialGraph) validateAdminCertificate(value AdminCertificate, history []string) error {
	bound := false
	check := func(prior AdminCertificate) error {
		if prior.ID == value.ID {
			if prior.CertificateDER != value.CertificateDER {
				return errors.New("administrator certificate ID cannot change its original leaf")
			}
			bound = true
		} else if prior.CertificateDER == value.CertificateDER {
			return errors.New("administrator leaf already has a different stable ID")
		}
		return nil
	}
	for _, prior := range graph.genesis.Payload.(Genesis).AdminCertificates {
		if err := check(prior); err != nil {
			return err
		}
	}
	for _, id := range history {
		if prior, ok := graph.facts[id].Payload.(AdminCertificate); ok {
			if err := check(prior); err != nil {
				return err
			}
		}
	}
	der, _ := base64.RawURLEncoding.DecodeString(value.CertificateDER)
	if !bound && value.ID != AdminCertificateID(der) {
		return errors.New("new administrator ID must identify the complete certificate")
	}
	return nil
}

func (server *Server) verifyAdminGrant(value AdminCertificate) error {
	leaf, err := ValidateAdminLeaf(value)
	if err != nil {
		return err
	}
	if server.Config.BrowserTLS == nil {
		return errors.New("administrator grant requires configured browser client trust")
	}
	roots, err := loadTLSRoots(server.Config.BrowserTLS.TrustFile)
	if err != nil {
		return errors.New("administrator trust input is unavailable")
	}
	_, err = leaf.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: server.now(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	if err != nil {
		return errors.New("administrator certificate does not verify against this control's client trust or current validity")
	}
	return nil
}

func certificateChainsCurrent(chains [][]*x509.Certificate, now time.Time) bool {
	for _, chain := range chains {
		current := len(chain) > 0
		for _, certificate := range chain {
			current = current && !now.Before(certificate.NotBefore) && !now.After(certificate.NotAfter)
		}
		if current {
			return true
		}
	}
	return false
}

func projectWebAdministrators(projection Projection) []WebAdministrator {
	values := []WebAdministrator{}
	for _, value := range projection.AdminCertificates {
		der, _ := base64.RawURLEncoding.DecodeString(value.CertificateDER)
		leaf, err := x509.ParseCertificate(der)
		if err != nil {
			continue
		}
		sum := sha256.Sum256(der)
		values = append(values, WebAdministrator{ID: value.ID, Subject: leaf.Subject.CommonName,
			Fingerprint: "sha256:" + hex.EncodeToString(sum[:]), NotBefore: leaf.NotBefore.UTC().Format(time.RFC3339), NotAfter: leaf.NotAfter.UTC().Format(time.RFC3339)})
	}
	return values
}
