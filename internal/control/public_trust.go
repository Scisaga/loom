package control

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"net/http"
	"strconv"
	"time"
)

// PublicTrust is a public certificate grant in NetworkIntent, never a private
// signing input or an assertion about a device's operating-system trust store.
type PublicTrust struct {
	ID             string `json:"id"`
	Purpose        string `json:"purpose"`
	CertificateDER string `json:"certificate_der"`
}

func (PublicTrust) materialPayload() {}

func WebsiteTrustID(der []byte) string {
	sum := sha256.Sum256(der)
	return "website-" + hex.EncodeToString(sum[:])
}

func (value PublicTrust) certificate() (*x509.Certificate, error) {
	der, err := base64.RawURLEncoding.DecodeString(value.CertificateDER)
	if err != nil || len(der) > 32<<10 || base64.RawURLEncoding.EncodeToString(der) != value.CertificateDER ||
		value.Purpose != "website" || value.ID != WebsiteTrustID(der) {
		return nil, errors.New("public trust requires a canonical website certificate and its immutable digest identity")
	}
	return ValidateWebsiteRoot(der)
}

func (value PublicTrust) Validate() error {
	_, err := value.certificate()
	return err
}

// WebsiteTrustPEM projects one already authenticated grant for explicit export.
// Its caller must obtain the value from a verified View or control projection.
func WebsiteTrustPEM(value PublicTrust, now time.Time) ([]byte, error) {
	root, err := value.certificate()
	if err != nil {
		return nil, err
	}
	if now.Before(root.NotBefore) || !now.Before(root.NotAfter) {
		return nil, errors.New("website trust root is outside its validity")
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw}), nil
}

func validatePublicTrust(values []PublicTrust) error {
	for index, value := range values {
		if err := value.Validate(); err != nil {
			return err
		}
		if index > 0 && values[index-1].ID >= value.ID {
			return errors.New("public trust must have uniquely sorted certificate identities")
		}
	}
	return nil
}

func (server *Server) verifyPublicTrustGrant(value PublicTrust) error {
	root, err := value.certificate()
	if err != nil {
		return err
	}
	now := server.now()
	if now.Before(root.NotBefore) || !now.Before(root.NotAfter) {
		return errors.New("website trust root is outside its validity")
	}
	return nil
}

func (server *Server) websiteRootDownload(w http.ResponseWriter, request *http.Request) {
	if server.Runtime == nil || server.Runtime.Authority == nil {
		http.Error(w, "control projection unavailable", http.StatusServiceUnavailable)
		return
	}
	id := request.PathValue("id")
	if ValidateID(id) != nil || request.URL.RawQuery != "" {
		http.NotFound(w, request)
		return
	}
	for _, value := range server.Runtime.Authority.Snapshot().NetworkIntent.PublicTrust {
		if value.ID != id {
			continue
		}
		body, err := WebsiteTrustPEM(value, server.now())
		if err != nil {
			http.Error(w, "website root is not currently valid", http.StatusConflict)
			return
		}
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Header().Set("Content-Disposition", "attachment; filename=\""+id+".pem\"")
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		_, _ = w.Write(body)
		return
	}
	http.NotFound(w, request)
}
