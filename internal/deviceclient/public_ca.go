package deviceclient

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
)

// SavePublicDataPlaneCA materializes the public CA from a certified DeviceView
// as a replaceable runtime cache. It deliberately accepts no private key and
// does not create another source of authority.
func SavePublicDataPlaneCA(path, value string) (retErr error) {
	if path == "" || !filepath.IsAbs(path) || len(value) == 0 || len(value) > 1<<20 {
		return errors.New("public data-plane CA input is invalid")
	}
	rest := []byte(value)
	certificates := 0
	for len(rest) > 0 {
		block, remainder := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" {
			return errors.New("public data-plane CA is not a certificate bundle")
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !certificate.IsCA {
			return errors.New("public data-plane CA certificate is invalid")
		}
		certificates++
		rest = remainder
	}
	if certificates == 0 {
		return errors.New("public data-plane CA is empty")
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	file, err := os.CreateTemp(directory, ".data-plane-ca-*")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer func() {
		_ = file.Close()
		if retErr != nil {
			_ = os.Remove(temporary)
		}
	}()
	if err = file.Chmod(0o644); err == nil {
		_, err = file.WriteString(value)
	}
	if err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err := replaceProtectedFile(temporary, path); err != nil {
		return err
	}
	return syncProtectedDirectory(directory)
}
