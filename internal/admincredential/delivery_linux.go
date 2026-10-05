// Package admincredential generates local certificate delivery files. It never
// grants authority, changes installed trust, or reads an existing admin key.
package admincredential

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"loom/internal/control"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

type Options struct {
	Directory, IssuerCertificate, IssuerKey, Name string
	ValidDays                                     int
	Now                                           time.Time
	Random                                        io.Reader
}

var names = []string{"admin-root.crt", "admin.crt", "admin.json", "admin.key", "admin.p12", "admin.p12.password"}

func protected(path string, directory bool) (os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 ||
		directory && !info.IsDir() || !directory && (!info.Mode().IsRegular() || stat.Nlink != 1) {
		return nil, errors.New("administrator input must be an owned, protected, unlinked regular file or directory")
	}
	return info, nil
}

func read(path string) ([]byte, error) {
	info, err := protected(path, false)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(info, opened) || opened.Size() > 1<<20 {
		return nil, errors.New("administrator input changed or exceeds bounds")
	}
	body, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	after, statErr := f.Stat()
	if err != nil || statErr != nil || len(body) > 1<<20 || after.Size() != opened.Size() || !after.ModTime().Equal(opened.ModTime()) {
		return nil, errors.New("administrator input changed while reading")
	}
	return body, nil
}

func certificate(body []byte) (*x509.Certificate, error) {
	b, rest := pem.Decode(body)
	if b == nil || b.Type != "CERTIFICATE" || len(b.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("expected one PEM certificate")
	}
	return x509.ParseCertificate(b.Bytes)
}

func privateKey(body []byte) (*ecdsa.PrivateKey, error) {
	b, rest := pem.Decode(body)
	if b == nil || b.Type != "PRIVATE KEY" || len(b.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("expected one PKCS8 private key")
	}
	v, err := x509.ParsePKCS8PrivateKey(b.Bytes)
	if err != nil {
		return nil, errors.New("invalid administrator signing key")
	}
	k, ok := v.(*ecdsa.PrivateKey)
	if !ok || k.Curve != elliptic.P256() {
		return nil, errors.New("administrator signing key must be P-256")
	}
	return k, nil
}

// Issue installs a complete delivery directory once, or verifies the existing
// directory on retry. Entropy and time are supplied by the command, including
// entropy used to encrypt the P12; no clock enters the authority projection.
func Issue(options Options) (control.AdminCertificate, error) {
	var zero control.AdminCertificate
	for _, path := range []string{options.Directory, options.IssuerCertificate, options.IssuerKey} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return zero, errors.New("administrator file references must be canonical absolute paths")
		}
	}
	if control.ValidateText(options.Name) != nil || options.ValidDays < 1 || options.ValidDays > 365 || options.Now.IsZero() || options.Random == nil {
		return zero, errors.New("administrator name, validity, clock and entropy are required")
	}
	issuerPEM, err := read(options.IssuerCertificate)
	if err != nil {
		return zero, err
	}
	issuer, err := certificate(issuerPEM)
	if err != nil {
		return zero, err
	}
	keyPEM, err := read(options.IssuerKey)
	if err != nil {
		return zero, err
	}
	key, err := privateKey(keyPEM)
	if err != nil {
		return zero, err
	}
	public, ok := issuer.PublicKey.(*ecdsa.PublicKey)
	now := options.Now.UTC().Truncate(time.Second)
	if !ok || public.Curve != elliptic.P256() || !public.Equal(key.Public()) || !issuer.IsCA || !issuer.BasicConstraintsValid ||
		issuer.KeyUsage&x509.KeyUsageCertSign == 0 || !bytes.Equal(issuer.RawIssuer, issuer.RawSubject) || issuer.CheckSignatureFrom(issuer) != nil || now.Before(issuer.NotBefore) || !now.Before(issuer.NotAfter) {
		return zero, errors.New("administrator issuer is not a matching, valid P-256 root")
	}
	if _, err = os.Lstat(options.Directory); err == nil {
		return verify(options, issuer)
	} else if !errors.Is(err, os.ErrNotExist) {
		return zero, err
	}
	parent := filepath.Dir(options.Directory)
	if _, err = protected(parent, true); err != nil {
		return zero, err
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), options.Random)
	if err != nil {
		return zero, err
	}
	serialBytes := make([]byte, 20)
	if _, err = io.ReadFull(options.Random, serialBytes); err != nil {
		return zero, err
	}
	serialBytes[0] &= 0x7f
	serialBytes[0] |= 1
	end := now.Add(time.Duration(options.ValidDays) * 24 * time.Hour)
	if end.After(issuer.NotAfter) {
		return zero, errors.New("requested administrator validity exceeds the issuer; select a shorter duration")
	}
	start := now.Add(-5 * time.Minute)
	if start.Before(issuer.NotBefore) {
		start = issuer.NotBefore
	}
	template := &x509.Certificate{SerialNumber: new(big.Int).SetBytes(serialBytes), Subject: pkix.Name{CommonName: options.Name}, NotBefore: start, NotAfter: end,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(options.Random, template, issuer, leafKey.Public(), key)
	if err != nil {
		return zero, err
	}
	value := control.AdminCertificate{ID: control.AdminCertificateID(der), CertificateDER: base64.RawURLEncoding.EncodeToString(der)}
	leaf, err := control.ValidateAdminLeaf(value)
	if err != nil {
		return zero, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(issuer)
	if _, err = leaf.Verify(x509.VerifyOptions{Roots: pool, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return zero, errors.New("administrator issuer does not permit client authentication")
	}
	passwordBytes := make([]byte, 32)
	if _, err = io.ReadFull(options.Random, passwordBytes); err != nil {
		return zero, err
	}
	password := base64.RawURLEncoding.EncodeToString(passwordBytes)
	p12, err := pkcs12.Modern2023.WithRand(options.Random).Encode(leafKey, leaf, []*x509.Certificate{issuer}, password)
	if err != nil {
		return zero, errors.New("administrator P12 generation failed")
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		return zero, err
	}
	publicJSON, err := control.CanonicalEncode(value)
	if err != nil {
		return zero, err
	}
	files := map[string][]byte{"admin-root.crt": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuer.Raw}), "admin.crt": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		"admin.json": publicJSON, "admin.key": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}), "admin.p12": p12, "admin.p12.password": []byte(password + "\n")}
	temporary, err := os.MkdirTemp(parent, ".admin-delivery-*")
	if err != nil {
		return zero, err
	}
	defer os.RemoveAll(temporary)
	for _, name := range names {
		f, e := os.OpenFile(filepath.Join(temporary, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if e != nil {
			return zero, e
		}
		_, e = f.Write(files[name])
		if e == nil {
			e = f.Sync()
		}
		closed := f.Close()
		if e == nil {
			e = closed
		}
		if e != nil {
			return zero, e
		}
	}
	check := options
	check.Directory = temporary
	if _, err = verify(check, issuer); err != nil {
		return zero, err
	}
	if err = syncDirectory(temporary); err != nil {
		return zero, err
	}
	if err = unix.Renameat2(unix.AT_FDCWD, temporary, unix.AT_FDCWD, options.Directory, unix.RENAME_NOREPLACE); err != nil {
		return zero, errors.New("administrator delivery destination already exists or could not be installed")
	}
	if err = syncDirectory(parent); err != nil {
		return zero, err
	}
	return verify(options, issuer)
}

func syncDirectory(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func verify(options Options, issuer *x509.Certificate) (control.AdminCertificate, error) {
	var value control.AdminCertificate
	if _, err := protected(options.Directory, true); err != nil {
		return value, err
	}
	entries, err := os.ReadDir(options.Directory)
	if err != nil {
		return value, err
	}
	if len(entries) != len(names) {
		return value, errors.New("administrator delivery directory has missing or unexpected files")
	}
	files := map[string][]byte{}
	for _, name := range names {
		body, e := read(filepath.Join(options.Directory, name))
		if e != nil {
			return value, e
		}
		files[name] = body
	}
	if err = control.DecodeCanonical(files["admin.json"], &value, control.ContractDecodeLimits{MaxBytes: 64 << 10, MaxDepth: 4, MaxItems: 8}); err != nil {
		return value, err
	}
	leaf, err := control.ValidateAdminLeaf(value)
	if err != nil {
		return value, err
	}
	if value.ID != control.AdminCertificateID(leaf.Raw) || leaf.Subject.CommonName != options.Name || leaf.CheckSignatureFrom(issuer) != nil ||
		options.Now.Before(leaf.NotBefore) || options.Now.After(leaf.NotAfter) || leaf.NotAfter.After(issuer.NotAfter) {
		return value, errors.New("existing administrator delivery identity, issuer or validity differs")
	}
	requested := time.Duration(options.ValidDays) * 24 * time.Hour
	if duration := leaf.NotAfter.Sub(leaf.NotBefore); duration < requested || duration > requested+5*time.Minute {
		return value, errors.New("existing administrator delivery has a different requested lifetime")
	}
	actualLeaf, e1 := certificate(files["admin.crt"])
	actualRoot, e2 := certificate(files["admin-root.crt"])
	key, e3 := privateKey(files["admin.key"])
	if e1 != nil || e2 != nil || e3 != nil || !bytes.Equal(actualLeaf.Raw, leaf.Raw) || !bytes.Equal(actualRoot.Raw, issuer.Raw) || !leaf.PublicKey.(*ecdsa.PublicKey).Equal(key.Public()) {
		return value, errors.New("administrator delivery certificate or key differs")
	}
	password := string(files["admin.p12.password"])
	if !strings.HasSuffix(password, "\n") {
		return value, errors.New("administrator password file is incomplete")
	}
	password = strings.TrimSuffix(password, "\n")
	raw, err := base64.RawURLEncoding.DecodeString(password)
	if err != nil || len(raw) != 32 || base64.RawURLEncoding.EncodeToString(raw) != password {
		return value, errors.New("administrator password is not a complete generated value")
	}
	p12Key, p12Leaf, chain, err := pkcs12.DecodeChain(files["admin.p12"], password)
	if err != nil {
		return value, errors.New("administrator P12 verification failed")
	}
	k, ok := p12Key.(*ecdsa.PrivateKey)
	if !ok || !k.Equal(key) || !bytes.Equal(p12Leaf.Raw, leaf.Raw) || len(chain) != 1 || !bytes.Equal(chain[0].Raw, issuer.Raw) {
		return value, errors.New("administrator P12 does not contain the exact leaf, issuer and only the leaf private key")
	}
	return value, nil
}
