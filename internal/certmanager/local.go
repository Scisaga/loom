// Package certmanager 管理 TLS 终止节点本地 key/CSR、可恢复 ACME DNS-01
// 签发和证书 LKG/overlap。private key 永不进入 ControlSet、CRDT 或公开 distribution。
package certmanager

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"loom/internal/wire"
)

type LocalIdentity struct {
	PrivateKeyPath string
	CSRPath        string
	CSRDER         []byte
	SPKIHash       string
}

// EnsureLocalIdentity 创建或复用 exact P-256 key，再为目标 FQDN 构造 CSR。
// 随机只发生在 proposal preparation/executor 的私有 artifact 阶段，不在 reducer。
func EnsureLocalIdentity(privateKeyPath, fqdn string) (LocalIdentity, error) {
	if privateKeyPath == "" || !wire.ValidFQDN(fqdn) {
		return LocalIdentity{}, errors.New("[TLS] private key path/FQDN 无效")
	}
	privateKey, err := loadP256(privateKeyPath)
	if errors.Is(err, os.ErrNotExist) {
		privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return LocalIdentity{}, err
		}
		if err := saveP256(privateKeyPath, privateKey); err != nil {
			return LocalIdentity{}, err
		}
	} else if err != nil {
		return LocalIdentity{}, err
	}
	csrPath := privateKeyPath + ".csr"
	csrDER, err := readRegularFile(csrPath, 256<<10, false)
	if errors.Is(err, os.ErrNotExist) {
		csrDER, err = x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: fqdn}, DNSNames: []string{fqdn}, SignatureAlgorithm: x509.ECDSAWithSHA256}, privateKey)
		if err == nil {
			err = saveAtomic(csrPath, csrDER, 0o644)
		}
	}
	if err != nil {
		return LocalIdentity{}, err
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	wantSPKI, marshalErr := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil || marshalErr != nil || csr.CheckSignature() != nil || len(csr.DNSNames) != 1 || csr.DNSNames[0] != fqdn ||
		!bytes.Equal(csr.RawSubjectPublicKeyInfo, wantSPKI) {
		return LocalIdentity{}, errors.New("[TLS] 本地 CSR 自检失败")
	}
	sum := sha256.Sum256(wantSPKI)
	return LocalIdentity{PrivateKeyPath: privateKeyPath, CSRPath: csrPath, CSRDER: csrDER, SPKIHash: "sha256:" + hex.EncodeToString(sum[:])}, nil
}

func loadP256(path string) (*ecdsa.PrivateKey, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || before.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("[TLS] private key 文件权限必须不宽于 0600")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	after, err := file.Stat()
	if err != nil || !after.Mode().IsRegular() || after.Mode().Perm()&0o077 != 0 || !os.SameFile(before, after) {
		return nil, errors.New("[TLS] private key 文件在打开期间被替换或不是安全 regular file")
	}
	body, err := io.ReadAll(io.LimitReader(file, 64<<10))
	if err != nil || len(body) == 64<<10 {
		return nil, errors.New("[TLS] private key 文件读取失败或超过 64KiB")
	}
	block, rest := pem.Decode(body)
	if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("[TLS] private key PEM 无效")
	}
	keyAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	key, ok := keyAny.(*ecdsa.PrivateKey)
	if err != nil || !ok || key.Curve != elliptic.P256() {
		return nil, errors.New("[TLS] private key 必须是 PKCS#8 P-256")
	}
	return key, nil
}

func saveP256(path string, key *ecdsa.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	body := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	return saveAtomic(path, body, 0o600)
}

func saveAtomic(path string, body []byte, mode os.FileMode) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".tls-key-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(body); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	dir, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("[TLS] private key directory fsync 失败: %w", err)
	}
	return nil
}
