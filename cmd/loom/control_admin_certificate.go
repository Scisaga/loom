package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

func makeP256AdminCA(commonName string, notBefore, notAfter time.Time) ([]byte, *x509.Certificate, crypto.Signer, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	serial, err := randomCertificateSerial()
	if err != nil {
		return nil, nil, nil, err
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: commonName},
		NotBefore: notBefore.UTC(), NotAfter: notAfter.UTC(), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		return nil, nil, nil, err
	}
	certificate, err := x509.ParseCertificate(der)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), certificate, key, err
}

func generateAdminKey(public crypto.PublicKey) (crypto.Signer, error) {
	switch key := public.(type) {
	case ed25519.PublicKey:
		_, private, err := ed25519.GenerateKey(rand.Reader)
		return private, err
	case *ecdsa.PublicKey:
		if key.Curve == elliptic.P256() {
			return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		}
	}
	return nil, errors.New("[admin] issuer 必须是 Ed25519 或 P-256")
}

func parseAdminPrivateKey(encoded []byte) (crypto.Signer, error) {
	block, trailing := pem.Decode(encoded)
	if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(trailing)) != 0 {
		return nil, errors.New("[admin] key 必须是单一 PKCS#8 PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	switch key := parsed.(type) {
	case ed25519.PrivateKey:
		return key, nil
	case *ecdsa.PrivateKey:
		if key.Curve == elliptic.P256() {
			return key, nil
		}
	}
	return nil, errors.New("[admin] 私钥算法未获支持")
}

func cmdControlExportAdmin(args []string) error {
	fs := flag.NewFlagSet("control export-admin", flag.ContinueOnError)
	dir := fs.String("admin-dir", "", "包含管理员证书、私钥和签发根的受保护目录")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dir == "" || fs.NArg() != 0 {
		return errors.New("control export-admin 必须指定 -admin-dir")
	}
	return exportAdminPKCS12(*dir, time.Now().UTC())
}

// 交付包必须自含完整的兼容链，只包含管理员私钥；历史 Ed25519 包禁止再次交付浏览器。
func exportAdminPKCS12(dir string, now time.Time) error {
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		return errors.New("[admin.p12] 交付目录必须是 owner-only 目录")
	}
	leafPEM, err := readOwnerOnlyFile(filepath.Join(dir, controlAdminCertName), 1<<20)
	if err != nil {
		return err
	}
	rootPEM, err := readOwnerOnlyFile(filepath.Join(dir, controlAdminRootName), 1<<20)
	if err != nil {
		return err
	}
	keyPEM, err := readOwnerOnlyFile(filepath.Join(dir, controlAdminKeyName), 1<<20)
	if err != nil {
		return err
	}
	leaf, err := parseSingleCertificatePEM(leafPEM)
	if err != nil {
		return err
	}
	root, err := parseSingleCertificatePEM(rootPEM)
	if err != nil {
		return err
	}
	key, err := parseAdminPrivateKey(keyPEM)
	if err != nil {
		return err
	}
	leafPublic, leafOK := leaf.PublicKey.(*ecdsa.PublicKey)
	rootPublic, rootOK := root.PublicKey.(*ecdsa.PublicKey)
	if !leafOK || !rootOK || leafPublic.Curve != elliptic.P256() || rootPublic.Curve != elliptic.P256() ||
		leaf.SignatureAlgorithm != x509.ECDSAWithSHA256 || root.SignatureAlgorithm != x509.ECDSAWithSHA256 ||
		!leafPublic.Equal(key.Public()) || leaf.IsCA || leaf.KeyUsage != x509.KeyUsageDigitalSignature ||
		len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth ||
		!root.IsCA || root.CheckSignatureFrom(root) != nil || leaf.CheckSignatureFrom(root) != nil {
		return errors.New("[admin.p12] 必须是匹配私钥的 P-256 clientAuth leaf 与 P-256 签发链；旧 Ed25519 身份须先 rotate-admin")
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return err
	}
	packagePath, passwordPath := filepath.Join(dir, "admin.p12"), filepath.Join(dir, "admin.p12.password")
	if _, err := os.Lstat(packagePath); err == nil {
		// 已有包也要验证内容；重复运行不能静默覆盖用户手中的身份或密码。
		return verifyAdminPKCS12(dir, leaf.Raw, root.Raw)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if _, err := os.Lstat(passwordPath); errors.Is(err, os.ErrNotExist) {
		raw := make([]byte, 32)
		if _, err := rand.Read(raw); err != nil {
			return err
		}
		if err := writeBytesAtomic(passwordPath, []byte(base64.RawURLEncoding.EncodeToString(raw)+"\n"), 0o600); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	if _, err := readOwnerOnlyFile(passwordPath, 4096); err != nil {
		return err
	}
	cmd := exec.Command("openssl", "pkcs12", "-export", "-inkey", filepath.Join(dir, controlAdminKeyName),
		"-in", filepath.Join(dir, controlAdminCertName), "-certfile", filepath.Join(dir, controlAdminRootName),
		"-name", "Loom control administrator", "-passout", "file:"+passwordPath)
	encoded, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("[admin.p12] OpenSSL 导出失败: %w", err)
	}
	if err := writeBytesAtomic(packagePath, encoded, 0o600); err != nil {
		return err
	}
	return verifyAdminPKCS12(dir, leaf.Raw, root.Raw)
}

func verifyAdminPKCS12(dir string, leafDER, rootDER []byte) error {
	path, password := filepath.Join(dir, "admin.p12"), filepath.Join(dir, "admin.p12.password")
	if _, err := readOwnerOnlyFile(path, 4<<20); err != nil {
		return err
	}
	if _, err := readOwnerOnlyFile(password, 4096); err != nil {
		return err
	}
	// 明文私钥只在子进程管道与内存内验证，不写日志、参数或临时文件。
	output, err := exec.Command("openssl", "pkcs12", "-in", path, "-passin", "file:"+password, "-noenc").Output()
	if err != nil {
		return fmt.Errorf("[admin.p12] MAC/密码/解码验证失败: %w", err)
	}
	var certs [][]byte
	var keys []crypto.Signer
	for len(output) != 0 {
		block, remaining := pem.Decode(output)
		if block == nil {
			break
		}
		output = remaining
		switch block.Type {
		case "CERTIFICATE":
			certs = append(certs, block.Bytes)
		case "PRIVATE KEY":
			key, err := parseAdminPrivateKey(pem.EncodeToMemory(block))
			if err != nil {
				return err
			}
			keys = append(keys, key)
		default:
			return errors.New("[admin.p12] 包内出现未声明的 PEM 对象")
		}
	}
	if len(certs) != 2 || len(keys) != 1 || !bytes.Equal(certs[0], leafDER) || !bytes.Equal(certs[1], rootDER) {
		return errors.New("[admin.p12] 包必须包含 exact leaf + issuer 与仅一把管理员私钥")
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return err
	}
	public, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || !public.Equal(keys[0].Public()) {
		return errors.New("[admin.p12] 包内私钥与管理员证书不匹配")
	}
	return nil
}
