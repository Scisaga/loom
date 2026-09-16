package certmanager

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"loom/internal/wire"
)

type existingCertificateFixture struct {
	request     ExistingCertificateRequestV1
	roots       *x509.CertPool
	now         time.Time
	dir         string
	leaf, chain []byte
}

func newExistingCertificateFixture(t *testing.T, rsaLeaf bool) existingCertificateFixture {
	t.Helper()
	now := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)
	newKey := func() *ecdsa.PrivateKey {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return key
	}
	rootKey, issuerKey := newKey(), newKey()
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Demo root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	create := func(cert, parent *x509.Certificate, public any, signer crypto.Signer) *x509.Certificate {
		der, err := x509.CreateCertificate(rand.Reader, cert, parent, public, signer)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return parsed
	}
	root = create(root, root, rootKey.Public(), rootKey)
	issuer := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Demo issuer"},
		NotBefore: root.NotBefore, NotAfter: root.NotAfter, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	issuer = create(issuer, root, issuerKey.Public(), rootKey)
	var leafKey crypto.Signer = newKey()
	if rsaLeaf {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		leafKey = key
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "Demo existing certificate"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), DNSNames: []string{"*.example.test", "example.test"},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	leaf = create(leaf, issuer, leafKey.Public(), issuerKey)
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})
	chain := append(append([]byte(nil), leafPEM...), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuer.Raw})...)
	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	source := t.TempDir()
	request := ExistingCertificateRequestV1{Schema: 1, RequestID: "demo-existing-certificate", ClusterID: "demo-cluster", DeviceID: "demo-edge",
		IdentityID: "demo-public", IdentityGeneration: 1, CertificateGeneration: 1, EndpointIDs: []string{"demo-bootstrap", "demo-distribution"},
		DNSNames: []string{"demo-edge.example.test"}, IssuerProfileRef: "public-webpki",
		CertificatePath: filepath.Join(source, "fullchain.pem"), PrivateKeyPath: filepath.Join(source, "private.pem")}
	if err := os.WriteFile(request.CertificatePath, chain, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(request.PrivateKeyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	return existingCertificateFixture{request: request, roots: roots, now: now, dir: filepath.Join(t.TempDir(), "materials"), leaf: leafPEM, chain: chain}
}

func TestExistingCertificatePreservesOwnerKeyAndExplicitNameSubset(t *testing.T) {
	for _, rsaLeaf := range []bool{false, true} {
		t.Run(map[bool]string{false: "ecdsa", true: "rsa"}[rsaLeaf], func(t *testing.T) {
			f := newExistingCertificateFixture(t, rsaLeaf)
			// 复用 live -> archive 形式；持久副本不依赖之后的源文件轮换。
			link := filepath.Join(filepath.Dir(f.request.PrivateKeyPath), "live.pem")
			if err := os.Symlink(f.request.PrivateKeyPath, link); err != nil {
				t.Fatal(err)
			}
			f.request.PrivateKeyPath = link
			binding, err := PrepareExistingCertificate(f.dir, f.request, f.roots, f.now)
			if err != nil {
				t.Fatal(err)
			}
			if len(binding.Identity.DNSNames) != 1 || binding.Identity.DNSNames[0] != "demo-edge.example.test" {
				t.Fatal("wildcard 扩大了授权名字")
			}
			runtime, err := LoadExistingRuntimeCertificate(f.dir, binding, binding.Identity, f.roots, f.now)
			if err != nil || runtime.CertificateIntentHash != "" || runtime.ExistingCertificateBindingHash == "" {
				t.Fatalf("existing runtime: %v", err)
			}
			chainPath, keyPath, err := ExistingRuntimeCertificatePaths(f.dir, binding, binding.Identity, f.roots, f.now)
			if err != nil || chainPath != existingCertificateArtifactPath(f.dir, binding.CertificateChainHash, "chain") ||
				keyPath != existingCertificateArtifactPath(f.dir, binding.Identity.KeyArtifactHash, "key") {
				t.Fatalf("existing runtime paths: %q %q %v", chainPath, keyPath, err)
			}
			if !bytes.Equal(runtime.TLSCertificate.Certificate[0], runtime.TLSCertificate.Leaf.Raw) {
				t.Fatal("leaf 不匹配")
			}
			assertFileMode(t, existingCertificateArtifactPath(f.dir, binding.Identity.KeyArtifactHash, "key"), 0600)
			if err := os.Remove(f.request.CertificatePath); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(link); err != nil {
				t.Fatal(err)
			}
			retry, err := PrepareExistingCertificate(f.dir, f.request, f.roots, f.now)
			if err != nil || !wire.EqualCanonical(binding, retry) {
				t.Fatalf("exact retry: %v", err)
			}
			changed := f.request
			changed.DNSNames = []string{"demo-other.example.test"}
			if _, err := PrepareExistingCertificate(f.dir, changed, f.roots, f.now); err == nil {
				t.Fatal("接受 changed request")
			}
			identity := binding.Identity
			identity.IdentityGeneration++
			if _, err := LoadExistingRuntimeCertificate(f.dir, binding, identity, f.roots, f.now); err == nil {
				t.Fatal("接受不同认证身份")
			}
		})
	}
}

func TestExistingCertificateRejectsUntrustedOrUnsafeMaterial(t *testing.T) {
	cases := map[string]func(*testing.T, *existingCertificateFixture){
		"expired": func(_ *testing.T, f *existingCertificateFixture) { f.now = f.now.Add(25 * time.Hour) },
		"future":  func(_ *testing.T, f *existingCertificateFixture) { f.now = f.now.Add(-2 * time.Hour) },
		"wrong_name": func(_ *testing.T, f *existingCertificateFixture) {
			f.request.DNSNames = []string{"demo-other.example.org"}
		},
		"untrusted_root": func(_ *testing.T, f *existingCertificateFixture) { f.roots = x509.NewCertPool() },
		"missing_intermediate": func(t *testing.T, f *existingCertificateFixture) {
			if err := os.WriteFile(f.request.CertificatePath, f.leaf, 0644); err != nil {
				t.Fatal(err)
			}
		},
		"wrong_key": func(t *testing.T, f *existingCertificateFixture) {
			other := newExistingCertificateFixture(t, false)
			f.request.PrivateKeyPath = other.request.PrivateKeyPath
		},
		"unsafe_key": func(t *testing.T, f *existingCertificateFixture) {
			if err := os.Chmod(f.request.PrivateKeyPath, 0644); err != nil {
				t.Fatal(err)
			}
		},
		"relative_source": func(_ *testing.T, f *existingCertificateFixture) { f.request.PrivateKeyPath = "private.pem" },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			f := newExistingCertificateFixture(t, false)
			change(t, &f)
			if _, err := PrepareExistingCertificate(f.dir, f.request, f.roots, f.now); err == nil {
				t.Fatal("接受无效证书")
			}
			entries, _ := os.ReadDir(f.dir)
			if len(entries) != 0 {
				t.Fatal("失败验证留下可用材料")
			}
		})
	}
}

func TestExistingCertificateRetryDoesNotRepairMissingOrAlteredPrivateKey(t *testing.T) {
	for _, remove := range []bool{true, false} {
		t.Run(map[bool]string{true: "missing", false: "altered"}[remove], func(t *testing.T) {
			f := newExistingCertificateFixture(t, false)
			binding, err := PrepareExistingCertificate(f.dir, f.request, f.roots, f.now)
			if err != nil {
				t.Fatal(err)
			}
			path := existingCertificateArtifactPath(f.dir, binding.Identity.KeyArtifactHash, "key")
			if remove {
				err = os.Remove(path)
			} else {
				err = os.WriteFile(path, []byte("corrupted"), 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := PrepareExistingCertificate(f.dir, f.request, f.roots, f.now); err == nil {
				t.Fatal("静默重新导入缺失或损坏私钥")
			}
		})
	}
}

func TestExistingCertificateConcurrentPreparationKeepsOneResult(t *testing.T) {
	f := newExistingCertificateFixture(t, false)
	const count = 8
	results := make([]ExistingCertificateBindingV1, count)
	errs := make([]error, count)
	var group sync.WaitGroup
	for i := range count {
		group.Go(func() { results[i], errs[i] = PrepareExistingCertificate(f.dir, f.request, f.roots, f.now) })
	}
	group.Wait()
	for i := range count {
		if errs[i] != nil || !wire.EqualCanonical(results[0], results[i]) {
			t.Fatalf("retry %d: %v", i, errs[i])
		}
	}
	link := filepath.Join(t.TempDir(), "linked-materials")
	if err := os.Symlink(f.dir, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadExistingRuntimeCertificate(link, results[0], results[0].Identity, f.roots, f.now); err == nil {
		t.Fatal("接受 symlink 材料目录")
	}
	missing := filepath.Join(t.TempDir(), "absent")
	if _, err := LoadExistingRuntimeCertificate(missing, results[0], results[0].Identity, f.roots, f.now); err == nil {
		t.Fatal("接受缺失目录")
	}
	if _, err := os.Lstat(missing); !os.IsNotExist(err) {
		t.Fatal("读取创建了材料目录")
	}
}
