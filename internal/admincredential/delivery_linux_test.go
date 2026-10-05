package admincredential

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func issuerFixture(t *testing.T) Options {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Demo administrator root"}, BasicConstraintsValid: true, IsCA: true,
		KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(400 * 24 * time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	options := Options{Directory: filepath.Join(root, "delivery"), IssuerCertificate: filepath.Join(root, "demo-root.crt"), IssuerKey: filepath.Join(root, "demo-root.key"), Name: "Demo administrator", ValidDays: 365, Now: now, Random: rand.Reader}
	if err := os.WriteFile(options.IssuerCertificate, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(options.IssuerKey, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}), 0o600); err != nil {
		t.Fatal(err)
	}
	return options
}

func TestIssueDeliveryRetryAndIndependentP12Decode(t *testing.T) {
	o := issuerFixture(t)
	value, err := Issue(o)
	if err != nil {
		t.Fatal(err)
	}
	before := map[string][]byte{}
	for _, name := range names {
		before[name], err = os.ReadFile(filepath.Join(o.Directory, name))
		if err != nil {
			t.Fatal(err)
		}
	}
	o.Now = o.Now.Add(time.Hour)
	if again, err := Issue(o); err != nil || again != value {
		t.Fatal("retry changed identity", err)
	}
	for _, name := range names {
		after, err := read(filepath.Join(o.Directory, name))
		if err != nil || !bytes.Equal(after, before[name]) {
			t.Fatal("retry changed delivery bytes", name, err)
		}
	}
	for _, change := range []func(*Options){func(v *Options) { v.Name = "Demo other name" }, func(v *Options) { v.ValidDays = 30 }} {
		changed := o
		change(&changed)
		if _, err := Issue(changed); err == nil {
			t.Fatal("changed issuance inputs reused prior delivery")
		}
	}
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("independent OpenSSL P12 reader unavailable")
	}
	// OpenSSL sees only file references; decrypted keys remain inside this test.
	command := exec.Command("openssl", "pkcs12", "-in", filepath.Join(o.Directory, "admin.p12"), "-passin", "file:"+filepath.Join(o.Directory, "admin.p12.password"), "-noenc")
	output, err := command.Output()
	if err != nil {
		t.Fatal("OpenSSL could not verify and decrypt generated P12")
	}
	var certs, keys int
	for len(output) > 0 {
		block, rest := pem.Decode(output)
		if block == nil {
			break
		}
		output = rest
		switch block.Type {
		case "CERTIFICATE":
			certs++
		case "PRIVATE KEY":
			keys++
			key, err := privateKey(pem.EncodeToMemory(block))
			if err != nil {
				t.Fatal(err)
			}
			original, err := privateKey(before["admin.key"])
			if err != nil || !key.Equal(original) {
				t.Fatal("P12 private key differs")
			}
		default:
			t.Fatal("unexpected P12 object")
		}
	}
	if certs != 2 || keys != 1 {
		t.Fatal("P12 does not contain exactly the leaf, root and leaf key")
	}
}

func TestIssueDeliveryRejectsDamageAndUnsafeReferences(t *testing.T) {
	for _, kind := range []string{"missing", "password", "p12", "symlink", "permissions", "extra"} {
		t.Run(kind, func(t *testing.T) {
			o := issuerFixture(t)
			if _, err := Issue(o); err != nil {
				t.Fatal(err)
			}
			key := filepath.Join(o.Directory, "admin.key")
			before, err := os.ReadFile(key)
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "missing":
				err = os.Remove(filepath.Join(o.Directory, "admin.json"))
			case "password":
				err = os.WriteFile(filepath.Join(o.Directory, "admin.p12.password"), []byte("demo-invalid-password\n"), 0o600)
			case "p12":
				err = os.WriteFile(filepath.Join(o.Directory, "admin.p12"), []byte("demo-invalid-p12"), 0o600)
			case "symlink":
				file := filepath.Join(o.Directory, "admin.crt")
				dest := filepath.Join(filepath.Dir(o.Directory), "demo-saved-leaf")
				if err = os.Rename(file, dest); err == nil {
					err = os.Symlink(dest, file)
				}
			case "permissions":
				err = os.Chmod(o.Directory, 0o755)
			case "extra":
				err = os.WriteFile(filepath.Join(o.Directory, "unexpected"), []byte("demo"), 0o600)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Issue(o); err == nil {
				t.Fatal("damaged directory was silently regenerated")
			}
			after, err := os.ReadFile(key)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("failed retry changed original identity")
			}
		})
	}
	for _, kind := range []string{"key-permissions", "wrong-key", "expired-issuer", "relative-path"} {
		t.Run(kind, func(t *testing.T) {
			o := issuerFixture(t)
			switch kind {
			case "key-permissions":
				if err := os.Chmod(o.IssuerKey, 0o644); err != nil {
					t.Fatal(err)
				}
			case "wrong-key":
				o.IssuerKey = issuerFixture(t).IssuerKey
			case "expired-issuer":
				o.Now = o.Now.Add(401 * 24 * time.Hour)
			case "relative-path":
				o.IssuerCertificate = "demo-root.crt"
			}
			if _, err := Issue(o); err == nil {
				t.Fatal("unsafe issuer input accepted")
			}
			if _, err := os.Lstat(o.Directory); !os.IsNotExist(err) {
				t.Fatal("rejected issuance left a delivery directory")
			}
		})
	}
}
