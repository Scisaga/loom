package attest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

// testCA 造一套自足的测试材料,不依赖机器上真实的 PKI。
type testCA struct {
	certPEM []byte
	key     *ecdsa.PrivateKey
	cert    *x509.Certificate
}

func newCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Loom Internal CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	crt, _ := x509.ParseCertificate(der)
	return &testCA{
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		key:     key, cert: crt,
	}
}

// issue 给某个节点签一张证书,返回 (keyPEM, certPEM)。
func (ca *testCA) issue(t *testing.T, node string) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: node + nodeSuffix},
		DNSNames:     []string{node + nodeSuffix},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func claim(node string) Claim {
	return Claim{Node: node, TS: "2026-08-25T12:00:00Z",
		Commit: "426961f342b0", Binary: "72a1f1abde95", Applied: "2b06535d1dbf"}
}

func TestSignThenVerify(t *testing.T) {
	ca := newCA(t)
	key, crt := ca.issue(t, "gz02")
	s, err := Sign(claim("gz02"), key, crt)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Verify(s, ca.certPEM)
	if err != nil {
		t.Fatalf("自己签的自己验不过:%v", err)
	}
	if got.Node != "gz02" || got.Commit != "426961f342b0" {
		t.Fatalf("验出来的内容不对:%+v", got)
	}
}

// **这是本文件存在的主要理由。** 没有这一条,任何一台有合法证书的机器
// 都能替别人发言 —— 而"替别人发言"正是转述,正是签名要根治的东西。
func TestCannotSpeakForAnotherNode(t *testing.T) {
	ca := newCA(t)
	key, crt := ca.issue(t, "ber01") // ber01 的合法证书
	c := claim("gz02")               // 却声称自己是 gz02
	s, err := Sign(c, key, crt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(s, ca.certPEM); err == nil {
		t.Fatal("ber01 拿自己的钥匙替 gz02 发言,必须被拒绝")
	} else if !strings.Contains(err.Error(), "替") {
		t.Errorf("错误要说清楚是冒名,得到:%v", err)
	}
}

// 自签证书链不到 CA —— 否则谁都能造一张。
func TestSelfSignedCertIsRejected(t *testing.T) {
	real := newCA(t)
	rogue := newCA(t)
	key, crt := rogue.issue(t, "gz02")
	s, _ := Sign(claim("gz02"), key, crt)
	if _, err := Verify(s, real.certPEM); err == nil {
		t.Fatal("别的 CA 签的证书必须被拒绝")
	}
}

// 内容被改过就验不过 —— 转述路径上任何一环动了手脚都会暴露。
func TestTamperedClaimFailsVerification(t *testing.T) {
	ca := newCA(t)
	key, crt := ca.issue(t, "gz02")
	s, _ := Sign(claim("gz02"), key, crt)

	for _, tc := range []struct {
		name string
		mut  func(*Signed)
	}{
		{"改 commit", func(s *Signed) { s.Commit = "deadbeefcafe" }},
		{"改 applied", func(s *Signed) { s.Applied = "0000000000ff" }},
		{"改时间", func(s *Signed) { s.TS = "2026-08-25T13:00:00Z" }},
		{"改二进制", func(s *Signed) { s.Binary = "ffffffffffff" }},
	} {
		bad := *s
		tc.mut(&bad)
		if _, err := Verify(&bad, ca.certPEM); err == nil {
			t.Errorf("%s 之后仍然验过了", tc.name)
		}
	}
}

// canonical 必须是确定的,而且**字段之间不能互相串位** ——
// 否则把 commit 的一段挪到 binary 里能算出同样的字节。
func TestCanonicalIsUnambiguous(t *testing.T) {
	a := Claim{Node: "n", TS: "t", Commit: "ab", Binary: "cd"}
	b := Claim{Node: "n", TS: "t", Commit: "abcd", Binary: ""}
	if string(a.canonical()) == string(b.canonical()) {
		t.Fatal("相邻字段串位算出了同样的字节 —— 分隔符没起作用")
	}
	if string(a.canonical()) != string(a.canonical()) {
		t.Fatal("同样的输入两次算出不同字节")
	}
}

func TestVerifyRejectsGarbage(t *testing.T) {
	ca := newCA(t)
	key, crt := ca.issue(t, "gz02")
	s, _ := Sign(claim("gz02"), key, crt)

	bad := *s
	bad.Sig = "这不是 base64!!!"
	if _, err := Verify(&bad, ca.certPEM); err == nil {
		t.Error("坏签名应报错")
	}
	bad = *s
	bad.Cert = "不是 PEM"
	if _, err := Verify(&bad, ca.certPEM); err == nil {
		t.Error("坏证书应报错")
	}
	if _, err := Verify(s, []byte("不是 CA")); err == nil {
		t.Error("坏 CA 应报错")
	}
}
