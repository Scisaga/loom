// Package attest 让一台机器**关于自己的陈述**在转述之后仍然可信。
//
// # 要解决的是什么
//
// gz02 和 hz01 与中控之间没有隧道(这是拓扑,不是故障),它们的消息只能
// 由 sg02 / ber01 转述过来。观测转述是没问题的 —— 快照 id、RTT 这类
// 数字,B 转述 C 的观测,可信度就是 B 的可信度,而观测本来就是尽力而为。
//
// **但身份不一样。** "C 跑的是 commit X"这句话如果只由 B 说,那么排障时
// 恰恰不能假设 B 可信 —— 出问题的往往就是链路上某一环。所以 D71/D73
// 的结论是"版本核不了转述来的节点",代价是 `loom status` 只能报
// "3/5 台核对过",另外两台永远是空白。
//
// 签名把这条限制取消掉:**转述的是密文,不是信任**。B 转述 C 的签名陈述,
// 篡改会被验签发现,伪造需要 C 的私钥。于是 C 够不够得到就不重要了。
//
// # 为什么用现成的 PKI
//
// 每台机器早就有 `/etc/loom/tls/node.key` 和 `node.crt`(CN 是
// `<节点>.node.internal`,由内部 CA 签发)。不需要引入新的密钥材料,
// 也就不需要新的分发和轮换路径 —— 那是这个系统里最贵的东西。
package attest

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strings"
)

// Claim 是一台机器关于**它自己**的陈述。
//
// 只装"身份"这一类事实:我是谁、我跑的是哪一版。观测数据(RTT、可达性)
// 不进来 —— 那些本来就可以转述,签名只会让它们变贵。
type Claim struct {
	Node    string `json:"node"`
	TS      string `json:"ts"`
	Commit  string `json:"commit,omitempty"`
	Binary  string `json:"binary,omitempty"`
	Applied string `json:"applied,omitempty"`
}

// canonical 是签名覆盖的字节。
//
// **固定顺序、固定分隔符,不走 JSON。** JSON 的字段顺序、空白、转义都
// 可能因库版本而变,而签名是针对字节的 —— 换个 Go 版本就验不过的签名
// 不如没有。分隔符用 \x1f(单元分隔符),它不会出现在这些字段里。
func (c *Claim) canonical() []byte {
	return []byte(strings.Join([]string{
		"loom-attest-v1", c.Node, c.TS, c.Commit, c.Binary, c.Applied,
	}, "\x1f"))
}

// Signed 是 Claim 加上"它确实来自那台机器"的证明。
//
// Cert 随签名一起走,所以验证方**不需要事先有对方的证书** —— 只要有 CA。
// 这正是转述场景需要的:中控不必为每台够不到的机器单独准备材料。
type Signed struct {
	Claim `json:",inline"`
	Cert  string `json:"cert"`
	Sig   string `json:"sig"`
}

// Sign 用本机私钥给陈述签名。
func Sign(c Claim, keyPEM, certPEM []byte) (*Signed, error) {
	key, err := parseKey(keyPEM)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(c.canonical())
	sig, err := ecdsa.SignASN1(rand.Reader, key, sum[:])
	if err != nil {
		return nil, fmt.Errorf("签名:%w", err)
	}
	return &Signed{
		Claim: c,
		Cert:  string(certPEM),
		Sig:   base64.StdEncoding.EncodeToString(sig),
	}, nil
}

// Verify 校验一条陈述,返回其中可信的部分。
//
// 三件事都要查,少一件这个机制就是摆设:
//
//  1. 证书链得到 CA —— 否则谁都能自签一张
//  2. **证书的名字要和 Claim.Node 对上** —— 否则 ber01 可以拿自己的
//     私钥签一条"gz02 跑的是 commit X"
//  3. 签名覆盖 canonical 字节
func Verify(s *Signed, caPEM []byte) (*Claim, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("CA 证书读不出来")
	}
	blk, _ := pem.Decode([]byte(s.Cert))
	if blk == nil {
		return nil, fmt.Errorf("陈述里的证书不是 PEM")
	}
	crt, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("解析证书:%w", err)
	}
	if _, err := crt.Verify(x509.VerifyOptions{Roots: pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return nil, fmt.Errorf("证书链不到 CA:%w", err)
	}
	if !nameMatches(crt, s.Node) {
		// **这一条是整个机制的关键。** 没有它,任何一台有合法证书的机器
		// 都能替别人发言 —— 而"替别人发言"正是转述,正是要根治的东西。
		return nil, fmt.Errorf("证书是 %q 的,却在替 %q 发言", certName(crt), s.Node)
	}
	pub, ok := crt.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("证书里不是 ECDSA 公钥")
	}
	sig, err := base64.StdEncoding.DecodeString(s.Sig)
	if err != nil {
		return nil, fmt.Errorf("签名不是 base64:%w", err)
	}
	sum := sha256.Sum256(s.Claim.canonical())
	if !ecdsa.VerifyASN1(pub, sum[:], sig) {
		return nil, fmt.Errorf("签名对不上 —— 内容被改过,或者不是这把钥匙签的")
	}
	c := s.Claim
	return &c, nil
}

// nodeSuffix 是节点证书的命名约定(§13.3):`<节点 id>.node.internal`。
const nodeSuffix = ".node.internal"

func nameMatches(crt *x509.Certificate, node string) bool {
	want := node + nodeSuffix
	if crt.Subject.CommonName == want {
		return true
	}
	for _, d := range crt.DNSNames {
		if d == want {
			return true
		}
	}
	return false
}

func certName(crt *x509.Certificate) string {
	if crt.Subject.CommonName != "" {
		return crt.Subject.CommonName
	}
	if len(crt.DNSNames) > 0 {
		return crt.DNSNames[0]
	}
	return "(无名)"
}

func parseKey(keyPEM []byte) (*ecdsa.PrivateKey, error) {
	// 文件里可能先有一段 EC PARAMETERS,要跳过去找真正的私钥块。
	rest := keyPEM
	for {
		blk, r := pem.Decode(rest)
		if blk == nil {
			return nil, fmt.Errorf("私钥里没有可用的 PEM 块")
		}
		rest = r
		switch blk.Type {
		case "EC PRIVATE KEY":
			return x509.ParseECPrivateKey(blk.Bytes)
		case "PRIVATE KEY":
			k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
			if err != nil {
				return nil, err
			}
			ec, ok := k.(*ecdsa.PrivateKey)
			if !ok {
				return nil, fmt.Errorf("私钥不是 ECDSA")
			}
			return ec, nil
		}
	}
}
