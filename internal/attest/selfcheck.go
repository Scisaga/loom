package attest

// This file defines a signature domain separate from Claim. A self-check is
// optional during a rolling upgrade and changes every observation round;
// adding it to loom-attest-v5 would change v5's canonical bytes and break
// verification between old and new nodes.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	SelfCheckClaimVersion   = 1
	SelfCheckMaxProblems    = 64
	SelfCheckMaxProblemSize = 512
	SelfCheckMaxTotalSize   = 16 << 10
	selfCheckMaxCertSize    = 32 << 10
	selfCheckMaxSignature   = 512
)

// SelfCheckClaim is a node-owned verdict derived from that node's complete
// local Status. Problems is deliberately compact: detailed counters and
// component state continue to use their existing observation fields.
//
// Healthy is explicit rather than inferred by a reader. Validation enforces
// Healthy == (len(Problems) == 0), so neither a relay nor a buggy producer can
// present a green verdict alongside hidden failures.
type SelfCheckClaim struct {
	Version  int      `json:"version"`
	Node     string   `json:"node"`
	TS       string   `json:"ts"`
	Healthy  bool     `json:"healthy"`
	Problems []string `json:"problems,omitempty"`
}

// SelfCheckAttest carries a self-check and proof made with the existing node
// TLS identity. Old Observation readers ignore this optional attachment.
type SelfCheckAttest struct {
	SelfCheckClaim `json:",inline"`
	Cert           string `json:"cert"`
	Sig            string `json:"sig"`
}

func (c *SelfCheckClaim) canonical() []byte {
	problems := append([]string(nil), c.Problems...)
	// validateSelfCheckClaim requires this exact ordering. Sorting a copy here
	// keeps canonical construction defensive without mutating caller memory.
	sort.Strings(problems)
	var b bytes.Buffer
	field := func(s string) {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(s)))
		b.Write(size[:])
		b.WriteString(s)
	}
	field("loom-selfcheck-v1")
	field(strconv.Itoa(c.Version))
	field(c.Node)
	field(c.TS)
	field(strconv.FormatBool(c.Healthy))
	field(strconv.Itoa(len(problems)))
	for _, problem := range problems {
		field(problem)
	}
	return b.Bytes()
}

func validateSelfCheckClaim(c *SelfCheckClaim) error {
	if c == nil {
		return fmt.Errorf("自检陈述为空")
	}
	if c.Version != SelfCheckClaimVersion {
		return fmt.Errorf("不支持 self-check claim version=%d", c.Version)
	}
	if !validTrafficNodeID(c.Node) {
		return fmt.Errorf("自检陈述 node 无效:%q", c.Node)
	}
	if _, err := time.Parse(time.RFC3339, c.TS); err != nil {
		return fmt.Errorf("自检陈述时间 %q 无法解析:%w", c.TS, err)
	}
	if len(c.Problems) > SelfCheckMaxProblems {
		return fmt.Errorf("自检陈述 problems 过多:%d（上限 %d）", len(c.Problems), SelfCheckMaxProblems)
	}
	if c.Healthy != (len(c.Problems) == 0) {
		return fmt.Errorf("自检陈述 healthy=%t 与 problems 数量 %d 不一致", c.Healthy, len(c.Problems))
	}
	total := 0
	previous := ""
	for i, problem := range c.Problems {
		if problem == "" || strings.TrimSpace(problem) != problem {
			return fmt.Errorf("自检陈述 problem[%d] 为空或首尾含空白", i)
		}
		if !utf8.ValidString(problem) || len(problem) > SelfCheckMaxProblemSize {
			return fmt.Errorf("自检陈述 problem[%d] 编码或长度无效", i)
		}
		for _, r := range problem {
			if unicode.IsControl(r) {
				return fmt.Errorf("自检陈述 problem[%d] 含控制字符", i)
			}
		}
		if i > 0 && previous >= problem {
			return fmt.Errorf("自检陈述 problems 必须严格排序且不能重复")
		}
		previous = problem
		total += len(problem)
		if total > SelfCheckMaxTotalSize {
			return fmt.Errorf("自检陈述 problems 总长度超过 %d", SelfCheckMaxTotalSize)
		}
	}
	return nil
}

// SignSelfCheck signs only in the loom-selfcheck-v1 domain. It never calls
// Sign and therefore cannot change loom-attest-v1..v5 canonical bytes.
func SignSelfCheck(c SelfCheckClaim, keyPEM, certPEM []byte) (*SelfCheckAttest, error) {
	if err := validateSelfCheckClaim(&c); err != nil {
		return nil, err
	}
	if len(certPEM) == 0 || len(certPEM) > selfCheckMaxCertSize {
		return nil, fmt.Errorf("自检陈述证书长度无效")
	}
	key, err := parseKey(keyPEM)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(c.canonical())
	sig, err := ecdsa.SignASN1(rand.Reader, key, sum[:])
	if err != nil {
		return nil, fmt.Errorf("签名自检陈述:%w", err)
	}
	return &SelfCheckAttest{
		SelfCheckClaim: c,
		Cert:           string(certPEM),
		Sig:            base64.StdEncoding.EncodeToString(sig),
	}, nil
}

// VerifySelfCheck verifies structure, CA chain, node certificate name and the
// independent signature. It does not assert freshness.
func VerifySelfCheck(s *SelfCheckAttest, caPEM []byte) (*SelfCheckClaim, error) {
	if s == nil {
		return nil, fmt.Errorf("自检签名陈述为空")
	}
	if err := validateSelfCheckClaim(&s.SelfCheckClaim); err != nil {
		return nil, err
	}
	if len(s.Cert) == 0 || len(s.Cert) > selfCheckMaxCertSize {
		return nil, fmt.Errorf("自检陈述证书长度无效")
	}
	if len(s.Sig) == 0 || len(s.Sig) > selfCheckMaxSignature {
		return nil, fmt.Errorf("自检签名长度无效")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("CA 证书读不出来")
	}
	blk, rest := pem.Decode([]byte(s.Cert))
	if blk == nil || blk.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("自检陈述里的证书不是单个 PEM certificate")
	}
	crt, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("解析自检陈述证书:%w", err)
	}
	if _, err := crt.Verify(x509.VerifyOptions{Roots: pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return nil, fmt.Errorf("自检陈述证书链不到 CA:%w", err)
	}
	if !nameMatches(crt, s.Node) {
		return nil, fmt.Errorf("证书是 %q 的,却在替 %q 签自检", certName(crt), s.Node)
	}
	pub, ok := crt.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("自检陈述证书里不是 ECDSA 公钥")
	}
	sig, err := base64.StdEncoding.DecodeString(s.Sig)
	if err != nil {
		return nil, fmt.Errorf("自检签名不是 base64:%w", err)
	}
	if len(sig) == 0 || len(sig) > selfCheckMaxSignature {
		return nil, fmt.Errorf("自检签名 DER 长度无效")
	}
	sum := sha256.Sum256(s.SelfCheckClaim.canonical())
	if !ecdsa.VerifyASN1(pub, sum[:], sig) {
		return nil, fmt.Errorf("自检签名对不上 —— verdict 被改过,或者不是这把钥匙签的")
	}
	c := s.SelfCheckClaim
	c.Problems = append([]string(nil), s.Problems...)
	return &c, nil
}

// VerifySelfCheckFresh additionally prevents a previously green verdict from
// being replayed forever.
func VerifySelfCheckFresh(s *SelfCheckAttest, caPEM []byte, now time.Time,
	maxAge time.Duration) (*SelfCheckClaim, error) {
	c, err := VerifySelfCheck(s, caPEM)
	if err != nil {
		return nil, err
	}
	if maxAge <= 0 {
		return nil, fmt.Errorf("自检陈述新鲜度上限必须为正")
	}
	ts, _ := time.Parse(time.RFC3339, c.TS)
	age := now.UTC().Sub(ts.UTC())
	if age < -2*time.Minute {
		return nil, fmt.Errorf("自检陈述时间在未来 %s", (-age).Round(time.Second))
	}
	if age > maxAge {
		return nil, fmt.Errorf("自检陈述已过期(%s,上限 %s)", age.Round(time.Second), maxAge)
	}
	return c, nil
}
