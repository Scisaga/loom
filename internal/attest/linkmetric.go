package attest

// Link metrics use a signature domain separate from Claim. They are optional
// point-in-time observations and must not change loom-attest-v5 canonical
// bytes during a rolling upgrade.

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
	LinkMetricClaimVersion = 1

	LinkMetricTransportHysteria2 = "hysteria2"
	LinkMetricScopeSingleHop     = "single_hop"
	LinkMetricCarrierPublic      = "public"

	LinkMetricMaxMetrics                  = 64
	LinkMetricMaxSamples            int64 = 1_000_000
	LinkMetricMaxRTTMS              int64 = 10 * 60 * 1000
	LinkMetricMaxTransferBytes      int64 = 1 << 40
	LinkMetricMaxTransferDurationMS int64 = 24 * 60 * 60 * 1000
	LinkMetricMaxErrorSize                = 512

	linkMetricMaxCertSize  = 32 << 10
	linkMetricMaxSignature = 512
)

// LinkMetric is a node-owned observation of one directed, public Hysteria2
// hop. Direction is always LinkMetricClaim.Node -> PeerNode. These values are
// active single-hop probe results; they are neither WireGuard counters nor an
// end-to-end Agent path measurement.
type LinkMetric struct {
	PeerNode           string `json:"peer_node"`
	Transport          string `json:"transport"`
	Scope              string `json:"scope"`
	Carrier            string `json:"carrier"`
	ObservedAt         string `json:"observed_at"`
	RTTMS              int64  `json:"rtt_ms"`
	P50MS              int64  `json:"p50_ms"`
	P95MS              int64  `json:"p95_ms"`
	Samples            int64  `json:"samples"`
	Failures           int64  `json:"failures"`
	TransferBytes      int64  `json:"transfer_bytes"`
	TransferDurationMS int64  `json:"transfer_duration_ms"`
	Error              string `json:"error,omitempty"`
}

// LinkMetricClaim is a node-owned snapshot of its directed single-hop probes.
// TS is the claim creation time; each metric keeps its own actual observation
// time so a freshly re-signed stale measurement can still be rejected.
type LinkMetricClaim struct {
	Version int          `json:"version"`
	Node    string       `json:"node"`
	TS      string       `json:"ts"`
	Metrics []LinkMetric `json:"metrics,omitempty"`
}

// LinkMetricAttest carries an independently signed LinkMetricClaim. Old
// Observation readers can ignore this optional attachment.
type LinkMetricAttest struct {
	LinkMetricClaim `json:",inline"`
	Cert            string `json:"cert"`
	Sig             string `json:"sig"`
}

func (c *LinkMetricClaim) canonical() []byte {
	metrics := append([]LinkMetric(nil), c.Metrics...)
	sort.Slice(metrics, func(i, j int) bool { return metrics[i].PeerNode < metrics[j].PeerNode })
	var b bytes.Buffer
	field := func(s string) {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(s)))
		b.Write(size[:])
		b.WriteString(s)
	}
	field("loom-linkmetric-v1")
	field(strconv.Itoa(c.Version))
	field(c.Node)
	field(c.TS)
	field(strconv.Itoa(len(metrics)))
	for _, metric := range metrics {
		field(metric.PeerNode)
		field(metric.Transport)
		field(metric.Scope)
		field(metric.Carrier)
		field(metric.ObservedAt)
		field(strconv.FormatInt(metric.RTTMS, 10))
		field(strconv.FormatInt(metric.P50MS, 10))
		field(strconv.FormatInt(metric.P95MS, 10))
		field(strconv.FormatInt(metric.Samples, 10))
		field(strconv.FormatInt(metric.Failures, 10))
		field(strconv.FormatInt(metric.TransferBytes, 10))
		field(strconv.FormatInt(metric.TransferDurationMS, 10))
		field(metric.Error)
	}
	return b.Bytes()
}

func validateLinkMetricClaim(c *LinkMetricClaim) error {
	if c == nil {
		return fmt.Errorf("链路度量陈述为空")
	}
	if c.Version != LinkMetricClaimVersion {
		return fmt.Errorf("不支持 link-metric claim version=%d", c.Version)
	}
	if !validTrafficNodeID(c.Node) {
		return fmt.Errorf("链路度量陈述 node 无效:%q", c.Node)
	}
	if _, err := time.Parse(time.RFC3339, c.TS); err != nil {
		return fmt.Errorf("链路度量陈述时间 %q 无法解析:%w", c.TS, err)
	}
	if len(c.Metrics) > LinkMetricMaxMetrics {
		return fmt.Errorf("链路度量过多:%d（上限 %d）", len(c.Metrics), LinkMetricMaxMetrics)
	}
	seen := make(map[string]bool, len(c.Metrics))
	for i, metric := range c.Metrics {
		if !validTrafficNodeID(metric.PeerNode) || metric.PeerNode == c.Node {
			return fmt.Errorf("链路度量 metric[%d] peer_node 无效:%q", i, metric.PeerNode)
		}
		if seen[metric.PeerNode] {
			return fmt.Errorf("链路度量 metric[%d] peer_node 重复:%q", i, metric.PeerNode)
		}
		seen[metric.PeerNode] = true
		if metric.Transport != LinkMetricTransportHysteria2 {
			return fmt.Errorf("链路度量 metric[%d] transport 必须为 %q", i, LinkMetricTransportHysteria2)
		}
		if metric.Scope != LinkMetricScopeSingleHop {
			return fmt.Errorf("链路度量 metric[%d] scope 必须为 %q", i, LinkMetricScopeSingleHop)
		}
		if metric.Carrier != LinkMetricCarrierPublic {
			return fmt.Errorf("链路度量 metric[%d] carrier 必须为 %q", i, LinkMetricCarrierPublic)
		}
		if _, err := time.Parse(time.RFC3339, metric.ObservedAt); err != nil {
			return fmt.Errorf("链路度量 metric[%d] observed_at %q 无法解析:%w", i, metric.ObservedAt, err)
		}
		if metric.RTTMS < 0 || metric.RTTMS > LinkMetricMaxRTTMS ||
			metric.P50MS < 0 || metric.P50MS > LinkMetricMaxRTTMS ||
			metric.P95MS < 0 || metric.P95MS > LinkMetricMaxRTTMS {
			return fmt.Errorf("链路度量 metric[%d] RTT 超出范围", i)
		}
		if metric.P95MS < metric.P50MS {
			return fmt.Errorf("链路度量 metric[%d] p95_ms 小于 p50_ms", i)
		}
		if metric.Samples <= 0 || metric.Samples > LinkMetricMaxSamples {
			return fmt.Errorf("链路度量 metric[%d] samples 超出范围", i)
		}
		if metric.Failures < 0 || metric.Failures > metric.Samples {
			return fmt.Errorf("链路度量 metric[%d] failures 超出范围", i)
		}
		if metric.TransferBytes < 0 || metric.TransferBytes > LinkMetricMaxTransferBytes {
			return fmt.Errorf("链路度量 metric[%d] transfer_bytes 超出范围", i)
		}
		if metric.TransferDurationMS < 0 || metric.TransferDurationMS > LinkMetricMaxTransferDurationMS {
			return fmt.Errorf("链路度量 metric[%d] transfer_duration_ms 超出范围", i)
		}
		if (metric.TransferBytes == 0) != (metric.TransferDurationMS == 0) {
			return fmt.Errorf("链路度量 metric[%d] transfer bytes/duration 必须同时存在", i)
		}
		if metric.Failures == metric.Samples {
			if metric.RTTMS != 0 || metric.P50MS != 0 || metric.P95MS != 0 ||
				metric.TransferBytes != 0 || metric.TransferDurationMS != 0 {
				return fmt.Errorf("链路度量 metric[%d] 全部失败却携带成功数值", i)
			}
			if metric.Error == "" {
				return fmt.Errorf("链路度量 metric[%d] 全部失败但没有 error", i)
			}
		}
		if metric.Error != "" {
			if strings.TrimSpace(metric.Error) != metric.Error ||
				!utf8.ValidString(metric.Error) || len(metric.Error) > LinkMetricMaxErrorSize {
				return fmt.Errorf("链路度量 metric[%d] error 编码或长度无效", i)
			}
			for _, r := range metric.Error {
				if unicode.IsControl(r) {
					return fmt.Errorf("链路度量 metric[%d] error 含控制字符", i)
				}
			}
		}
	}
	return nil
}

// SignLinkMetric signs only in the loom-linkmetric-v1 domain.
func SignLinkMetric(c LinkMetricClaim, keyPEM, certPEM []byte) (*LinkMetricAttest, error) {
	if err := validateLinkMetricClaim(&c); err != nil {
		return nil, err
	}
	if len(certPEM) == 0 || len(certPEM) > linkMetricMaxCertSize {
		return nil, fmt.Errorf("链路度量陈述证书长度无效")
	}
	key, err := parseKey(keyPEM)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(c.canonical())
	sig, err := ecdsa.SignASN1(rand.Reader, key, sum[:])
	if err != nil {
		return nil, fmt.Errorf("签名链路度量陈述:%w", err)
	}
	return &LinkMetricAttest{
		LinkMetricClaim: c,
		Cert:            string(certPEM),
		Sig:             base64.StdEncoding.EncodeToString(sig),
	}, nil
}

// VerifyLinkMetric verifies structure, CA chain, node certificate name and the
// independent signature. It does not assert freshness.
func VerifyLinkMetric(s *LinkMetricAttest, caPEM []byte) (*LinkMetricClaim, error) {
	if s == nil {
		return nil, fmt.Errorf("链路度量签名陈述为空")
	}
	if err := validateLinkMetricClaim(&s.LinkMetricClaim); err != nil {
		return nil, err
	}
	if len(s.Cert) == 0 || len(s.Cert) > linkMetricMaxCertSize {
		return nil, fmt.Errorf("链路度量陈述证书长度无效")
	}
	if len(s.Sig) == 0 || len(s.Sig) > linkMetricMaxSignature {
		return nil, fmt.Errorf("链路度量签名长度无效")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("CA 证书读不出来")
	}
	blk, rest := pem.Decode([]byte(s.Cert))
	if blk == nil || blk.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("链路度量陈述里的证书不是单个 PEM certificate")
	}
	crt, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("解析链路度量陈述证书:%w", err)
	}
	if _, err := crt.Verify(x509.VerifyOptions{Roots: pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return nil, fmt.Errorf("链路度量陈述证书链不到 CA:%w", err)
	}
	if !nameMatches(crt, s.Node) {
		return nil, fmt.Errorf("证书是 %q 的,却在替 %q 签链路度量", certName(crt), s.Node)
	}
	pub, ok := crt.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("链路度量陈述证书里不是 ECDSA 公钥")
	}
	sig, err := base64.StdEncoding.DecodeString(s.Sig)
	if err != nil {
		return nil, fmt.Errorf("链路度量签名不是 base64:%w", err)
	}
	if len(sig) == 0 || len(sig) > linkMetricMaxSignature {
		return nil, fmt.Errorf("链路度量签名 DER 长度无效")
	}
	sum := sha256.Sum256(s.LinkMetricClaim.canonical())
	if !ecdsa.VerifyASN1(pub, sum[:], sig) {
		return nil, fmt.Errorf("链路度量签名对不上 —— metric 被改过,或者不是这把钥匙签的")
	}
	c := s.LinkMetricClaim
	c.Metrics = append([]LinkMetric(nil), s.Metrics...)
	sort.Slice(c.Metrics, func(i, j int) bool { return c.Metrics[i].PeerNode < c.Metrics[j].PeerNode })
	return &c, nil
}

// VerifyLinkMetricFresh rejects both replayed claims and stale measurements
// copied into a newly signed claim.
func VerifyLinkMetricFresh(s *LinkMetricAttest, caPEM []byte, now time.Time,
	maxAge time.Duration) (*LinkMetricClaim, error) {
	c, err := VerifyLinkMetric(s, caPEM)
	if err != nil {
		return nil, err
	}
	if maxAge <= 0 {
		return nil, fmt.Errorf("链路度量陈述新鲜度上限必须为正")
	}
	checkFresh := func(label, raw string) error {
		ts, _ := time.Parse(time.RFC3339, raw)
		age := now.UTC().Sub(ts.UTC())
		if age < -2*time.Minute {
			return fmt.Errorf("%s时间在未来 %s", label, (-age).Round(time.Second))
		}
		if age > maxAge {
			return fmt.Errorf("%s已过期(%s,上限 %s)", label, age.Round(time.Second), maxAge)
		}
		return nil
	}
	if err := checkFresh("链路度量陈述", c.TS); err != nil {
		return nil, err
	}
	for i, metric := range c.Metrics {
		if err := checkFresh(fmt.Sprintf("链路度量 metric[%d]", i), metric.ObservedAt); err != nil {
			return nil, err
		}
	}
	return c, nil
}
