package attest

// This file deliberately defines a signature domain separate from Claim.
// Traffic counters change every sampling round and are optional during a
// rolling upgrade; adding them to loom-attest-v5 would change v5's canonical
// bytes and make old and new nodes unable to verify each other.

import (
	"bytes"
	"cmp"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

const TrafficClaimVersion = 1

// TrafficCounter is one node's current WireGuard peer counter. PeerNode and
// LinkID are the stable aggregation identity. PeerPublicKey is diagnostic only:
// key rotation must not create a new logical link in the UI or history store.
//
// CounterEpoch identifies the reset boundary. It is derived from the host boot
// ID, Linux interface index, and peer-key fingerprint. Counters are monotonic
// only while this value is unchanged; a lower value within the same epoch must
// also be treated as a reset rather than as negative traffic.
type TrafficCounter struct {
	Interface     string `json:"interface"`
	PeerNode      string `json:"peer_node"`
	LinkID        string `json:"link_id"`
	PeerPublicKey string `json:"peer_public_key,omitempty"`
	CounterEpoch  string `json:"counter_epoch"`
	RXBytes       int64  `json:"rx_bytes"`
	TXBytes       int64  `json:"tx_bytes"`
}

// TrafficClaim is a node-owned, point-in-time counter snapshot. TS is the
// sampling time (and is bound to the containing report Observation by report).
// It is intentionally not part of Claim or MeasurementsSHA256.
type TrafficClaim struct {
	Version  int              `json:"version"`
	Node     string           `json:"node"`
	TS       string           `json:"ts"`
	Counters []TrafficCounter `json:"counters,omitempty"`
}

// TrafficAttest carries a TrafficClaim and proof made with the existing node
// TLS identity. Old JSON readers ignore the entire optional Observation field;
// new readers must call VerifyTrafficFresh before using a counter.
type TrafficAttest struct {
	TrafficClaim `json:",inline"`
	Cert         string `json:"cert"`
	Sig          string `json:"sig"`
}

// CanonicalTrafficLinkID returns the stable, direction-independent link key.
// Node IDs cannot contain '/', so this representation is unambiguous. RX/TX
// direction remains relative to TrafficClaim.Node and is not normalized.
func CanonicalTrafficLinkID(a, b string) string {
	if a > b {
		a, b = b, a
	}
	return a + "/" + b
}

func (c *TrafficClaim) canonical() []byte {
	counters := append([]TrafficCounter(nil), c.Counters...)
	sort.Slice(counters, func(i, j int) bool {
		a, b := counters[i], counters[j]
		return slices.Compare([]string{
			a.Interface, a.PeerNode, a.LinkID, a.PeerPublicKey, a.CounterEpoch,
			strconv.FormatInt(a.RXBytes, 10), strconv.FormatInt(a.TXBytes, 10),
		}, []string{
			b.Interface, b.PeerNode, b.LinkID, b.PeerPublicKey, b.CounterEpoch,
			strconv.FormatInt(b.RXBytes, 10), strconv.FormatInt(b.TXBytes, 10),
		}) < 0
	})
	var b bytes.Buffer
	field := func(s string) {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(s)))
		b.Write(size[:])
		b.WriteString(s)
	}
	field("loom-traffic-v1")
	field(strconv.Itoa(c.Version))
	field(c.Node)
	field(c.TS)
	field(strconv.Itoa(len(counters)))
	for _, counter := range counters {
		field(counter.Interface)
		field(counter.PeerNode)
		field(counter.LinkID)
		field(counter.PeerPublicKey)
		field(counter.CounterEpoch)
		field(strconv.FormatInt(counter.RXBytes, 10))
		field(strconv.FormatInt(counter.TXBytes, 10))
	}
	return b.Bytes()
}

func validateTrafficClaim(c *TrafficClaim) error {
	if c == nil {
		return fmt.Errorf("流量陈述为空")
	}
	if c.Version != TrafficClaimVersion {
		return fmt.Errorf("不支持 traffic claim version=%d", c.Version)
	}
	if !validTrafficNodeID(c.Node) {
		return fmt.Errorf("流量陈述 node 无效:%q", c.Node)
	}
	if _, err := time.Parse(time.RFC3339, c.TS); err != nil {
		return fmt.Errorf("流量陈述时间 %q 无法解析:%w", c.TS, err)
	}
	seen := make(map[string]bool, len(c.Counters))
	for i, counter := range c.Counters {
		if !validTrafficNodeID(counter.PeerNode) || counter.PeerNode == c.Node {
			return fmt.Errorf("流量 counter[%d] peer_node 无效:%q", i, counter.PeerNode)
		}
		if counter.Interface != "wg-"+counter.PeerNode || len(counter.Interface) > 15 {
			return fmt.Errorf("流量 counter[%d] interface %q 与 peer %q 不一致",
				i, counter.Interface, counter.PeerNode)
		}
		if want := CanonicalTrafficLinkID(c.Node, counter.PeerNode); counter.LinkID != want {
			return fmt.Errorf("流量 counter[%d] link_id=%q，期望 %q", i, counter.LinkID, want)
		}
		if counter.PeerPublicKey == "" || len(counter.PeerPublicKey) > 128 ||
			strings.ContainsAny(counter.PeerPublicKey, "\r\n\t") {
			return fmt.Errorf("流量 counter[%d] peer public key 无效", i)
		}
		if counter.CounterEpoch == "" || len(counter.CounterEpoch) > 160 ||
			strings.ContainsAny(counter.CounterEpoch, "\r\n\t") {
			return fmt.Errorf("流量 counter[%d] counter_epoch 无效", i)
		}
		if counter.RXBytes < 0 || counter.TXBytes < 0 {
			return fmt.Errorf("流量 counter[%d] 出现负数", i)
		}
		// Loom's carrier invariant is one interface per peer. Accepting two
		// public keys on one managed interface would make a consumer either
		// overwrite one counter or double count during rotation.
		key := counter.Interface
		if seen[key] {
			return fmt.Errorf("流量 counter[%d] 重复 managed interface %q", i, counter.Interface)
		}
		seen[key] = true
	}
	return nil
}

func validTrafficNodeID(id string) bool {
	if len(id) == 0 || len(id) > 63 {
		return false
	}
	for i := 0; i < len(id); i++ {
		ch := id[i]
		if (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') {
			continue
		}
		if ch != '-' || i == 0 || i == len(id)-1 {
			return false
		}
	}
	return true
}

// SignTraffic signs in the loom-traffic-v1 domain. It does not call Sign and
// cannot change the canonical bytes of loom-attest-v1..v5.
func SignTraffic(c TrafficClaim, keyPEM, certPEM []byte) (*TrafficAttest, error) {
	if err := validateTrafficClaim(&c); err != nil {
		return nil, err
	}
	key, err := parseKey(keyPEM)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(c.canonical())
	sig, err := ecdsa.SignASN1(rand.Reader, key, sum[:])
	if err != nil {
		return nil, fmt.Errorf("签名流量陈述:%w", err)
	}
	return &TrafficAttest{
		TrafficClaim: c,
		Cert:         string(certPEM),
		Sig:          base64.StdEncoding.EncodeToString(sig),
	}, nil
}

// VerifyTraffic verifies the CA chain, node certificate name, traffic-domain
// signature, and structural link identities. It does not assert freshness.
func VerifyTraffic(s *TrafficAttest, caPEM []byte) (*TrafficClaim, error) {
	if s == nil {
		return nil, fmt.Errorf("流量签名陈述为空")
	}
	if err := validateTrafficClaim(&s.TrafficClaim); err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("CA 证书读不出来")
	}
	blk, _ := pem.Decode([]byte(s.Cert))
	if blk == nil {
		return nil, fmt.Errorf("流量陈述里的证书不是 PEM")
	}
	crt, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("解析流量陈述证书:%w", err)
	}
	if _, err := crt.Verify(x509.VerifyOptions{Roots: pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return nil, fmt.Errorf("流量陈述证书链不到 CA:%w", err)
	}
	if !nameMatches(crt, s.Node) {
		return nil, fmt.Errorf("证书是 %q 的,却在替 %q 签流量", certName(crt), s.Node)
	}
	pub, ok := crt.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("流量陈述证书里不是 ECDSA 公钥")
	}
	sig, err := base64.StdEncoding.DecodeString(s.Sig)
	if err != nil {
		return nil, fmt.Errorf("流量签名不是 base64:%w", err)
	}
	sum := sha256.Sum256(s.TrafficClaim.canonical())
	if !ecdsa.VerifyASN1(pub, sum[:], sig) {
		return nil, fmt.Errorf("流量签名对不上 —— counter 被改过,或者不是这把钥匙签的")
	}
	c := s.TrafficClaim
	c.Counters = append([]TrafficCounter(nil), s.Counters...)
	sort.Slice(c.Counters, func(i, j int) bool {
		a, b := c.Counters[i], c.Counters[j]
		if n := cmp.Compare(a.Interface, b.Interface); n != 0 {
			return n < 0
		}
		return a.PeerPublicKey < b.PeerPublicKey
	})
	return &c, nil
}

// VerifyTrafficFresh additionally prevents an old cumulative snapshot from
// being replayed forever. Reset handling still uses CounterEpoch, not TS.
func VerifyTrafficFresh(s *TrafficAttest, caPEM []byte, now time.Time,
	maxAge time.Duration) (*TrafficClaim, error) {
	c, err := VerifyTraffic(s, caPEM)
	if err != nil {
		return nil, err
	}
	if maxAge <= 0 {
		return nil, fmt.Errorf("流量陈述新鲜度上限必须为正")
	}
	ts, _ := time.Parse(time.RFC3339, c.TS) // validateTrafficClaim already checked it
	age := now.UTC().Sub(ts.UTC())
	if age < -2*time.Minute {
		return nil, fmt.Errorf("流量陈述时间在未来 %s", (-age).Round(time.Second))
	}
	if age > maxAge {
		return nil, fmt.Errorf("流量陈述已过期(%s,上限 %s)", age.Round(time.Second), maxAge)
	}
	return c, nil
}
