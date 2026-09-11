// Package dnsprovider 定义托管 DNS 的 provider-neutral 收敛边界。
// Provider 只执行已认证调用方给出的 exact RRSet；它不读取 current、也不决定
// EndpointSet 或 ControlSet，避免 DNS 反向成为 authority（D103、D108、D125）。
package dnsprovider

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"
)

var ErrNotFound = errors.New("[D125 DNS] RRSet 不存在")

type RRSet struct {
	Zone   string   `json:"zone"`
	Name   string   `json:"name"`
	Type   string   `json:"type"`
	TTL    int64    `json:"ttl"`
	Values []string `json:"values"`
}

type Readback struct {
	RRSet      RRSet     `json:"rrset"`
	ObservedAt time.Time `json:"observed_at"`
}

type Provider interface {
	Read(ctx context.Context, zone, name, rrType string) (Readback, error)
	Replace(ctx context.Context, desired RRSet) (Readback, error)
	Delete(ctx context.Context, zone, name, rrType string) error
}

func Normalize(in RRSet) (RRSet, error) {
	in.Zone = canonicalDNSName(in.Zone)
	in.Name = canonicalRecordName(in.Name)
	in.Type = strings.ToUpper(strings.TrimSpace(in.Type))
	if in.Zone == "" || in.Name == "" {
		return RRSet{}, errors.New("[D125 DNS] zone/name 不能为空或包含非法 DNS label")
	}
	if in.TTL < 60 || in.TTL > 86400 {
		return RRSet{}, errors.New("[D125 DNS] TTL 必须位于 60..86400 秒")
	}
	if !oneOf(in.Type, "A", "AAAA", "CNAME", "TXT") {
		return RRSet{}, fmt.Errorf("[D125 DNS] 不支持 RR type %q", in.Type)
	}
	if len(in.Values) == 0 || len(in.Values) > 32 {
		return RRSet{}, errors.New("[D125 DNS] RRSet values 数量必须位于 1..32")
	}
	values := append([]string(nil), in.Values...)
	for i := range values {
		values[i] = strings.TrimSpace(values[i])
		if values[i] == "" || strings.ContainsAny(values[i], "\r\n") {
			return RRSet{}, errors.New("[D125 DNS] RR value 为空或含换行")
		}
		switch in.Type {
		case "A", "AAAA":
			address, err := netip.ParseAddr(values[i])
			if err != nil || address.String() != values[i] || in.Type == "A" && !address.Is4() || in.Type == "AAAA" && !address.Is6() {
				return RRSet{}, errors.New("[D125 DNS] A/AAAA value 必须是对应地址族的规范 IP")
			}
		case "CNAME":
			values[i] = canonicalDNSName(values[i])
			if values[i] == "" {
				return RRSet{}, errors.New("[D125 DNS] CNAME value 必须是规范 FQDN")
			}
		case "TXT":
			if len(values[i]) > 1024 {
				return RRSet{}, errors.New("[D125 DNS] TXT value 超过 1024 bytes 边界")
			}
		}
	}
	if in.Type == "CNAME" && len(values) != 1 {
		return RRSet{}, errors.New("[D125 DNS] CNAME RRSet 必须恰有一个 value")
	}
	sort.Strings(values)
	for i := 1; i < len(values); i++ {
		if values[i] == values[i-1] {
			return RRSet{}, errors.New("[D125 DNS] RR values 必须唯一")
		}
	}
	in.Values = values
	return in, nil
}

func Equal(a, b RRSet) bool {
	na, errA := Normalize(a)
	nb, errB := Normalize(b)
	if errA != nil || errB != nil || na.Zone != nb.Zone || na.Name != nb.Name || na.Type != nb.Type || na.TTL != nb.TTL || len(na.Values) != len(nb.Values) {
		return false
	}
	for i := range na.Values {
		if na.Values[i] != nb.Values[i] {
			return false
		}
	}
	return true
}

func canonicalDNSName(value string) string {
	value = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
	if len(value) == 0 || len(value) > 253 {
		return ""
	}
	for _, label := range strings.Split(value, ".") {
		if !validDNSLabel(label) {
			return ""
		}
	}
	return value
}

func canonicalRecordName(value string) string {
	value = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
	if value == "@" {
		return value
	}
	if value == "_acme-challenge" {
		return value
	}
	if strings.HasPrefix(value, "_acme-challenge.") {
		value = strings.TrimPrefix(value, "_acme-challenge.")
		if canonicalDNSName(value) == "" {
			return ""
		}
		return "_acme-challenge." + value
	}
	return canonicalDNSName(value)
}

func validDNSLabel(label string) bool {
	if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for _, r := range label {
		if !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') && r != '-' {
			return false
		}
	}
	return true
}

func oneOf(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}
