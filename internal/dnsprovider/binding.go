package dnsprovider

import (
	"errors"
	"net/netip"
	"strings"

	"loom/internal/wire"
)

const BindingOperationKind = "set_dns_binding"

// BindingV1 是节点与稳定域名、地址的期望绑定。端口和 NAT 映射不属于 DNS
// 记录，也不作为 DNS 更新的前置条件。
type BindingV1 struct {
	Schema              int      `json:"schema"`
	ClusterID           string   `json:"cluster_id"`
	ServerID            string   `json:"server_id"`
	Generation          int64    `json:"generation"`
	PreviousBindingHash string   `json:"previous_binding_hash"`
	Zone                string   `json:"zone"`
	Name                string   `json:"name"`
	Addresses           []string `json:"addresses"`
	TTL                 int64    `json:"ttl"`
}

func BindingHash(binding BindingV1) (string, error) {
	if _, err := binding.RRSets(); err != nil {
		return "", err
	}
	return wire.HashObject("loom-server-dns-binding-v1", binding)
}

func (binding BindingV1) RRSets() ([]RRSet, error) {
	if binding.Schema != 1 || !validAuditID(binding.ClusterID) || !validAuditID(binding.ServerID) ||
		binding.Generation < 1 || binding.Zone != canonicalDNSName(binding.Zone) || !strings.Contains(binding.Zone, ".") ||
		binding.Name != canonicalDNSName(binding.Name) || binding.Name == "" ||
		len(binding.Name)+1+len(binding.Zone) > 253 || binding.TTL < 60 || binding.TTL > 86400 ||
		len(binding.Addresses) == 0 || len(binding.Addresses) > 32 {
		return nil, errors.New("[DNS] 节点域名绑定字段无效")
	}
	if _, err := wire.ParseHash(binding.PreviousBindingHash); err != nil ||
		(binding.Generation == 1) != (binding.PreviousBindingHash == wire.EmptyHashV1) {
		return nil, errors.New("[DNS] 节点域名绑定代次/前驱无效")
	}
	v4, v6 := []string{}, []string{}
	for index, raw := range binding.Addresses {
		address, err := netip.ParseAddr(raw)
		if err != nil || address.String() != raw || !address.IsGlobalUnicast() || address.IsPrivate() || address.Is4In6() ||
			(index > 0 && binding.Addresses[index-1] >= raw) {
			return nil, errors.New("[DNS] 地址须为排序且唯一的公网 IP")
		}
		if address.Is4() {
			v4 = append(v4, raw)
		} else {
			v6 = append(v6, raw)
		}
	}
	sets := []RRSet{}
	for _, family := range []struct {
		kind   string
		values []string
	}{{"A", v4}, {"AAAA", v6}} {
		if len(family.values) != 0 {
			set, err := Normalize(RRSet{Zone: binding.Zone, Name: binding.Name, Type: family.kind, TTL: binding.TTL, Values: family.values})
			if err != nil {
				return nil, err
			}
			sets = append(sets, set)
		}
	}
	return sets, nil
}
