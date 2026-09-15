package rotation

import (
	"encoding/base64"
	"errors"
	"net/netip"
	"sort"

	"loom/internal/wire"
)

// WireGuardGeneration 单独描述 interface/peer/route ownership；不能用修改同一
// interface listen port 冒充无中断轮换。
type WireGuardGeneration struct {
	Generation    int64    `json:"generation"`
	InterfaceName string   `json:"interface_name"`
	ListenTuple   Tuple    `json:"listen_tuple"`
	PrivateKeyRef string   `json:"private_key_ref"`
	PeerPublicKey string   `json:"peer_public_key"`
	TunnelAddress string   `json:"tunnel_address"`
	RouteTable    int64    `json:"route_table"`
	FwMark        int64    `json:"fwmark"`
	AllowedIPs    []string `json:"allowed_ips"`
	State         string   `json:"state"`
}

type WireGuardOverlap struct {
	Old WireGuardGeneration `json:"old"`
	New WireGuardGeneration `json:"new"`
}

func (o WireGuardOverlap) Validate() error {
	if err := validateWireGuardGeneration(o.Old); err != nil {
		return err
	}
	if err := validateWireGuardGeneration(o.New); err != nil {
		return err
	}
	if !oneOf(o.Old.State, "active", "draining") || !oneOf(o.New.State, "prepared", "active") {
		return errors.New("[WG] overlap phase 必须是 old active/draining + new prepared/active")
	}
	if o.Old.Generation >= o.New.Generation || o.Old.InterfaceName == o.New.InterfaceName || o.Old.ListenTuple == o.New.ListenTuple ||
		o.Old.PrivateKeyRef == o.New.PrivateKeyRef || o.Old.PeerPublicKey == o.New.PeerPublicKey ||
		o.Old.TunnelAddress == o.New.TunnelAddress || o.Old.RouteTable == o.New.RouteTable || o.Old.FwMark == o.New.FwMark {
		return errors.New("[WG] old/new 必须拥有独立 interface/key/address/tuple/route/fwmark")
	}
	if !equalStrings(o.Old.AllowedIPs, o.New.AllowedIPs) {
		return errors.New("[WG] old/new 必须保持 exact route scope，禁止轮换夹带扩权")
	}
	return ValidateTupleOwnership([]Tuple{o.Old.ListenTuple, o.New.ListenTuple})
}

func validateWireGuardGeneration(generation WireGuardGeneration) error {
	if generation.Generation < 1 || !validInterfaceName(generation.InterfaceName) || generation.ListenTuple.Transport != "udp" ||
		generation.RouteTable < 1 || generation.FwMark < 1 || len(generation.AllowedIPs) == 0 ||
		!oneOf(generation.State, "prepared", "active", "draining") {
		return errors.New("[WG] generation 字段无效")
	}
	if _, err := wire.ParseHash(generation.PrivateKeyRef); err != nil {
		return errors.New("[WG] private key ref 必须是 content-addressed secret artifact")
	}
	peerKey, err := base64.StdEncoding.DecodeString(generation.PeerPublicKey)
	if err != nil || len(peerKey) != 32 || base64.StdEncoding.EncodeToString(peerKey) != generation.PeerPublicKey {
		return errors.New("[WG] peer public key 必须是 canonical WireGuard key")
	}
	bindAddress, err := netip.ParseAddr(generation.ListenTuple.Address)
	if err != nil || bindAddress.String() != generation.ListenTuple.Address || generation.ListenTuple.Port < 1 || generation.ListenTuple.Port > 65535 {
		return errors.New("[WG] listen tuple 必须是规范 IP/UDP port")
	}
	tunnel, err := netip.ParsePrefix(generation.TunnelAddress)
	if err != nil || tunnel.String() != generation.TunnelAddress || !tunnel.Addr().IsPrivate() || tunnel.Bits() != tunnel.Addr().BitLen() {
		return errors.New("[WG] tunnel address 必须是规范私有 /32 或 /128")
	}
	if !sort.StringsAreSorted(generation.AllowedIPs) {
		return errors.New("[WG] AllowedIPs 必须严格排序")
	}
	for index, raw := range generation.AllowedIPs {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil || prefix.String() != raw || index > 0 && generation.AllowedIPs[index-1] == raw {
			return errors.New("[WG] AllowedIPs 必须是规范且唯一的 prefix")
		}
	}
	return nil
}

func validInterfaceName(value string) bool {
	if value == "" || len(value) > 15 {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') && character != '_' && character != '-' && character != '.' {
			return false
		}
	}
	return true
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
