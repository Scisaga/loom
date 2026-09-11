package rotation

import "errors"

// WireGuardGeneration 单独描述 interface/peer/route ownership；不能用修改同一
// interface listen port 冒充无中断轮换（D120 §14.4）。
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
	for _, generation := range []WireGuardGeneration{o.Old, o.New} {
		if generation.Generation < 1 || generation.InterfaceName == "" || len(generation.InterfaceName) > 15 || generation.ListenTuple.Transport != "udp" || generation.PrivateKeyRef == "" || generation.PeerPublicKey == "" || generation.TunnelAddress == "" || generation.RouteTable < 1 || generation.FwMark < 1 || len(generation.AllowedIPs) == 0 || !oneOf(generation.State, "prepared", "active", "draining") {
			return errors.New("[D120 WG] generation 字段无效")
		}
	}
	if o.Old.Generation >= o.New.Generation || o.Old.InterfaceName == o.New.InterfaceName || o.Old.ListenTuple == o.New.ListenTuple || o.Old.PrivateKeyRef == o.New.PrivateKeyRef || o.Old.TunnelAddress == o.New.TunnelAddress || o.Old.RouteTable == o.New.RouteTable || o.Old.FwMark == o.New.FwMark {
		return errors.New("[D120 WG] old/new 必须拥有独立 interface/key/address/tuple/route/fwmark")
	}
	return ValidateTupleOwnership([]Tuple{o.Old.ListenTuple, o.New.ListenTuple})
}
