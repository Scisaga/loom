package clientruntime

import (
	"encoding/json"
	"errors"
	"net"
	"sort"

	"loom/internal/agent"
)

// WindowsEntries 从已验证配置的真实 detour 找第一跳；不能从 opaque tag 猜节点（§5.1）。
// 调用方在启动 TUN 前捕获出口网卡，保证 ping 只走本机到入口这一段。
func WindowsEntries(body []byte, cfg *agent.Config) ([]agent.ClientEntry, error) {
	if cfg == nil {
		return nil, nil
	}
	var sb singBoxConfig
	if err := json.Unmarshal(body, &sb); err != nil {
		return nil, err
	}
	byTag := map[string]singBoxOutbound{}
	for _, o := range sb.Outbounds {
		byTag[o.Tag] = o
	}
	byNode := map[string]agent.ClientEntry{}
	for _, d := range cfg.Declarations {
		for _, c := range d.Candidates {
			if len(c.Chain) == 0 {
				continue
			}
			tag := c.Tag
			seen := map[string]bool{}
			var address string
			for {
				o, ok := byTag[tag]
				if !ok || seen[tag] {
					return nil, errors.New("[§5.1] 入口出站缺失或 detour 成环")
				}
				seen[tag] = true
				if o.Type == "hysteria2" || o.Type == "trojan" {
					address = o.Server
				}
				if o.Detour == "" {
					break
				}
				tag = o.Detour
			}
			if address == "" {
				return nil, errors.New("[§5.1] 授权入口缺少连接地址")
			}
			node := c.Chain[0]
			if old, ok := byNode[node]; ok && old.Address != address {
				return nil, errors.New("[§5.1] 同一入口映射到不同地址")
			}
			byNode[node] = agent.ClientEntry{Node: node, Address: address}
		}
	}
	var out []agent.ClientEntry
	for _, e := range byNode {
		e.Source = entrySource(e.Address)
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Node < out[j].Node })
	return out, nil
}

// §5.6：renderer 的 NextHopAddr 只可能取隧道地址或同一节点的公网入口地址。
// 对照实际出站与授权入口即可选择既有度量来源，无需服务端下发另一份拓扑。
func WindowsRoutingInputs(body []byte, cfg *agent.Config) (agent.ClientOptions, error) {
	var out agent.ClientOptions
	entries, err := WindowsEntries(body, cfg)
	if err != nil || cfg == nil {
		return out, err
	}
	out.Entries = entries
	out.HopCarriers = map[string][]string{}
	addresses := map[string]string{}
	for _, e := range entries {
		addresses[e.Node] = e.Address
	}
	var sb singBoxConfig
	if err := json.Unmarshal(body, &sb); err != nil {
		return out, err
	}
	byTag := map[string]singBoxOutbound{}
	for _, o := range sb.Outbounds {
		byTag[o.Tag] = o
	}
	for _, d := range cfg.Declarations {
		for _, c := range d.Candidates {
			var reverse []singBoxOutbound
			for tag := c.Tag; tag != ""; {
				o, ok := byTag[tag]
				if !ok {
					break
				}
				if o.Type == "hysteria2" || o.Type == "trojan" {
					reverse = append(reverse, o)
				}
				tag = o.Detour
			}
			var carriers []string
			for i := 1; i < len(c.Chain); i++ {
				carrier := "unknown"
				if len(reverse) == len(c.Chain) {
					hop := reverse[len(reverse)-1-i]
					if public := addresses[c.Chain[i]]; public != "" {
						if hop.Server != public {
							carrier = "neighbor"
						} else if hop.Type == "hysteria2" {
							carrier = "public-hysteria2"
						}
					} else if ip := net.ParseIP(hop.Server); ip != nil && ip.IsPrivate() {
						// §5.6：反向接入服务器没有可直拨入口；配置里的私有下一跳
						// 仍由该来源的已签名邻接观测匹配，不能要求它先成为入口。
						carrier = "neighbor"
					}
				}
				carriers = append(carriers, carrier)
			}
			out.HopCarriers[c.Tag] = carriers
		}
	}
	return out, nil
}
