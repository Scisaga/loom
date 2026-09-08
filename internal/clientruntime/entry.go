package clientruntime

import (
	"encoding/json"
	"errors"
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
