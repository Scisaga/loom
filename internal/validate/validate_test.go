package validate

import (
	"fmt"
	"strings"
	"testing"

	"loom/internal/model"
)

// 反例测试。每条对应 design.md 中一条具体规则 —— 校验器的价值全在于
// 这些输入会被拒绝,而不是能通过一份写对的配置。
func TestRejects(t *testing.T) {
	cases := []struct {
		name string
		want string // 期望出现在某条发现里的子串
		yaml string
	}{
		{
			// 退役的意思就是"这个端口不通,别再回去"。两者矛盾时症状是
			// "换了端口还是不通",而人会去查网络,查不到原因。
			name: "§6 当前端口在退役名单里",
			want: "退役的端口不该再用回来",
			yaml: `
defaults: {dns: [223.5.5.5], components: {sing_box: 1, wireguard: 1, agent: 1}}
nodes:
  - {id: a, public_endpoint: 1.1.1.1, server: {direction: bidirectional, inbound_port: 4433, wg_public_key: k1}}
  - {id: b, public_endpoint: 2.2.2.2, server: {direction: reverse_only, inbound_port: 4433, wg_public_key: k2}}
tunnels:
  - {from: a, to: b, listen_port: 61637, retired_ports: [61637], from_addr: 10.99.0.1/32, to_addr: 10.99.0.2/32}
`,
		},
		{
			name: "§6 退役端口不在保留段内",
			want: "不在保留段",
			yaml: `
defaults: {dns: [223.5.5.5], components: {sing_box: 1, wireguard: 1, agent: 1}}
nodes:
  - {id: a, public_endpoint: 1.1.1.1, server: {direction: bidirectional, inbound_port: 4433, wg_public_key: k1}}
  - {id: b, public_endpoint: 2.2.2.2, server: {direction: reverse_only, inbound_port: 4433, wg_public_key: k2}}
tunnels:
  - {from: a, to: b, listen_port: 61637, retired_ports: [8080], from_addr: 10.99.0.1/32, to_addr: 10.99.0.2/32}
`,
		},
		{
			name: "§2.2 两端都是 reverse_only",
			want: "无人接受",
			yaml: `
defaults: {dns: [223.5.5.5], components: {sing_box: 1, wireguard: 1, agent: 1}}
nodes:
  - {id: a, public_endpoint: 1.1.1.1, server: {direction: reverse_only, wg_public_key: k1}}
  - {id: b, public_endpoint: 1.1.1.2, server: {direction: reverse_only, inbound_port: 4433, wg_public_key: k2}}
tunnels:
  - {from: a, to: b, listen_port: 61611, from_addr: 10.0.0.1/32, to_addr: 10.0.0.2/32}`,
		},
		{
			name: "§2.2 两端都是 direct_only",
			want: "无人发起",
			yaml: `
defaults: {dns: [223.5.5.5], components: {sing_box: 1, wireguard: 1, agent: 1}}
nodes:
  - {id: a, public_endpoint: 1.1.1.1, server: {direction: direct_only, wg_public_key: k1}}
  - {id: b, public_endpoint: 1.1.1.2, server: {direction: direct_only, wg_public_key: k2}}
tunnels:
  - {from: a, to: b, listen_port: 61611, from_addr: 10.0.0.1/32, to_addr: 10.0.0.2/32}`,
		},
		{
			name: "§15.1 同一接受方端口冲突",
			want: "已被",
			yaml: `
defaults: {dns: [223.5.5.5], components: {sing_box: 1, wireguard: 1, agent: 1}}
nodes:
  - {id: acc, public_endpoint: 1.1.1.1, server: {direction: bidirectional, inbound_port: 4433, wg_public_key: k0}}
  - {id: t1, public_endpoint: 1.1.1.2, server: {direction: reverse_only, wg_public_key: k1}}
  - {id: t2, public_endpoint: 1.1.1.3, server: {direction: reverse_only, inbound_port: 4433, wg_public_key: k2}}
tunnels:
  - {from: acc, to: t1, listen_port: 61637, from_addr: 10.0.0.1/32, to_addr: 10.0.0.2/32}
  - {from: acc, to: t2, listen_port: 61637, from_addr: 10.0.0.3/32, to_addr: 10.0.0.4/32}`,
		},
		{
			name: "§20.1 地址撞车",
			want: "已被",
			yaml: `
defaults: {dns: [223.5.5.5], components: {sing_box: 1, wireguard: 1, agent: 1}}
nodes:
  - {id: acc, public_endpoint: 1.1.1.1, server: {direction: bidirectional, inbound_port: 4433, wg_public_key: k0}}
  - {id: t1, public_endpoint: 1.1.1.2, server: {direction: reverse_only, wg_public_key: k1}}
  - {id: t2, public_endpoint: 1.1.1.3, server: {direction: reverse_only, inbound_port: 4433, wg_public_key: k2}}
tunnels:
  - {from: acc, to: t1, listen_port: 61611, from_addr: 10.0.0.1/32, to_addr: 10.0.0.2/32}
  - {from: acc, to: t2, listen_port: 61612, from_addr: 10.0.0.1/32, to_addr: 10.0.0.3/32}`,
		},
		{
			name: "§20.1 非 /32 会让 AllowedIPs 越界",
			want: "应为 /32",
			yaml: `
defaults: {dns: [223.5.5.5], components: {sing_box: 1, wireguard: 1, agent: 1}}
nodes:
  - {id: a, public_endpoint: 1.1.1.1, server: {direction: bidirectional, inbound_port: 4433, wg_public_key: k1}}
  - {id: b, public_endpoint: 1.1.1.2, server: {direction: reverse_only, inbound_port: 4433, wg_public_key: k2}}
tunnels:
  - {from: a, to: b, listen_port: 61611, from_addr: 10.0.0.0/24, to_addr: 10.0.1.2/32}`,
		},
		{
			name: "§20.1 接受方无 public_endpoint 则发起方无处可拨",
			want: "无处可拨",
			yaml: `
defaults: {dns: [223.5.5.5], components: {sing_box: 1, wireguard: 1, agent: 1}}
nodes:
  - {id: a, server: {direction: bidirectional, inbound_port: 4433, wg_public_key: k1}}
  - {id: b, public_endpoint: 1.1.1.2, server: {direction: reverse_only, inbound_port: 4433, wg_public_key: k2}}
tunnels:
  - {from: a, to: b, listen_port: 61611, from_addr: 10.0.0.1/32, to_addr: 10.0.0.2/32}`,
		},
		{
			name: "§13.1 缺少公钥",
			want: "缺少 wg_public_key",
			yaml: `
defaults: {dns: [223.5.5.5], components: {sing_box: 1, wireguard: 1, agent: 1}}
nodes:
  - {id: a, public_endpoint: 1.1.1.1, server: {direction: bidirectional, inbound_port: 4433}}
  - {id: b, public_endpoint: 1.1.1.2, server: {direction: reverse_only, inbound_port: 4433, wg_public_key: k2}}
tunnels:
  - {from: a, to: b, listen_port: 61611, from_addr: 10.0.0.1/32, to_addr: 10.0.0.2/32}`,
		},
		{
			name: "§6.3 同一对节点重复建隧道",
			want: "重复",
			yaml: `
defaults: {dns: [223.5.5.5], components: {sing_box: 1, wireguard: 1, agent: 1}}
nodes:
  - {id: a, public_endpoint: 1.1.1.1, server: {direction: bidirectional, inbound_port: 4433, wg_public_key: k1}}
  - {id: b, public_endpoint: 1.1.1.2, server: {direction: reverse_only, inbound_port: 4433, wg_public_key: k2}}
tunnels:
  - {from: a, to: b, listen_port: 61611, from_addr: 10.0.0.1/32, to_addr: 10.0.0.2/32}
  - {from: b, to: a, listen_port: 61612, from_addr: 10.0.0.3/32, to_addr: 10.0.0.4/32}`,
		},
		{
			name: "§20.1 接口名超长",
			want: "超过 15 字符",
			yaml: `
defaults: {dns: [223.5.5.5], components: {sing_box: 1, wireguard: 1, agent: 1}}
nodes:
  - {id: a, public_endpoint: 1.1.1.1, server: {direction: bidirectional, inbound_port: 4433, wg_public_key: k1}}
  - {id: server-in-a-very-long-city, public_endpoint: 1.1.1.2, server: {direction: reverse_only, inbound_port: 4433, wg_public_key: k2}}
tunnels:
  - {from: a, to: server-in-a-very-long-city, listen_port: 61611, from_addr: 10.0.0.1/32, to_addr: 10.0.0.2/32}`,
		},
		{
			name: "§1.3 两个角色块都缺",
			want: "不承担任何角色",
			yaml: `
defaults: {dns: [223.5.5.5], components: {sing_box: 1, wireguard: 1, agent: 1}}
nodes:
  - {id: a, city: 北京}`,
		},
		{
			name: "§19 节点 id 重复",
			want: "id 重复",
			yaml: `
defaults: {dns: [223.5.5.5], components: {sing_box: 1, wireguard: 1, agent: 1}}
nodes:
  - {id: a, server: {direction: bidirectional, inbound_port: 4433}}
  - {id: a, server: {direction: bidirectional, inbound_port: 4433}}`,
		},
		{
			name: "§19 节点 id 不能越出分发目录",
			want: "id \"../escape\" 格式非法",
			yaml: `
defaults: {dns: [223.5.5.5], components: {sing_box: 1, wireguard: 1, agent: 1}}
nodes:
  - {id: ../escape, server: {direction: bidirectional, inbound_port: 4433}}`,
		},
		{
			name: "隧道引用了不存在的节点",
			want: "不存在的节点",
			yaml: `
defaults: {dns: [223.5.5.5], components: {sing_box: 1, wireguard: 1, agent: 1}}
nodes:
  - {id: a, public_endpoint: 1.1.1.1, server: {direction: bidirectional, inbound_port: 4433, wg_public_key: k1}}
tunnels:
  - {from: a, to: ghost, listen_port: 61611, from_addr: 10.0.0.1/32, to_addr: 10.0.0.2/32}`,
		},
		{
			name: "§6.3 两端都能被公网拨到就不该手工建隧道",
			want: "不需要隧道",
			yaml: `
defaults: {dns: [223.5.5.5], components: {sing_box: 1, wireguard: 1, agent: 1}}
nodes:
  - {id: a, public_endpoint: 1.1.1.1, server: {direction: bidirectional, inbound_port: 4433, wg_public_key: k1}}
  - {id: b, public_endpoint: 1.1.1.2, server: {direction: direct_only, inbound_port: 4433, wg_public_key: k2}}
tunnels:
  - {from: a, to: b, listen_port: 61611, from_addr: 10.0.0.1/32, to_addr: 10.0.0.2/32}`,
		},
		{
			name: "§8.1 被声明引用却没有 inbound_port",
			want: "无法接受上游连接",
			yaml: `
defaults: {dns: [223.5.5.5], components: {sing_box: 1, wireguard: 1, agent: 1}}
nodes:
  - {id: a, public_endpoint: 1.1.1.1, server: {direction: bidirectional, egress_capable: true}}
declarations:
  - {id: d1, address_axis: from_request, egress_axis: any, objective: latency, tuning_period: 10m, allowed_servers: [a]}`,
		},
		{
			name: "§5.4 window 装不下 min_samples,排序永远不会启动",
			want: "排序永远不会启动",
			yaml: `
defaults: {dns: [223.5.5.5], components: {sing_box: 1, wireguard: 1, agent: 1}}
nodes:
  - {id: a, public_endpoint: 1.1.1.1, server: {direction: bidirectional, inbound_port: 4433, egress_capable: true, wg_public_key: k1}}
declarations:
  - {id: d1, address_axis: from_request, egress_axis: any, objective: latency, probe_url: "https://x/", tuning_period: 5m, window: 5m, min_samples: 20, stale_after: 15m, allowed_servers: [a]}`,
		},
		{
			name: "§5.8 stale_after 比 tuning_period 还短",
			want: "立刻就过期",
			yaml: `
defaults: {dns: [223.5.5.5], components: {sing_box: 1, wireguard: 1, agent: 1}}
nodes:
  - {id: a, public_endpoint: 1.1.1.1, server: {direction: bidirectional, inbound_port: 4433, egress_capable: true, wg_public_key: k1}}
declarations:
  - {id: d1, address_axis: from_request, egress_axis: any, objective: latency, probe_url: "https://x/", tuning_period: 10m, window: 2h, min_samples: 6, stale_after: 1m, allowed_servers: [a]}`,
		},
		{
			name: "§5.5 switch_threshold 不是相对幅度",
			want: "相对改善幅度",
			yaml: `
defaults: {dns: [223.5.5.5], components: {sing_box: 1, wireguard: 1, agent: 1}}
nodes:
  - {id: a, public_endpoint: 1.1.1.1, server: {direction: bidirectional, inbound_port: 4433, egress_capable: true, wg_public_key: k1}}
declarations:
  - {id: d1, address_axis: from_request, egress_axis: any, objective: latency, probe_url: "https://x/", tuning_period: 10m, window: 2h, min_samples: 6, stale_after: 30m, switch_threshold: 20, allowed_servers: [a]}`,
		},
		{
			name: "§5.8 把声明钉死的出口排空了",
			want: "已排空",
			yaml: `
defaults: {dns: [223.5.5.5], components: {sing_box: 1, wireguard: 1, agent: 1}}
nodes:
  - {id: a, public_endpoint: 1.1.1.1, server: {direction: bidirectional, inbound_port: 4433, egress_capable: true, wg_public_key: k1, }, drain: true}
  - {id: b, public_endpoint: 1.1.1.2, server: {direction: bidirectional, inbound_port: 4433, egress_capable: true, wg_public_key: k2}}
declarations:
  - {id: d1, address_axis: from_request, egress_axis: "pinned:a", objective: latency, probe_url: "https://x/", tuning_period: 10m, window: 2h, min_samples: 6, stale_after: 30m, allowed_servers: [a, b]}`,
		},
		{
			name: "§5.8 所有出口都被排空",
			want: "全网没有任何可用候选",
			yaml: `
defaults: {dns: [223.5.5.5], components: {sing_box: 1, wireguard: 1, agent: 1}}
nodes:
  - {id: a, public_endpoint: 1.1.1.1, server: {direction: bidirectional, inbound_port: 4433, egress_capable: true, wg_public_key: k1}, drain: true}
  - {id: b, public_endpoint: 1.1.1.2, server: {direction: bidirectional, inbound_port: 4433, egress_capable: true, wg_public_key: k2}, drain: true}`,
		},
		{
			name: "§14.4 已下线的节点还挂着隧道",
			want: "已标记下线,却仍有隧道引用它",
			yaml: `
defaults: {dns: [223.5.5.5], components: {sing_box: 1, wireguard: 1, agent: 1}}
nodes:
  - {id: a, public_endpoint: 1.1.1.1, server: {direction: bidirectional, inbound_port: 4433, egress_capable: true, wg_public_key: k1}}
  - {id: b, public_endpoint: 1.1.1.2, server: {direction: reverse_only, inbound_port: 4433, egress_capable: true, wg_public_key: k2}, decommission: true}
tunnels:
  - {from: a, to: b, listen_port: 61611, from_addr: 10.0.0.1/32, to_addr: 10.0.0.2/32}`,
		},
		{
			name: "§5.8 排空一个接入节点没有意义",
			want: "drain 只对服务器有意义",
			yaml: `
defaults: {dns: [223.5.5.5], components: {sing_box: 1, wireguard: 1, agent: 1}}
nodes:
  - {id: a, public_endpoint: 1.1.1.1, server: {direction: bidirectional, inbound_port: 4433, egress_capable: true, wg_public_key: k1}}
  - id: p
    drain: true
    access: {platform: linux-server, credentials: []}`,
		},
		{
			name: "§4.5 两个服务抢同一个地址",
			want: "已被服务",
			yaml: `
defaults: {dns: [223.5.5.5], components: {sing_box: 1, wireguard: 1, agent: 1}}
nodes:
  - id: acc
    public_endpoint: 1.1.1.9
    server: {direction: bidirectional, wg_public_key: k0}
    access: {platform: linux-server, credentials: [c1], mixed_ports: [{port: 1082, services: true}]}
  - {id: a, public_endpoint: 1.1.1.1, server: {direction: bidirectional, inbound_port: 4433, egress_capable: true, wg_public_key: k1}}
declarations:
  - {id: d1, address_axis: from_request, egress_axis: any, objective: latency, probe_url: "https://t/", tuning_period: 5m, window: 1h, min_samples: 6, stale_after: 20m, allowed_servers: [a]}
credentials:
  - {id: c1, declaration: d1, secret_ref: "cred/c1"}
services:
  - {id: s1, declaration: d1, addresses: [a.example.com]}
  - {id: s2, declaration: d1, addresses: [a.example.com]}`,
		},
		{
			name: "§4.5 服务没有地址",
			want: "永远匹配不到任何流量",
			yaml: `
defaults: {dns: [223.5.5.5], components: {sing_box: 1, wireguard: 1, agent: 1}}
nodes:
  - id: acc
    public_endpoint: 1.1.1.9
    server: {direction: bidirectional, wg_public_key: k0}
    access: {platform: linux-server, credentials: [c1], mixed_ports: [{port: 1082, services: true}]}
  - {id: a, public_endpoint: 1.1.1.1, server: {direction: bidirectional, inbound_port: 4433, egress_capable: true, wg_public_key: k1}}
declarations:
  - {id: d1, address_axis: from_request, egress_axis: any, objective: latency, probe_url: "https://t/", tuning_period: 5m, window: 1h, min_samples: 6, stale_after: 20m, allowed_servers: [a]}
credentials:
  - {id: c1, declaration: d1, secret_ref: "cred/c1"}
services:
  - {id: s1, declaration: d1, addresses: []}`,
		},
		{
			name: "§4.5 服务只有后缀地址",
			want: "探测无从下手",
			yaml: `
defaults: {dns: [223.5.5.5], components: {sing_box: 1, wireguard: 1, agent: 1}}
nodes:
  - id: acc
    public_endpoint: 1.1.1.9
    server: {direction: bidirectional, wg_public_key: k0}
    access: {platform: linux-server, credentials: [c1], mixed_ports: [{port: 1082, services: true}]}
  - {id: a, public_endpoint: 1.1.1.1, server: {direction: bidirectional, inbound_port: 4433, egress_capable: true, wg_public_key: k1}}
declarations:
  - {id: d1, address_axis: from_request, egress_axis: any, objective: latency, probe_url: "https://t/", tuning_period: 5m, window: 1h, min_samples: 6, stale_after: 20m, allowed_servers: [a]}
credentials:
  - {id: c1, declaration: d1, secret_ref: "cred/c1"}
services:
  - {id: s1, declaration: d1, addresses: [.example.com]}`,
		},
		{
			name: "§4.5 地址写成了 URL",
			want: "这里要的是 host",
			yaml: `
defaults: {dns: [223.5.5.5], components: {sing_box: 1, wireguard: 1, agent: 1}}
nodes:
  - id: acc
    public_endpoint: 1.1.1.9
    server: {direction: bidirectional, wg_public_key: k0}
    access: {platform: linux-server, credentials: [c1], mixed_ports: [{port: 1082, services: true}]}
  - {id: a, public_endpoint: 1.1.1.1, server: {direction: bidirectional, inbound_port: 4433, egress_capable: true, wg_public_key: k1}}
declarations:
  - {id: d1, address_axis: from_request, egress_axis: any, objective: latency, probe_url: "https://t/", tuning_period: 5m, window: 1h, min_samples: 6, stale_after: 20m, allowed_servers: [a]}
credentials:
  - {id: c1, declaration: d1, secret_ref: "cred/c1"}
services:
  - {id: s1, declaration: d1, addresses: ["https://a.example.com/x"]}`,
		},
		{
			name: "§4.5 端口既绑声明又开 services",
			want: "不能既是又是",
			yaml: `
defaults: {dns: [223.5.5.5], components: {sing_box: 1, wireguard: 1, agent: 1}}
nodes:
  - id: acc
    public_endpoint: 1.1.1.9
    server: {direction: bidirectional, wg_public_key: k0}
    access: {platform: linux-server, credentials: [c1], mixed_ports: [{port: 1082, services: true, declaration: d1}]}
  - {id: a, public_endpoint: 1.1.1.1, server: {direction: bidirectional, inbound_port: 4433, egress_capable: true, wg_public_key: k1}}
declarations:
  - {id: d1, address_axis: from_request, egress_axis: any, objective: latency, probe_url: "https://t/", tuning_period: 5m, window: 1h, min_samples: 6, stale_after: 20m, allowed_servers: [a]}
credentials:
  - {id: c1, declaration: d1, secret_ref: "cred/c1"}
services:
  - {id: s1, declaration: d1, addresses: [a.example.com]}`,
		},
		{
			name: "§4.5 只能有一个中控托管主入口",
			want: "service-aware mixed 主入口只能有一个",
			yaml: `
defaults: {dns: [223.5.5.5], components: {sing_box: 1, wireguard: 1, agent: 1}}
nodes:
  - id: acc
    public_endpoint: 1.1.1.9
    server: {direction: bidirectional, wg_public_key: k0}
    access:
      platform: linux-server
      credentials: [c1]
      mixed_ports:
        - {port: 1083, services: true}
        - {port: 1080, services: true}
  - {id: a, public_endpoint: 1.1.1.1, server: {direction: bidirectional, inbound_port: 4433, egress_capable: true, wg_public_key: k1}}
declarations:
  - {id: d1, address_axis: from_request, egress_axis: any, objective: latency, probe_url: "https://t/", tuning_period: 5m, window: 1h, min_samples: 6, stale_after: 20m, allowed_servers: [a]}
credentials:
  - {id: c1, declaration: d1, secret_ref: "cred/c1"}
services:
  - {id: s1, declaration: d1, addresses: [a.example.com]}`,
		},
		{
			name: "§4.5 服务引用了不存在的声明",
			want: "引用了不存在的声明",
			yaml: `
defaults: {dns: [223.5.5.5], components: {sing_box: 1, wireguard: 1, agent: 1}}
nodes:
  - id: acc
    public_endpoint: 1.1.1.9
    server: {direction: bidirectional, wg_public_key: k0}
    access: {platform: linux-server, credentials: [c1], mixed_ports: [{port: 1082, services: true}]}
  - {id: a, public_endpoint: 1.1.1.1, server: {direction: bidirectional, inbound_port: 4433, egress_capable: true, wg_public_key: k1}}
declarations:
  - {id: d1, address_axis: from_request, egress_axis: any, objective: latency, probe_url: "https://t/", tuning_period: 5m, window: 1h, min_samples: 6, stale_after: 20m, allowed_servers: [a]}
credentials:
  - {id: c1, declaration: d1, secret_ref: "cred/c1"}
services:
  - {id: s1, declaration: 不存在, addresses: [a.example.com]}`,
		},
		{
			name: "§16.2 预算太小,轮换攒不够样本",
			want: "才轮到一次",
			yaml: `
defaults: {dns: [223.5.5.5], components: {sing_box: 1, wireguard: 1, agent: 1}}
nodes:
  - id: acc
    public_endpoint: 1.1.1.9
    server: {direction: bidirectional, wg_public_key: k0}
    access: {platform: linux-server, credentials: [c1], mixed_ports: [{port: 1080, declaration: d1}]}
  - {id: a, public_endpoint: 1.1.1.1, server: {direction: bidirectional, inbound_port: 4433, egress_capable: true, wg_public_key: k1}}
  - {id: b, public_endpoint: 1.1.1.2, server: {direction: bidirectional, inbound_port: 4433, egress_capable: true, wg_public_key: k2}}
  - {id: c, public_endpoint: 1.1.1.3, server: {direction: bidirectional, inbound_port: 4433, egress_capable: true, wg_public_key: k3}}
declarations:
  - {id: d1, address_axis: from_request, egress_axis: any, objective: latency, probe_url: "https://t/", tuning_period: 10m, window: 2h, min_samples: 6, stale_after: 30m, max_hops: 2, probe_budget: 2, allowed_servers: [a, b, c]}
credentials:
  - {id: c1, declaration: d1, secret_ref: "cred/c1"}`,
		},
		{
			name: "§16.2 预算 1 等于关掉选优",
			want: "等于关掉了选优",
			yaml: `
defaults: {dns: [223.5.5.5], components: {sing_box: 1, wireguard: 1, agent: 1}}
nodes:
  - {id: a, public_endpoint: 1.1.1.1, server: {direction: bidirectional, inbound_port: 4433, egress_capable: true, wg_public_key: k1}}
declarations:
  - {id: d1, address_axis: from_request, egress_axis: any, objective: latency, probe_url: "https://t/", tuning_period: 10m, window: 2h, min_samples: 6, stale_after: 30m, probe_budget: 1, allowed_servers: [a]}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := model.Load([]byte(tc.yaml))
			if err != nil {
				t.Fatalf("加载失败:%v", err)
			}
			fs := Validate(s)
			if len(fs) == 0 {
				t.Fatal("期望有发现,实际通过了校验")
			}
			if !strings.Contains(Format(fs), tc.want) {
				t.Errorf("发现里没有 %q:\n%s", tc.want, Format(fs))
			}
		})
	}
}

// TestValidateIsDeterministic:发现的顺序必须稳定,否则 CI 输出会抖动。
func TestValidateIsDeterministic(t *testing.T) {
	src := []byte(`
nodes:
  - {id: z, server: {direction: bogus}}
  - {id: a, server: {direction: reverse_only}}
  - {id: m, server: {direction: bidirectional}}`)
	s, err := model.Load(src)
	if err != nil {
		t.Fatal(err)
	}
	first := Format(Validate(s))
	for i := 0; i < 20; i++ {
		if got := Format(Validate(s)); got != first {
			t.Fatalf("第 %d 次校验输出不同:\n%s\n---\n%s", i, first, got)
		}
	}
	if !strings.Contains(first, "a:") || !strings.Contains(first, "z:") {
		t.Errorf("发现未按节点排序:\n%s", first)
	}
}

func TestLocalEgressDoesNotRequireAnInboundPort(t *testing.T) {
	const localOnly = `
defaults: {dns: [223.5.5.5], components: {sing_box: 1, wireguard: 1, agent: 1}}
nodes:
  - id: access
    server: {direction: bidirectional, egress_capable: true}
    access: {platform: linux-server, credentials: [c1], mixed_ports: [{port: 1080, declaration: d1}]}
declarations:
  - {id: d1, address_axis: from_request, egress_axis: any, objective: latency, probe_url: "https://x/", tuning_period: 10m, window: 2h, min_samples: 2, stale_after: 30m, allowed_servers: [access]}
credentials:
  - {id: c1, owner: access, declaration: d1, secret_ref: "cred/c1"}
`
	s, err := model.Load([]byte(localOnly))
	if err != nil {
		t.Fatal(err)
	}
	if got := Format(Validate(s)); strings.Contains(got, "inbound_port") {
		t.Fatalf("zero-hop local egress was treated as an upstream hop:\n%s", got)
	}

	shared := strings.Replace(localOnly,
		"declarations:\n",
		`  - id: other
    access: {platform: linux-server, credentials: [c2], mixed_ports: [{port: 1080, declaration: d1}]}
declarations:
`, 1)
	shared += `  - {id: c2, owner: other, declaration: d1, secret_ref: "cred/c2"}
`
	s, err = model.Load([]byte(shared))
	if err != nil {
		t.Fatal(err)
	}
	if got := Format(Validate(s)); !strings.Contains(got, "inbound_port") {
		t.Fatalf("shared egress stopped requiring an inbound for the other access node:\n%s", got)
	}
}

// TestSecretGenerationFailClosed 钉住秘密层代次的最小可兑现边界。
// 0 是未声明的旧配置，1 是首代基线；轮换代次还没有部署/核验链，不能假生效。
func TestSecretGenerationFailClosed(t *testing.T) {
	for _, tc := range []struct {
		generation int
		wantReject bool
	}{
		{generation: 0},
		{generation: 1},
		{generation: -1, wantReject: true},
		{generation: 2, wantReject: true},
	} {
		t.Run(fmt.Sprintf("generation_%d", tc.generation), func(t *testing.T) {
			src := fmt.Sprintf(`
defaults: {dns: [223.5.5.5], components: {sing_box: 1, wireguard: 1, agent: 1}}
nodes:
  - {id: a, public_endpoint: 1.1.1.1, server: {direction: bidirectional, inbound_port: 4433, wg_public_key: k1, secret_generation: %d}}
`, tc.generation)
			s, err := model.Load([]byte(src))
			if err != nil {
				t.Fatal(err)
			}
			gotReject := strings.Contains(Format(Validate(s)), "secret_generation")
			if gotReject != tc.wantReject {
				t.Errorf("secret_generation=%d: reject=%v, 期望 %v\n%s",
					tc.generation, gotReject, tc.wantReject, Format(Validate(s)))
			}
		})
	}
}

func TestTailscaleVersionCannotActivateAnUnimplementedWorkload(t *testing.T) {
	src := `
defaults:
  dns: [223.5.5.5]
  components: {sing_box: 1, wireguard: 1, tailscale: 1.80.0, agent: 1}
nodes:
  - {id: a, public_endpoint: 1.1.1.1, server: {direction: bidirectional, inbound_port: 4433, wg_public_key: k1}}
`
	s, err := model.Load([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	got := Format(Validate(s))
	if !strings.Contains(got, "版本字段冒充已启用能力") {
		t.Fatalf("components.tailscale 未被 fail-closed 拒绝:\n%s", got)
	}
}

func TestAttestationUpgradeGateOnlyAllowsCompatibilityOrV5(t *testing.T) {
	s := &model.SSOT{Defaults: &model.SSOTDefaults{AttestationMinVersion: 6}}
	if got := Format(Validate(s)); !strings.Contains(got, "attestation_min_version") {
		t.Fatalf("未知 attestation 门禁没有被 SSOT 校验拒绝:%s", got)
	}
	s.Defaults.AttestationMinVersion = 5
	if got := Format(Validate(s)); strings.Contains(got, "attestation_min_version") {
		t.Fatalf("合法 phase-B 门禁被误拒:%s", got)
	}
}

func TestDistributionURLMustBeAnUncredentialedHTTPURL(t *testing.T) {
	for _, raw := range []string{"ssh://mirror/loom/", "https://user:pass@mirror/loom/", "https://mirror/loom/?token=x"} {
		s := &model.SSOT{Defaults: &model.SSOTDefaults{DistributionURL: raw}}
		if got := Format(Validate(s)); !strings.Contains(got, "distribution_url") {
			t.Errorf("unsafe distribution URL %q was accepted: %s", raw, got)
		}
	}
	s := &model.SSOT{
		Defaults: &model.SSOTDefaults{DistributionURL: "https://public.example/loom/"},
		Nodes:    []model.Node{{ID: "sv01", DistributionURL: "http://10.99.2.2/loom/"}},
	}
	if got := Format(Validate(s)); strings.Contains(got, "distribution_url") {
		t.Fatalf("safe node distribution override was rejected: %s", got)
	}
}

func TestDistributionMirrorListRejectsAmbiguityAndDuplicates(t *testing.T) {
	s := &model.SSOT{Defaults: &model.SSOTDefaults{
		DistributionURL:  "https://one.example/loom/",
		DistributionURLs: []string{"https://two.example/loom/"},
	}}
	if got := Format(Validate(s)); !strings.Contains(got, "不能同时声明") {
		t.Fatalf("新旧字段并存未被拒绝:%s", got)
	}
	s = &model.SSOT{Defaults: &model.SSOTDefaults{DistributionURLs: []string{
		"https://one.example/loom", "https://one.example/loom/",
	}}}
	if got := Format(Validate(s)); !strings.Contains(got, "镜像地址重复") {
		t.Fatalf("等价镜像重复未被拒绝:%s", got)
	}
}

func TestCountryUsesCanonicalAlpha2Representation(t *testing.T) {
	s := &model.SSOT{Nodes: []model.Node{{
		ID: "edge", Country: "hk", Server: &model.ServerRole{Direction: model.Bidirectional},
	}}}
	if got := Format(Validate(s)); !strings.Contains(got, "country") || !strings.Contains(got, "ISO 3166-1") {
		t.Fatalf("non-canonical country was not rejected: %s", got)
	}
	s.Nodes[0].Country = "HK"
	if got := Format(Validate(s)); strings.Contains(got, "country") {
		t.Fatalf("canonical country was rejected: %s", got)
	}
}
