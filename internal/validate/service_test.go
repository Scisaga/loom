package validate

import (
	"os"
	"strings"
	"testing"

	"loom/internal/model"
)

// 最小可用的拓扑前缀,让服务侧的反例只需声明它关心的那部分。
const topo = `
defaults:
  dns: [223.5.5.5]
  components: {sing_box: 1.11.4, wireguard: 1.0.20250521, agent: 0.1.0}
nodes:
  - {id: cn-a, public_endpoint: 1.1.1.1, server: {direction: bidirectional, inbound_port: 4433, egress_capable: true, wg_public_key: k1}}
  - {id: cn-b, public_endpoint: 1.1.1.2, server: {direction: bidirectional, inbound_port: 4433, wg_public_key: k2}}
  - {id: sg-v, public_endpoint: 1.1.1.3, server: {direction: reverse_only, inbound_port: 4433, egress_capable: true, wg_public_key: k3}}
`

// TestRejectsService 覆盖 §19"校验器必须拒绝的矛盾配置"表里依赖等价类与
// 访问声明的那几条。
func TestRejectsService(t *testing.T) {
	cases := []struct {
		name string
		want string // 期望出现在某条发现里的子串;空串表示期望通过
		yaml string
	}{
		{
			name: "§1 把节点 id 写进等价类成员",
			want: "目标不是节点",
			yaml: topo + `
equivalence_classes:
  - id: c1
    carrier: l4_direct
    observation_point: l4_tunnel
    members:
      - {address: cn-a, access_contract: {}}`,
		},
		{
			name: "§4.4 l4_direct 但成员契约不同构",
			want: "l7_gateway 承载",
			yaml: topo + `
equivalence_classes:
  - id: c1
    carrier: l4_direct
    observation_point: l4_tunnel
    members:
      - {address: "https://a.internal/v1", access_contract: {domain: a.internal, cert_ca: ca1, credential: v1}}
      - {address: "https://b.example.net/v1", access_contract: {domain: b.example.net, cert_ca: webpki, credential: v2}}`,
		},
		{
			name: "§4.4 l7_gateway 允许契约不同构",
			want: "",
			yaml: topo + `
equivalence_classes:
  - id: c1
    carrier: l7_gateway
    observation_point: l7_gateway
    members:
      - {address: "https://a.internal/v1", access_contract: {domain: a.internal, cert_ca: ca1, credential: v1}}
      - {address: "https://b.example.net/v1", access_contract: {domain: b.example.net, cert_ca: webpki, credential: v2}}`,
		},
		{
			name: "§16.2 objective ttft 但只有 L4 观测点",
			want: "不是 L4 能被动观测的量",
			yaml: topo + `
equivalence_classes:
  - id: c1
    carrier: l4_direct
    observation_point: l4_tunnel
    members: [{address: "https://a.internal/v1", access_contract: {}}]
declarations:
  - {id: d1, address_axis: "class:c1", egress_axis: any, objective: ttft, top_n: 2, tuning_period: 10m}`,
		},
		{
			name: "§5.2 objective cost 但没有价格数据源",
			want: "不会从度量里长出来",
			yaml: topo + `
equivalence_classes:
  - id: c1
    carrier: l4_direct
    observation_point: endpoint
    members: [{address: "https://a.internal/v1", access_contract: {}}]
declarations:
  - {id: d1, address_axis: "class:c1", egress_axis: any, objective: cost, top_n: 2, tuning_period: 10m}`,
		},
		{
			name: "§5.8 有合规约束但 fallback 不是 fail_closed",
			want: "等于绕过它",
			yaml: topo + `
declarations:
  - id: d1
    address_axis: from_request
    egress_axis: any
    objective: stability
    tuning_period: 10m
    fallback: last_known_good
    constraints:
      - {kind: compliance, expr: 数据不出省}`,
		},
		{
			name: "§5.5 地址由请求决定却配了 ranking_period",
			want: "排序周期无意义",
			yaml: topo + `
declarations:
  - {id: d1, address_axis: from_request, egress_axis: any, objective: stability, tuning_period: 10m, ranking_period: 30m}`,
		},
		{
			name: "§4 address_axis 取值非法",
			want: "address_axis 非法",
			yaml: topo + `
declarations:
  - {id: d1, address_axis: whatever, egress_axis: any, objective: latency, tuning_period: 10m}`,
		},
		{
			name: "§4 egress_axis 钉死了不存在的节点",
			want: "钉死了不存在的节点",
			yaml: topo + `
declarations:
  - {id: d1, address_axis: from_request, egress_axis: "pinned:ghost", objective: latency, tuning_period: 10m}`,
		},
		{
			name: "§4 钉死的出口没有 egress_capable",
			want: "它出不了公网",
			yaml: topo + `
declarations:
  - {id: d1, address_axis: from_request, egress_axis: "pinned:cn-b", objective: latency, tuning_period: 10m, allowed_servers: [cn-b]}`,
		},
		{
			name: "§5.1 钉死的出口不在 allowed_servers 里",
			want: "不在 allowed_servers 里",
			yaml: topo + `
declarations:
  - {id: d1, address_axis: from_request, egress_axis: "pinned:sg-v", objective: latency, tuning_period: 10m, allowed_servers: [cn-a]}`,
		},
		{
			name: "§5.6 地址从等价类里选却缺 top_n",
			want: "显式声明 top_n",
			yaml: topo + `
equivalence_classes:
  - id: c1
    carrier: l4_direct
    observation_point: l4_tunnel
    members: [{address: "https://a.internal/v1", access_contract: {}}]
declarations:
  - {id: d1, address_axis: "class:c1", egress_axis: any, objective: latency, tuning_period: 10m}`,
		},
		{
			name: "§7.2 Android 不应有 mixed_ports",
			want: "只能走 TUN",
			yaml: topo + `  - {id: p1, access: {platform: android, credentials: [cr1], mixed_ports: [{port: 1080, declaration: d1}]}}
declarations:
  - {id: d1, address_axis: from_request, egress_axis: any, objective: stability, tuning_period: 10m}
credentials:
  - {id: cr1, declaration: d1, secret_ref: v}`,
		},
		{
			name: "§18 Android 多凭据无法按端口区分",
			want: "无法按端口区分声明",
			yaml: topo + `  - {id: p1, access: {platform: android, credentials: [cr1, cr2], default_declaration: d1}}
declarations:
  - {id: d1, address_axis: from_request, egress_axis: any, objective: stability, tuning_period: 10m}
credentials:
  - {id: cr1, declaration: d1, secret_ref: v}
  - {id: cr2, declaration: d1, secret_ref: v}`,
		},
		{
			name: "§7.2 桌面多凭据必须声明 TUN 兜底走哪条",
			want: "兜底流量走哪条声明是歧义的",
			yaml: topo + `  - {id: p1, access: {platform: desktop, credentials: [cr1, cr2], mixed_ports: [{port: 1080, declaration: d1}]}}
declarations:
  - {id: d1, address_axis: from_request, egress_axis: any, objective: stability, tuning_period: 10m}
  - {id: d2, address_axis: from_request, egress_axis: any, objective: latency, tuning_period: 10m}
credentials:
  - {id: cr1, declaration: d1, secret_ref: v}
  - {id: cr2, declaration: d2, secret_ref: v}`,
		},
		{
			name: "§7.2 linux-server 没有 mixed 端口就接管不到流量",
			want: "接管不到任何流量",
			yaml: topo + `  - {id: p1, access: {platform: linux-server, credentials: [cr1]}}
declarations:
  - {id: d1, address_axis: from_request, egress_axis: any, objective: stability, tuning_period: 10m}
credentials:
  - {id: cr1, declaration: d1, secret_ref: v}`,
		},
		{
			name: "§18 引用已吊销的凭据",
			want: "已吊销",
			yaml: topo + `  - {id: p1, access: {platform: linux-server, credentials: [cr1], mixed_ports: [{port: 1080, declaration: d1}]}}
declarations:
  - {id: d1, address_axis: from_request, egress_axis: any, objective: stability, tuning_period: 10m}
credentials:
  - {id: cr1, declaration: d1, secret_ref: v, revoked_at: "2026-01-01T00:00:00Z"}`,
		},
		{
			name: "§8.2 凭据未绑定访问声明",
			want: "凭据即访问声明",
			yaml: topo + `
credentials:
  - {id: cr1, secret_ref: v}`,
		},
		{
			name: "§7.3 端口绑定了不存在的声明",
			want: "不存在的访问声明",
			yaml: topo + `  - {id: p1, access: {platform: linux-server, credentials: [cr1], mixed_ports: [{port: 1080, declaration: ghost}]}}
declarations:
  - {id: d1, address_axis: from_request, egress_axis: any, objective: stability, tuning_period: 10m}
credentials:
  - {id: cr1, declaration: d1, secret_ref: v}`,
		},
		{
			name: "§5.1 allowed_servers 里的节点不是服务器",
			want: "不持有 server 能力",
			yaml: topo + `  - {id: laptop, access: {}}
declarations:
  - {id: d1, address_axis: from_request, egress_axis: any, objective: stability, tuning_period: 10m, allowed_servers: [laptop]}`,
		},
		{
			name: "§5.5 缺少 tuning_period",
			want: "缺少 tuning_period",
			yaml: topo + `
declarations:
  - {id: d1, address_axis: from_request, egress_axis: any, objective: stability}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := model.Load([]byte(tc.yaml))
			if err != nil {
				t.Fatalf("加载失败:%v", err)
			}
			got := Format(Validate(s))
			if tc.want == "" {
				if got != "" {
					t.Fatalf("期望通过校验,却有发现:\n%s", got)
				}
				return
			}
			if !strings.Contains(got, tc.want) {
				t.Errorf("发现里没有 %q:\n%s", tc.want, got)
			}
		})
	}
}

// TestPlatformDerivesTUN:接管方式由平台推导,不是独立配置项(§7.2)。
func TestPlatformDerivesTUN(t *testing.T) {
	for _, tc := range []struct {
		p     model.Platform
		tun   bool
		mixed bool
	}{
		{model.Android, true, false},
		{model.Desktop, true, true},
		{model.LinuxServer, false, true},
	} {
		if got := tc.p.UsesTUN(); got != tc.tun {
			t.Errorf("%s.UsesTUN() = %v,期望 %v", tc.p, got, tc.tun)
		}
		if got := tc.p.UsesMixed(); got != tc.mixed {
			t.Errorf("%s.UsesMixed() = %v,期望 %v", tc.p, got, tc.mixed)
		}
	}
}

// TestDeployConfigOnlyMissingKeys 钉住本地部署配置"还差什么"。
//
// deploy/ssot.yaml 是被 Git 忽略的本地 SSOT,`wg_public_key` 现在是空的 —— 公钥由
// 节点本地生成并上报,bootstrap 之前拿不到(§13.1)。这个测试断言**除此之外
// 没有别的问题**:一旦 bootstrap 完成、公钥填上,它就应当直接可用。
//
// 它同时是个反向保险:改了模型或校验规则后,本地配置如果因为别的原因失效,
// 这里会立刻变红,而不是等到部署时才发现。
func TestDeployConfigOnlyMissingKeys(t *testing.T) {
	raw, err := os.ReadFile("../../deploy/ssot.yaml")
	if err != nil {
		t.Skipf("没有本地部署配置,跳过:%v", err)
	}
	s, err := model.Load(raw)
	if err != nil {
		t.Fatalf("本地部署配置解析失败:%v", err)
	}
	for _, f := range Validate(s) {
		if !strings.Contains(f.Msg, "缺少 wg_public_key") {
			t.Errorf("本地部署配置有公钥之外的问题:%s", f)
		}
	}
}

// TestServerNeedsDirection:server 块存在但缺 direction 必须报错。
//
// 惰性字段已由解码层挡住(见 model.TestLoadRejectsDerivedFields);
// 这里管的是反方向 —— 真正会影响产物的字段不能缺。
func TestServerNeedsDirection(t *testing.T) {
	s, err := model.Load([]byte(topo + `  - {id: n1, server: {inbound_port: 61698}}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := Format(Validate(s)); !strings.Contains(got, "direction 缺失或非法") {
		t.Errorf("server 缺 direction 应报错:\n%s", got)
	}
}

// TestRejectsPortClashAcrossRoles:同一台机器上的监听端口必须全局唯一。
//
// mixed 端口和 server 的 inbound_port 在同一台机器上,两个进程抢同一个
// 端口时后起的那个静默失败。原来两者用的是两个独立的桶,查不出来。
func TestRejectsPortClashAcrossRoles(t *testing.T) {
	s, err := model.Load([]byte(topo + `  - {id: both, public_endpoint: 1.1.1.9, server: {direction: bidirectional, inbound_port: 1080, egress_capable: true, wg_public_key: k9}, access: {platform: linux-server, credentials: [cr1], mixed_ports: [{port: 1080, declaration: d1}]}}
declarations:
  - {id: d1, address_axis: from_request, egress_axis: any, objective: latency, tuning_period: 10m}
credentials:
  - {id: cr1, declaration: d1, secret_ref: v}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := Format(Validate(s)); !strings.Contains(got, "已被server 的 inbound_port占用") {
		t.Errorf("同机端口冲突应被检出:\n%s", got)
	}
}
