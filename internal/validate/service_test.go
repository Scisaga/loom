package validate

import (
	"strings"
	"testing"

	"loom/internal/model"
)

// 最小可用的拓扑前缀,让服务侧的反例只需声明它关心的那部分。
const topo = `
nodes:
  - {id: relay-bj, capabilities: [relay], direction: bidirectional, public_endpoint: 1.1.1.1, wg_public_key: k1}
  - {id: t-a, capabilities: [target], direction: reverse_only, public_endpoint: 1.1.1.2, wg_public_key: k2}
  - {id: t-b, capabilities: [target], direction: reverse_only, public_endpoint: 1.1.1.3, wg_public_key: k3}
`

// TestRejectsService 覆盖 §19"校验器必须拒绝的矛盾配置"表里依赖等价类与
// 访问声明的那几条。它们在只有拓扑模型的阶段无法实现,因此曾长期缺失。
func TestRejectsService(t *testing.T) {
	cases := []struct {
		name string
		want string
		yaml string
	}{
		{
			name: "§4.4 l4_direct 但成员契约不同构",
			want: "l7_gateway 承载",
			yaml: topo + `
equivalence_classes:
  - id: c1
    carrier: l4_direct
    observation_point: l4_tunnel
    members:
      - {node: t-a, access_contract: {domain: a.internal, cert_ca: ca1, credential: v1}}
      - {node: t-b, access_contract: {domain: b.example.net, cert_ca: webpki, credential: v2}}`,
		},
		{
			name: "§4.4 l7_gateway 允许契约不同构",
			want: "", // 期望通过
			yaml: topo + `
equivalence_classes:
  - id: c1
    carrier: l7_gateway
    observation_point: l7_gateway
    members:
      - {node: t-a, access_contract: {domain: a.internal, cert_ca: ca1, credential: v1}}
      - {node: t-b, access_contract: {domain: b.example.net, cert_ca: webpki, credential: v2}}`,
		},
		{
			name: "§16.2 objective ttft 但只有 L4 观测点",
			want: "不是 L4 能被动观测的量",
			yaml: topo + `
equivalence_classes:
  - id: c1
    carrier: l4_direct
    observation_point: l4_tunnel
    members:
      - {node: t-a, access_contract: {}}
      - {node: t-b, access_contract: {}}
declarations:
  - id: d1
    mode: by_service
    equivalence_class: c1
    objective: ttft
    top_n: 2
    tuning_period: 10m`,
		},
		{
			name: "§5.2 objective cost 但没有价格数据源",
			want: "不会从度量里长出来",
			yaml: topo + `
equivalence_classes:
  - id: c1
    carrier: l4_direct
    observation_point: l4_tunnel
    members:
      - {node: t-a, access_contract: {}}
      - {node: t-b, access_contract: {}}
declarations:
  - id: d1
    mode: by_service
    equivalence_class: c1
    objective: cost
    top_n: 2
    tuning_period: 10m`,
		},
		{
			name: "§5.8 有合规约束但 fallback 不是 fail_closed",
			want: "等于绕过它",
			yaml: topo + `
declarations:
  - id: d1
    mode: pinned_target
    target_node: t-a
    objective: stability
    tuning_period: 10m
    fallback: last_known_good
    constraints:
      - {kind: compliance, expr: 数据不出省}`,
		},
		{
			name: "§5.5 模式 A 配置了 ranking_period",
			want: "排序周期无意义",
			yaml: topo + `
declarations:
  - id: d1
    mode: pinned_target
    target_node: t-a
    objective: stability
    tuning_period: 10m
    ranking_period: 30m`,
		},
		{
			name: "§4 模式 A 不应声明 equivalence_class",
			want: "目标轴已钉死",
			yaml: topo + `
equivalence_classes:
  - id: c1
    carrier: l4_direct
    observation_point: l4_tunnel
    members: [{node: t-a, access_contract: {}}]
declarations:
  - id: d1
    mode: pinned_target
    target_node: t-a
    equivalence_class: c1
    objective: stability
    tuning_period: 10m`,
		},
		{
			name: "§5.6 模式 B 缺 top_n",
			want: "显式声明 top_n",
			yaml: topo + `
equivalence_classes:
  - id: c1
    carrier: l4_direct
    observation_point: l4_tunnel
    members: [{node: t-a, access_contract: {}}]
declarations:
  - id: d1
    mode: by_service
    equivalence_class: c1
    objective: latency
    tuning_period: 10m`,
		},
		{
			name: "§7.2 Android 不应有 mixed_ports",
			want: "只能走 TUN",
			yaml: topo + `
declarations:
  - {id: d1, mode: pinned_target, target_node: t-a, objective: stability, tuning_period: 10m}
credentials:
  - {id: cr1, declaration: d1, secret_ref: v}
profiles:
  - id: p1
    platform: android
    credentials: [cr1]
    mixed_ports: [{port: 1080, declaration: d1}]`,
		},
		{
			name: "§18 Android 多凭据无法按端口区分",
			want: "无法按端口区分声明",
			yaml: topo + `
declarations:
  - {id: d1, mode: pinned_target, target_node: t-a, objective: stability, tuning_period: 10m}
credentials:
  - {id: cr1, declaration: d1, secret_ref: v}
  - {id: cr2, declaration: d1, secret_ref: v}
profiles:
  - {id: p1, platform: android, credentials: [cr1, cr2]}`,
		},
		{
			name: "§7.2 linux-server 没有 mixed 端口就接管不到流量",
			want: "接管不到任何流量",
			yaml: topo + `
declarations:
  - {id: d1, mode: pinned_target, target_node: t-a, objective: stability, tuning_period: 10m}
credentials:
  - {id: cr1, declaration: d1, secret_ref: v}
profiles:
  - {id: p1, platform: linux-server, credentials: [cr1]}`,
		},
		{
			name: "§18 引用已吊销的凭据",
			want: "已吊销",
			yaml: topo + `
declarations:
  - {id: d1, mode: pinned_target, target_node: t-a, objective: stability, tuning_period: 10m}
credentials:
  - {id: cr1, declaration: d1, secret_ref: v, revoked_at: "2026-01-01T00:00:00Z"}
profiles:
  - {id: p1, platform: desktop, credentials: [cr1], mixed_ports: [{port: 1080, declaration: d1}]}`,
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
			yaml: topo + `
declarations:
  - {id: d1, mode: pinned_target, target_node: t-a, objective: stability, tuning_period: 10m}
credentials:
  - {id: cr1, declaration: d1, secret_ref: v}
profiles:
  - id: p1
    platform: desktop
    credentials: [cr1]
    mixed_ports: [{port: 1080, declaration: ghost}]`,
		},
		{
			name: "§4.3 等价类成员不持有 target 能力",
			want: "不持有 target 能力",
			yaml: topo + `
equivalence_classes:
  - id: c1
    carrier: l4_direct
    observation_point: l4_tunnel
    members: [{node: relay-bj, access_contract: {}}]`,
		},
		{
			name: "§5.1 allowed_relays 里的节点不是中继",
			want: "不持有 relay 能力",
			yaml: topo + `
declarations:
  - id: d1
    mode: pinned_target
    target_node: t-a
    objective: stability
    tuning_period: 10m
    allowed_relays: [t-b]`,
		},
		{
			name: "§5.5 缺少 tuning_period",
			want: "缺少 tuning_period",
			yaml: topo + `
declarations:
  - {id: d1, mode: pinned_target, target_node: t-a, objective: stability}`,
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

// TestFallbackDefaultsToFailClosed:§5.8 的默认必须落在安全那一侧。
func TestFallbackDefaultsToFailClosed(t *testing.T) {
	s, err := model.Load([]byte(topo + `
declarations:
  - {id: d1, mode: pinned_target, target_node: t-a, objective: stability, tuning_period: 10m}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := s.Declarations[0].Fallback; got != model.FailClosed {
		t.Errorf("fallback 默认值是 %q,应为 fail_closed —— 空候选集需要人介入,不需要自动兜底", got)
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
