package validate

import (
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
			name: "§2.2 两端都是 reverse_only",
			want: "无人接受",
			yaml: `
nodes:
  - {id: a, capabilities: [target], direction: reverse_only, public_endpoint: 1.1.1.1, wg_public_key: k1}
  - {id: b, capabilities: [target], direction: reverse_only, public_endpoint: 1.1.1.2, wg_public_key: k2}
tunnels:
  - {from: a, to: b, listen_port: 1, from_addr: 10.0.0.1/32, to_addr: 10.0.0.2/32}`,
		},
		{
			name: "§2.2 两端都是 direct_only",
			want: "无人发起",
			yaml: `
nodes:
  - {id: a, capabilities: [target], direction: direct_only, public_endpoint: 1.1.1.1, wg_public_key: k1}
  - {id: b, capabilities: [target], direction: direct_only, public_endpoint: 1.1.1.2, wg_public_key: k2}
tunnels:
  - {from: a, to: b, listen_port: 1, from_addr: 10.0.0.1/32, to_addr: 10.0.0.2/32}`,
		},
		{
			name: "§2.2 relay 与 reverse_only 不相容",
			want: "二者不相容",
			yaml: `
nodes:
  - {id: a, capabilities: [relay], direction: reverse_only}`,
		},
		{
			name: "§1.3 第三方端点必须是 direct_only",
			want: "必须是 direct_only",
			yaml: `
nodes:
  - {id: a, capabilities: [target], direction: bidirectional, managed: false}`,
		},
		{
			name: "§9.2 第三方端点不能作隧道端点",
			want: "不参与配置渲染",
			yaml: `
nodes:
  - {id: a, capabilities: [relay], direction: bidirectional, public_endpoint: 1.1.1.1, wg_public_key: k1}
  - {id: b, capabilities: [target], direction: direct_only, managed: false, public_endpoint: 1.1.1.2}
tunnels:
  - {from: a, to: b, listen_port: 1, from_addr: 10.0.0.1/32, to_addr: 10.0.0.2/32}`,
		},
		{
			name: "§15.1 同一接受方端口冲突",
			want: "已被",
			yaml: `
nodes:
  - {id: acc, capabilities: [relay], direction: bidirectional, public_endpoint: 1.1.1.1, wg_public_key: k0}
  - {id: t1, capabilities: [target], direction: reverse_only, public_endpoint: 1.1.1.2, wg_public_key: k1}
  - {id: t2, capabilities: [target], direction: reverse_only, public_endpoint: 1.1.1.3, wg_public_key: k2}
tunnels:
  - {from: acc, to: t1, listen_port: 51820, from_addr: 10.0.0.1/32, to_addr: 10.0.0.2/32}
  - {from: acc, to: t2, listen_port: 51820, from_addr: 10.0.0.3/32, to_addr: 10.0.0.4/32}`,
		},
		{
			name: "§20.1 地址撞车",
			want: "已被",
			yaml: `
nodes:
  - {id: acc, capabilities: [relay], direction: bidirectional, public_endpoint: 1.1.1.1, wg_public_key: k0}
  - {id: t1, capabilities: [target], direction: reverse_only, public_endpoint: 1.1.1.2, wg_public_key: k1}
  - {id: t2, capabilities: [target], direction: reverse_only, public_endpoint: 1.1.1.3, wg_public_key: k2}
tunnels:
  - {from: acc, to: t1, listen_port: 1, from_addr: 10.0.0.1/32, to_addr: 10.0.0.2/32}
  - {from: acc, to: t2, listen_port: 2, from_addr: 10.0.0.1/32, to_addr: 10.0.0.3/32}`,
		},
		{
			name: "§20.1 非 /32 会让 AllowedIPs 越界",
			want: "应为 /32",
			yaml: `
nodes:
  - {id: a, capabilities: [relay], direction: bidirectional, public_endpoint: 1.1.1.1, wg_public_key: k1}
  - {id: b, capabilities: [target], direction: reverse_only, public_endpoint: 1.1.1.2, wg_public_key: k2}
tunnels:
  - {from: a, to: b, listen_port: 1, from_addr: 10.0.0.0/24, to_addr: 10.0.1.2/32}`,
		},
		{
			name: "§20.1 接受方无 public_endpoint 则发起方无处可拨",
			want: "无处可拨",
			yaml: `
nodes:
  - {id: a, capabilities: [relay], direction: bidirectional, wg_public_key: k1}
  - {id: b, capabilities: [target], direction: reverse_only, public_endpoint: 1.1.1.2, wg_public_key: k2}
tunnels:
  - {from: a, to: b, listen_port: 1, from_addr: 10.0.0.1/32, to_addr: 10.0.0.2/32}`,
		},
		{
			name: "§13.1 缺少公钥",
			want: "缺少 wg_public_key",
			yaml: `
nodes:
  - {id: a, capabilities: [relay], direction: bidirectional, public_endpoint: 1.1.1.1}
  - {id: b, capabilities: [target], direction: reverse_only, public_endpoint: 1.1.1.2, wg_public_key: k2}
tunnels:
  - {from: a, to: b, listen_port: 1, from_addr: 10.0.0.1/32, to_addr: 10.0.0.2/32}`,
		},
		{
			name: "§6.3 同一对节点重复建隧道",
			want: "重复",
			yaml: `
nodes:
  - {id: a, capabilities: [relay], direction: bidirectional, public_endpoint: 1.1.1.1, wg_public_key: k1}
  - {id: b, capabilities: [target], direction: reverse_only, public_endpoint: 1.1.1.2, wg_public_key: k2}
tunnels:
  - {from: a, to: b, listen_port: 1, from_addr: 10.0.0.1/32, to_addr: 10.0.0.2/32}
  - {from: b, to: a, listen_port: 2, from_addr: 10.0.0.3/32, to_addr: 10.0.0.4/32}`,
		},
		{
			name: "§20.1 接口名超长",
			want: "超过 15 字符",
			yaml: `
nodes:
  - {id: a, capabilities: [relay], direction: bidirectional, public_endpoint: 1.1.1.1, wg_public_key: k1}
  - {id: target-in-a-very-long-city, capabilities: [target], direction: reverse_only, public_endpoint: 1.1.1.2, wg_public_key: k2}
tunnels:
  - {from: a, to: target-in-a-very-long-city, listen_port: 1, from_addr: 10.0.0.1/32, to_addr: 10.0.0.2/32}`,
		},
		{
			name: "§1.1 能力集不能为空",
			want: "capabilities 为空",
			yaml: `
nodes:
  - {id: a, capabilities: [], direction: bidirectional}`,
		},
		{
			name: "§19 节点 id 重复",
			want: "id 重复",
			yaml: `
nodes:
  - {id: a, capabilities: [relay], direction: bidirectional}
  - {id: a, capabilities: [relay], direction: bidirectional}`,
		},
		{
			name: "隧道引用了不存在的节点",
			want: "不存在的节点",
			yaml: `
nodes:
  - {id: a, capabilities: [relay], direction: bidirectional, public_endpoint: 1.1.1.1, wg_public_key: k1}
tunnels:
  - {from: a, to: ghost, listen_port: 1, from_addr: 10.0.0.1/32, to_addr: 10.0.0.2/32}`,
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
  - {id: z, capabilities: [], direction: bogus}
  - {id: a, capabilities: [relay], direction: reverse_only}
  - {id: m, capabilities: [target], direction: bidirectional, managed: false}`)
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
