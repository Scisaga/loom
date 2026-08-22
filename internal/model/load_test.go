package model

import "strings"
import "testing"

// TestLoadRejectsDerivedFields 是 §2.2 与 §19"校验器应拒绝手工指定推导值"
// 的第一道闸:严格解码让这些键根本无法被写进 SSOT。
//
// 如果它们被静默忽略,SSOT 里会留下一个看起来生效、实际不生效的声明 ——
// 这比报错糟得多。
func TestLoadRejectsDerivedFields(t *testing.T) {
	cases := map[string]string{
		"mesh_eligible": `
nodes:
  - id: n1
    capabilities: [server]
    direction: bidirectional
    mesh_eligible: true
`,
		"tunnel initiator": `
nodes:
  - id: n1
    capabilities: [server]
    direction: bidirectional
tunnels:
  - from: n1
    to: n1
    initiator: n1
`,
		"任意拼写错误": `
nodes:
  - id: n1
    capabilities: [server]
    directoin: bidirectional
`,
		"目标写成节点": `
nodes:
  - id: api
    capabilities: [server]
    direction: direct_only
    target_kind: endpoint
`,
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Load([]byte(src)); err == nil {
				t.Fatal("期望解码失败,实际成功")
			}
		})
	}
}

func TestLoadDefaults(t *testing.T) {
	s, err := Load([]byte(`
nodes:
  - {id: n1, capabilities: [server], direction: bidirectional}
  - {id: n2, capabilities: [server], direction: reverse_only}
tunnels:
  - {from: n1, to: n2, listen_port: 61611, from_addr: 10.0.0.1/32, to_addr: 10.0.0.2/32}
declarations:
  - {id: d1, objective: latency, tuning_period: 10m}
`))
	if err != nil {
		t.Fatal(err)
	}
	if got := s.Tunnels[0].Protocol; got != WG {
		t.Errorf("protocol 未声明时应默认为 wg,得到 %q", got)
	}
	d := &s.Declarations[0]
	// 两个轴的默认值都落在"最少假设"那一侧(§4)。
	if d.AddressAxis != FromRequest {
		t.Errorf("address_axis 默认应为 from_request,得到 %q", d.AddressAxis)
	}
	if d.EgressAxis != EgressAny {
		t.Errorf("egress_axis 默认应为 any,得到 %q", d.EgressAxis)
	}
	if d.Fallback != FailClosed {
		t.Errorf("fallback 默认应为 fail_closed,得到 %q", d.Fallback)
	}
}

// TestMeshEligibleIsDerived:能否进 mesh 由 direction 推导,直接决定
// 隧道矩阵有多大(§6.3、D13)。
func TestMeshEligibleIsDerived(t *testing.T) {
	for _, tc := range []struct {
		d    Direction
		mesh bool
		dial bool
	}{
		{Bidirectional, true, true},
		{DirectOnly, true, true},
		{ReverseOnly, false, false}, // 进不了 mesh,也拨不到
	} {
		n := &Node{ID: "n", Direction: tc.d, PublicEndpoint: "1.1.1.1", InboundPort: 1}
		if got := n.MeshEligible(); got != tc.mesh {
			t.Errorf("%s.MeshEligible() = %v,期望 %v", tc.d, got, tc.mesh)
		}
		if got := n.DialableFromAccess(); got != tc.dial {
			t.Errorf("%s.DialableFromAccess() = %v,期望 %v", tc.d, got, tc.dial)
		}
	}
}

// TestAxesParsing:两个轴的取值解析(§4)。
func TestAxesParsing(t *testing.T) {
	d := &AccessDeclaration{AddressAxis: "class:llm:qwen3@v1", EgressAxis: "pinned:sg-vps"}
	if got := d.ClassID(); got != "llm:qwen3@v1" {
		t.Errorf("ClassID() = %q", got)
	}
	if got := d.PinnedEgress(); got != "sg-vps" {
		t.Errorf("PinnedEgress() = %q", got)
	}
	if d.AddressFromRequest() {
		t.Error("class: 形式不应报告为 from_request")
	}
	plain := &AccessDeclaration{AddressAxis: FromRequest, EgressAxis: EgressAny}
	if plain.ClassID() != "" || plain.PinnedEgress() != "" {
		t.Error("from_request/any 不应解析出 id")
	}
	if a, e := plain.AxesValid(); !a || !e {
		t.Error("from_request/any 应当合法")
	}
	if a, _ := (&AccessDeclaration{AddressAxis: "bogus"}).AxesValid(); a {
		t.Error("未知 address_axis 应当非法")
	}
}

func TestLoadIsDeterministic(t *testing.T) {
	src := []byte(`
nodes:
  - id: n1
    capabilities: [server]
    direction: bidirectional
`)
	a, err := Load(src)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Load(src)
	if err != nil {
		t.Fatal(err)
	}
	if a.Nodes[0].ID != b.Nodes[0].ID || len(a.Nodes) != len(b.Nodes) {
		t.Error("两次加载结果不同")
	}
	if strings.TrimSpace(string(a.Nodes[0].Direction)) == "" {
		t.Error("direction 丢失")
	}
}
