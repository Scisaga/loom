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
    capabilities: [relay]
    direction: bidirectional
    mesh_eligible: true
`,
		"tunnel initiator": `
nodes:
  - id: n1
    capabilities: [relay]
    direction: bidirectional
tunnels:
  - from: n1
    to: n1
    initiator: n1
`,
		"任意拼写错误": `
nodes:
  - id: n1
    capabilities: [relay]
    directoin: bidirectional
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
  - id: n1
    capabilities: [target]
    direction: direct_only
  - id: n2
    capabilities: [target]
    direction: direct_only
    managed: false
tunnels:
  - {from: n1, to: n2, listen_port: 1, from_addr: 10.0.0.1/32, to_addr: 10.0.0.2/32}
`))
	if err != nil {
		t.Fatal(err)
	}
	if !s.Nodes[0].IsManaged() {
		t.Error("managed 未声明时应默认为 true")
	}
	if s.Nodes[1].IsManaged() {
		t.Error("managed: false 应被保留")
	}
	if got := s.Tunnels[0].Protocol; got != WG {
		t.Errorf("protocol 未声明时应默认为 wg,得到 %q", got)
	}
}

func TestLoadIsDeterministic(t *testing.T) {
	src := []byte(`
nodes:
  - id: n1
    capabilities: [relay]
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
