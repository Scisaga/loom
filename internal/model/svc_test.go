package model

import (
	"strings"
	"testing"
)

const svcSSOT = `
defaults: {dns: [223.5.5.5], distribution_url: "https://x/", components: {sing_box: 1, wireguard: 1, agent: 1}}
nodes:
  - id: acc
    public_endpoint: 1.1.1.9
    server: {direction: bidirectional, wg_public_key: aGVsbG93b3JsZGhlbGxvd29ybGRoZWxsb3dvcmxkMTI=}
    access:
      platform: linux-server
      credentials: [c1]
      mixed_ports: [{port: 1082, services: true}]
  - {id: a, public_endpoint: 1.1.1.1, server: {direction: bidirectional, inbound_port: 4433, egress_capable: true, wg_public_key: aGVsbG93b3JsZGhlbGxvd29ybGRoZWxsb3dvcmxkMTM=}}
  - {id: b, public_endpoint: 1.1.1.2, server: {direction: bidirectional, inbound_port: 4433, egress_capable: true, wg_public_key: aGVsbG93b3JsZGhlbGxvd29ybGRoZWxsb3dvcmxkMTQ=}}
declarations:
  - {id: d1, address_axis: from_request, egress_axis: any, objective: latency, probe_url: "https://t/", tuning_period: 5m, window: 1h, min_samples: 6, stale_after: 20m, max_hops: 1, allowed_servers: [a, b]}
credentials:
  - {id: c1, declaration: d1, secret_ref: "cred/c1"}
services:
  - {id: cn, declaration: d1, addresses: [www.baidu.com, .baidu.com]}
  - {id: intl, declaration: d1, addresses: [api.ipify.org]}
`

func loadSvc(t *testing.T) *SSOT {
	t.Helper()
	s, err := Load([]byte(svcSSOT))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// **同一条声明治理的多个服务必须各自独立选路。** 这是 D43 修正的核心:
// 共用一个 selector 就又回到"一个候选服务所有目标",而实测没有任何候选
// 对所有目标都好。
func TestServicesGetIndependentCandidateSets(t *testing.T) {
	s := loadSvc(t)
	acc := s.NodeByID()["acc"]
	d := s.DeclarationByID()["d1"]

	tags := map[string][]string{}
	for _, svc := range s.ServicesFor("d1") {
		cands, _ := s.EnumerateServiceCandidates(acc, d, svc)
		for i := range cands {
			tags[svc.ID] = append(tags[svc.ID], cands[i].Tag())
		}
	}
	if len(tags) != 2 {
		t.Fatalf("期望两个服务各有候选,得到 %v", tags)
	}
	// tag 里必须带服务 —— 否则两个服务的候选同名,就成了同一个 selector。
	for id, ts := range tags {
		if len(ts) == 0 {
			t.Errorf("服务 %s 没有候选", id)
		}
		for _, tag := range ts {
			if !strings.HasPrefix(tag, "cand:"+id+":") {
				t.Errorf("服务 %s 的候选 tag 不带服务名:%s", id, tag)
			}
		}
	}
	// 两个服务的候选集合不能有交集。
	seen := map[string]string{}
	for id, ts := range tags {
		for _, tag := range ts {
			if prev, dup := seen[tag]; dup {
				t.Errorf("服务 %s 与 %s 共用候选 %s —— 它们会共用一个 selector", id, prev, tag)
			}
			seen[tag] = id
		}
	}
}

// 服务只归组,不选地址 —— 挑地址是等价类的事(§4.3)。
func TestServiceCandidatesHaveNoAddressAxis(t *testing.T) {
	s := loadSvc(t)
	acc := s.NodeByID()["acc"]
	cands, _ := s.EnumerateServiceCandidates(acc, s.DeclarationByID()["d1"], s.ServiceByID()["cn"])
	for i := range cands {
		if cands[i].Address != "" {
			t.Errorf("服务候选带了地址轴:%s", cands[i].Tag())
		}
	}
	// 一个服务的候选数 = 链数,不随地址数变化。
	byDecl, _ := s.EnumerateCandidates(acc, s.DeclarationByID()["d1"])
	if len(cands) != len(byDecl) {
		t.Errorf("服务候选 %d 条,按声明枚举 %d 条 —— 应当一样(都是链)", len(cands), len(byDecl))
	}
}

func TestSuffixDetection(t *testing.T) {
	if !IsSuffix(".baidu.com") || IsSuffix("www.baidu.com") {
		t.Error("后缀判断不对")
	}
}

// 端口两种模式互斥,而且各自的语义要清楚。
func TestPortModes(t *testing.T) {
	s := loadSvc(t)
	mp := s.NodeByID()["acc"].Access.MixedPorts[0]
	if !mp.ByService() || mp.Declaration != "" {
		t.Errorf("按服务分流的端口不该绑声明:%+v", mp)
	}
}
