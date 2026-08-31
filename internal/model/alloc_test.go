package model

import (
	"strings"
	"testing"
)

func allocSSOT(t *testing.T) *SSOT {
	t.Helper()
	s, err := Load([]byte(`
defaults: {dns: [223.5.5.5], components: {sing_box: 1, wireguard: 1, agent: 1}}
nodes:
  - {id: cn1, public_endpoint: 1.1.1.1, server: {direction: bidirectional, inbound_port: 4433, wg_public_key: k1}}
  - {id: cn2, public_endpoint: 1.1.1.2, server: {direction: bidirectional, inbound_port: 4433, wg_public_key: k2}}
  - {id: v1,  public_endpoint: 2.2.2.1, server: {direction: reverse_only, inbound_port: 4433, wg_public_key: k3}}
  - {id: v2,  public_endpoint: 2.2.2.2, server: {direction: reverse_only, inbound_port: 4433, wg_public_key: k4}}
tunnels:
  - {from: cn1, to: v1, listen_port: 61637, from_addr: 10.99.0.1/32, to_addr: 10.99.0.2/32}
  - {from: cn2, to: v1, listen_port: 61619, from_addr: 10.99.0.3/32, to_addr: 10.99.0.4/32}
  - {from: cn1, to: v2, listen_port: 61682, from_addr: 10.99.1.1/32, to_addr: 10.99.1.2/32}
`))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// 恰好一端是 reverse_only 时才需要隧道。两端都能被公网拨到的直接互拨(D29),
// 两端都是 reverse_only 的建不起来(§2.2 真值表)。
func TestNeedsTunnel(t *testing.T) {
	s := allocSSOT(t)
	n := s.NodeByID()
	cases := []struct {
		a, b string
		want bool
	}{
		{"cn1", "v1", true},
		{"v1", "cn1", true},
		{"cn1", "cn2", false},
		{"v1", "v2", false},
	}
	for _, c := range cases {
		if got := NeedsTunnel(n[c.a], n[c.b]); got != c.want {
			t.Errorf("NeedsTunnel(%s,%s)=%v,期望 %v", c.a, c.b, got, c.want)
		}
	}
}

// 新的 reverse_only 节点要和每台 bidirectional 建隧道,反之亦然。
func TestTunnelPeersFor(t *testing.T) {
	s := allocSSOT(t)
	newVPS := &Node{ID: "v3", Server: &ServerRole{Direction: ReverseOnly}}
	peers := s.TunnelPeersFor(newVPS)
	var ids []string
	for _, p := range peers {
		ids = append(ids, p.ID)
	}
	if strings.Join(ids, ",") != "cn1,cn2" {
		t.Errorf("新 VPS 的对端是 %v,期望 cn1,cn2", ids)
	}
}

// /24 归 reverse_only 那一端 —— 现有部署就是这么排的(edge-a 占 10.99.0.x,
// edge-b 占 10.99.1.x)。新节点要落进对端已有的那个段,不能另起一个。
func TestAllocationReusesOwnersSubnet(t *testing.T) {
	s := allocSSOT(t)
	n := s.NodeByID()
	from, to, port, err := s.AllocateTunnel(n["cn2"], n["v2"])
	if err != nil {
		t.Fatal(err)
	}
	// v2 已经占了 10.99.1.x,新的一对必须也在那儿,而且接着 .1/.2 往后。
	if from != "10.99.1.3/32" || to != "10.99.1.4/32" {
		t.Errorf("分到 %s / %s,期望 10.99.1.3 / 10.99.1.4", from, to)
	}
	if port < TunnelPortMin || port > TunnelPortMax {
		t.Errorf("端口 %d 不在保留段内", port)
	}
	for i := range s.Tunnels {
		if s.Tunnels[i].ListenPort == port {
			t.Errorf("端口 %d 和已有隧道撞了", port)
		}
	}
}

// 全新的 reverse_only 节点拿一个空闲 /24。
func TestNewReverseOnlyGetsFreshSubnet(t *testing.T) {
	s := allocSSOT(t)
	n := s.NodeByID()
	v3 := &Node{ID: "v3", Server: &ServerRole{Direction: ReverseOnly}}
	from, _, _, err := s.AllocateTunnel(n["cn1"], v3)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(from, "10.99.2.") {
		t.Errorf("新 VPS 分到 %s,期望 10.99.2.x(0 和 1 已被占)", from)
	}
}

// **端口刻意不连号** —— 连号本身是个特征(deploy/README)。
// 所以不能是"上一个 +1"。
func TestPortsAreNotSequential(t *testing.T) {
	s := allocSSOT(t)
	n := s.NodeByID()
	_, _, p1, _ := s.AllocateTunnel(n["cn2"], n["v2"])
	max := 0
	for i := range s.Tunnels {
		if s.Tunnels[i].ListenPort > max {
			max = s.Tunnels[i].ListenPort
		}
	}
	if p1 == max+1 {
		t.Errorf("端口 %d 正好是已有最大值 +1 —— 连号是个特征", p1)
	}
}

// 确定性:跑两遍结果一样,而且与参数顺序无关。
func TestAllocationIsDeterministic(t *testing.T) {
	s := allocSSOT(t)
	n := s.NodeByID()
	f1, t1, p1, _ := s.AllocateTunnel(n["cn2"], n["v2"])
	f2, t2, p2, _ := s.AllocateTunnel(n["cn2"], n["v2"])
	if f1 != f2 || t1 != t2 || p1 != p2 {
		t.Error("跑两遍分到不同的东西")
	}
	// 换个参数顺序,端口应当不变(免得 A→B 和 B→A 算出两个)。
	_, _, p3, _ := s.AllocateTunnel(n["v2"], n["cn2"])
	if p1 != p3 {
		t.Errorf("换参数顺序端口变了:%d vs %d", p1, p3)
	}
}

// 不需要隧道的组合要明确拒绝,而不是分一对地址出来。
func TestRefusesUnneededTunnel(t *testing.T) {
	s := allocSSOT(t)
	n := s.NodeByID()
	if _, _, _, err := s.AllocateTunnel(n["cn1"], n["cn2"]); err == nil {
		t.Error("给两台公网可拨的机器分了隧道")
	}
	if _, _, _, err := s.AllocateTunnel(n["v1"], n["v2"]); err == nil {
		t.Error("给两台 reverse_only 分了隧道 —— 那建不起来")
	}
}

// **轮换必须记住换掉了什么。**
//
// 起因是实测:hz01 ↔ ber01 在某个端口上被单向丢包丢了 15.8 小时,换个端口
// 七分钟就通。而如果分配器不记退役端口,轮换两次就会转回那个已知不通的
// 端口 —— 症状是"换了端口还是不通",跟真实原因毫不相干。
func TestRotationNeverRevisitsARetiredPort(t *testing.T) {
	s := allocSSOT(t)
	seen := map[int]bool{}
	for i := range s.Tunnels {
		if s.Tunnels[i].From == "cn1" && s.Tunnels[i].To == "v1" {
			seen[s.Tunnels[i].ListenPort] = true
		}
	}

	// 连着轮换 20 次,每次都把结果写回去,模拟真实用法。
	for i := 0; i < 20; i++ {
		port, retired, err := s.RotateTunnelPort("cn1", "v1")
		if err != nil {
			t.Fatalf("第 %d 次轮换失败:%v", i+1, err)
		}
		if seen[port] {
			t.Fatalf("第 %d 次轮换转回了用过的端口 %d", i+1, port)
		}
		seen[port] = true
		for j := range s.Tunnels {
			if s.Tunnels[j].From == "cn1" && s.Tunnels[j].To == "v1" {
				s.Tunnels[j].ListenPort = port
				s.Tunnels[j].RetiredPorts = retired
			}
		}
	}
}

// **退役端口不只是被跳过,还要改变哈希起点。**
//
// 只跳不换起点的话,线性探测会挑中退役端口的紧邻位(61654 → 61655)——
// 而如果丢弃是按范围或邻近特征做的,那等于没换。
func TestRotationDoesNotLandNextToTheRetiredPort(t *testing.T) {
	s := allocSSOT(t)
	var old int
	for i := range s.Tunnels {
		if s.Tunnels[i].From == "cn1" && s.Tunnels[i].To == "v1" {
			old = s.Tunnels[i].ListenPort
		}
	}
	port, _, err := s.RotateTunnelPort("cn1", "v1")
	if err != nil {
		t.Fatal(err)
	}
	if port == old+1 || port == old-1 {
		t.Errorf("换到了退役端口的紧邻位:%d → %d", old, port)
	}
}

// **既有分配不能因为加了轮换而改变。** 没有退役端口时哈希输入与从前一致,
// 所以 `loom addnode` 对同一份 SSOT 给出的端口必须还是原来那个。
func TestNewAllocationUnchangedByRotationSupport(t *testing.T) {
	s := allocSSOT(t)
	n := s.NodeByID()
	_, _, got, err := s.AllocateTunnel(n["cn2"], n["v2"])
	if err != nil {
		t.Fatal(err)
	}
	// 直接问分配器要"没有退役端口"的结果,两者必须一致。
	want, err := s.allocPort("cn2", "v2", n["cn2"], nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("新建隧道的端口变了:%d ≠ %d", got, want)
	}
}

// 新隧道的 listen_port 和接受节点的 sing-box inbound 都会在同一台机器
// 上监听；分配器必须直接避开，而不是生成一份永远过不了 validate 的片段。
// 新节点尚未写进 SSOT，所以测试也要保证使用调用方传入的节点事实。
func TestAllocationAvoidsNewAcceptorInboundPort(t *testing.T) {
	s := allocSSOT(t)
	peer := s.NodeByID()["v1"]
	acceptor := &Node{ID: "cn3", Server: &ServerRole{Direction: Bidirectional}}

	_, _, baseline, err := s.AllocateTunnel(acceptor, peer)
	if err != nil {
		t.Fatal(err)
	}
	acceptor.Server.InboundPort = baseline
	_, _, got, err := s.AllocateTunnel(acceptor, peer)
	if err != nil {
		t.Fatal(err)
	}
	if got == acceptor.Server.InboundPort {
		t.Fatalf("新隧道端口 %d 与接受节点 inbound_port 冲突", got)
	}
}

// jm24 这一类既有 bidirectional 节点会接受新 reverse_only 节点发起的
// 隧道。即使新节点尚未加入 SSOT，分配也必须避开既有接受方的公网 inbound。
func TestAllocationForNewReverseOnlyAvoidsExistingAcceptorInboundPort(t *testing.T) {
	s := allocSSOT(t)
	acceptor := s.NodeByID()["cn2"]
	initiator := &Node{ID: "v3", Server: &ServerRole{Direction: ReverseOnly}}

	acceptor.Server.InboundPort = 0
	_, _, baseline, err := s.AllocateTunnel(initiator, acceptor)
	if err != nil {
		t.Fatal(err)
	}
	acceptor.Server.InboundPort = baseline
	_, _, got, err := s.AllocateTunnel(initiator, acceptor)
	if err != nil {
		t.Fatal(err)
	}
	if got == acceptor.Server.InboundPort {
		t.Fatalf("新 reverse_only 隧道端口 %d 与既有接受节点 inbound_port 冲突", got)
	}
}

// rotate 使用同一个确定性起点；若新配置的 inbound_port 正好落在那里，
// 它也必须向后寻找下一个端口，否则每次重试都会得到同一份无效建议。
func TestRotationAvoidsAcceptorInboundPort(t *testing.T) {
	s := allocSSOT(t)
	acceptor := s.NodeByID()["cn1"]
	acceptor.Server.InboundPort = 0
	baseline, _, err := s.RotateTunnelPort("cn1", "v1")
	if err != nil {
		t.Fatal(err)
	}
	acceptor.Server.InboundPort = baseline
	got, _, err := s.RotateTunnelPort("v1", "cn1")
	if err != nil {
		t.Fatal(err)
	}
	if got == acceptor.Server.InboundPort {
		t.Fatalf("轮换端口 %d 与接受节点 inbound_port 冲突", got)
	}
}

// 轮换本身也要确定性:同样的输入跑两遍给同一个端口。
func TestRotationIsDeterministic(t *testing.T) {
	s := allocSSOT(t)
	p1, r1, err := s.RotateTunnelPort("cn1", "v1")
	if err != nil {
		t.Fatal(err)
	}
	p2, r2, err := s.RotateTunnelPort("v1", "cn1") // 顺序无关
	if err != nil {
		t.Fatal(err)
	}
	if p1 != p2 || len(r1) != len(r2) {
		t.Errorf("跑两遍(且换了参数顺序)结果不同:%d/%v vs %d/%v", p1, r1, p2, r2)
	}
}

// 没有那条隧道时要明确报错,而不是分一个端口出来。
func TestRotateRefusesUnknownTunnel(t *testing.T) {
	s := allocSSOT(t)
	if _, _, err := s.RotateTunnelPort("cn1", "cn2"); err == nil {
		t.Fatal("两个节点之间没有隧道,却轮换成功了")
	} else if !strings.Contains(err.Error(), "没有隧道") {
		t.Errorf("报错没说清:%v", err)
	}
}
