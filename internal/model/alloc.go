package model

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"
	"sort"
)

// 本文件给新隧道分配地址与端口。
//
// **手工分配是个真实的错误来源** —— 我自己配 6 条时校验器抓到过冲突。
// 这里的规则不是发明的,是从现有 SSOT 里读出来的,改动会让已有部署失配。

// TunnelBase 是隧道内网段。每个 reverse_only 节点占其中一个 /24。
const tunnelBase = "10.99."

// NeedsTunnel 报告两个节点之间该不该有隧道。
//
// **恰好一端是 reverse_only 时才需要**(§2.2、§6.3):
//
//	rev ↔ rev   非法 —— 双方都要发起,无人接受
//	bi  ↔ rev   需要 —— rev 拨不进去,只能自己拨出来
//	bi  ↔ bi    不需要 —— 两台都能被公网拨到,直接互拨(D29)
func NeedsTunnel(a, b *Node) bool {
	if !a.IsServer() || !b.IsServer() {
		return false
	}
	ra := a.Server.Direction == ReverseOnly
	rb := b.Server.Direction == ReverseOnly
	return ra != rb
}

// TunnelPeersFor 列出一个节点(可能还不在 SSOT 里)需要建隧道的对端,按 id 排序。
func (s *SSOT) TunnelPeersFor(n *Node) []*Node {
	var out []*Node
	for i := range s.Nodes {
		p := &s.Nodes[i]
		if p.ID == n.ID || !NeedsTunnel(n, p) {
			continue
		}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// AllocateTunnel 为一对节点算出地址与端口。
//
// 确定性的:同样的输入永远得到同样的输出。跑两遍不会换一套答案,两个人
// 各跑一遍也一致 —— 这不是纯函数渲染的要求(分配发生在生成片段时,不在
// 渲染时),但"再跑一次结果就变了"是个很讨厌的性质。
func (s *SSOT) AllocateTunnel(a, b *Node) (fromAddr, toAddr string, port int, err error) {
	if !NeedsTunnel(a, b) {
		return "", "", 0, fmt.Errorf("%s 与 %s 之间不需要隧道 —— 两端都能被公网拨到,直接互拨即可(D29)", a.ID, b.ID)
	}
	// /24 归 reverse_only 那一端。现有 SSOT 就是这么排的:
	// edge-a 占 10.99.0.x,edge-b 占 10.99.1.x。
	owner := a
	if b.Server.Direction == ReverseOnly {
		owner = b
	}
	octet, err := s.subnetFor(owner)
	if err != nil {
		return "", "", 0, err
	}
	lo, err := s.nextPair(octet)
	if err != nil {
		return "", "", 0, err
	}
	port, err = s.allocPort(a.ID, b.ID, nil)
	if err != nil {
		return "", "", 0, err
	}
	return fmt.Sprintf("%s%d.%d/32", tunnelBase, octet, lo),
		fmt.Sprintf("%s%d.%d/32", tunnelBase, octet, lo+1), port, nil
}

// subnetFor 找出某个 reverse_only 节点占的 /24;没有就分一个新的。
func (s *SSOT) subnetFor(owner *Node) (int, error) {
	used := map[int]bool{}
	for i := range s.Tunnels {
		t := &s.Tunnels[i]
		for _, a := range []string{t.FromAddr, t.ToAddr} {
			if o, ok := octetOf(a); ok {
				used[o] = true
				if t.From == owner.ID || t.To == owner.ID {
					return o, nil
				}
			}
		}
	}
	for o := 0; o < 256; o++ {
		if !used[o] {
			return o, nil
		}
	}
	return 0, fmt.Errorf("%s 段里没有空闲的 /24 了", tunnelBase)
}

// nextPair 在某个 /24 里找下一对空闲地址。
//
// **成对分配,低位在前** —— 现有 SSOT 用的就是 .1/.2、.3/.4、.5/.6。
// 隧道内地址不怕连号(它们不在公网上,扫不到),所以这里追求可读。
func (s *SSOT) nextPair(octet int) (int, error) {
	used := map[int]bool{}
	for i := range s.Tunnels {
		for _, a := range []string{s.Tunnels[i].FromAddr, s.Tunnels[i].ToAddr} {
			if o, ok := octetOf(a); ok && o == octet {
				if h, ok := hostOf(a); ok {
					used[h] = true
				}
			}
		}
	}
	for h := 1; h < 254; h += 2 {
		if !used[h] && !used[h+1] {
			return h, nil
		}
	}
	return 0, fmt.Errorf("%s%d.0/24 里没有空闲地址对了", tunnelBase, octet)
}

// allocPort 在保留段里挑一个端口,跳过已用的和已退役的。
//
// **刻意不连号。** 连号本身是个特征(见 deploy/README)。所以从节点对的
// 哈希起步,而不是从上一个端口 +1;撞了就线性向后探,保持确定性。
//
// **退役端口既被跳过,也改变哈希起点。** 只跳不换起点的话,线性探测会挑中
// 退役端口的紧邻位(61654 → 61655)—— 而如果丢弃是按范围或邻近特征做的,
// 那等于没换。退役个数进哈希,每轮换一次就得到一个全新的、分布均匀的起点。
//
// 没有退役端口时哈希输入与从前完全一致,所以既有分配不会因为这个改动而变。
func (s *SSOT) allocPort(a, b string, retired []int) (int, error) {
	blocked := map[int]bool{}
	for i := range s.Tunnels {
		blocked[s.Tunnels[i].ListenPort] = true
	}
	for _, p := range retired {
		blocked[p] = true
	}
	span := TunnelPortMax - TunnelPortMin + 1
	pair := a + "|" + b
	if b < a {
		pair = b + "|" + a // 与顺序无关,免得 A→B 和 B→A 算出两个端口
	}
	if len(retired) > 0 {
		pair = fmt.Sprintf("%s|%d", pair, len(retired))
	}
	h := sha256.Sum256([]byte(pair))
	start := int(binary.BigEndian.Uint32(h[:4]) % uint32(span))
	for i := 0; i < span; i++ {
		p := TunnelPortMin + (start+i)%span
		if !blocked[p] {
			return p, nil
		}
	}
	return 0, fmt.Errorf("保留段 %d-%d 里没有空闲端口了(已退役 %d 个)",
		TunnelPortMin, TunnelPortMax, len(retired))
}

// RotateTunnelPort 给一条已有隧道换一个端口,并把旧端口记进退役名单。
//
// **换端口是修复也是诊断。** 实测过一次:hz01 ↔ ber01 在原端口上被单向
// 丢包 15.8 小时,配置、IP 可达性、UDP 封锁、包内容全都排除了,换端口
// 七分钟就通。但"这条流被标记了"和"某处状态坏了"两个假设对换端口的反应
// 一样 —— 判据是能撑多久,所以每次换都值得记下时间和理由。
//
// 它**只算不写**:返回新端口与新的退役名单,由调用方决定怎么落进 SSOT。
// 与 `AllocateTunnel` 同一个道理 —— SSOT 是人的声明,工具给料,不代笔。
func (s *SSOT) RotateTunnelPort(a, b string) (port int, retired []int, err error) {
	t := s.tunnelBetween(a, b)
	if t == nil {
		return 0, nil, fmt.Errorf("%s 与 %s 之间没有隧道", a, b)
	}
	retired = append(append([]int(nil), t.RetiredPorts...), t.ListenPort)
	sort.Ints(retired)
	port, err = s.allocPort(t.From, t.To, retired)
	if err != nil {
		return 0, nil, err
	}
	return port, retired, nil
}

// tunnelBetween 找两个节点之间的隧道,与写的顺序无关。
func (s *SSOT) tunnelBetween(a, b string) *Tunnel {
	for i := range s.Tunnels {
		t := &s.Tunnels[i]
		if (t.From == a && t.To == b) || (t.From == b && t.To == a) {
			return t
		}
	}
	return nil
}

func octetOf(cidr string) (int, bool) {
	ip, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return 0, false
	}
	v4 := ip.To4()
	if v4 == nil || v4[0] != 10 || v4[1] != 99 {
		return 0, false
	}
	return int(v4[2]), true
}

func hostOf(cidr string) (int, bool) {
	ip, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return 0, false
	}
	v4 := ip.To4()
	if v4 == nil {
		return 0, false
	}
	return int(v4[3]), true
}
