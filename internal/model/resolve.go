package model

import "fmt"

// LinuxIfnameMax 是 Linux 网络接口名的可用长度上限(IFNAMSIZ 16,含结尾 NUL)。
const LinuxIfnameMax = 15

// IfaceName 是节点上承载"到 peer 的隧道"的接口名。
//
// 每条隧道一个接口,而不是一个接口挂多个 peer。理由是 §17 的混淆参数
// 是接口级的:Jc/S1-S4/H1-H4 无法按 peer 区分,共用接口就无法按隧道
// 独立设置。这也是 §20.1 说 12 条隧道产生 24 个文件的原因。
func IfaceName(peerID string) string { return "wg-" + peerID }

// SecretPath 是节点本地私钥的约定路径。
//
// 渲染层只写这个引用,私钥本身属于秘密层,不进 SSOT、不进快照(§12.1)。
// 用 %i 让 wg-quick 自己展开接口名,避免文件名与接口名在两处各写一遍。
const SecretPath = "/etc/loom/secrets/%i.key"

// ResolvedTunnel 是一条隧道加上从 direction 推导出的角色分配。
//
// 渲染与校验都基于它,以保证"两端严格对应"这件事只有一处实现。
type ResolvedTunnel struct {
	*Tunnel

	// Initiator 主动发起并维持隧道;Acceptor 监听等待。
	Initiator *Node
	Acceptor  *Node

	// InitiatorAddr/AcceptorAddr 是各自在隧道内的地址,已按角色对齐。
	InitiatorAddr string
	AcceptorAddr  string
}

// Resolve 把一条隧道的两端解析成具体节点并推导角色。
func Resolve(t *Tunnel, idx map[string]*Node) (*ResolvedTunnel, error) {
	from, ok := idx[t.From]
	if !ok {
		return nil, fmt.Errorf("隧道 %s:from 引用了不存在的节点 %q", t.Pair(), t.From)
	}
	to, ok := idx[t.To]
	if !ok {
		return nil, fmt.Errorf("隧道 %s:to 引用了不存在的节点 %q", t.Pair(), t.To)
	}

	fromInitiates, err := ResolveInitiator(from.ID, from.Direction, to.ID, to.Direction)
	if err != nil {
		return nil, err
	}

	r := &ResolvedTunnel{Tunnel: t}
	if fromInitiates {
		r.Initiator, r.InitiatorAddr = from, t.FromAddr
		r.Acceptor, r.AcceptorAddr = to, t.ToAddr
	} else {
		r.Initiator, r.InitiatorAddr = to, t.ToAddr
		r.Acceptor, r.AcceptorAddr = from, t.FromAddr
	}
	return r, nil
}

// ResolveAll 解析全部隧道,遇到第一个错误即返回。
func (s *SSOT) ResolveAll() ([]*ResolvedTunnel, error) {
	idx := s.NodeByID()
	out := make([]*ResolvedTunnel, 0, len(s.Tunnels))
	for i := range s.Tunnels {
		r, err := Resolve(&s.Tunnels[i], idx)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}
