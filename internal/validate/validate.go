// Package validate 在渲染之前拒绝不一致的 SSOT。
//
// 它存在的理由见 design.md §20.1:隧道矩阵两端必须逐字段吻合,写错一个
// 字符的后果是隧道静默不通 —— 不报错,只是连不上。校验器把这类错误从
// "两地之间来回比对"降级成一条编译期消息。
//
// 校验返回全部发现而非第一个错误。修一个 24 文件的矩阵时,一次看到
// 所有问题比修一次跑一次重要。
package validate

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"loom/internal/model"
)

// Finding 是一条校验发现。Rule 对应 design.md 中的条款,便于回溯理由。
type Finding struct {
	Rule  string // 如 "§2.2 direction"
	Where string // 节点 id 或隧道 pair
	Msg   string
}

func (f Finding) String() string { return fmt.Sprintf("[%s] %s:%s", f.Rule, f.Where, f.Msg) }

type findings []Finding

func (fs *findings) add(rule, where, format string, args ...any) {
	*fs = append(*fs, Finding{Rule: rule, Where: where, Msg: fmt.Sprintf(format, args...)})
}

// Validate 检查整份 SSOT,返回按 (Where, Rule) 排序的稳定结果。
func Validate(s *model.SSOT) []Finding {
	var fs findings
	idx := checkNodes(s, &fs)
	checkTunnels(s, idx, &fs)
	checkService(s, idx, &fs)

	sort.SliceStable(fs, func(i, j int) bool {
		if fs[i].Where != fs[j].Where {
			return fs[i].Where < fs[j].Where
		}
		return fs[i].Rule < fs[j].Rule
	})
	return fs
}

func checkNodes(s *model.SSOT, fs *findings) map[string]*model.Node {
	idx := make(map[string]*model.Node, len(s.Nodes))
	for i := range s.Nodes {
		n := &s.Nodes[i]
		where := n.ID
		if where == "" {
			where = fmt.Sprintf("nodes[%d]", i)
			fs.add("§19 schema", where, "节点缺少 id")
		}
		if _, dup := idx[n.ID]; dup && n.ID != "" {
			fs.add("§19 schema", where, "节点 id 重复")
		}
		if n.ID != "" {
			idx[n.ID] = n
		}

		if len(n.Capabilities) == 0 {
			fs.add("§1.1 capabilities", where, "capabilities 为空 —— 能力是集合,但不能是空集")
		}
		for _, c := range n.Capabilities {
			if !c.Valid() {
				fs.add("§1.1 capabilities", where, "未知能力 %q(只能是 access/relay/target)", c)
			}
		}

		if !n.Direction.Valid() {
			fs.add("§2.1 direction", where, "direction 非法:%q", n.Direction)
			continue // 后面的规则都依赖 direction 有效
		}

		// §2.2:relay 必须接受接入节点连接,reverse_only 禁止被主动连接。
		if n.Has(model.Relay) && n.Direction == model.ReverseOnly {
			fs.add("§2.2 相容性", where,
				"同时持有 relay 能力与 reverse_only —— 中继必须接受入站连接(§8.1),二者不相容")
		}

		// §1.3:第三方端点没有 Agent,只能被观测,方向恒为 direct_only。
		if !n.IsManaged() && n.Direction != model.DirectOnly {
			fs.add("§1.3 managed", where,
				"managed: false 的第三方端点 direction 必须是 direct_only,当前是 %q", n.Direction)
		}
		if !n.IsManaged() && n.WGPublicKey != "" {
			fs.add("§1.3 managed", where,
				"managed: false 的节点不应有 wg_public_key —— 你无法在别人的服务上装任何东西")
		}

		if n.TargetKind != "" && !n.Has(model.Target) {
			fs.add("§1.3 target_kind", where, "声明了 target_kind 但不持有 target 能力")
		}
		switch n.TargetKind {
		case "", model.Landing, model.Endpoint:
		default:
			fs.add("§1.3 target_kind", where, "未知 target_kind:%q", n.TargetKind)
		}
	}
	return idx
}

func checkTunnels(s *model.SSOT, idx map[string]*model.Node, fs *findings) {
	seenPair := map[string]string{} // 无序节点对 -> 首次出现的 pair
	seenAddr := map[string]string{} // 隧道内地址 -> 占用者
	seenPort := map[string]string{} // "节点/端口" -> 占用者

	// sing-box inbound 端口先占位,这样 WG 监听口撞上它时能报出来。
	// 同一台机器上两个进程抢同一个端口,后起的那个静默失败。
	for i := range s.Nodes {
		if n := &s.Nodes[i]; n.InboundPort > 0 {
			seenPort[fmt.Sprintf("%s/%d", n.ID, n.InboundPort)] = n.ID + " 的 sing-box inbound"
		}
	}

	for i := range s.Tunnels {
		t := &s.Tunnels[i]
		where := t.Pair()

		if !t.Protocol.Valid() {
			fs.add("§6 protocol", where, "未知协议:%q", t.Protocol)
		}
		if t.From == t.To {
			fs.add("§6.3 矩阵", where, "隧道两端是同一个节点")
			continue
		}

		// 无序对去重:relay-bj→target-sg 与 target-sg→relay-bj 是同一条边。
		key := t.From + "\x00" + t.To
		if t.To < t.From {
			key = t.To + "\x00" + t.From
		}
		if first, dup := seenPair[key]; dup {
			fs.add("§6.3 矩阵", where, "与 %s 重复 —— 同一对节点之间只能有一条隧道", first)
			continue
		}
		seenPair[key] = where

		r, err := model.Resolve(t, idx)
		if err != nil {
			// Resolve 的失败要么是引用不存在的节点,要么是 §2.2 的非法组合。
			fs.add("§2.2 direction", where, "%v", err)
			continue
		}

		// §9.2:第三方端点不参与配置渲染,自然也不能是隧道的一端。
		for _, n := range []*model.Node{r.Initiator, r.Acceptor} {
			if !n.IsManaged() {
				fs.add("§9.2 managed", where,
					"节点 %s 是 managed: false 的第三方端点,不参与配置渲染,不能作为隧道端点", n.ID)
			}
		}

		checkAddr(where, "from_addr", t.FromAddr, seenAddr, fs)
		checkAddr(where, "to_addr", t.ToAddr, seenAddr, fs)
		if t.FromAddr != "" && t.FromAddr == t.ToAddr {
			fs.add("§20.1 对应", where, "两端地址相同:%s", t.FromAddr)
		}

		// 端口只在接受方生效。发起方不监听。
		switch {
		case t.ListenPort <= 0 || t.ListenPort > 65535:
			fs.add("§15.1 端口", where, "listen_port 非法:%d", t.ListenPort)
		default:
			pk := fmt.Sprintf("%s/%d", r.Acceptor.ID, t.ListenPort)
			if first, dup := seenPort[pk]; dup {
				fs.add("§15.1 端口冲突", where,
					"接受方 %s 的端口 %d 已被 %s 占用", r.Acceptor.ID, t.ListenPort, first)
			}
			seenPort[pk] = where
		}

		// 发起方需要写 Endpoint = <接受方公网地址>:<端口>,所以接受方必须可达。
		if r.Acceptor.PublicEndpoint == "" {
			fs.add("§20.1 对应", where,
				"接受方 %s 缺少 public_endpoint —— 发起方 %s 无处可拨",
				r.Acceptor.ID, r.Initiator.ID)
		}

		if t.Protocol == model.WG || t.Protocol == model.AWG {
			for _, n := range []*model.Node{r.Initiator, r.Acceptor} {
				if n.IsManaged() && n.WGPublicKey == "" {
					fs.add("§13.1 密钥", where, "节点 %s 缺少 wg_public_key", n.ID)
				}
			}
		}

		// 接口名由对端 id 派生,超长会在 ip link 阶段才失败 —— 提前拦。
		for _, n := range []*model.Node{r.Initiator, r.Acceptor} {
			peer := r.Initiator.ID
			if n == r.Initiator {
				peer = r.Acceptor.ID
			}
			if ifn := model.IfaceName(peer); len(ifn) > model.LinuxIfnameMax {
				fs.add("§20.1 对应", where,
					"节点 %s 上的接口名 %q 超过 %d 字符 —— 缩短节点 id %q",
					n.ID, ifn, model.LinuxIfnameMax, peer)
			}
		}
	}
}

func checkAddr(where, field, addr string, seen map[string]string, fs *findings) {
	if addr == "" {
		fs.add("§20.1 对应", where, "%s 为空", field)
		return
	}
	p, err := netip.ParsePrefix(addr)
	if err != nil {
		fs.add("§20.1 对应", where, "%s 不是合法的带掩码地址:%q", field, addr)
		return
	}
	// 点对点隧道两端各占一个地址。非 /32(或 /128)会让 AllowedIPs 覆盖到
	// 计划外的范围,是 §20.1 说的"IP 撞了"最常见的形态。
	bits := 32
	if p.Addr().Is6() {
		bits = 128
	}
	if p.Bits() != bits {
		fs.add("§20.1 对应", where, "%s 应为 /%d 主机地址,当前是 %s", field, bits, addr)
	}
	norm := p.String()
	if first, dup := seen[norm]; dup {
		fs.add("§20.1 对应", where, "%s 地址 %s 已被 %s 占用", field, norm, first)
		return
	}
	seen[norm] = where + "." + field
}

// Format 把发现渲染成人可读的多行文本。
func Format(fs []Finding) string {
	if len(fs) == 0 {
		return ""
	}
	var b strings.Builder
	for _, f := range fs {
		b.WriteString(f.String())
		b.WriteByte('\n')
	}
	return b.String()
}
