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
	"encoding/base64"
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
			fs.add("§1.3 capabilities", where, "capabilities 为空 —— 能力是集合,但不能是空集")
		}
		for _, c := range n.Capabilities {
			if !c.Valid() {
				fs.add("§1.3 capabilities", where,
					"未知能力 %q —— 只能是 access/server。"+
						"目标不是节点(§1),出口是路径上的位置而非节点类型(§1.1)", c)
			}
		}

		checkRoleFields(n, where, fs)

		isServer := n.Has(model.Server)
		if isServer && !n.Direction.Valid() {
			fs.add("§2.1 direction", where, "direction 缺失或非法:%q", n.Direction)
			continue // 后面的规则都依赖 direction 有效
		}

		// §2.2:reverse_only 拨不到,只能由前一跳经反连隧道推给它。
		// 它可以是出口,但永远不能是链上第一跳。
		if isServer && n.Direction == model.ReverseOnly && n.PublicEndpoint == "" {
			fs.add("§2.2 相容性", where,
				"reverse_only 的服务器仍需 public_endpoint —— 它主动连出去时,"+
					"对端要写 Endpoint 指回来的是**对端**的地址,而本机地址用于排障与探测标注")
		}
		if isServer && n.InboundPort == 0 {
			fs.add("§8.1 inbound", where,
				"持有 server 能力但没有 inbound_port —— 无法接受上游连接")
		}

		// §15.4:版本必须显式钉住,永不使用 latest。自动的是下载,不是
		// 升级决策 —— 上游一次不兼容发布可在一个轮询周期内打挂全部节点。
		v := s.VersionsFor(n)
		// 用切片而不是 map:map 的遍历顺序不确定,会让校验输出在两次运行
		// 之间抖动,CI 里就是间歇性失败。
		for _, c := range []struct{ name, got string }{
			{"sing_box", v.SingBox}, {"wireguard", v.WireGuard}, {"agent", v.Agent},
		} {
			name, got := c.name, c.got
			switch got {
			case "":
				fs.add("§15.4 版本", where, "组件 %s 没有钉住版本", name)
			case "latest":
				fs.add("§15.4 版本", where,
					"组件 %s 的版本是 latest —— 自动的是下载,不是升级决策", name)
			}
		}

	}
	return idx
}

// checkRoleFields 要求字段与能力一一对应。
//
// 这里防的是**惰性字段**:写了不报错、也不影响任何产物。它比缺字段更糟 ——
// 缺字段会被发现,写了不生效的字段会让人以为配置已经生效。
//
// 与 D4 的"推导字段不可表达"是两回事:那些字段写了会与推导结果**矛盾**,
// 所以连位置都不给;这些字段只是在错误的角色上**无效**,给一条说清楚的
// 拒绝就够了。
func checkRoleFields(n *model.Node, where string, fs *findings) {
	server, access := n.Has(model.Server), n.Has(model.Access)

	// 只对 server 有意义的字段。
	for _, f := range []struct {
		name string
		set  bool
	}{
		{"direction", n.Direction != ""},
		{"inbound_port", n.InboundPort != 0},
		{"inbound_protocol", n.InboundProtocol != ""},
		{"egress_capable", n.EgressCapable},
		{"wg_public_key", n.WGPublicKey != ""},
		{"secret_generation", n.SecretGeneration != 0},
	} {
		if f.set && !server {
			fs.add("§1.1 能力", where,
				"%s 只对服务器节点有意义,而本节点不持有 server 能力 —— "+
					"写在这里不会生效", f.name)
		}
	}

	// 只对 access 有意义的字段。
	for _, f := range []struct {
		name string
		set  bool
	}{
		{"platform", n.Platform != ""},
		{"credentials", len(n.Credentials) > 0},
		{"mixed_ports", len(n.MixedPorts) > 0},
		{"default_declaration", n.DefaultDeclaration != ""},
	} {
		if f.set && !access {
			fs.add("§1.1 能力", where,
				"%s 只对接入节点有意义,而本节点不持有 access 能力 —— "+
					"写在这里不会生效", f.name)
		}
	}
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

		// §6.3 / D13:隧道矩阵只覆盖 reverse_only 的服务器。能进 mesh 的
		// 由 Headscale 自动分发密钥与 peer,手工建隧道是白做工,而且是
		// 全系统最容易出错的那种白做工。
		if r.Initiator.MeshEligible() && r.Acceptor.MeshEligible() {
			fs.add("§6.3 mesh", where,
				"两端(%s=%s, %s=%s)都能进 mesh —— 这条隧道该交给 Headscale 自动分发(§8.3),"+
					"不要手工建",
				r.Initiator.ID, r.Initiator.Direction, r.Acceptor.ID, r.Acceptor.Direction)
		}

		checkAddr(where, "from_addr", t.FromAddr, seenAddr, fs)
		checkAddr(where, "to_addr", t.ToAddr, seenAddr, fs)
		if t.FromAddr != "" && t.FromAddr == t.ToAddr {
			fs.add("§20.1 对应", where, "两端地址相同:%s", t.FromAddr)
		}

		// 端口只在接受方生效。发起方不监听。
		switch {
		case t.ListenPort < model.TunnelPortMin || t.ListenPort > model.TunnelPortMax:
			fs.add("§15.1 端口", where,
				"listen_port=%d 不在保留范围 %d-%d 内 —— 低于 61000 会和内核分配给"+
					"出站连接的临时端口冲突,而 51820 是公认的 WireGuard 端口",
				t.ListenPort, model.TunnelPortMin, model.TunnelPortMax)
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
				switch {
				case n.WGPublicKey == "":
					fs.add("§13.1 密钥", where,
						"节点 %s 缺少 wg_public_key —— 它由节点本地生成并上报,"+
							"bootstrap 之前拿不到(§13.1)", n.ID)
				case !validWGKey(n.WGPublicKey):
					fs.add("§13.1 密钥", where,
						"节点 %s 的 wg_public_key 不是合法的 WireGuard 公钥"+
							"(应为 44 字符 base64,解出 32 字节):%q", n.ID, n.WGPublicKey)
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

// validWGKey 报告是否是一把形状正确的 WireGuard 公钥。
//
// 这条不是洁癖:占位符("待填""TODO"之类)混进 SSOT 会被渲染进配置文件,
// 而 WireGuard 拿到无效公钥的表现是**握手静默失败** —— 不报错,只是不通。
func validWGKey(s string) bool {
	if len(s) != 44 {
		return false
	}
	b, err := base64.StdEncoding.DecodeString(s)
	return err == nil && len(b) == 32
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
