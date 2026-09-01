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
	"net/url"
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
	if s.Defaults != nil {
		checkDistributionURLs(&fs, "defaults", s.Defaults.DistributionURL, s.Defaults.DistributionURLs)
	}
	if v := s.AttestationMinVersion(); v != 0 && v != 5 {
		fs.add("§13.3 签名", "defaults",
			"attestation_min_version 只能是 0（兼容阶段）或 5（全网 reader 升级后的强制阶段），收到 %d", v)
	}
	idx := checkNodes(s, &fs)
	checkTunnels(s, idx, &fs)
	checkService(s, idx, &fs)
	checkEnrollmentProfiles(s, &fs)
	checkDrain(&fs, s)
	checkServices(&fs, s)
	checkCredentialRotation(&fs, s)
	checkServicePorts(&fs, s)

	sort.SliceStable(fs, func(i, j int) bool {
		if fs[i].Where != fs[j].Where {
			return fs[i].Where < fs[j].Where
		}
		return fs[i].Rule < fs[j].Rule
	})
	return fs
}

func checkEnrollmentProfiles(s *model.SSOT, fs *findings) {
	if len(s.EnrollmentProfiles) == 0 {
		return
	}
	declarations := s.DeclarationByID()
	seenRefs := map[string]bool{}
	defaults := 0
	for i := range s.EnrollmentProfiles {
		profile := &s.EnrollmentProfiles[i]
		where := fmt.Sprintf("enrollment_profiles[%d]", i)
		if profile.ID != "" {
			where = "profile:" + profile.Reference()
		}
		if !model.ValidNodeID(profile.ID) {
			fs.add("Device Enrollment", where, "profile id %q 格式非法", profile.ID)
		}
		if profile.Version == 0 {
			fs.add("Device Enrollment", where, "version 必须大于 0")
		}
		if seenRefs[profile.Reference()] {
			fs.add("Device Enrollment", where, "profile version 重复")
		}
		seenRefs[profile.Reference()] = true
		if profile.Default {
			defaults++
		}
		checkCanonicalProfileList(fs, where, "responsibilities", profile.Responsibilities)
		checkCanonicalProfileList(fs, where, "destination_grants", profile.DestinationGrants)
		responsibilities := map[string]bool{}
		for _, responsibility := range profile.Responsibilities {
			responsibilities[responsibility] = true
			switch responsibility {
			case "use_loom", "forward", "internet_egress":
			default:
				fs.add("Device Enrollment", where, "未知 responsibility %q", responsibility)
			}
		}
		if responsibilities["internet_egress"] && !responsibilities["forward"] {
			fs.add("Device Enrollment", where, "internet_egress 必须同时声明 forward")
		}
		if len(profile.DestinationGrants) > 0 && !responsibilities["use_loom"] {
			fs.add("Device Enrollment", where, "destination_grants 要求 responsibility use_loom")
		}
		for _, grant := range profile.DestinationGrants {
			declaration := declarations[grant]
			if declaration == nil {
				fs.add("Device Enrollment", where, "destination grant 引用了不存在的声明 %q", grant)
			} else if !declaration.AddressFromRequest() {
				fs.add("Device Enrollment", where, "destination grant %q 不是 from_request 声明", grant)
			}
		}
	}
	if defaults != 1 {
		fs.add("Device Enrollment", "enrollment_profiles", "声明了 %d 个 default profile version，必须恰好为 1", defaults)
	}
}

func checkCanonicalProfileList(fs *findings, where, field string, values []string) {
	seen := map[string]bool{}
	previous := ""
	for i, value := range values {
		if strings.TrimSpace(value) == "" || value != strings.TrimSpace(value) {
			fs.add("Device Enrollment", where, "%s[%d] 不能为空或包含首尾空白", field, i)
		}
		if seen[value] {
			fs.add("Device Enrollment", where, "%s 包含重复值 %q", field, value)
		}
		seen[value] = true
		if i > 0 && value < previous {
			fs.add("Device Enrollment", where, "%s 必须按字典序排列，以稳定版本摘要", field)
			break
		}
		previous = value
	}
}

func checkDistributionURL(fs *findings, where, raw string) {
	if raw == "" {
		return
	}
	parsed, err := url.ParseRequestURI(raw)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") ||
		parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		fs.add("§14.2 分发", where,
			"distribution_url(s) 分发镜像必须是无凭据、query 和 fragment 的完整 http(s) URL，收到 %q", raw)
	}
}

func checkDistributionURLs(fs *findings, where, legacy string, mirrors []string) {
	if legacy != "" && len(mirrors) > 0 {
		fs.add("§14.2 分发", where,
			"distribution_url 与 distribution_urls 不能同时声明；请把全部镜像放进 distribution_urls")
	}
	if legacy != "" {
		checkDistributionURL(fs, where, legacy)
	}
	seen := map[string]bool{}
	for i, raw := range mirrors {
		itemWhere := fmt.Sprintf("%s.distribution_urls[%d]", where, i)
		if raw == "" {
			fs.add("§14.2 分发", itemWhere, "镜像地址不能为空")
			continue
		}
		checkDistributionURL(fs, itemWhere, raw)
		canonical := strings.TrimRight(raw, "/")
		if seen[canonical] {
			fs.add("§14.2 分发", itemWhere, "镜像地址重复:%q", raw)
		}
		seen[canonical] = true
	}
}

func checkNodes(s *model.SSOT, fs *findings) map[string]*model.Node {
	// 哪些服务器真的会被连:出现在某条访问声明的 allowed_servers 里。
	usedAsHop := map[string]string{}
	for i := range s.Declarations {
		for _, id := range s.Declarations[i].AllowedServers {
			// A hybrid access/server node may list itself as the declaration's
			// local egress. That candidate is zero-hop and needs no inbound. Keep
			// requiring inbound as soon as any other access node uses the same
			// declaration, because that would be a real upstream connection.
			if declarationUsedOnlyByLocalAccess(s, s.Declarations[i].ID, id) {
				continue
			}
			if _, seen := usedAsHop[id]; !seen {
				usedAsHop[id] = "声明 " + s.Declarations[i].ID
			}
		}
	}

	idx := make(map[string]*model.Node, len(s.Nodes))
	for i := range s.Nodes {
		n := &s.Nodes[i]
		where := n.ID
		if where == "" {
			where = fmt.Sprintf("nodes[%d]", i)
			fs.add("§19 schema", where, "节点缺少 id")
		} else if !model.ValidNodeID(n.ID) {
			fs.add("§19 schema", where,
				"节点 id %q 格式非法 —— 只能使用 1–63 个小写 ASCII 字母、数字或内连字符，且首尾必须是字母或数字", n.ID)
		}
		if _, dup := idx[n.ID]; dup && n.ID != "" {
			fs.add("§19 schema", where, "节点 id 重复")
		}
		if n.ID != "" {
			idx[n.ID] = n
		}
		checkDistributionURLs(fs, where, n.DistributionURL, n.DistributionURLs)
		if country := n.Country; country != "" && !model.ValidCountryCode(country) {
			fs.add("§19 schema", where,
				"country %q 格式非法 —— 必须是两个大写 ASCII 字母组成的 ISO 3166-1 alpha-2 代码", country)
		}

		// 至少要承担一种角色。两种都有是合法的 —— 一台服务器自己也要
		// 走代理出去是真实需求(§1.3)。
		if !n.IsServer() && !n.IsAccess() {
			fs.add("§1.3 角色", where,
				"既没有 server 块也没有 access 块 —— 这个节点不承担任何角色")
		}

		// 直连自检目标要能被当成 URL 用 —— 写成裸主机名的话,上报者每轮
		// 都会失败一次,而症状是"这台机器直连坏了",跟真实原因毫不相干。
		for _, t := range n.ProbeTargets {
			if !strings.HasPrefix(t, "http://") && !strings.HasPrefix(t, "https://") {
				fs.add("§16.1 自检", where,
					"probe_targets 要写成完整 URL(http:// 或 https://),收到 %q", t)
			}
		}

		isServer := n.IsServer()
		if isServer {
			switch {
			case n.Server.SecretGeneration < 0:
				fs.add("§13.4 秘密层", where,
					"secret_generation 不能为负:%d", n.Server.SecretGeneration)
			case n.Server.SecretGeneration > 1:
				fs.add("§13.4 秘密层", where,
					"secret_generation=%d 声明了秘密层轮换，但当前运行时未实现对应代次的部署或核验；"+
						"拒绝假生效，只能省略(0)或使用第一代(1)", n.Server.SecretGeneration)
			}
		}
		if isServer && !n.Server.Direction.Valid() {
			fs.add("§2.1 direction", where, "direction 缺失或非法:%q", n.Server.Direction)
			continue // 后面的规则都依赖 direction 有效
		}

		// §2.2:reverse_only 拨不到,只能由前一跳经反连隧道推给它。
		// 它可以是出口,但永远不能是链上第一跳。
		if isServer && n.Server.Direction == model.ReverseOnly && n.PublicEndpoint == "" {
			fs.add("§2.2 相容性", where,
				"reverse_only 的服务器仍需 public_endpoint —— 它主动连出去时,"+
					"对端要写 Endpoint 指回来的是**对端**的地址,而本机地址用于排障与探测标注")
		}
		// inbound_port 只在真有人要连它时才必需。
		//
		// 一个节点可以只为了当**隧道端点**而有 server 块 —— 比如接入节点
		// 与境外机建反连隧道,好把两跳压成一跳(§2.3)。它不接受任何
		// sing-box 连接,强求 inbound_port 会逼出一个没人用的监听。
		if by, used := usedAsHop[n.ID]; isServer && n.Server.InboundPort == 0 && used {
			fs.add("§8.1 inbound", where,
				"被%s的 allowed_servers 引用,却没有 inbound_port —— 无法接受上游连接", by)
		}

		// 没有解析器时 sing-box 会退回系统解析器 —— 而它坏掉的表现是
		// "只有直连候选失败",极难诊断。
		if len(s.DNSFor(n)) == 0 {
			fs.add("§7.4 DNS", where,
				"没有配置 dns —— sing-box 会退回系统解析器。系统解析器坏掉时"+
					"只有直连候选会失败,代理候选一切正常(域名交给出口解析),"+
					"这种不对称极难诊断")
		}

		// §15.4:版本必须显式钉住,永不使用 latest。自动的是下载,不是
		// 升级决策 —— 上游一次不兼容发布可在一个轮询周期内打挂全部节点。
		v := s.VersionsFor(n)
		if v.Tailscale != "" {
			fs.add("§15.4 版本", where,
				"components.tailscale=%q 只有版本坐标，但当前模型没有启用 Tailscale 的 workload 真值，"+
					"运行时也不会安装或启动它；拒绝用版本字段冒充已启用能力", v.Tailscale)
		}
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

func declarationUsedOnlyByLocalAccess(s *model.SSOT, declaration, serverID string) bool {
	credentials := s.CredentialByID()
	usedLocally := false
	for _, access := range s.AccessNodes() {
		uses := false
		for _, credentialID := range access.Access.Credentials {
			if credential := credentials[credentialID]; credential != nil && credential.Declaration == declaration {
				uses = true
				break
			}
		}
		if !uses {
			continue
		}
		if access.ID != serverID {
			return false
		}
		usedLocally = true
	}
	return usedLocally
}

func checkTunnels(s *model.SSOT, idx map[string]*model.Node, fs *findings) {
	seenPair := map[string]string{} // 无序节点对 -> 首次出现的 pair
	seenAddr := map[string]string{} // 隧道内地址 -> 占用者
	seenPort := map[string]string{} // "节点/端口" -> 占用者

	// sing-box inbound 端口先占位,这样 WG 监听口撞上它时能报出来。
	// 同一台机器上两个进程抢同一个端口,后起的那个静默失败。
	for i := range s.Nodes {
		if n := &s.Nodes[i]; n.IsServer() && n.Server.InboundPort > 0 {
			seenPort[fmt.Sprintf("%s/%d", n.ID, n.Server.InboundPort)] = n.ID + " 的 sing-box inbound"
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

		// **当前端口不能在退役名单里。** 退役的意思就是"这个端口不通,
		// 别再回去" —— 两者矛盾时,症状是"换了端口还是不通",而人会去查
		// 网络,查不到原因。这条关系不检查就没有任何东西会发现它。
		for _, rp := range t.RetiredPorts {
			if rp == t.ListenPort {
				fs.add("§6 端口", where,
					"listen_port %d 同时在 retired_ports 里 —— 退役的端口不该再用回来",
					rp)
			}
			if rp < model.TunnelPortMin || rp > model.TunnelPortMax {
				fs.add("§6 端口", where,
					"retired_ports 里的 %d 不在保留段 %d-%d 内",
					rp, model.TunnelPortMin, model.TunnelPortMax)
			}
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

		// §6.3 / D13 / D29:隧道矩阵只覆盖包含 reverse_only 端点的关系。
		// 两端都能被公网拨到时，当前直接用 Hysteria2；Headscale 是未来
		// 可选项，不是拒绝这条隧道所依赖的现有组件。
		if r.Initiator.MeshEligible() && r.Acceptor.MeshEligible() {
			fs.add("§6.3 mesh", where,
				"两端(%s=%s, %s=%s)都能被公网拨到,不需要隧道 —— "+
					"直接用各自的 inbound_port 互拨即可,手工建隧道是白做工。"+
					"(启用 mesh 之后由 Headscale 自动分发,§8.3)",
				r.Initiator.ID, r.Initiator.Server.Direction, r.Acceptor.ID, r.Acceptor.Server.Direction)
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
				case n.Server.WGPublicKey == "":
					fs.add("§13.1 密钥", where,
						"节点 %s 缺少 wg_public_key —— 它由节点本地生成并上报,"+
							"bootstrap 之前拿不到(§13.1)", n.ID)
				case !validWGKey(n.Server.WGPublicKey):
					fs.add("§13.1 密钥", where,
						"节点 %s 的 wg_public_key 不是合法的 WireGuard 公钥"+
							"(应为 44 字符 base64,解出 32 字节):%q", n.ID, n.Server.WGPublicKey)
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
