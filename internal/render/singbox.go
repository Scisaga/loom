package render

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"loom/internal/model"
)

// 本文件渲染三类节点的 sing-box 配置:接入(客户端档案)、中继、落地目标。
//
// 全部用结构体而非 map 序列化 —— 结构体的字段顺序是确定的,map 不是,
// 而渲染必须是纯函数(§12)。

// TLS 材料的约定路径。与 WireGuard 私钥同理,渲染层只写引用,文件本身属于
// 秘密层(§12.1)。
//
// 注意这里的 node.key 是 **TLS 私钥**,与 WireGuard 的
// /etc/wireguard/node.key 是两把不同的钥匙 —— 前者给 Hysteria2 的 QUIC
// 用,后者给隧道用。放在不同目录以免混淆。
const (
	tlsCertPath = "/etc/loom/tls/node.crt"
	tlsKeyPath  = "/etc/loom/tls/node.key"
	tlsCAPath   = "/etc/loom/tls/ca.crt"
)

// secretRef 把秘密层引用渲染成占位符,而不是明文。
//
// 凭据是秘密。明文写进渲染层会有三个后果:`loom diff` 把它打到终端、
// 快照哈希覆盖了它、配置包在分发链路上处处是明文。Agent 在写盘前用本地
// 秘密层替换占位符;替换失败时 sing-box 会因密码非法而拒绝启动 ——
// 这正是想要的行为,总好过拿着字面量去连。
func secretRef(ref string) string { return "${secret:" + ref + "}" }

type sbLog struct {
	Level string `json:"level"`
}

type sbUser struct {
	Name     string `json:"name"`
	Password string `json:"password"`
}

type sbTLS struct {
	Enabled         bool     `json:"enabled"`
	ServerName      string   `json:"server_name,omitempty"`
	CertificatePath string   `json:"certificate_path,omitempty"`
	KeyPath         string   `json:"key_path,omitempty"`
	ALPN            []string `json:"alpn,omitempty"`
}

type sbInbound struct {
	Type       string `json:"type"`
	Tag        string `json:"tag"`
	Listen     string `json:"listen,omitempty"`
	ListenPort int    `json:"listen_port,omitempty"`

	// tun
	Address   []string `json:"address,omitempty"`
	AutoRoute bool     `json:"auto_route,omitempty"`
	Stack     string   `json:"stack,omitempty"`

	// hysteria2
	Users []sbUser `json:"users,omitempty"`
	TLS   *sbTLS   `json:"tls,omitempty"`
}

type sbOutbound struct {
	Type       string `json:"type"`
	Tag        string `json:"tag"`
	Server     string `json:"server,omitempty"`
	ServerPort int    `json:"server_port,omitempty"`
	Password   string `json:"password,omitempty"`
	Version    string `json:"version,omitempty"`
	TLS        *sbTLS `json:"tls,omitempty"`
	Detour     string `json:"detour,omitempty"`

	// selector
	Outbounds []string `json:"outbounds,omitempty"`
	Default   string   `json:"default,omitempty"`

	// direct
	BindInterface   string `json:"bind_interface,omitempty"`
	OverrideAddress string `json:"override_address,omitempty"`
	OverridePort    int    `json:"override_port,omitempty"`
}

type sbRule struct {
	Inbound  []string `json:"inbound,omitempty"`
	AuthUser []string `json:"auth_user,omitempty"`
	IPCIDR   []string `json:"ip_cidr,omitempty"`
	Domain   []string `json:"domain,omitempty"`
	Port     []int    `json:"port,omitempty"`
	Outbound string   `json:"outbound"`
}

type sbRoute struct {
	Rules []sbRule `json:"rules,omitempty"`
	Final string   `json:"final"`
}

// APIListen 是 sing-box 本地控制端点。
//
// selector 是**手动开关**:它自己不测速也不切换(这是 D11 刻意的选择 ——
// urltest 会成为第二个互不知情的决策者)。切换由 Agent 通过这个端点做。
//
// 没有它,渲染出的 selector 永远停在 default 上 —— 调度层做完了也落不了地。
// 只监听回环,并且带一把口令:同机的其他进程不该能改你的选路。
const APIListen = "127.0.0.1:61800"

type sbAPI struct {
	ExternalController string `json:"external_controller"`
	Secret             string `json:"secret"`
}

type sbExperimental struct {
	ClashAPI *sbAPI `json:"clash_api,omitempty"`
}

type sbConfig struct {
	Log          sbLog           `json:"log"`
	Inbounds     []sbInbound     `json:"inbounds"`
	Outbounds    []sbOutbound    `json:"outbounds"`
	Route        sbRoute         `json:"route"`
	Experimental *sbExperimental `json:"experimental,omitempty"`
}

func encode(c *sbConfig) (string, error) {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b) + "\n", nil
}

// nodeTLSDomain 是节点证书的域名后缀。节点间的 hysteria2 一律用
// <node-id>.<后缀> 作为 TLS server_name —— 直接用 IP 做 SNI 时证书对不上,
// 而节点在链路里可能被隧道地址或公网地址两种方式拨到,名字必须统一。
const nodeTLSDomain = "node.internal"

func serverName(n *model.Node) string { return n.ID + "." + nodeTLSDomain }

func clientTLS(name string) *sbTLS {
	return &sbTLS{Enabled: true, ServerName: name, CertificatePath: tlsCAPath, ALPN: []string{"h3"}}
}

func serverTLS() *sbTLS {
	return &sbTLS{Enabled: true, CertificatePath: tlsCertPath, KeyPath: tlsKeyPath, ALPN: []string{"h3"}}
}

// ---------------------------------------------------------------------------
// 接入节点
// ---------------------------------------------------------------------------

// renderAccess 渲染一个接入节点的 sing-box 配置(§7)。
//
// 每个 mixed 端口绑定一个访问声明(§7.3);每条声明有一个 selector,成员是
// 它的全部 RouteCandidate(§5.6)。
//
// 用 selector 而不是 urltest 是刻意的:§5.6 要求选路的决策者只有一个。
// urltest 会按自己的节奏和判据独立选路,与 Agent 的 §5.5 阻尼规则形成两个
// 互不知情的决策者。selector 的当前选择由 Agent 设置;Agent 尚未实现时它
// 停在 default 上,即 §20.2 的"路径静态指定"。
func accessInto(cfg *sbConfig, s *model.SSOT, p *model.Node) ([]Skip, error) {
	nodes := s.NodeByID()
	decls := s.DeclarationByID()
	creds := s.CredentialByID()

	var skips []Skip
	note := func(where, format string, args ...any) {
		skips = append(skips, Skip{Where: where, Reason: fmt.Sprintf(format, args...)})
	}

	// 凭据决定这个档案能用哪些声明。
	credOf := map[string]*model.Credential{}
	var declIDs []string
	for _, cid := range p.Access.Credentials {
		c, ok := creds[cid]
		if !ok || c.Revoked() {
			continue
		}
		if _, dup := credOf[c.Declaration]; !dup {
			declIDs = append(declIDs, c.Declaration)
		}
		credOf[c.Declaration] = c
	}
	sort.Strings(declIDs)

	if p.Access.Platform.UsesTUN() {
		cfg.Inbounds = append(cfg.Inbounds, sbInbound{
			Type: "tun", Tag: "tun-in",
			Address:   []string{"172.19.0.1/30"},
			AutoRoute: true, Stack: "system",
		})
	}
	ports := append([]model.MixedPort(nil), p.Access.MixedPorts...)
	sort.Slice(ports, func(i, j int) bool { return ports[i].Port < ports[j].Port })
	for _, mp := range ports {
		cfg.Inbounds = append(cfg.Inbounds, sbInbound{
			Type: "mixed", Tag: fmt.Sprintf("in-%d", mp.Port),
			Listen: "127.0.0.1", ListenPort: mp.Port,
		})
	}

	hops := map[string]bool{}
	routable := map[string]bool{}
	for _, did := range declIDs {
		d, ok := decls[did]
		if !ok {
			continue
		}
		cands, cskips := s.EnumerateCandidates(d)
		for _, cs := range cskips {
			note("access:"+p.ID+"/"+cs.Declaration, "%s", cs.Reason)
		}
		if len(cands) == 0 {
			note("access:"+p.ID+"/"+did, "该声明没有任何可表达的 L4 候选,已跳过其 outbound 与路由规则")
			continue
		}

		var tags []string
		for i := range cands {
			c := &cands[i]
			tags = append(tags, c.Tag())
			cfg.Outbounds = append(cfg.Outbounds,
				buildChain(s, nodes, c, credOf[did].SecretRef, hops)...)
		}
		cfg.Outbounds = append(cfg.Outbounds, sbOutbound{
			Type: "selector", Tag: "decl:" + did, Outbounds: tags, Default: tags[0],
		})
		routable[did] = true

		if d.Fallback != model.FailClosed {
			note("access:"+p.ID+"/"+did,
				"fallback=%s 尚未在数据平面实现,当前行为等同 fail_closed(§5.8)", d.Fallback)
		}
	}

	for _, mp := range ports {
		// 引用一个没生成的 selector 会让 sing-box 直接启动失败。宁可不写
		// 这条规则 —— 流量落到 final: block,与 fail_closed 一致。
		if !routable[mp.Declaration] {
			note("access:"+p.ID,
				"端口 %d 绑定的声明 %q 没有可用候选,该端口不生成路由规则,流量将被阻断",
				mp.Port, mp.Declaration)
			continue
		}
		cfg.Route.Rules = append(cfg.Route.Rules, sbRule{
			Inbound: []string{fmt.Sprintf("in-%d", mp.Port)}, Outbound: "decl:" + mp.Declaration,
		})
	}
	if p.Access.Platform.UsesTUN() {
		tunDecl := p.Access.DefaultDeclaration
		if tunDecl == "" && len(declIDs) == 1 {
			tunDecl = declIDs[0]
		}
		switch {
		case tunDecl == "":
			note("access:"+p.ID, "未声明 default_declaration,TUN 兜底流量将被阻断")
		case !routable[tunDecl]:
			note("access:"+p.ID, "default_declaration %q 没有可用候选,TUN 兜底流量将被阻断", tunDecl)
		default:
			cfg.Route.Rules = append(cfg.Route.Rules, sbRule{
				Inbound: []string{"tun-in"}, Outbound: "decl:" + tunDecl,
			})
		}
	}
	return skips, nil
}

// buildChain 生成一条候选所需的全部出站,最后一个的 tag 就是候选本身。
//
// 链上每一跳都是普通的代理连接:先连第一台服务器,再让它连第二台,
// 最后一跳直接连目标地址(§5.6)。没有额外发明的机制。
func buildChain(
	s *model.SSOT,
	nodes map[string]*model.Node,
	c *model.RouteCandidate,
	secret string,
	hops map[string]bool,
) []sbOutbound {
	var out []sbOutbound
	detour, prefix := "", ""
	lastIsChainHop := c.Address == ""

	for i, id := range c.ServerChain {
		sv := nodes[id]
		if i > 0 {
			prefix += ">"
		}
		prefix += id

		// 去重键必须是**整条前缀**,不能只是 (声明, 序号, 节点):第二跳
		// 的 detour 与拨的地址都随前一跳变化,只按节点去重会把不同链的
		// 第二跳当成同一个,结果是后面几条链只剩第一跳。
		tag := "hop:" + c.Declaration + ":" + prefix
		if lastIsChainHop && i == len(c.ServerChain)-1 {
			tag = c.Tag()
		}
		if hops[tag] {
			detour = tag
			continue
		}
		hops[tag] = true

		o := sbOutbound{Type: string(sv.Server.InboundProtocol.Or()), Tag: tag,
			Password: secretRef(secret), Detour: detour}
		if i == 0 {
			// 第一跳由接入节点直接拨公网地址。
			o.Server, o.ServerPort = sv.PublicEndpoint, sv.Server.InboundPort
		} else {
			// 后续跳由前一跳转发,拨的是它在那条链路上的地址。
			o.Server, o.ServerPort = s.NextHopAddr(nodes[c.ServerChain[i-1]], sv), sv.Server.InboundPort
		}
		o.TLS = clientTLS(serverName(sv))
		if sv.Server.InboundProtocol.Or() == model.Trojan {
			o.TLS.ALPN = []string{"h2", "http/1.1"}
		}
		out = append(out, o)
		detour = tag
	}

	if lastIsChainHop {
		if len(c.ServerChain) > 0 {
			return out
		}
		// 零跳直连(§3.1)。
		return append(out, sbOutbound{Type: "direct", Tag: c.Tag()})
	}

	// 地址从等价类里选:用一个覆盖目的地的 direct 收尾。客户端发出的
	// TLS SNI 与 Host 原样不动 —— 这正是 §4.4 要求成员契约同构的原因。
	addr := findAddress(s, c)
	return append(out, sbOutbound{
		Type: "direct", Tag: c.Tag(), Detour: detour,
		OverrideAddress: addr.Host(), OverridePort: addr.Port(),
	})
}

func findAddress(s *model.SSOT, c *model.RouteCandidate) *model.ServiceAddress {
	for i := range s.EquivalenceClasses {
		cl := &s.EquivalenceClasses[i]
		for j := range cl.Members {
			if cl.Members[j].Address == c.Address {
				return &cl.Members[j]
			}
		}
	}
	return &model.ServiceAddress{Address: c.Address}
}

// ---------------------------------------------------------------------------
// 服务器
// ---------------------------------------------------------------------------

// renderServer 渲染一台服务器的 sing-box 配置(§8)。
//
// **中继与出口不是两种节点,是同一台机器在不同路径上的两种位置**(§1.1)。
// 所以只有这一个渲染函数:同一份配置里既有"转给下一跳"的规则,也有
// "本机就是出口,直接出去"的规则,按连接的目的地分流。
//
// 服务器做准入校验,不做选路(§5.6):白名单之外一律阻断。
func serverInto(cfg *sbConfig, s *model.SSOT, sv *model.Node) {
	nodes := s.NodeByID()
	decls := s.DeclarationByID()

	type rule struct {
		user     string
		nextHops map[string]string // 下一跳地址 -> 出站 tag
		egress   bool
		domains  []string // 出口规则的域名限制;空表示不限(地址随请求走)
	}
	var rules []rule
	var users []sbUser

	creds := append([]model.Credential(nil), s.Credentials...)
	sort.Slice(creds, func(i, j int) bool { return creds[i].ID < creds[j].ID })

	for i := range creds {
		c := &creds[i]
		if c.Revoked() {
			continue // §18:吊销后所有服务器在下一轮询周期移除该 user
		}
		d, ok := decls[c.Declaration]
		if !ok {
			continue
		}
		cands, _ := s.EnumerateCandidates(d)

		r := rule{user: c.ID, nextHops: map[string]string{}}
		domains := map[string]bool{}
		for j := range cands {
			cand := &cands[j]
			for k, id := range cand.ServerChain {
				if id != sv.ID {
					continue
				}
				if k+1 < len(cand.ServerChain) {
					// 本机是中间一跳:转给下一台服务器。
					next := nodes[cand.ServerChain[k+1]]
					if addr := s.NextHopAddr(sv, next); addr != "" {
						r.nextHops[addr+"/32"] = "via-" + next.ID
					}
					continue
				}
				// 本机是链末尾 —— 这次它就是出口(§1.1)。
				r.egress = true
				if cand.Address != "" {
					domains[findAddress(s, cand).Host()] = true
				}
			}
		}
		if len(r.nextHops) == 0 && !r.egress {
			continue // 这张凭据不经过本机
		}
		// 只要有一条候选是"地址随请求走",出口规则就不能限制域名。
		if r.egress && len(domains) > 0 {
			for k := range domains {
				r.domains = append(r.domains, k)
			}
			sort.Strings(r.domains)
			for j := range cands {
				if cands[j].Address == "" && cands[j].Egress() == sv.ID {
					r.domains = nil
					break
				}
			}
		}
		rules = append(rules, r)
		users = append(users, sbUser{Name: c.ID, Password: secretRef(c.SecretRef)})
	}

	in := sbInbound{
		Tag: "in", Listen: "::", ListenPort: sv.Server.InboundPort,
		Users: users, TLS: serverTLS(),
	}
	in.Type = string(sv.Server.InboundProtocol.Or())
	if sv.Server.InboundProtocol.Or() == model.Trojan {
		// Trojan 走 TCP,ALPN 用 h2/http1.1 才像正常 HTTPS;h3 是 QUIC 的。
		in.TLS.ALPN = []string{"h2", "http/1.1"}
	}
	cfg.Inbounds = append(cfg.Inbounds, in)

	// 每个下一跳一个出站。有隧道时绑到对应网卡 —— 绑接口而不是靠路由表,
	// 是为了让"这条流量必须走这条隧道"在配置里显式可见。
	var nextIDs []string
	seen := map[string]bool{}
	for _, r := range rules {
		for _, tag := range r.nextHops {
			id := strings.TrimPrefix(tag, "via-")
			if !seen[id] {
				seen[id] = true
				nextIDs = append(nextIDs, id)
			}
		}
	}
	sort.Strings(nextIDs)
	for _, id := range nextIDs {
		o := sbOutbound{Type: "direct", Tag: "via-" + id}
		if s.TunnelAddrOn(id, sv.ID) != "" {
			o.BindInterface = model.IfaceName(id)
		}
		cfg.Outbounds = append(cfg.Outbounds, o)
	}
	if sv.Server.EgressCapable {
		cfg.Outbounds = append(cfg.Outbounds, sbOutbound{Type: "direct", Tag: "egress"})
	}
	// 转发规则在前、出口规则在后:出口是兜底,先匹配具体的下一跳。
	for _, r := range rules {
		var cidrs []string
		byTag := map[string][]string{}
		for cidr, tag := range r.nextHops {
			byTag[tag] = append(byTag[tag], cidr)
			cidrs = append(cidrs, cidr)
		}
		var tags []string
		for t := range byTag {
			tags = append(tags, t)
		}
		sort.Strings(tags)
		for _, t := range tags {
			sort.Strings(byTag[t])
			cfg.Route.Rules = append(cfg.Route.Rules, sbRule{
				AuthUser: []string{r.user}, IPCIDR: byTag[t], Outbound: t,
			})
		}
	}
	for _, r := range rules {
		if !r.egress || !sv.Server.EgressCapable {
			continue
		}
		cfg.Route.Rules = append(cfg.Route.Rules, sbRule{
			AuthUser: []string{r.user}, Domain: r.domains, Outbound: "egress",
		})
	}
}

// renderSingBox 生成一台机器的 sing-box 配置。
//
// **一台机器一个 sing-box 进程,因此只有一份配置。** 同时持有两种角色的
// 机器(服务器自己也要走代理出去)把两边的 inbound、outbound 与路由规则
// 合并进同一份 —— 两种角色喂的是不相干的逻辑,只在这里汇合。
//
// 配置源只有一个(SSOT → 渲染器),投递也只有一条(该机的 Agent),
// 所以合并不存在"两个源互相覆盖"的问题。§18 那套一次性链接是给**没有
// Agent 的设备**用的,而那种设备只可能是纯接入节点。
func renderSingBox(s *model.SSOT, n *model.Node) (File, []Skip, error) {
	cfg := &sbConfig{Log: sbLog{Level: "warn"}}
	var skips []Skip

	if n.IsAccess() {
		sk, err := accessInto(cfg, s, n)
		if err != nil {
			return File{}, nil, err
		}
		skips = sk
		// 只有接入节点才有 selector 要切,服务器开了这个端点也没用。
		cfg.Experimental = &sbExperimental{ClashAPI: &sbAPI{
			ExternalController: APIListen,
			Secret:             secretRef("api/" + n.ID),
		}}
	}
	if n.IsServer() && n.Server.InboundPort > 0 {
		serverInto(cfg, s, n)
	}

	// block 出站两边都要用,收尾时统一加一次。
	cfg.Outbounds = append(cfg.Outbounds, sbOutbound{Type: "block", Tag: "block"})
	// 未匹配一律阻断:回落到 direct 会让一条本该受声明约束的连接悄悄绕开
	// 调度,和 §5.8 的 fail_closed 是同一个道理。
	cfg.Route.Final = "block"

	content, err := encode(cfg)
	if err != nil {
		return File{}, nil, err
	}
	return File{Path: "sing-box/config.json", Content: content}, skips, nil
}
