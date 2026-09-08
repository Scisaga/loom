package render

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
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
	tlsCertPath      = "/etc/loom/tls/node.crt"
	tlsKeyPath       = "/etc/loom/tls/node.key"
	tlsCAPath        = "/etc/loom/tls/ca.crt"
	windowsTLSCAPath = `C:\ProgramData\Loom\tls\ca.crt`
	androidTLSCAPath = "tls/ca.crt"
)

// secretRef 把秘密层引用渲染成占位符,而不是明文。
//
// 凭据是秘密。明文写进渲染层会有三个后果:`loom diff` 把它打到终端、
// 快照哈希覆盖了它、配置包在分发链路上处处是明文。Agent 在写盘前用本地
// 秘密层替换占位符;替换失败时 sing-box 会因密码非法而拒绝启动 ——
// 这正是想要的行为,总好过拿着字面量去连。
func secretRef(ref string) string { return "${secret:" + ref + "}" }

func probeHost() string { h, _, _ := strings.Cut(ProbeListen, ":"); return h }

func probePort() int {
	_, p, _ := strings.Cut(ProbeListen, ":")
	n := 0
	for _, c := range p {
		n = n*10 + int(c-'0')
	}
	return n
}

type sbLog struct {
	Level string `json:"level"`
}

// sbUser 是 hysteria2 / trojan 入站的用户。
type sbUser struct {
	Name     string `json:"name"`
	Password string `json:"password"`
}

// sbMixedUser 是 mixed(HTTP+SOCKS)入站的用户。
//
// **字段名和 sbUser 不一样** —— mixed 用 username,hysteria2/trojan 用 name。
// 用错的后果是 sing-box 启动即 FATAL:`unknown field "name"`。
type sbMixedUser struct {
	Username string `json:"username"`
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

	// Users 是 []sbUser(hysteria2/trojan)或 []sbMixedUser(mixed)。
	// 两者字段名不同(name vs username)且互斥,所以这里用 any 承载 ——
	// 拆成两个字段会让其中一个的 json tag 冲突。
	Users any    `json:"users,omitempty"`
	TLS   *sbTLS `json:"tls,omitempty"`
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
	// DomainSuffix 让服务的地址清单能用后缀兜住子域 —— 清单几乎一定不全,
	// 这是最省事的补救(§4.5)。
	DomainSuffix []string `json:"domain_suffix,omitempty"`
	Port         []int    `json:"port,omitempty"`
	Outbound     string   `json:"outbound"`
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

type sbDNSServer struct {
	Tag     string `json:"tag"`
	Address string `json:"address"`
	// Detour 指定这条 DNS 查询走哪个出站。
	//
	// **必须显式指定。** 不指定时查询会走 route 规则,而我们的 route.final
	// 是 block(未匹配一律阻断,§5.8 的 fail_closed) —— 于是 sing-box 连
	// 解析器都问不到。症状只有"直连候选失败":走代理的域名是交给出口解析
	// 的(§7.4),根本不用本地 DNS,所以代理候选一切正常。
	Detour string `json:"detour"`
}

// dnsOutbound 是 DNS 查询专用的直连出站。
//
// 它不参与选路,也不该被任何访问声明引用 —— 它存在的唯一目的是让解析器
// 可达。
const dnsOutbound = "dns-out"

// ProbeListen 是探测专用入口。
//
// **一个端口,用用户名区分候选。** 路由规则按 auth_user 把每个用户名映射到
// 同名的候选出站,于是 Agent 只要用不同用户名连同一个端口,就能把探测流量
// 精确打到指定候选上 —— 不切 selector、不打断真实流量、目标 URL 任选。
//
// 为什么不用 sing-box 自带的 delay 接口:**它忽略传入的 url 参数**(实测传
// 一个独特域名,它照样连内置的 www.gstatic.com)。而目标选错的后果不是数字
// 不准,是把不可达的候选排在第一位。
//
// 只监听回环。它按设计绕过访问控制 —— 它是测量工具,不是数据通路。
const ProbeListen = "127.0.0.1:61801"

// ProbeUser 是某条候选在探测入口上的用户名。
//
// **不能直接用候选 tag。** tag 里有冒号,而 SOCKS5 客户端普遍在第一个冒号处
// 切分 user:pass —— curl 就是这样,结果 username 变成 "cand"、密码变成剩下
// 的一整串,认证必然失败。
//
// 用 tag 的哈希前缀:无冒号、稳定、唯一。可读性由紧邻的路由规则补上 ——
// 规则里写着 auth_user: [probe-xxxx] → outbound: <候选 tag>,一眼能对上。
func ProbeUser(candidateTag string) string {
	h := sha256.Sum256([]byte(candidateTag))
	return "probe-" + hex.EncodeToString(h[:5])
}

type sbDNS struct {
	Servers  []sbDNSServer `json:"servers"`
	Strategy string        `json:"strategy,omitempty"`
}

type sbConfig struct {
	Log          sbLog           `json:"log"`
	DNS          *sbDNS          `json:"dns,omitempty"`
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

func clientTLS(name, caPath string) *sbTLS {
	return &sbTLS{Enabled: true, ServerName: name, CertificatePath: caPath, ALPN: []string{"h3"}}
}

func serverTLS() *sbTLS {
	return &sbTLS{Enabled: true, CertificatePath: tlsCertPath, KeyPath: tlsKeyPath, ALPN: []string{"h3"}}
}

// accessTLSCAPath 把平台无关的信任语义落到明确宿主路径。
// Android 的相对路径由 VpnService 将工作目录固定在应用私有目录；Windows
// 使用 ProgramData。未知平台不猜路径，校验器会在渲染前拒绝。
func accessTLSCAPath(platform model.Platform) string {
	switch platform {
	case model.WindowsDesktop:
		return windowsTLSCAPath
	case model.Android:
		return androidTLSCAPath
	case model.LinuxServer:
		return tlsCAPath
	default:
		return ""
	}
}

// ---------------------------------------------------------------------------
// 接入节点
// ---------------------------------------------------------------------------

// renderAccess 渲染一个接入节点的 sing-box 配置(§7)。
//
// 正常的 mixed 主入口按 host 反查 Service;只有显式 override/兼容入口才
// 直接绑定访问声明(§7.3)。每条声明有一个 selector,成员是它的全部
// RouteCandidate(§5.6)。
//
// 用 selector 而不是 urltest 是刻意的:§5.6 要求选路的决策者只有一个。
// urltest 会按自己的节奏和判据独立选路,与 Agent 的 §5.5 阻尼规则形成两个
// 互不知情的决策者。selector 的当前选择由 Agent 设置(§5.5.1);Agent 没跑
// 起来时它停在 default 上,而 default 刻意不取直连(D22)。
func accessInto(cfg *sbConfig, s *model.SSOT, p *model.Node) ([]Skip, error) {
	nodes := s.NodeByID()
	decls := s.DeclarationByID()

	var skips []Skip
	note := func(where, format string, args ...any) {
		skips = append(skips, Skip{Where: where, Reason: fmt.Sprintf(format, args...)})
	}

	declIDs, credOf := accessDecls(s, p)

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

	// 显式覆盖或设备默认策略需要声明级 selector。只治理服务的声明不需要 ——
	// 那些流量按 host 反查服务,走服务自己的 selector(§4.5)。
	pinned, defaultDecl := pinnedDecls(p)
	managedInbounds := managedAutomaticInbounds(p, ports)
	byService := len(managedInbounds) > 0

	hops := map[string]bool{}
	routable := map[string]bool{}
	var probeUsers []sbMixedUser // 每条候选一个用户名(见 ProbeListen)
	var probeRules []sbRule
	for _, did := range declIDs {
		d, ok := decls[did]
		if !ok {
			continue
		}
		if !pinned[did] {
			continue // 只治理服务,没有端口钉着它
		}
		cands, cskips := s.EnumerateCandidates(p, d)
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
				buildChain(s, p, nodes, c, credOf[did].Ref(), hops)...)
			// 探测入口:用户名 = 候选 tag,规则把它打到同名出站上。
			probeUsers = append(probeUsers, sbMixedUser{
				Username: ProbeUser(c.Tag()), Password: secretRef("probe/" + p.ID)})
			probeRules = append(probeRules, sbRule{
				Inbound:  []string{"probe-in"},
				AuthUser: []string{ProbeUser(c.Tag())},
				Outbound: c.Tag(),
			})
		}
		cfg.Outbounds = append(cfg.Outbounds, sbOutbound{
			Type: "selector", Tag: "decl:" + did, Outbounds: tags, Default: selectorDefault(tags),
		})
		routable[did] = true

		if d.Fallback != model.FailClosed {
			note("access:"+p.ID+"/"+did,
				"fallback=%s 尚未在数据平面实现,当前行为等同 fail_closed(§5.8)", d.Fallback)
		}
	}

	// 服务:每个服务一个 selector,按 host 反查(§4.5)。
	//
	// 同一条声明治理的多个服务**各自独立选路** —— 这正是 D43 修正的那点:
	// 一个候选服务所有目标,而实测没有任何候选对所有目标都好。
	var svcRules []sbRule
	if byService {
		for _, svc := range s.Services {
			d, ok := decls[svc.Declaration]
			if !ok || credOf[svc.Declaration] == nil {
				continue // 这个接入节点的凭据没覆盖这条声明
			}
			cands, cskips := s.EnumerateServiceCandidates(p, d, &svc)
			for _, cs := range cskips {
				note("access:"+p.ID+"/svc:"+svc.ID, "%s", cs.Reason)
			}
			if len(cands) == 0 {
				note("access:"+p.ID+"/svc:"+svc.ID,
					"该服务没有任何可表达的 L4 候选,它的流量将落到兜底")
				continue
			}
			var tags []string
			for i := range cands {
				c := &cands[i]
				tags = append(tags, c.Tag())
				cfg.Outbounds = append(cfg.Outbounds,
					buildChain(s, p, nodes, c, credOf[svc.Declaration].Ref(), hops)...)
				probeUsers = append(probeUsers, sbMixedUser{
					Username: ProbeUser(c.Tag()), Password: secretRef("probe/" + p.ID)})
				probeRules = append(probeRules, sbRule{
					Inbound:  []string{"probe-in"},
					AuthUser: []string{ProbeUser(c.Tag())},
					Outbound: c.Tag(),
				})
			}
			cfg.Outbounds = append(cfg.Outbounds, sbOutbound{
				Type: "selector", Tag: svc.Tag(), Outbounds: tags, Default: selectorDefault(tags),
			})
			svcRules = append(svcRules, serviceRule(&svc, managedInbounds))
		}
	}

	for _, mp := range ports {
		if mp.ManagedAutomatic() {
			continue // 规则由 serviceRule 生成,按 host 匹配而不是按端口
		}
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
	// 服务规则排在端口规则之后:钉死出口的端口是接入端的显式意图,
	// 它压过按 host 的自动判断。
	cfg.Route.Rules = append(cfg.Route.Rules, svcRules...)

	// 设备默认策略只接未命中 Service 的流量，所以必须排在 Service 规则之后。
	// managed mixed 与 TUN 复用同一条规则，不需要为“默认德国”再开一个端口。
	if len(managedInbounds) > 0 && defaultDecl != "" {
		if !routable[defaultDecl] {
			note("access:"+p.ID,
				"default_declaration %q 没有可用候选,未匹配 Service 的流量将被阻断", defaultDecl)
		} else {
			cfg.Route.Rules = append(cfg.Route.Rules, sbRule{
				Inbound: append([]string(nil), managedInbounds...), Outbound: "decl:" + defaultDecl,
			})
		}
	}
	// 探测入口:一个端口,用户名区分候选(见 ProbeListen)。
	// 规则排在最前 —— 它按 auth_user 匹配,与业务规则不重叠,但放前面能
	// 保证探测流量永远走它自己那条候选。
	if len(probeUsers) > 0 {
		cfg.Inbounds = append(cfg.Inbounds, sbInbound{
			Type: "mixed", Tag: "probe-in",
			Listen: probeHost(), ListenPort: probePort(),
			Users: probeUsers,
		})
		cfg.Route.Rules = append(probeRules, cfg.Route.Rules...)
	}

	return skips, nil
}

// buildChain 生成一条候选所需的全部出站,最后一个的 tag 就是候选本身。
//
// 链上每一跳都是普通的代理连接:先连第一台服务器,再让它连第二台,
// 最后一跳直接连目标地址(§5.6)。没有额外发明的机制。
func buildChain(
	s *model.SSOT,
	access *model.Node,
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
			// 第一跳由接入节点拨:公网地址,或两者之间隧道内的地址。
			o.Server, o.ServerPort = s.AccessHopAddr(access, sv), sv.Server.InboundPort
		} else {
			// 后续跳由前一跳转发,拨的是它在那条链路上的地址。
			o.Server, o.ServerPort = s.NextHopAddr(nodes[c.ServerChain[i-1]], sv), sv.Server.InboundPort
		}
		o.TLS = clientTLS(serverName(sv), accessTLSCAPath(access.Access.Platform))
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
		user string
		// prevUser 非空表示这份凭据正在轮换的过渡窗口里 —— 路由规则要
		// 同时匹配两代的用户名,否则用旧凭据连上来的流量认证过了却没有
		// 规则接,落到 final: block。
		prevUser       string
		nextHops       map[string]string // 下一跳 CIDR -> 出站 tag
		nextHopDomains map[string]string // 下一跳域名 -> 出站 tag
		egress         bool
		domains        []string // 出口规则的域名限制;空表示不限(地址随请求走)
	}
	var rules []rule
	var users []sbUser
	var telemetry []hy2LinkProbePlan

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
		// 候选集因接入节点而异,所以先找出这张凭据是谁的。
		owner := s.AccessNodeForCredential(c.ID)
		if owner == nil || owner.Paused {
			continue
		}
		cands, _ := s.EnumerateCandidates(owner, d)

		r := rule{user: c.ID, nextHops: map[string]string{}, nextHopDomains: map[string]string{}}
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
						if net.ParseIP(addr) != nil {
							r.nextHops[addr+"/32"] = "via-" + next.ID
						} else {
							r.nextHopDomains[addr] = "via-" + next.ID
						}
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
		users = append(users, sbUser{Name: c.ID, Password: secretRef(c.Ref())})
		// 轮换的过渡窗口:同时收上一代(§13.4)。
		//
		// 分发是最终一致的 —— 节点各自按自己的节奏取配置,顺序还带抖动。
		// 客户端和服务器不可能在同一刻切换,所以必须有一段两代都收的时间,
		// 否则轮换的瞬间连接全断。
		if c.RotationPending() {
			users = append(users, sbUser{Name: c.PrevUser(), Password: secretRef(c.PrevRef())})
			// **必须在 append 之前赋值** —— rules 存的是值,append 之后再改
			// 局部变量不会写回切片。
			r.prevUser = c.PrevUser()
		}
		rules = append(rules, r)
	}
	for _, plan := range hy2LinkProbePlans(s) {
		if plan.To != sv.ID {
			continue
		}
		telemetry = append(telemetry, plan)
		users = append(users, sbUser{
			Name: plan.user(), Password: secretRef(plan.secretRef()),
		})
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
		for _, tag := range r.nextHopDomains {
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
	if len(telemetry) > 0 {
		cfg.Outbounds = append(cfg.Outbounds, sbOutbound{Type: "direct", Tag: "hy2-link-reflector"})
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
				AuthUser: authUsers(r.user, r.prevUser), IPCIDR: byTag[t], Outbound: t,
			})
		}
		byDomainTag := map[string][]string{}
		for domain, tag := range r.nextHopDomains {
			byDomainTag[tag] = append(byDomainTag[tag], domain)
		}
		tags = tags[:0]
		for tag := range byDomainTag {
			tags = append(tags, tag)
		}
		sort.Strings(tags)
		for _, tag := range tags {
			sort.Strings(byDomainTag[tag])
			cfg.Route.Rules = append(cfg.Route.Rules, sbRule{
				AuthUser: authUsers(r.user, r.prevUser), Domain: byDomainTag[tag], Outbound: tag,
			})
		}
	}
	for _, r := range rules {
		if !r.egress || !sv.Server.EgressCapable {
			continue
		}
		cfg.Route.Rules = append(cfg.Route.Rules, sbRule{
			AuthUser: authUsers(r.user, r.prevUser), Domain: r.domains, Outbound: "egress",
		})
	}
	// Telemetry credentials are intentionally unable to use the ordinary
	// egress path.  They can reach only the report reflector on target loopback;
	// /status and arbitrary destinations stay outside this trust boundary.
	for _, plan := range telemetry {
		cfg.Route.Rules = append(cfg.Route.Rules, sbRule{
			AuthUser: []string{plan.user()}, IPCIDR: []string{"127.0.0.1/32"},
			Port: []int{LinkMetricReflectorPort}, Outbound: "hy2-link-reflector",
		})
	}
}

// linkMetricInto adds the source half of each direct inner-ring measurement:
// one loopback-only mixed listener and one dedicated public Hysteria2 outbound.
// No selector or business route participates, so the sample cannot silently
// turn into an end-to-end candidate measurement.
func linkMetricInto(cfg *sbConfig, s *model.SSOT, n *model.Node) {
	nodes := s.NodeByID()
	for _, plan := range hy2LinkProbePlans(s) {
		if plan.From != n.ID {
			continue
		}
		peer := nodes[plan.To]
		if peer == nil || !peer.PubliclyDialable() ||
			peer.Server.InboundProtocol.Or() != model.Hysteria2 {
			continue
		}
		cfg.Inbounds = append(cfg.Inbounds, sbInbound{
			Type: "mixed", Tag: plan.inboundTag(),
			Listen: "127.0.0.1", ListenPort: plan.Port,
		})
		cfg.Outbounds = append(cfg.Outbounds, sbOutbound{
			Type: string(model.Hysteria2), Tag: plan.outboundTag(),
			Server: peer.PublicEndpoint, ServerPort: peer.Server.InboundPort,
			Password: secretRef(plan.secretRef()), TLS: clientTLS(serverName(peer), tlsCAPath),
		})
		cfg.Route.Rules = append(cfg.Route.Rules, sbRule{
			Inbound: []string{plan.inboundTag()}, Outbound: plan.outboundTag(),
		})
	}
}

// renderSingBox 生成一台机器的 sing-box 配置。
//
// **一台机器一个 sing-box 进程,因此只有一份配置。** 同时持有两种角色的
// 机器(服务器自己也要走代理出去)把两边的 inbound、outbound 与路由规则
// 合并进同一份 —— 两种角色喂的是不相干的逻辑,只在这里汇合。
//
// 配置源只有一个(SSOT → 渲染器),所以合并不存在"两个源互相覆盖"的问题。
// §18 的加入输入只把中控已创建的 Device 与本机身份绑定并引导首次签名配置；
// 它适用于包括服务器在内的所有新 Device，不是另一个配置源。
func renderSingBox(s *model.SSOT, n *model.Node) (File, []Skip, error) {
	cfg := &sbConfig{Log: sbLog{Level: "warn"}}
	var skips []Skip

	// 显式指定解析器,不依赖系统的。系统解析器坏掉时,表现是"直连候选
	// 永远失败、代理候选一切正常" —— 因为走代理的域名是交给出口解析的
	// (§7.4),根本不经过本机。这种不对称极难往 DNS 上想。
	if dns := s.DNSFor(n); len(dns) > 0 {
		d := &sbDNS{Strategy: "prefer_ipv4"}
		for i, addr := range dns {
			d.Servers = append(d.Servers, sbDNSServer{
				Tag: fmt.Sprintf("dns%d", i), Address: addr, Detour: dnsOutbound})
		}
		cfg.DNS = d
		cfg.Outbounds = append(cfg.Outbounds, sbOutbound{Type: "direct", Tag: dnsOutbound})
	}

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
	linkMetricInto(cfg, s, n)

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

// accessDecls 返回一个接入节点凭据允许使用的声明(按 id 排序)与对应凭据。
//
// 提取出来是因为 Agent 的配置必须与 sing-box 配置枚举出**同一批**声明和
// 候选:两边各写一遍,迟早会分叉,而分叉的表现是 Agent 去切一个不存在的
// selector,或者漏掉某条候选从不探测。
func accessDecls(s *model.SSOT, p *model.Node) ([]string, map[string]*model.Credential) {
	creds := s.CredentialByID()
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
	return declIDs, credOf
}

// selectorDefault 挑一个"什么都还不知道时"的默认候选。
//
// 原来取 tags[0],那是枚举顺序的副产物 —— 枚举零跳优先,于是默认永远是
// 直连。对一条存在的意义就是绕道的声明来说,直连是**最不该**盲选的那个:
// 实测 best-egress 的直连候选对目标超时 10 秒,而 selector 每次 sing-box
// 重启都回到它,流量就一直打在一条已知不通的路上。
//
// 所以默认优先取第一条经过服务器的候选;只有直连一个选项时才用它。这仍是
// 个静态猜测 —— 真正的选择由 Agent 按实测数据接管(§5.5),这里只保证
// Agent 没跑起来的那段时间里不至于停在最差的一个上。
func selectorDefault(tags []string) string {
	for _, t := range tags {
		if !strings.HasSuffix(t, ":direct") {
			return t
		}
	}
	return tags[0]
}

// managedAutomaticInbounds 返回共享中控规则的全部入口。TUN 与 services:true
// mixed 必须看到同一组 Service 与设备默认策略；显式 override 端口不在这里。
func managedAutomaticInbounds(p *model.Node, ports []model.MixedPort) []string {
	var out []string
	if p.Access.Platform.UsesTUN() {
		out = append(out, "tun-in")
	}
	for _, mp := range ports {
		if mp.ManagedAutomatic() {
			out = append(out, fmt.Sprintf("in-%d", mp.Port))
		}
	}
	return out
}

// serviceRule 生成"这些 host 走这个服务的 selector"的路由规则。
func serviceRule(svc *model.Service, inbounds []string) sbRule {
	r := sbRule{Inbound: append([]string(nil), inbounds...), Outbound: svc.Tag()}
	for _, a := range svc.SortedAddresses() {
		if model.IsSuffix(a) {
			// `.openai.com` → 匹配 api.openai.com,也匹配 openai.com 本身。
			r.DomainSuffix = append(r.DomainSuffix, a)
			r.Domain = append(r.Domain, strings.TrimPrefix(a, "."))
			continue
		}
		r.Domain = append(r.Domain, a)
	}
	return r
}

// pinnedDecls 返回被显式 override 或设备默认策略钉住的声明,以及生效的默认
// 声明。managed automatic 的已匹配流量不在这里;它按 Service 各自选路。
//
// **这是唯一的推导来源。** 渲染 sing-box 和渲染 Agent 配置都要用它 ——
// 两边各写一遍的结果是 Agent 去切一个没渲染出来的 selector,而这个错误
// 只有在跑起来之后才看得见。
func pinnedDecls(p *model.Node) (map[string]bool, string) {
	out := map[string]bool{}
	for _, mp := range p.Access.MixedPorts {
		if !mp.ManagedAutomatic() && mp.ExplicitOverride() {
			out[mp.Declaration] = true
		}
	}
	defaultDecl := p.Access.EffectiveDefaultDeclaration()
	if defaultDecl != "" {
		out[defaultDecl] = true
	}
	return out, defaultDecl
}

// authUsers 是一条规则要匹配的用户名。
//
// 轮换的过渡窗口里有两个:当前代和上一代。**两个都要匹配** —— 只匹配当前代
// 的话,用旧凭据连上来的流量认证过了却没有规则接,落到 `final: block`。
// 那种失败比"认证失败"难查得多:客户端看到的是连上了然后没反应。
func authUsers(cur, prev string) []string {
	if prev == "" {
		return []string{cur}
	}
	return []string{cur, prev}
}
