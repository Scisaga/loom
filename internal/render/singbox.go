package render

import (
	"encoding/json"
	"fmt"
	"sort"

	"loom/internal/model"
)

// 本文件渲染三类节点的 sing-box 配置:接入(客户端档案)、中继、落地目标。
//
// 全部用结构体而非 map 序列化 —— 结构体的字段顺序是确定的,map 不是,
// 而渲染必须是纯函数(§12)。

// TLS 材料的约定路径。与私钥同理,渲染层只写引用,文件本身属于秘密层(§12.1)。
const (
	tlsCertPath = "/etc/loom/tls/node.crt"
	tlsKeyPath  = "/etc/loom/secrets/node.key"
	tlsCAPath   = "/etc/loom/tls/loom-ca.crt"
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
	BindInterface string `json:"bind_interface,omitempty"`
}

type sbRule struct {
	Inbound  []string `json:"inbound,omitempty"`
	AuthUser []string `json:"auth_user,omitempty"`
	IPCIDR   []string `json:"ip_cidr,omitempty"`
	Port     []int    `json:"port,omitempty"`
	Outbound string   `json:"outbound"`
}

type sbRoute struct {
	Rules []sbRule `json:"rules,omitempty"`
	Final string   `json:"final"`
}

type sbConfig struct {
	Log       sbLog        `json:"log"`
	Inbounds  []sbInbound  `json:"inbounds"`
	Outbounds []sbOutbound `json:"outbounds"`
	Route     sbRoute      `json:"route"`
}

func encode(c *sbConfig) (string, error) {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b) + "\n", nil
}

func clientTLS(serverName string) *sbTLS {
	return &sbTLS{Enabled: true, ServerName: serverName, CertificatePath: tlsCAPath, ALPN: []string{"h3"}}
}

func serverTLS() *sbTLS {
	return &sbTLS{Enabled: true, CertificatePath: tlsCertPath, KeyPath: tlsKeyPath, ALPN: []string{"h3"}}
}

// ---------------------------------------------------------------------------
// 接入节点
// ---------------------------------------------------------------------------

// renderProfile 渲染一个客户端档案的 sing-box 配置(§7)。
//
// 每个 mixed 端口绑定一个访问声明(§7.3);每条声明有一个 selector,
// 成员是它的全部 RouteCandidate(§5.6)。
//
// 用 selector 而不是 urltest 是刻意的:§5.6 要求选路的决策者只有一个。
// urltest 会按自己的节奏和判据独立选路,与 Agent 的 §5.5 阻尼规则形成
// 两个互不知情的决策者。selector 的当前选择由 Agent 设置;Agent 尚未
// 实现时它停在 default 上,即 §20.2 的"路径静态指定"。
func renderProfile(s *model.SSOT, p *model.ClientProfile) (File, []Skip, error) {
	nodes := s.NodeByID()
	decls := s.DeclarationByID()
	creds := s.CredentialByID()

	cfg := &sbConfig{Log: sbLog{Level: "warn"}}
	var skips []Skip

	// 凭据决定这个档案能用哪些声明。
	declOf := map[string]*model.Credential{} // declaration id -> credential
	var declIDs []string
	for _, cid := range p.Credentials {
		c, ok := creds[cid]
		if !ok || c.Revoked() {
			continue
		}
		if _, dup := declOf[c.Declaration]; !dup {
			declIDs = append(declIDs, c.Declaration)
		}
		declOf[c.Declaration] = c
	}
	sort.Strings(declIDs)

	if p.Platform.UsesTUN() {
		cfg.Inbounds = append(cfg.Inbounds, sbInbound{
			Type: "tun", Tag: "tun-in",
			Address:   []string{"172.19.0.1/30"},
			AutoRoute: true, Stack: "system",
		})
	}
	ports := append([]model.MixedPort(nil), p.MixedPorts...)
	sort.Slice(ports, func(i, j int) bool { return ports[i].Port < ports[j].Port })
	for _, mp := range ports {
		cfg.Inbounds = append(cfg.Inbounds, sbInbound{
			Type: "mixed", Tag: fmt.Sprintf("in-%d", mp.Port),
			Listen: "127.0.0.1", ListenPort: mp.Port,
		})
	}

	hops := map[string]bool{}     // 已生成的中继跳,避免重复
	routable := map[string]bool{} // 实际生成了 selector 的声明
	for _, did := range declIDs {
		d, ok := decls[did]
		if !ok {
			continue
		}
		cands, cskips := s.EnumerateCandidates(d)
		for _, cs := range cskips {
			skips = append(skips, Skip{Where: "profile:" + p.ID + "/" + cs.Declaration, Reason: cs.Reason})
		}
		if len(cands) == 0 {
			skips = append(skips, Skip{
				Where:  "profile:" + p.ID + "/" + did,
				Reason: "该声明没有任何可表达的 L4 候选,已跳过其 outbound 与路由规则",
			})
			continue
		}

		var tags []string
		for _, c := range cands {
			relay := nodes[c.RelayChain[0]]
			hopTag := "hop:" + did + ":" + relay.ID
			if !hops[hopTag] {
				hops[hopTag] = true
				cfg.Outbounds = append(cfg.Outbounds, sbOutbound{
					Type: "hysteria2", Tag: hopTag,
					Server: relay.PublicEndpoint, ServerPort: relay.InboundPort,
					Password: secretRef(declOf[did].SecretRef),
					TLS:      clientTLS(relay.PublicEndpoint),
				})
			}
			// 目标腿:连到目标在该隧道中的地址。下一跳就是一个 IP:port,
			// 这样 §8.2 的允许下一跳集合才能表达成中继上的准入白名单。
			cfg.Outbounds = append(cfg.Outbounds, sbOutbound{
				Type: "socks", Tag: c.Tag(), Version: "5",
				Server: s.TunnelAddrOn(c.Target, relay.ID), ServerPort: nodes[c.Target].InboundPort,
				Detour: hopTag,
			})
			tags = append(tags, c.Tag())
		}

		cfg.Outbounds = append(cfg.Outbounds, sbOutbound{
			Type: "selector", Tag: "decl:" + did,
			Outbounds: tags, Default: tags[0],
		})
		routable[did] = true

		// §5.8 的 fallback 尚未在数据平面实现。fail_closed 恰好等同于
		// route.final = block,所以只有其余两个取值需要报出。
		if d.Fallback != model.FailClosed {
			skips = append(skips, Skip{
				Where: "profile:" + p.ID + "/" + did,
				Reason: fmt.Sprintf("fallback=%s 尚未在数据平面实现,当前行为等同 fail_closed(§5.8)",
					d.Fallback),
			})
		}
	}

	// 不生成 direct 出站:没有任何规则引用它,留着会让人以为存在一条
	// 直连兜底。§5.8 的 fallback: direct 尚未实现。
	cfg.Outbounds = append(cfg.Outbounds, sbOutbound{Type: "block", Tag: "block"})

	for _, mp := range ports {
		// 引用一个没生成的 selector 会让 sing-box 直接启动失败。宁可不写
		// 这条规则 —— 流量落到 final: block,与 fail_closed 一致。
		if !routable[mp.Declaration] {
			skips = append(skips, Skip{
				Where: "profile:" + p.ID,
				Reason: fmt.Sprintf("端口 %d 绑定的声明 %q 没有可用候选,该端口不生成路由规则,"+
					"流量将被阻断", mp.Port, mp.Declaration),
			})
			continue
		}
		cfg.Route.Rules = append(cfg.Route.Rules, sbRule{
			Inbound:  []string{fmt.Sprintf("in-%d", mp.Port)},
			Outbound: "decl:" + mp.Declaration,
		})
	}
	// TUN 兜底走哪条声明由档案显式声明;Android 只有一把凭据时可推导(§7.2)。
	if p.Platform.UsesTUN() {
		tunDecl := p.DefaultDeclaration
		if tunDecl == "" && len(declIDs) == 1 {
			tunDecl = declIDs[0]
		}
		switch {
		case tunDecl == "":
			skips = append(skips, Skip{
				Where:  "profile:" + p.ID,
				Reason: "未声明 default_declaration,TUN 兜底流量将被阻断",
			})
		case !routable[tunDecl]:
			skips = append(skips, Skip{
				Where:  "profile:" + p.ID,
				Reason: fmt.Sprintf("default_declaration %q 没有可用候选,TUN 兜底流量将被阻断", tunDecl),
			})
		default:
			cfg.Route.Rules = append(cfg.Route.Rules, sbRule{
				Inbound: []string{"tun-in"}, Outbound: "decl:" + tunDecl,
			})
		}
	}
	// 未匹配的流量一律阻断,而不是回落到 direct:回落会让一条本该受
	// 声明约束的连接悄悄绕开调度,和 §5.8 的 fail_closed 是同一个道理。
	cfg.Route.Final = "block"

	content, err := encode(cfg)
	if err != nil {
		return File{}, nil, err
	}
	return File{Path: "sing-box/config.json", Content: content}, skips, nil
}

// ---------------------------------------------------------------------------
// 中继
// ---------------------------------------------------------------------------

// renderRelay 渲染中继的 sing-box 配置(§8)。
//
// 中继做准入校验,不做选路(§5.6):按凭据白名单允许的下一跳集合放行,
// 其余一律阻断。允许集合是 AccessDeclaration 与候选枚举的渲染产物 ——
// 拿到一张凭据不等于能经这个中继访问任意地方(§8.2)。
func renderRelay(s *model.SSOT, relay *model.Node) (File, error) {
	nodes := s.NodeByID()
	decls := s.DeclarationByID()

	cfg := &sbConfig{Log: sbLog{Level: "warn"}}

	// 凭据 → 允许的下一跳集合。
	type entry struct {
		user   string
		secret string // 必须与接入侧引用同一个条目,否则两边查不到同一把密钥
		hops   []string
		iface  map[string]string // 下一跳地址 -> 出接口
	}
	var entries []entry
	seenUser := map[string]bool{}

	creds := append([]model.Credential(nil), s.Credentials...)
	sort.Slice(creds, func(i, j int) bool { return creds[i].ID < creds[j].ID })

	for i := range creds {
		c := &creds[i]
		if c.Revoked() {
			continue // §18:吊销后所有中继在下一轮询周期移除该 user
		}
		d, ok := decls[c.Declaration]
		if !ok {
			continue
		}
		cands, _ := s.EnumerateCandidates(d)
		e := entry{user: c.ID, secret: c.SecretRef, iface: map[string]string{}}
		for _, cand := range cands {
			if cand.RelayChain[0] != relay.ID {
				continue // 这条候选不经过本中继
			}
			addr := s.TunnelAddrOn(cand.Target, relay.ID)
			if addr == "" {
				continue
			}
			cidr := addr + "/32"
			if _, dup := e.iface[cidr]; dup {
				continue
			}
			e.hops = append(e.hops, cidr)
			e.iface[cidr] = model.IfaceName(cand.Target)
			_ = nodes
		}
		if len(e.hops) == 0 {
			continue
		}
		sort.Strings(e.hops)
		if !seenUser[c.ID] {
			seenUser[c.ID] = true
			entries = append(entries, e)
		}
	}

	var users []sbUser
	for _, e := range entries {
		users = append(users, sbUser{Name: e.user, Password: secretRef(e.secret)})
	}
	cfg.Inbounds = append(cfg.Inbounds, sbInbound{
		Type: "hysteria2", Tag: "in",
		Listen: "::", ListenPort: relay.InboundPort,
		Users: users, TLS: serverTLS(),
	})

	// 每个下一跳一个绑定到对应隧道接口的出站。绑接口而不是靠路由表,
	// 是为了让"这条流量必须走这条隧道"在配置里显式可见。
	var ifaces []string
	seenIface := map[string]bool{}
	for _, e := range entries {
		for _, cidr := range e.hops {
			ifn := e.iface[cidr]
			if seenIface[ifn] {
				continue
			}
			seenIface[ifn] = true
			ifaces = append(ifaces, ifn)
		}
	}
	sort.Strings(ifaces)
	for _, ifn := range ifaces {
		cfg.Outbounds = append(cfg.Outbounds, sbOutbound{
			Type: "direct", Tag: "via-" + ifn, BindInterface: ifn,
		})
	}
	cfg.Outbounds = append(cfg.Outbounds, sbOutbound{Type: "block", Tag: "block"})

	for _, e := range entries {
		byIface := map[string][]string{}
		for _, cidr := range e.hops {
			ifn := e.iface[cidr]
			byIface[ifn] = append(byIface[ifn], cidr)
		}
		var ks []string
		for k := range byIface {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		for _, ifn := range ks {
			cfg.Route.Rules = append(cfg.Route.Rules, sbRule{
				AuthUser: []string{e.user},
				IPCIDR:   byIface[ifn],
				Outbound: "via-" + ifn,
			})
		}
	}
	// 白名单之外一律阻断 —— 这就是"准入校验"的全部含义。
	cfg.Route.Final = "block"

	content, err := encode(cfg)
	if err != nil {
		return File{}, err
	}
	return File{Path: "sing-box/config.json", Content: content}, nil
}

// ---------------------------------------------------------------------------
// 落地目标
// ---------------------------------------------------------------------------

// renderLanding 渲染落地型目标的 sing-box 配置(§9.1)。
//
// 它在每条隧道的本端地址上开一个 socks inbound。不做用户认证:该地址只在
// WireGuard 隧道内可达,隧道本身就是认证边界。
func renderLanding(s *model.SSOT, target *model.Node) (File, error) {
	cfg := &sbConfig{Log: sbLog{Level: "warn"}}

	var addrs []string
	for i := range s.Tunnels {
		t := &s.Tunnels[i]
		switch target.ID {
		case t.From:
			addrs = append(addrs, stripMaskStr(t.FromAddr))
		case t.To:
			addrs = append(addrs, stripMaskStr(t.ToAddr))
		}
	}
	sort.Strings(addrs)
	for _, a := range addrs {
		cfg.Inbounds = append(cfg.Inbounds, sbInbound{
			Type: "socks", Tag: "in-" + a,
			Listen: a, ListenPort: target.InboundPort,
		})
	}

	// 落地出公网。ip_forward 与 MASQUERADE 由系统配置负责,不在 sing-box 里。
	cfg.Outbounds = append(cfg.Outbounds, sbOutbound{Type: "direct", Tag: "direct"})
	cfg.Route.Final = "direct"

	content, err := encode(cfg)
	if err != nil {
		return File{}, err
	}
	return File{Path: "sing-box/config.json", Content: content}, nil
}

func stripMaskStr(a string) string {
	for i := 0; i < len(a); i++ {
		if a[i] == '/' {
			return a[:i]
		}
	}
	return a
}
