package render

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"loom/internal/model"
)

// conf 是渲染出的 sing-box 配置的松散视图。测试刻意不复用渲染用的结构体
// —— 那样只能证明"我序列化了我构造的东西",证明不了产物本身自洽。
type conf struct {
	DNS *struct {
		Servers []struct {
			Tag     string `json:"tag"`
			Address string `json:"address"`
			Detour  string `json:"detour"`
		} `json:"servers"`
		Rules []struct {
			Inbound   []string `json:"inbound"`
			QueryType []string `json:"query_type"`
			Server    string   `json:"server"`
		} `json:"rules"`
		ReverseMapping   bool `json:"reverse_mapping"`
		IndependentCache bool `json:"independent_cache"`
		FakeIP           *struct {
			Enabled    bool   `json:"enabled"`
			Inet4Range string `json:"inet4_range"`
			Inet6Range string `json:"inet6_range"`
		} `json:"fakeip"`
	} `json:"dns"`
	Inbounds []struct {
		Type       string   `json:"type"`
		Tag        string   `json:"tag"`
		Listen     string   `json:"listen"`
		ListenPort int      `json:"listen_port"`
		Address    []string `json:"address"`
		AutoRoute  bool     `json:"auto_route"`
		Stack      string   `json:"stack"`
		MTU        int      `json:"mtu"`
		Users      []struct {
			Name     string `json:"name"`
			Username string `json:"username"`
			Password string `json:"password"`
		} `json:"users"`
	} `json:"inbounds"`
	Outbounds []struct {
		Type            string   `json:"type"`
		Tag             string   `json:"tag"`
		Server          string   `json:"server"`
		ServerPort      int      `json:"server_port"`
		Password        string   `json:"password"`
		Detour          string   `json:"detour"`
		Outbounds       []string `json:"outbounds"`
		Default         string   `json:"default"`
		OverrideAddress string   `json:"override_address"`
		OverridePort    int      `json:"override_port"`
	} `json:"outbounds"`
	Route struct {
		AutoDetectInterface bool `json:"auto_detect_interface"`
		Rules               []struct {
			Type        string   `json:"type"`
			Mode        string   `json:"mode"`
			Action      string   `json:"action"`
			DomainRegex []string `json:"domain_regex"`
			Invert      bool     `json:"invert"`
			Rules       []struct {
				Inbound     []string `json:"inbound"`
				DomainRegex []string `json:"domain_regex"`
				Invert      bool     `json:"invert"`
			} `json:"rules"`
			Inbound      []string `json:"inbound"`
			AuthUser     []string `json:"auth_user"`
			IPCIDR       []string `json:"ip_cidr"`
			Domain       []string `json:"domain"`
			DomainSuffix []string `json:"domain_suffix"`
			Port         []int    `json:"port"`
			Outbound     string   `json:"outbound"`
		} `json:"rules"`
		Final string `json:"final"`
	} `json:"route"`
	Experimental *struct {
		CacheFile *struct {
			Enabled     bool   `json:"enabled"`
			Path        string `json:"path"`
			StoreFakeIP bool   `json:"store_fakeip"`
		} `json:"cache_file"`
	} `json:"experimental"`
}

// TestManagedAutomaticAndExplicitOverrideRouting 把 mixed 入口的两种派生语义
// 钉在最终数据平面上:正常入口只按 Service 分流;声明绑定端口只是显式
// override;自动入口未匹配到 Service 时必须 fail closed。
func TestManagedAutomaticAndExplicitOverrideRouting(t *testing.T) {
	s, err := model.Load([]byte(`
defaults:
  dns: [223.5.5.5]
  components: {sing_box: 1.11.4, wireguard: 1.0.20250521, agent: 0.1.0}
nodes:
  - id: access
    access:
      platform: linux-server
      credentials: [cred-fixed, cred-auto]
      mixed_ports:
        - {port: 1080, declaration: fixed}
        - {port: 1083, services: true}
  - id: egress
    public_endpoint: 192.0.2.10
    server:
      direction: bidirectional
      inbound_port: 4433
      egress_capable: true
      wg_public_key: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
declarations:
  - id: fixed
    address_axis: from_request
    egress_axis: pinned:egress
    objective: latency
    probe_url: https://managed.example/
    tuning_period: 5m
    allowed_servers: [egress]
    max_hops: 1
  - id: automatic
    address_axis: from_request
    egress_axis: any
    objective: latency
    probe_url: https://managed.example/
    tuning_period: 5m
    allowed_servers: [egress]
    max_hops: 1
credentials:
  - {id: cred-fixed, declaration: fixed, secret_ref: cred/fixed}
  - {id: cred-auto, declaration: automatic, secret_ref: cred/automatic}
services:
  - {id: web, declaration: automatic, addresses: [managed.example]}
`))
	if err != nil {
		t.Fatal(err)
	}
	res, err := Render(s)
	if err != nil {
		t.Fatal(err)
	}

	var c conf
	found := false
	for _, b := range res.Bundles {
		if b.Owner != "access" {
			continue
		}
		for _, f := range b.Files {
			if f.Path != "sing-box/config.json" {
				continue
			}
			if err := json.Unmarshal([]byte(f.Content), &c); err != nil {
				t.Fatal(err)
			}
			found = true
		}
	}
	if !found {
		t.Fatal("接入节点没有 sing-box 配置")
	}

	overrideRule, automaticRule := -1, -1
	for i, r := range c.Route.Rules {
		hasOverride, hasAutomatic := false, false
		for _, in := range r.Inbound {
			hasOverride = hasOverride || in == "in-1080"
			hasAutomatic = hasAutomatic || in == "in-1083"
		}
		if hasOverride {
			if r.Outbound != "decl:fixed" || len(r.Domain) != 0 || len(r.DomainSuffix) != 0 {
				t.Errorf("显式 override 入口被 Service 规则接管:%+v", r)
			}
			overrideRule = i
		}
		if hasAutomatic {
			if r.Outbound != "svc:web" || len(r.Domain) != 1 || r.Domain[0] != "managed.example" {
				t.Errorf("managed automatic 入口没有按 Service 分流:%+v", r)
			}
			automaticRule = i
		}
	}
	if overrideRule < 0 || automaticRule < 0 {
		t.Fatalf("缺少入口路由规则:override=%d automatic=%d", overrideRule, automaticRule)
	}
	if overrideRule >= automaticRule {
		t.Errorf("显式 override 规则应先于自动 Service 规则:override=%d automatic=%d",
			overrideRule, automaticRule)
	}
	if c.Route.Final != "block" {
		t.Errorf("自动入口未匹配 Service 时必须阻断,route.final=%q", c.Route.Final)
	}
}

// 设备默认策略复用现有入口：Linux 只复用 managed mixed；Windows 的配置
// 形状(TUN + services:true mixed)则让两种接管方式共享 Service 与默认规则。
func TestDeviceDefaultReusesManagedInbounds(t *testing.T) {
	for _, tc := range []struct {
		name     string
		platform model.Platform
		inbounds []string
	}{
		{name: "linux-server", platform: model.LinuxServer, inbounds: []string{"in-1080"}},
		{name: "windows-desktop", platform: model.WindowsDesktop, inbounds: []string{"tun-in", "in-1080"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := model.Load([]byte(fmt.Sprintf(`
defaults:
  dns: [223.5.5.5]
  components: {sing_box: 1.11.4, wireguard: 1.0.20250521, agent: 0.1.0}
nodes:
  - id: access
    access:
      platform: %s
      credentials: [cred-service, cred-default]
      default_declaration: fixed
      mixed_ports: [{port: 1080, services: true}]
  - id: egress
    public_endpoint: 192.0.2.10
    server:
      direction: bidirectional
      inbound_port: 4433
      egress_capable: true
      wg_public_key: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
declarations:
  - id: automatic
    address_axis: from_request
    egress_axis: any
    objective: latency
    probe_url: https://managed.example/
    tuning_period: 5m
    allowed_servers: [egress]
    max_hops: 1
  - id: fixed
    address_axis: from_request
    egress_axis: pinned:egress
    objective: stability
    probe_url: https://fallback.example/
    tuning_period: 5m
    allowed_servers: [egress]
    max_hops: 1
credentials:
  - {id: cred-service, declaration: automatic, secret_ref: cred/service}
  - {id: cred-default, declaration: fixed, secret_ref: cred/default}
services:
  - {id: web, declaration: automatic, addresses: [managed.example]}
`, tc.platform)))
			if err != nil {
				t.Fatal(err)
			}
			res, err := Render(s)
			if err != nil {
				t.Fatal(err)
			}

			var c conf
			for _, bundle := range res.Bundles {
				if bundle.Owner != "access" {
					continue
				}
				for _, file := range bundle.Files {
					if file.Path == "sing-box/config.json" {
						if err := json.Unmarshal([]byte(file.Content), &c); err != nil {
							t.Fatal(err)
						}
					}
				}
			}
			var trafficInbounds []string
			for _, inbound := range c.Inbounds {
				if inbound.Tag == "tun-in" || strings.HasPrefix(inbound.Tag, "in-") {
					trafficInbounds = append(trafficInbounds, inbound.Tag)
				}
			}
			if !slices.Equal(trafficInbounds, tc.inbounds) {
				t.Fatalf("设备默认策略不应创建额外入口:got=%v want=%v", trafficInbounds, tc.inbounds)
			}
			serviceAt, defaultAt := -1, -1
			for i, rule := range c.Route.Rules {
				switch rule.Outbound {
				case "svc:web":
					serviceAt = i
					if !slices.Equal(rule.Inbound, tc.inbounds) || !slices.Equal(rule.Domain, []string{"managed.example"}) {
						t.Errorf("Service 规则没有复用全部入口:%+v", rule)
					}
				case "decl:fixed":
					if len(rule.Domain) != 0 || len(rule.DomainSuffix) != 0 {
						continue
					}
					defaultAt = i
					if !slices.Equal(rule.Inbound, tc.inbounds) {
						t.Errorf("设备默认规则没有复用全部入口:%+v", rule)
					}
				}
			}
			if serviceAt < 0 || defaultAt < 0 || serviceAt >= defaultAt {
				t.Fatalf("规则优先级错误:service=%d default=%d", serviceAt, defaultAt)
			}
			if c.Route.Final != "block" {
				t.Fatalf("设备默认之外仍必须 fail closed,final=%q", c.Route.Final)
			}
		})
	}
}

func TestLinkMetricReflectorAdmissionIsLoopbackPortOnly(t *testing.T) {
	_, cfgs := configs(t)
	telemetryUsers := map[string]string{} // user -> target owner
	for owner, c := range cfgs {
		for _, in := range c.Inbounds {
			for _, user := range in.Users {
				if strings.HasPrefix(user.Name, "telemetry-") {
					telemetryUsers[user.Name] = owner
				}
			}
		}
	}
	if len(telemetryUsers) == 0 {
		t.Fatal("fixture 没有渲染链路探测 telemetry 用户")
	}
	for user, owner := range telemetryUsers {
		c := cfgs[owner]
		matched := 0
		for _, rule := range c.Route.Rules {
			contains := false
			for _, got := range rule.AuthUser {
				contains = contains || got == user
			}
			if !contains {
				continue
			}
			matched++
			if len(rule.IPCIDR) != 1 || rule.IPCIDR[0] != "127.0.0.1/32" ||
				len(rule.Port) != 1 || rule.Port[0] != LinkMetricReflectorPort ||
				rule.Outbound != "hy2-link-reflector" {
				t.Errorf("%s 在 %s 的准入超出 127.0.0.1:%d: %+v",
					user, owner, LinkMetricReflectorPort, rule)
			}
		}
		if matched != 1 {
			t.Errorf("%s 在 %s 命中 %d 条 route，want exactly 1", user, owner, matched)
		}
	}
}

// configs 渲染 fixture 并返回 owner -> 解析后的 sing-box 配置。
func configs(t *testing.T) (*model.SSOT, map[string]*conf) {
	t.Helper()
	s := load(t)
	res, err := Render(s)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]*conf{}
	for _, b := range res.Bundles {
		for _, f := range b.Files {
			if f.Path != "sing-box/config.json" {
				continue
			}
			var c conf
			if err := json.Unmarshal([]byte(f.Content), &c); err != nil {
				t.Fatalf("%s 的 sing-box 配置不是合法 JSON:%v", b.Owner, err)
			}
			out[b.Owner] = &c
		}
	}
	if len(out) == 0 {
		t.Fatal("没有渲染出任何 sing-box 配置")
	}
	return s, out
}

// TestSingBoxReferentialIntegrity 断言配置内部没有悬空引用。
//
// sing-box 遇到不存在的 outbound tag 会直接拒绝启动。这类错误在渲染期
// 完全可以发现,不该留到部署时 —— 而部署时它长得像"节点起不来"。
func TestSingBoxReferentialIntegrity(t *testing.T) {
	_, cfgs := configs(t)
	for owner, c := range cfgs {
		t.Run(owner, func(t *testing.T) {
			outTags := map[string]bool{}
			for _, o := range c.Outbounds {
				if outTags[o.Tag] {
					t.Errorf("outbound tag 重复:%s", o.Tag)
				}
				outTags[o.Tag] = true
			}
			inTags := map[string]bool{}
			for _, i := range c.Inbounds {
				if inTags[i.Tag] {
					t.Errorf("inbound tag 重复:%s", i.Tag)
				}
				inTags[i.Tag] = true
			}

			for _, o := range c.Outbounds {
				if o.Detour != "" && !outTags[o.Detour] {
					t.Errorf("outbound %s 的 detour 指向不存在的 %q", o.Tag, o.Detour)
				}
				for _, m := range o.Outbounds {
					if !outTags[m] {
						t.Errorf("selector %s 的成员 %q 不存在", o.Tag, m)
					}
				}
				if o.Default != "" && !outTags[o.Default] {
					t.Errorf("selector %s 的 default %q 不存在", o.Tag, o.Default)
				}
			}
			for i, r := range c.Route.Rules {
				if r.Outbound != "" && !outTags[r.Outbound] {
					t.Errorf("route.rules[%d] 指向不存在的 outbound %q", i, r.Outbound)
				}
				if r.Outbound == "" && r.Action == "" {
					t.Errorf("route.rules[%d] 既没有 outbound 也没有 action", i)
				}
				for _, in := range r.Inbound {
					if !inTags[in] {
						t.Errorf("route.rules[%d] 引用了不存在的 inbound %q", i, in)
					}
				}
				for nestedIndex, nested := range r.Rules {
					for _, in := range nested.Inbound {
						if !inTags[in] {
							t.Errorf("route.rules[%d].rules[%d] 引用了不存在的 inbound %q", i, nestedIndex, in)
						}
					}
				}
			}
			if c.Route.Final != "" && !outTags[c.Route.Final] {
				t.Errorf("route.final 指向不存在的 outbound %q", c.Route.Final)
			}
		})
	}
}

// TestSingBoxSecretsArePlaceholders 断言渲染层不含任何明文密钥。
//
// 明文写进渲染层会让 `loom diff` 把它打到终端、让快照哈希覆盖它、
// 让配置包在分发链路上处处是明文(§12.1、§18)。
func TestSingBoxSecretsArePlaceholders(t *testing.T) {
	s, cfgs := configs(t)

	// 渲染层会引用三类秘密:接入凭据、控制端点口令、探测入口口令。
	// 前者来自 SSOT,后两者按节点派生 —— 它们不是凭据,不该混进 Credentials。
	refs := map[string]bool{}
	for i := range s.Credentials {
		refs[s.Credentials[i].SecretRef] = true
	}
	for _, n := range s.AccessNodes() {
		refs["api/"+n.ID] = true
		refs["probe/"+n.ID] = true
	}
	for _, plan := range hy2LinkProbePlans(s) {
		refs[plan.secretRef()] = true
	}

	for owner, c := range cfgs {
		check := func(field, v string) {
			if v == "" {
				return
			}
			if !strings.HasPrefix(v, "${secret:") || !strings.HasSuffix(v, "}") {
				t.Errorf("%s 的 %s 不是占位符:%q", owner, field, v)
				return
			}
			ref := strings.TrimSuffix(strings.TrimPrefix(v, "${secret:"), "}")
			if !refs[ref] {
				t.Errorf("%s 的 %s 引用了 SSOT 里不存在的 secret_ref %q", owner, field, ref)
			}
		}
		for _, o := range c.Outbounds {
			check("outbound "+o.Tag+".password", o.Password)
		}
		for _, in := range c.Inbounds {
			for _, u := range in.Users {
				check("inbound user "+u.Name, u.Password)
			}
		}
	}
}

// TestSingBoxPathCorrespondence 是这一层的对应性保险,对应 WireGuard 的
// TestPairCorrespondence。
//
// 对每一条 RouteCandidate,断言这条链上每一跳的两端配置互相吻合:接入节点
// 拨的地址、每台服务器放行的下一跳、末跳的出口权限。任何一处对不上,结果
// 都是连接建立后被静默阻断,而不是报错。
func TestSingBoxPathCorrespondence(t *testing.T) {
	s, cfgs := configs(t)
	nodes := s.NodeByID()
	creds := s.CredentialByID()
	decls := s.DeclarationByID()

	for _, p := range s.AccessNodes() {
		access := cfgs[p.ID]
		if access == nil {
			t.Fatalf("接入节点 %s 没有渲染出配置", p.ID)
		}
		byTag := map[string]int{}
		for i, o := range access.Outbounds {
			byTag[o.Tag] = i
		}

		activeDecls, _ := pinnedDecls(p)
		for _, cid := range p.Access.Credentials {
			cred := creds[cid]
			if cred == nil || cred.Revoked() {
				continue
			}
			if !activeDecls[cred.Declaration] {
				continue // 只读授权不等于当前配置已引用；Service 路径另有独立测试。
			}
			d := decls[cred.Declaration]
			if d == nil {
				continue
			}
			cands, _ := s.EnumerateCandidates(p, d)

			for ci := range cands {
				cand := &cands[ci]
				t.Run(p.ID+"/"+cand.Tag(), func(t *testing.T) {
					checkCandidate(t, s, nodes, cfgs, access, byTag, cid, cred.SecretRef, cand)
				})
			}
		}
	}
}

func checkCandidate(
	t *testing.T,
	s *model.SSOT,
	nodes map[string]*model.Node,
	cfgs map[string]*conf,
	access *conf,
	byTag map[string]int,
	credID, secret string,
	cand *model.RouteCandidate,
) {
	t.Helper()

	// 一 · 接入侧:候选出站存在,并且沿着链一跳一跳对得上。
	ci, ok := byTag[cand.Tag()]
	if !ok {
		t.Fatalf("接入侧缺少候选出站 %s", cand.Tag())
	}

	// 从候选出站沿 detour 往回走,得到实际的链(顺序与 ServerChain 相反)。
	var walked []int
	for i := ci; ; {
		walked = append([]int{i}, walked...)
		det := access.Outbounds[i].Detour
		if det == "" {
			break
		}
		j, ok := byTag[det]
		if !ok {
			t.Fatalf("出站 %s 的 detour %q 不存在", access.Outbounds[i].Tag, det)
		}
		i = j
	}

	// 地址随请求走时链长即跳数;从等价类选地址时末尾多一个覆盖目的地的 direct。
	wantLen := len(cand.ServerChain)
	if cand.Address != "" {
		wantLen++
	}
	if wantLen == 0 {
		wantLen = 1 // 零跳直连也是一个出站
	}
	if len(walked) != wantLen {
		t.Fatalf("链长 %d,期望 %d(ServerChain=%v, Address=%q)",
			len(walked), wantLen, cand.ServerChain, cand.Address)
	}

	for i, id := range cand.ServerChain {
		o := access.Outbounds[walked[i]]
		sv := nodes[id]
		wantAddr := sv.PublicEndpoint
		if i > 0 {
			// 后续跳由前一跳转发,拨的是它在那条链路上的地址。
			wantAddr = s.NextHopAddr(nodes[cand.ServerChain[i-1]], sv)
		}
		if o.Server != wantAddr || o.ServerPort != sv.Server.InboundPort {
			t.Errorf("第 %d 跳拨向 %s:%d,期望 %s:%d", i, o.Server, o.ServerPort, wantAddr, sv.Server.InboundPort)
		}
		if o.Password != "${secret:"+secret+"}" {
			t.Errorf("第 %d 跳的密码引用是 %q,期望 %q", i, o.Password, "${secret:"+secret+"}")
		}

		// 二 · 服务器侧:这台机器接纳该凭据,且放行这一跳该去的地方。
		sc := cfgs[id]
		if sc == nil {
			t.Fatalf("服务器 %s 没有渲染出配置", id)
		}
		var serverPwd string
		for _, u := range sc.Inbounds[0].Users {
			if u.Name == credID {
				serverPwd = u.Password
			}
		}
		if serverPwd == "" {
			t.Fatalf("服务器 %s 的 inbound 里没有凭据 %s", id, credID)
		}
		// 两端必须引用同一个秘密条目,否则查到的不是同一把钥匙。
		if serverPwd != o.Password {
			t.Errorf("服务器 %s 侧密码引用 %q ≠ 接入侧 %q", id, serverPwd, o.Password)
		}

		if i+1 < len(cand.ServerChain) {
			next := nodes[cand.ServerChain[i+1]]
			want := admittedNextHop(s.NextHopAddr(sv, next))
			if !admits(sc, credID, want) {
				t.Errorf("服务器 %s 未放行凭据 %s 到下一跳 %s —— 准入校验会阻断这条候选",
					id, credID, want)
			}
		} else if !hasEgressRule(sc, credID) {
			t.Errorf("服务器 %s 是这条候选的出口,却没有给凭据 %s 的出口规则", id, credID)
		}
	}

	// 三 · 从等价类选地址时,末尾那个 direct 要覆盖到选中的地址。
	if cand.Address != "" {
		last := access.Outbounds[walked[len(walked)-1]]
		if last.Type != "direct" {
			t.Errorf("末尾出站类型是 %s,期望 direct(需要覆盖目的地)", last.Type)
		}
		if last.OverrideAddress == "" {
			t.Error("末尾出站没有 override_address —— 换地址不会生效")
		}
	}
}

func admits(c *conf, user, cidr string) bool {
	for _, r := range c.Route.Rules {
		if len(r.AuthUser) != 1 || r.AuthUser[0] != user {
			continue
		}
		for _, x := range r.IPCIDR {
			if x == cidr {
				return true
			}
		}
		for _, x := range r.Domain {
			if x == cidr {
				return true
			}
		}
	}
	return false
}

func admittedNextHop(address string) string {
	if net.ParseIP(address) != nil {
		return address + "/32"
	}
	return address
}

func hasEgressRule(c *conf, user string) bool {
	for _, r := range c.Route.Rules {
		if len(r.AuthUser) == 1 && r.AuthUser[0] == user && r.Outbound == "egress" {
			return true
		}
	}
	return false
}

// TestServerAdmitsNothingExtra 断言服务器的白名单不宽于它该放行的集合。
// 准入校验的价值全在于"多出来的不放行"(§8.2)。
func TestServerAdmitsNothingExtra(t *testing.T) {
	s, cfgs := configs(t)
	nodes := s.NodeByID()
	decls := s.DeclarationByID()

	for i := range s.Nodes {
		n := &s.Nodes[i]
		sc := cfgs[n.ID]
		if sc == nil || !n.IsServer() {
			continue
		}
		want := map[string]bool{}
		for j := range s.Credentials {
			c := &s.Credentials[j]
			if c.Revoked() {
				continue
			}
			d := decls[c.Declaration]
			if d == nil {
				continue
			}
			owner := s.AccessNodeForCredential(c.ID)
			if owner == nil {
				continue
			}
			cands, _ := s.EnumerateCandidates(owner, d)
			for k := range cands {
				chain := cands[k].ServerChain
				for x, id := range chain {
					if id != n.ID || x+1 >= len(chain) {
						continue
					}
					want[c.ID+"|"+admittedNextHop(s.NextHopAddr(n, nodes[chain[x+1]]))] = true
				}
			}
		}
		for _, plan := range hy2LinkProbePlans(s) {
			if plan.To == n.ID {
				want[plan.user()+"|127.0.0.1/32"] = true
			}
		}
		for _, r := range sc.Route.Rules {
			if r.Outbound == "egress" {
				continue
			}
			for _, u := range r.AuthUser {
				for _, cidr := range r.IPCIDR {
					if !want[u+"|"+cidr] {
						t.Errorf("服务器 %s 多放行了 %s → %s", n.ID, u, cidr)
					}
				}
				for _, domain := range r.Domain {
					if !want[u+"|"+domain] {
						t.Errorf("服务器 %s 多放行了 %s → %s", n.ID, u, domain)
					}
				}
			}
		}
		if sc.Route.Final != "block" {
			t.Errorf("服务器 %s 的 route.final 是 %q,应为 block —— 白名单之外必须阻断",
				n.ID, sc.Route.Final)
		}
	}
}

func TestServerNextHopHostnameUsesDomainRuleNotInvalidCIDR(t *testing.T) {
	s := load(t)
	changed := false
	for index := range s.Nodes {
		if s.Nodes[index].IsServer() && s.Nodes[index].PublicEndpoint != "" {
			s.Nodes[index].PublicEndpoint = "edge.example.test"
			changed = true
			break
		}
	}
	if !changed {
		t.Fatal("fixture has no public server")
	}
	result, err := Render(s)
	if err != nil {
		t.Fatal(err)
	}
	foundDomain := false
	for _, bundle := range result.Bundles {
		for _, file := range bundle.Files {
			if file.Path != "sing-box/config.json" {
				continue
			}
			var config conf
			if err := json.Unmarshal([]byte(file.Content), &config); err != nil {
				t.Fatal(err)
			}
			for _, rule := range config.Route.Rules {
				for _, cidr := range rule.IPCIDR {
					if _, err := netip.ParsePrefix(cidr); err != nil {
						t.Fatalf("%s rendered invalid ip_cidr %q: %v", bundle.Owner, cidr, err)
					}
				}
				for _, domain := range rule.Domain {
					foundDomain = foundDomain || domain == "edge.example.test"
				}
			}
		}
	}
	if !foundDomain {
		t.Fatal("hostname next hop was not represented by a domain route rule")
	}
}

// TestEgressOnlyWhereCapable:没有 egress_capable 的服务器不该有出口出站。
func TestEgressOnlyWhereCapable(t *testing.T) {
	s, cfgs := configs(t)
	for i := range s.Nodes {
		n := &s.Nodes[i]
		sc := cfgs[n.ID]
		if sc == nil {
			continue
		}
		has := false
		for _, o := range sc.Outbounds {
			if o.Tag == "egress" {
				has = true
			}
		}
		if has && !n.Server.EgressCapable {
			t.Errorf("服务器 %s 没有 egress_capable 却渲染了出口出站", n.ID)
		}
	}
}

// TestRevokedCredentialNotRendered:吊销后所有服务器上必须不再有这个 user(§18)。
func TestRevokedCredentialNotRendered(t *testing.T) {
	s := load(t)
	found := false
	for i := range s.Credentials {
		if s.Credentials[i].ID == "cred-ws-eg" {
			s.Credentials[i].RevokedAt = "2026-01-01T00:00:00Z"
			found = true
		}
	}
	if !found {
		t.Fatal("fixture 里没有 cred-ws-eg")
	}
	res, err := Render(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range res.Bundles {
		for _, f := range b.Files {
			if f.Path == "sing-box/config.json" && strings.Contains(f.Content, "cred-ws-eg") {
				t.Errorf("%s 的配置里仍有已吊销的凭据 cred-ws-eg", b.Owner)
			}
		}
	}
}

// TestDNSHasEscapeFromBlock:DNS 查询必须能出去。
//
// route.final 是 block(未匹配一律阻断)。如果 DNS 服务器没有 detour,
// 查询会走 route 规则、落到 block,sing-box 连解析器都问不到 —— 而症状
// 只有"直连候选失败",因为走代理的域名是交给出口解析的(§7.4),
// 代理候选一切正常。这个 bug 真实发生过。
func TestDNSHasEscapeFromBlock(t *testing.T) {
	_, cfgs := configs(t)
	for owner, c := range cfgs {
		if c.DNS == nil || len(c.DNS.Servers) == 0 {
			continue
		}
		tags := map[string]bool{}
		for _, o := range c.Outbounds {
			tags[o.Tag] = true
		}
		for _, srv := range c.DNS.Servers {
			if srv.Address == androidFakeIPTransport {
				if srv.Tag != androidFakeIPDNSTag || srv.Detour != "" {
					t.Errorf("%s 的 FakeIP DNS 服务器形状无效：%+v", owner, srv)
				}
				continue
			}
			if srv.Detour == "" {
				t.Errorf("%s 的 DNS 服务器 %s 没有 detour —— 查询会落到 route.final=block",
					owner, srv.Address)
				continue
			}
			if !tags[srv.Detour] {
				t.Errorf("%s 的 DNS detour %q 指向不存在的出站", owner, srv.Detour)
			}
		}
	}
}

// TestAndroidDNSResolvesAtFinalEgress 钉住 Android TUN 的两个独立 DNS 边界：
// libbox 自己的入口/bootstrap 解析仍从受保护的直连套接字出去；应用的 A/AAAA
// 查询只得到 FakeIP，使后续连接恢复成 FQDN 并由代理链的最终出口解析。
// reverse_mapping 只补路由元数据，不能把已经污染的目标 IP 改回域名。
func TestAndroidDNSResolvesAtFinalEgress(t *testing.T) {
	s, cfgs := configs(t)
	for _, node := range s.AccessNodes() {
		config := cfgs[node.ID]
		if config == nil {
			t.Fatalf("接入节点 %s 没有 sing-box 配置", node.ID)
		}
		want := node.Access.Platform == model.Android
		if config.Route.AutoDetectInterface != want {
			t.Errorf("%s platform=%s auto_detect_interface=%t，期望 %t",
				node.ID, node.Access.Platform, config.Route.AutoDetectInterface, want)
		}
		if !want {
			if config.DNS != nil && (config.DNS.FakeIP != nil || config.DNS.IndependentCache) {
				t.Errorf("%s platform=%s 不应启用 Android FakeIP", node.ID, node.Access.Platform)
			}
			if config.Experimental != nil && config.Experimental.CacheFile != nil {
				t.Errorf("%s platform=%s 不应启用 Android FakeIP 缓存", node.ID, node.Access.Platform)
			}
			continue
		}
		if config.DNS == nil || !config.DNS.ReverseMapping {
			t.Errorf("%s 的 Android TUN 没有保留受管 DNS 域名", node.ID)
		}
		if len(config.DNS.Servers) < 2 || config.DNS.Servers[0].Address == androidFakeIPTransport {
			t.Fatalf("%s 必须把真实 bootstrap 解析器放在 FakeIP 之前", node.ID)
		}
		fakeServerCount := 0
		for _, server := range config.DNS.Servers {
			if server.Tag == androidFakeIPDNSTag && server.Address == androidFakeIPTransport && server.Detour == "" {
				fakeServerCount++
			}
		}
		if fakeServerCount != 1 {
			t.Errorf("%s 的 Android FakeIP DNS server 数量=%d，期望 1", node.ID, fakeServerCount)
		}
		if !config.DNS.IndependentCache {
			t.Errorf("%s 没有隔离应用 FakeIP 与 bootstrap DNS 缓存", node.ID)
		}
		if len(config.DNS.Rules) != 1 ||
			!slices.Equal(config.DNS.Rules[0].Inbound, []string{"tun-in"}) ||
			!slices.Equal(config.DNS.Rules[0].QueryType, []string{"A", "AAAA"}) ||
			config.DNS.Rules[0].Server != androidFakeIPDNSTag {
			t.Errorf("%s 的 FakeIP 规则未严格限定为 tun-in A/AAAA：%+v", node.ID, config.DNS.Rules)
		}
		if config.DNS.FakeIP == nil || !config.DNS.FakeIP.Enabled ||
			config.DNS.FakeIP.Inet4Range != androidFakeIPv4Range ||
			config.DNS.FakeIP.Inet6Range != androidFakeIPv6Range {
			t.Errorf("%s 的 Android FakeIP 地址池无效：%+v", node.ID, config.DNS.FakeIP)
		}
		if config.Experimental == nil || config.Experimental.CacheFile == nil ||
			!config.Experimental.CacheFile.Enabled || !config.Experimental.CacheFile.StoreFakeIP ||
			config.Experimental.CacheFile.Path != androidFakeIPCache {
			t.Errorf("%s 没有持久化 Android FakeIP 映射：%+v", node.ID, config.Experimental)
		}
		var tunAddresses []string
		for _, inbound := range config.Inbounds {
			if inbound.Tag == "tun-in" {
				tunAddresses = inbound.Address
				if !inbound.AutoRoute || inbound.Stack != "system" || inbound.MTU != androidTUNMTU {
					t.Errorf("%s 的 Android TUN 路由形状无效：%+v", node.ID, inbound)
				}
			}
		}
		if !slices.Equal(tunAddresses, []string{androidTUNIPv4, androidTUNIPv6}) {
			t.Errorf("%s 的 Android TUN 没有同时接管 FakeIP 双栈：%v", node.ID, tunAddresses)
		}
		dnsIndex, sniffIndex, businessIndex := -1, -1, len(config.Route.Rules)
		for index, rule := range config.Route.Rules {
			if rule.Action == "hijack-dns" && slices.Equal(rule.Inbound, []string{"tun-in"}) &&
				slices.Equal(rule.Port, []int{53}) {
				dnsIndex = index
			}
			if rule.Type == "logical" && rule.Mode == "and" && rule.Action == "sniff" &&
				len(rule.Rules) == 2 && slices.Equal(rule.Rules[0].Inbound, []string{"tun-in"}) &&
				slices.Equal(rule.Rules[1].DomainRegex, []string{".+"}) && rule.Rules[1].Invert {
				sniffIndex = index
			}
			if rule.Outbound != "" && slices.Contains(rule.Inbound, "tun-in") && index < businessIndex {
				businessIndex = index
			}
		}
		if dnsIndex < 0 || sniffIndex < 0 || dnsIndex >= sniffIndex || sniffIndex >= businessIndex {
			t.Errorf("%s 的 Android TUN DNS/嗅探规则顺序无效：dns=%d sniff=%d business=%d",
				node.ID, dnsIndex, sniffIndex, businessIndex)
		}
	}
}

// TestProbeInboundRoutesEachCandidate:探测入口必须能精确打到每条候选。
//
// sing-box 自带的 delay 接口忽略传入的 url,所有候选都对同一个内置目标测 ——
// 后果不是数字不准,是**排序被颠倒**:实测它把 direct 排第一(128ms),
// 而用真实目标探测时 direct 根本不通(超时 10 秒)。
//
// 所以渲染一个探测入口:一个回环端口,用户名区分候选,规则把每个用户名
// 打到同名出站。
func TestProbeInboundRoutesEachCandidate(t *testing.T) {
	s, cfgs := configs(t)
	for _, n := range s.AccessNodes() {
		c := cfgs[n.ID]
		if c == nil {
			continue
		}
		pi := -1
		for i := range c.Inbounds {
			if c.Inbounds[i].Tag == "probe-in" {
				pi = i
			}
		}
		if pi < 0 {
			t.Errorf("接入节点 %s 没有探测入口 —— 无法按候选测量", n.ID)
			continue
		}
		// 必须只监听回环:它按设计绕过访问控制,是测量工具不是数据通路。
		if c.Inbounds[pi].Listen != "127.0.0.1" {
			t.Errorf("%s 的探测入口监听在 %s,必须是回环", n.ID, c.Inbounds[pi].Listen)
		}
		// mixed 入站的用户字段是 username,不是 name。用错会让 sing-box
		// 启动即 FATAL: unknown field "name"。
		for _, u := range c.Inbounds[pi].Users {
			if u.Username == "" {
				t.Errorf("%s 探测入口的用户用了 name 而非 username —— sing-box 会拒绝启动", n.ID)
				break
			}
			if strings.Contains(u.Username, ":") {
				t.Errorf("%s 探测用户名 %q 含冒号 —— SOCKS5 客户端会在第一个冒号处切分",
					n.ID, u.Username)
			}
		}

		// 每条候选都要有一条把它接出去的规则。
		outs := map[string]bool{}
		for _, o := range c.Outbounds {
			outs[o.Tag] = true
		}
		users := map[string]bool{}
		for _, u := range c.Inbounds[pi].Users {
			users[u.Username] = true
		}
		routed := map[string]bool{}
		for _, r := range c.Route.Rules {
			if len(r.Inbound) == 1 && r.Inbound[0] == "probe-in" && len(r.AuthUser) == 1 {
				if !users[r.AuthUser[0]] {
					t.Errorf("%s 探测规则引用了不存在的用户 %q", n.ID, r.AuthUser[0])
				}
				if !outs[r.Outbound] {
					t.Errorf("%s 探测规则指向不存在的出站 %q", n.ID, r.Outbound)
				}
				routed[r.AuthUser[0]] = true
			}
		}
		for u := range users {
			if !routed[u] {
				t.Errorf("%s 探测用户 %q 没有对应的路由规则 —— 它的流量会落到 final:block", n.ID, u)
			}
		}
	}
}
