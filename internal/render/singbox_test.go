package render

import (
	"encoding/json"
	"strings"
	"testing"

	"loom/internal/model"
)

// conf 是渲染出的 sing-box 配置的松散视图。测试刻意不复用渲染用的结构体
// —— 那样只能证明"我序列化了我构造的东西",证明不了产物本身自洽。
type conf struct {
	Inbounds []struct {
		Type       string `json:"type"`
		Tag        string `json:"tag"`
		Listen     string `json:"listen"`
		ListenPort int    `json:"listen_port"`
		Users      []struct {
			Name     string `json:"name"`
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
		Rules []struct {
			Inbound  []string `json:"inbound"`
			AuthUser []string `json:"auth_user"`
			IPCIDR   []string `json:"ip_cidr"`
			Outbound string   `json:"outbound"`
		} `json:"rules"`
		Final string `json:"final"`
	} `json:"route"`
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
				if !outTags[r.Outbound] {
					t.Errorf("route.rules[%d] 指向不存在的 outbound %q", i, r.Outbound)
				}
				for _, in := range r.Inbound {
					if !inTags[in] {
						t.Errorf("route.rules[%d] 引用了不存在的 inbound %q", i, in)
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

	refs := map[string]bool{}
	for i := range s.Credentials {
		refs[s.Credentials[i].SecretRef] = true
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

		for _, cid := range p.Credentials {
			cred := creds[cid]
			if cred == nil || cred.Revoked() {
				continue
			}
			d := decls[cred.Declaration]
			if d == nil {
				continue
			}
			cands, _ := s.EnumerateCandidates(d)

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
		if o.Server != wantAddr || o.ServerPort != sv.InboundPort {
			t.Errorf("第 %d 跳拨向 %s:%d,期望 %s:%d", i, o.Server, o.ServerPort, wantAddr, sv.InboundPort)
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
			want := s.NextHopAddr(sv, next) + "/32"
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
	}
	return false
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
		if sc == nil || !n.Has(model.Server) {
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
			cands, _ := s.EnumerateCandidates(d)
			for k := range cands {
				chain := cands[k].ServerChain
				for x, id := range chain {
					if id != n.ID || x+1 >= len(chain) {
						continue
					}
					want[c.ID+"|"+s.NextHopAddr(n, nodes[chain[x+1]])+"/32"] = true
				}
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
			}
		}
		if sc.Route.Final != "block" {
			t.Errorf("服务器 %s 的 route.final 是 %q,应为 block —— 白名单之外必须阻断",
				n.ID, sc.Route.Final)
		}
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
		if has && !n.EgressCapable {
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
