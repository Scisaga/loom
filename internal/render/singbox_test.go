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
		Type       string   `json:"type"`
		Tag        string   `json:"tag"`
		Server     string   `json:"server"`
		ServerPort int      `json:"server_port"`
		Password   string   `json:"password"`
		Detour     string   `json:"detour"`
		Outbounds  []string `json:"outbounds"`
		Default    string   `json:"default"`
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
// 对每一条 RouteCandidate,断言这条路径上三个节点的配置互相吻合:
// 接入节点拨的中继地址、中继放行的下一跳、目标监听的地址。任何一处对不上,
// 结果都是连接建立后被静默阻断,而不是报错。
func TestSingBoxPathCorrespondence(t *testing.T) {
	s, cfgs := configs(t)
	nodes := s.NodeByID()
	creds := s.CredentialByID()

	for pi := range s.Profiles {
		p := &s.Profiles[pi]
		access := cfgs[p.ID]
		if access == nil {
			t.Fatalf("档案 %s 没有渲染出配置", p.ID)
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
			d := s.DeclarationByID()[cred.Declaration]
			if d == nil {
				continue
			}
			cands, _ := s.EnumerateCandidates(d)

			for _, cand := range cands {
				name := p.ID + "/" + cand.Tag()
				t.Run(name, func(t *testing.T) {
					relayID := cand.RelayChain[0]
					relay, target := nodes[relayID], nodes[cand.Target]
					nextHop := s.TunnelAddrOn(cand.Target, relayID)

					// 一 · 接入侧:候选出站存在,且经由到该中继的跳。
					ci, ok := byTag[cand.Tag()]
					if !ok {
						t.Fatalf("接入侧缺少候选出站 %s", cand.Tag())
					}
					co := access.Outbounds[ci]
					if co.Server != nextHop || co.ServerPort != target.InboundPort {
						t.Errorf("候选拨向 %s:%d,期望目标隧道地址 %s:%d",
							co.Server, co.ServerPort, nextHop, target.InboundPort)
					}
					hop := access.Outbounds[byTag[co.Detour]]
					if hop.Server != relay.PublicEndpoint || hop.ServerPort != relay.InboundPort {
						t.Errorf("跳拨向 %s:%d,期望中继 %s:%d",
							hop.Server, hop.ServerPort, relay.PublicEndpoint, relay.InboundPort)
					}

					// 二 · 中继侧:该凭据被接纳,且这个下一跳在白名单内。
					rc := cfgs[relayID]
					if rc == nil {
						t.Fatalf("中继 %s 没有渲染出配置", relayID)
					}
					var relayPwd string
					for _, u := range rc.Inbounds[0].Users {
						if u.Name == cid {
							relayPwd = u.Password
						}
					}
					if relayPwd == "" {
						t.Fatalf("中继 %s 的 inbound 里没有凭据 %s", relayID, cid)
					}
					// 两端必须引用同一个秘密条目,否则查到的不是同一把钥匙。
					if relayPwd != hop.Password {
						t.Errorf("中继侧密码引用 %q ≠ 接入侧 %q", relayPwd, hop.Password)
					}

					allowed := false
					for _, r := range rc.Route.Rules {
						if len(r.AuthUser) != 1 || r.AuthUser[0] != cid {
							continue
						}
						for _, cidr := range r.IPCIDR {
							if cidr == nextHop+"/32" {
								allowed = true
							}
						}
					}
					if !allowed {
						t.Errorf("中继 %s 未放行凭据 %s 到下一跳 %s —— 准入校验会阻断这条候选",
							relayID, cid, nextHop)
					}

					// 三 · 目标侧:确实在这个地址和端口上监听。
					tc := cfgs[cand.Target]
					if tc == nil {
						t.Fatalf("目标 %s 没有渲染出配置", cand.Target)
					}
					listening := false
					for _, in := range tc.Inbounds {
						if in.Listen == nextHop && in.ListenPort == target.InboundPort {
							listening = true
						}
					}
					if !listening {
						t.Errorf("目标 %s 没有在 %s:%d 上监听", cand.Target, nextHop, target.InboundPort)
					}
				})
			}
		}
	}
}

// TestRelayAdmitsNothingExtra 断言中继的白名单不宽于它该放行的集合。
// 准入校验的价值全在于"多出来的不放行"。
func TestRelayAdmitsNothingExtra(t *testing.T) {
	s, cfgs := configs(t)
	decls := s.DeclarationByID()

	for i := range s.Nodes {
		n := &s.Nodes[i]
		rc := cfgs[n.ID]
		if rc == nil || !n.Has(model.Relay) {
			continue
		}
		// 该中继本应放行的 (凭据, 下一跳) 集合。
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
			for _, cand := range cands {
				if cand.RelayChain[0] != n.ID {
					continue
				}
				want[c.ID+"|"+s.TunnelAddrOn(cand.Target, n.ID)+"/32"] = true
			}
		}
		for _, r := range rc.Route.Rules {
			for _, u := range r.AuthUser {
				for _, cidr := range r.IPCIDR {
					if !want[u+"|"+cidr] {
						t.Errorf("中继 %s 多放行了 %s → %s", n.ID, u, cidr)
					}
				}
			}
		}
		if rc.Route.Final != "block" {
			t.Errorf("中继 %s 的 route.final 是 %q,应为 block —— 白名单之外必须阻断",
				n.ID, rc.Route.Final)
		}
	}
}

// TestRevokedCredentialNotRendered:吊销后中继上必须不再有这个 user(§18)。
func TestRevokedCredentialNotRendered(t *testing.T) {
	s := load(t)
	// 吊销工作站的出口凭据。
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
