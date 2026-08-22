package render

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"loom/internal/model"
	"loom/internal/validate"
)

var update = flag.Bool("update", false, "重写 golden 文件")

const fixture = "../../testdata/matrix/ssot.yaml"
const goldenDir = "../../testdata/matrix/golden"

func load(t *testing.T) *model.SSOT {
	t.Helper()
	s, err := model.LoadFile(fixture)
	if err != nil {
		t.Fatalf("加载 fixture:%v", err)
	}
	return s
}

// TestFixtureValidates 断言 fixture 本身是干净的。
// 否则后面所有测试都在验证一个错误输入的渲染结果。
func TestFixtureValidates(t *testing.T) {
	if fs := validate.Validate(load(t)); len(fs) > 0 {
		t.Fatalf("fixture 未通过校验:\n%s", validate.Format(fs))
	}
}

// TestRenderIsPure 是 §12 的核心性质:同样输入必然产生同样输出。
// dry-run diff、漂移检测、回滚三个产物全都依赖它。
func TestRenderIsPure(t *testing.T) {
	a, err := Render(load(t))
	if err != nil {
		t.Fatal(err)
	}
	// 重新加载而非复用,以便同时覆盖 Load 的确定性。
	b, err := Render(load(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Bundles) != len(b.Bundles) {
		t.Fatalf("两次渲染的节点数不同:%d vs %d", len(a.Bundles), len(b.Bundles))
	}
	for i := range a.Bundles {
		if a.Bundles[i].Hash() != b.Bundles[i].Hash() {
			t.Errorf("节点 %s 两次渲染的哈希不同 —— 渲染函数不是纯的", a.Bundles[i].Owner)
		}
	}
	if d := Diff(a, b); d != "" {
		t.Errorf("两次渲染之间存在差异:\n%s", d)
	}
}

// TestMatrixShape 断言产物的规模。
//
// 隧道矩阵只覆盖 reverse_only 的服务器(§6.3、D13)—— 能进 mesh 的由
// Headscale 自动分发密钥,一份配置都不渲染。这个断言把那条规则钉住:
// 一旦有人给能进 mesh 的服务器加了隧道,文件数就对不上。
func TestMatrixShape(t *testing.T) {
	s := load(t)
	res, err := Render(s)
	if err != nil {
		t.Fatal(err)
	}

	wg, sb, units := 0, 0, 0
	for _, b := range res.Bundles {
		for _, f := range b.Files {
			switch {
			case strings.HasPrefix(f.Path, "wireguard/"):
				wg++
			case f.Path == "sing-box/config.json":
				sb++
			case f.Path == "systemd/sing-box.service":
				units++
			default:
				t.Errorf("未预期的产物:%s/%s", b.Owner, f.Path)
			}
		}
	}
	// 每份 sing-box 配置都必须配一个 unit —— 否则那份配置没人启动。
	if units != sb {
		t.Errorf("%d 份 sing-box 配置却只有 %d 个 systemd unit", sb, units)
	}
	if want := len(s.Tunnels) * 2; wg != want {
		t.Errorf("渲染出 %d 个 WireGuard 文件,期望 %d(每条隧道两端各一个)", wg, want)
	}

	// 每台服务器一份 sing-box,每个客户端档案一份。目标地址不产生任何
	// 产物 —— 它不是节点(§1、§9)。
	servers := 0
	for i := range s.Nodes {
		if s.Nodes[i].Has(model.Server) {
			servers++
		}
	}
	if want := servers + len(s.Profiles); sb != want {
		t.Errorf("渲染出 %d 份 sing-box 配置,期望 %d(%d 台服务器 + %d 个档案)",
			sb, want, servers, len(s.Profiles))
	}

	// 所有隧道两端都必须是进不了 mesh 的那一侧参与。
	nodes := s.NodeByID()
	for i := range s.Tunnels {
		t2 := &s.Tunnels[i]
		if nodes[t2.From].MeshEligible() && nodes[t2.To].MeshEligible() {
			t.Errorf("隧道 %s 两端都能进 mesh —— 该交给 Headscale(§6.3)", t2.Pair())
		}
	}
}

// TestSkipsAreExpected 把"哪些东西没被渲染"钉死。
//
// 跳过项是本项目对"静默截断"的防线(见 CLAUDE.md)。不钉住它,新增一个
// 静默跳过不会让任何测试变红。
func TestSkipsAreExpected(t *testing.T) {
	res, err := Render(load(t))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]int{
		"carrier 是 l7_gateway": 1, // 第三方等价类不由 L4 换地址(§4.4)
		"没有任何可表达的 L4 候选":       1,
		"该端口不生成路由规则":           1, // 上面那条声明绑的端口
	}
	got := map[string]int{}
	for _, sk := range res.Skipped {
		if sk.Reason == "" {
			t.Errorf("跳过项 %s 没有说明原因", sk.Where)
		}
		for k := range want {
			if strings.Contains(sk.Reason, k) {
				got[k]++
			}
		}
	}
	for k, n := range want {
		if got[k] != n {
			t.Errorf("跳过原因 %q 出现 %d 次,期望 %d 次", k, got[k], n)
		}
	}
	if len(res.Skipped) != 3 {
		t.Errorf("共 %d 条跳过,期望 3 条 —— 有新的静默跳过被引入:\n%+v",
			len(res.Skipped), res.Skipped)
	}
}

// TestPairCorrespondence 是这一层真正要买的保险。
//
// §20.1:密钥要配对、IP 不能撞、端口要一致、方向由 direction 推导,
// "手工写错一个字符的后果是隧道静默不通"。这个测试对每一条隧道断言
// 两端逐字段吻合 —— 它不依赖 golden 文本,因此改了模板也依然有效。
func TestPairCorrespondence(t *testing.T) {
	s := load(t)
	res, err := Render(s)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]map[string]string{} // node -> path -> content
	for _, b := range res.Bundles {
		files[b.Owner] = map[string]string{}
		for _, f := range b.Files {
			files[b.Owner][f.Path] = f.Content
		}
	}

	tunnels, err := s.ResolveAll()
	if err != nil {
		t.Fatal(err)
	}

	for _, tn := range tunnels {
		t.Run(tn.Pair(), func(t *testing.T) {
			accPath := "wireguard/" + model.IfaceName(tn.Initiator.ID) + ".conf"
			iniPath := "wireguard/" + model.IfaceName(tn.Acceptor.ID) + ".conf"

			accRaw, ok := files[tn.Acceptor.ID][accPath]
			if !ok {
				t.Fatalf("接受方 %s 缺少 %s", tn.Acceptor.ID, accPath)
			}
			iniRaw, ok := files[tn.Initiator.ID][iniPath]
			if !ok {
				t.Fatalf("发起方 %s 缺少 %s", tn.Initiator.ID, iniPath)
			}
			acc, ini := parseConf(accRaw), parseConf(iniRaw)

			// reverse_only 永远不能是接受方 —— 那正是它要避免的事。
			if tn.Acceptor.Direction == model.ReverseOnly {
				t.Errorf("reverse_only 节点 %s 被派成了接受方", tn.Acceptor.ID)
			}
			// direct_only 永远不能是发起方。
			if tn.Initiator.Direction == model.DirectOnly {
				t.Errorf("direct_only 节点 %s 被派成了发起方", tn.Initiator.ID)
			}

			// 公钥互指。
			if got := acc["Peer.PublicKey"]; got != tn.Initiator.WGPublicKey {
				t.Errorf("接受方记的对端公钥 %q ≠ 发起方公钥 %q", got, tn.Initiator.WGPublicKey)
			}
			if got := ini["Peer.PublicKey"]; got != tn.Acceptor.WGPublicKey {
				t.Errorf("发起方记的对端公钥 %q ≠ 接受方公钥 %q", got, tn.Acceptor.WGPublicKey)
			}

			// 一端的 Address 必须正好是另一端的 AllowedIPs。
			if acc["Interface.Address"] != ini["Peer.AllowedIPs"] {
				t.Errorf("接受方 Address %q ≠ 发起方 AllowedIPs %q",
					acc["Interface.Address"], ini["Peer.AllowedIPs"])
			}
			if ini["Interface.Address"] != acc["Peer.AllowedIPs"] {
				t.Errorf("发起方 Address %q ≠ 接受方 AllowedIPs %q",
					ini["Interface.Address"], acc["Peer.AllowedIPs"])
			}

			// 只有接受方监听;只有发起方拨号并维持 keepalive。
			if _, has := acc["Interface.ListenPort"]; !has {
				t.Error("接受方缺少 ListenPort")
			}
			if _, has := ini["Interface.ListenPort"]; has {
				t.Error("发起方不应有 ListenPort")
			}
			if _, has := acc["Peer.Endpoint"]; has {
				t.Error("接受方不应有 Endpoint —— 对端可能是 reverse_only,主动拨号违反其方向约束")
			}
			wantEP := tn.Acceptor.PublicEndpoint + ":" + acc["Interface.ListenPort"]
			if got := ini["Peer.Endpoint"]; got != wantEP {
				t.Errorf("发起方 Endpoint %q,期望 %q", got, wantEP)
			}
			if _, has := ini["Peer.PersistentKeepalive"]; !has {
				t.Error("发起方缺少 PersistentKeepalive —— reverse_only 隧道靠它存活")
			}

			// 私钥永不出现在渲染产物里(§13.1)。
			for name, raw := range map[string]string{"接受方": accRaw, "发起方": iniRaw} {
				if strings.Contains(raw, "PrivateKey") {
					t.Errorf("%s配置里出现了 PrivateKey —— 私钥属于秘密层,渲染层只写引用", name)
				}
			}
		})
	}
}

// TestGolden 锁定渲染输出的字节。用 -update 重写。
func TestGolden(t *testing.T) {
	res, err := Render(load(t))
	if err != nil {
		t.Fatal(err)
	}

	if *update {
		if err := os.RemoveAll(goldenDir); err != nil {
			t.Fatal(err)
		}
		for _, b := range res.Bundles {
			for _, f := range b.Files {
				p := filepath.Join(goldenDir, b.Owner, f.Path)
				if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(p, []byte(f.Content), 0o644); err != nil {
					t.Fatal(err)
				}
			}
		}
		t.Log("golden 已重写")
		return
	}

	seen := map[string]bool{}
	for _, b := range res.Bundles {
		for _, f := range b.Files {
			p := filepath.Join(goldenDir, b.Owner, f.Path)
			seen[p] = true
			want, err := os.ReadFile(p)
			if err != nil {
				t.Errorf("缺少 golden 文件 %s(用 -update 生成)", p)
				continue
			}
			if string(want) != f.Content {
				t.Errorf("%s/%s 与 golden 不一致:\n--- golden\n%s\n--- 实际\n%s",
					b.Owner, f.Path, want, f.Content)
			}
		}
	}

	// golden 里多出来的文件说明渲染少生成了东西。
	_ = filepath.Walk(goldenDir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if !seen[p] {
			t.Errorf("golden 中存在但本次未渲染的文件:%s", p)
		}
		return nil
	})
}

// parseConf 把 wg-quick 配置解析成 "Section.Key" -> value。
// 只够测试用:不处理重复 section,fixture 里每个文件恰好一个 Peer。
func parseConf(s string) map[string]string {
	out := map[string]string{}
	section := ""
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.Trim(line, "[]")
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		out[section+"."+strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return out
}
