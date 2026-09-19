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

	wg, sb, units, platformPlans := 0, 0, 0, 0
	for _, b := range res.Bundles {
		for _, f := range b.Files {
			switch {
			case strings.HasPrefix(f.Path, "wireguard/"):
				wg++
			case f.Path == "sing-box/config.json":
				sb++
			case f.Path == "systemd/sing-box.service":
				units++
			case f.Path == "agent/config.json":
				platformPlans++
			case strings.HasPrefix(f.Path, "systemd/loom-wg-reresolve."):
				// 只给有 DDNS 对端的节点渲染
			default:
				t.Errorf("未预期的产物:%s/%s", b.Owner, f.Path)
			}
		}
	}
	serverWorkloads := 0
	renderedConfigs := 0
	for i := range s.Nodes {
		n := &s.Nodes[i]
		if runsSingBox(n) {
			renderedConfigs++
		}
		if n.IsServer() && n.Server.InboundPort > 0 {
			serverWorkloads++
		}
	}
	if units != serverWorkloads {
		t.Errorf("渲染出 %d 个 sing-box systemd unit,期望 %d(server workload)", units, serverWorkloads)
	}
	if platformPlans != 2 {
		t.Errorf("渲染出 %d 份非 Linux 平台计划,期望 2", platformPlans)
	}
	if want := len(s.Tunnels) * 2; wg != want {
		t.Errorf("渲染出 %d 个 WireGuard 文件,期望 %d(每条隧道两端各一个)", wg, want)
	}

	// 接入设备的纯配置只用于构造 DeviceView；只有服务器获得 lifecycle unit。
	if sb != renderedConfigs {
		t.Errorf("渲染出 %d 份 sing-box 配置,期望 %d", sb, renderedConfigs)
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

// TestDualRoleNodeMergesIntoOneConfig:一台机器一个 sing-box 进程,
// 所以只有一份配置。
//
// 同时持有两种角色是合法的(服务器自己也要走代理出去)。分两次渲染会让
// 两份配置抢同一个路径 `sing-box/config.json`,后写的静默覆盖先写的 ——
// 而渲染报告的文件数仍然对得上,完全看不出来。这个 bug 真实存在过。
func TestDualRoleNodeMergesIntoOneConfig(t *testing.T) {
	s, err := model.Load([]byte(`
defaults:
  dns: [223.5.5.5]
  components: {sing_box: 1.11.4, wireguard: 1.0.20250521, agent: 0.1.0}
nodes:
  - id: laptop
    public_endpoint: 10.0.0.9
    server: {direction: bidirectional, inbound_port: 61698, egress_capable: true, wg_public_key: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=}
    access: {platform: linux-server, credentials: [cr1], default_declaration: d1, mixed_ports: [{port: 1080, declaration: d1}]}
declarations:
  - {id: d1, address_axis: from_request, egress_axis: any, objective: latency, tuning_period: 10m, allowed_servers: [laptop], max_hops: 1}
credentials:
  - {id: cr1, declaration: d1, secret_ref: "cred/x"}`))
	if err != nil {
		t.Fatal(err)
	}
	res, err := Render(s)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	var cfgFile string
	for _, f := range res.Bundles[0].Files {
		if f.Path == "sing-box/config.json" {
			n++
			cfgFile = f.Content
		}
	}
	if n != 1 {
		t.Fatalf("渲染出 %d 份 sing-box 配置,应当只有 1 份", n)
	}
	for _, want := range []string{`"type": "mixed"`, `"type": "hysteria2"`, `"type": "selector"`, `"tag": "egress"`} {
		if !strings.Contains(cfgFile, want) {
			t.Errorf("合并后丢了 %s", want)
		}
	}
}

// TestSkipsAreExpected 把服务器静态渲染的未实现项钉死。接入设备已经不属于
// 这个渲染入口，因此不把“未渲染客户端”伪装成 skip。
func TestSkipsAreExpected(t *testing.T) {
	res, err := Render(load(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, sk := range res.Skipped {
		if sk.Reason == "" {
			t.Errorf("跳过项 %s 没有说明原因", sk.Where)
		}
	}
	want := []string{
		"cost 需要价格数据源",
		"ttft 只能由 L7 观测点产出",
		"platform=android 保留同一签名 bundle",
		"platform=windows-desktop 保留同一签名 bundle",
	}
	for _, fragment := range want {
		found := false
		for _, skipped := range res.Skipped {
			found = found || strings.Contains(skipped.Reason, fragment)
		}
		if !found {
			t.Errorf("缺少预期 skip %q", fragment)
		}
	}
	if len(res.Skipped) != len(want) {
		t.Errorf("skip 数量=%d,期望 %d:\n%+v", len(res.Skipped), len(want), res.Skipped)
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
			if tn.Acceptor.Server.Direction == model.ReverseOnly {
				t.Errorf("reverse_only 节点 %s 被派成了接受方", tn.Acceptor.ID)
			}
			// direct_only 永远不能是发起方。
			if tn.Initiator.Server.Direction == model.DirectOnly {
				t.Errorf("direct_only 节点 %s 被派成了发起方", tn.Initiator.ID)
			}

			// 公钥互指。
			if got := acc["Peer.PublicKey"]; got != tn.Initiator.Server.WGPublicKey {
				t.Errorf("接受方记的对端公钥 %q ≠ 发起方公钥 %q", got, tn.Initiator.Server.WGPublicKey)
			}
			if got := ini["Peer.PublicKey"]; got != tn.Acceptor.Server.WGPublicKey {
				t.Errorf("发起方记的对端公钥 %q ≠ 接受方公钥 %q", got, tn.Acceptor.Server.WGPublicKey)
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
