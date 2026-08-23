package main

import (
	"flag"
	"fmt"

	"loom/internal/model"
	"loom/internal/render"
)

// addnode 生成加一台机器所需的两样东西:**粘进 SSOT 的片段**,和**在新机器
// 上执行的 bootstrap**。
//
// 它不改 SSOT。原因和界面一样(D36):改 SSOT 会触发发布,而这里生成的东西
// 需要人过目 —— 尤其是分配出来的地址和端口。
//
// 自动分配的是真正容易错的那部分:隧道地址与端口。我自己手工配 6 条时,
// 校验器抓到过冲突。规则不是发明的,是从现有 SSOT 里读出来的(§20.1):
// /24 归 reverse_only 那一端、段内成对顺排、**端口刻意不连号**。
func cmdAddNode(args []string) error {
	fs := flag.NewFlagSet("addnode", flag.ExitOnError)
	id := fs.String("id", "", "新节点 id(必需)")
	city := fs.String("city", "", "城市,只用于人读")
	endpoint := fs.String("endpoint", "", "公网地址或 DDNS 域名")
	dir := fs.String("direction", "", "bidirectional | reverse_only | direct_only(必需)")
	inbound := fs.Int("inbound-port", 61698, "接受上游连接的端口")
	egress := fs.Bool("egress", true, "能不能当出口")
	pubkey := fs.String("pubkey", "", "新机器上生成的 WireGuard 公钥;不给则先打印生成步骤")

	rest, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	if len(rest) != 1 || *id == "" || *dir == "" {
		return fmt.Errorf("用法:loom addnode <ssot.yaml> -id <id> -direction <方向> [-endpoint <地址>] [-pubkey <公钥>]")
	}
	s, err := loadAndValidate(rest[0])
	if err != nil {
		return err
	}
	if s.NodeByID()[*id] != nil {
		return fmt.Errorf("SSOT 里已经有叫 %q 的节点了", *id)
	}
	d := model.Direction(*dir)
	if !d.Valid() {
		return fmt.Errorf("direction 非法:%q", *dir)
	}

	n := &model.Node{
		ID: *id, City: *city, PublicEndpoint: *endpoint,
		Server: &model.ServerRole{
			Direction: d, InboundPort: *inbound, EgressCapable: *egress,
			WGPublicKey: *pubkey,
		},
	}

	// 第一步:没有公钥就先让新机器生成一个。
	//
	// **私钥必须在新机器上生成,只把公钥拿回来**(§13.1)—— 平台永不持有
	// 节点私钥。所以这一步躲不掉一次来回。
	if *pubkey == "" {
		fmt.Printf("第一步 —— 在 %s 上执行,然后把输出的公钥带回来:\n\n", *id)
		fmt.Printf("    umask 077\n")
		fmt.Printf("    wg genkey > /etc/wireguard/node.key\n")
		fmt.Printf("    wg pubkey < /etc/wireguard/node.key\n\n")
		fmt.Printf("  路径必须是 /etc/wireguard/ 下:Ubuntu 的 AppArmor 只允许 wg 读这个\n")
		fmt.Printf("  目录,放别处 wg-quick 会失败却仍然 exit 0(D16)。\n\n")
		fmt.Printf("第二步 —— 带着公钥再跑一次:\n\n")
		fmt.Printf("    loom addnode %s -id %s -direction %s%s%s -pubkey <公钥>\n",
			rest[0], *id, *dir, optFlag("-city", *city), optFlag("-endpoint", *endpoint))
		return nil
	}

	// 第二步:算出隧道,生成片段。
	peers := s.TunnelPeersFor(n)
	type alloc struct {
		peer         *model.Node
		from, to     string
		port         int
		fromID, toID string
	}
	var tunnels []alloc
	// 逐条分配时要把已分配的算进去,否则两条新隧道会撞在一起。
	work := *s
	for _, p := range peers {
		from, to, port, err := work.AllocateTunnel(n, p)
		if err != nil {
			return err
		}
		// 发起方由方向真值表推导,不由这里决定(§2.2)。写进 SSOT 的
		// from/to 只是书写顺序,渲染时会重新解析。
		a := alloc{peer: p, from: from, to: to, port: port, fromID: n.ID, toID: p.ID}
		tunnels = append(tunnels, a)
		work.Tunnels = append(work.Tunnels, model.Tunnel{
			From: a.fromID, To: a.toID, ListenPort: port,
			FromAddr: from, ToAddr: to,
		})
	}

	fmt.Printf("把下面这段粘进 %s:\n\n", rest[0])
	fmt.Printf("nodes:\n")
	fmt.Printf("  - id: %s\n", *id)
	if *city != "" {
		fmt.Printf("    city: %s\n", *city)
	}
	if *endpoint != "" {
		fmt.Printf("    public_endpoint: %s\n", *endpoint)
	}
	fmt.Printf("    server:\n")
	fmt.Printf("      direction: %s\n", *dir)
	if *inbound > 0 {
		fmt.Printf("      inbound_port: %d\n", *inbound)
	}
	fmt.Printf("      egress_capable: %v\n", *egress)
	fmt.Printf("      wg_public_key: %s\n", *pubkey)

	if len(tunnels) > 0 {
		fmt.Printf("\ntunnels:\n")
		for _, a := range tunnels {
			fmt.Printf("  - {from: %s, to: %s, listen_port: %d, from_addr: %s, to_addr: %s}\n",
				a.fromID, a.toID, a.port, a.from, a.to)
		}
	} else {
		fmt.Printf("\n(不需要隧道 —— 它和现有节点都能被公网拨到,直接互拨即可)\n")
	}

	fmt.Printf("\n还要把 %s 加进用得到它的声明的 allowed_servers。\n", *id)
	fmt.Printf("\n──────────────────────────────────────────────\n\n")
	fmt.Printf("发布之后,在 %s 上执行 bootstrap:\n\n", *id)
	fmt.Printf("    # 这几样躲不掉手工:节点上还没有 loom,自然也不会自己升级\n")
	fmt.Printf("    scp /usr/local/bin/loom %s:/tmp/loom.new\n", *id)
	fmt.Printf("    scp deploy/keys/platform-signing.pub %s:/tmp/\n", *id)
	fmt.Printf("    loom secrets split %s -secrets deploy/secrets.env -o /tmp/ns\n", rest[0])
	fmt.Printf("    scp /tmp/ns/%s.env %s:/tmp/node.env\n\n", *id, *id)
	fmt.Printf("    ssh %s 'set -e\n", *id)
	fmt.Printf("      install -m 0755 /tmp/loom.new /usr/local/bin/loom\n")
	fmt.Printf("      install -d -m 0755 /etc/loom/trust; install -d -m 0700 /etc/loom/secrets\n")
	fmt.Printf("      install -m 0644 /tmp/platform-signing.pub %s\n", render.TrustedKeyPath)
	fmt.Printf("      install -m 0600 /tmp/node.env %s\n", render.NodeSecretsPath)
	fmt.Printf("      echo %s > /etc/loom/node-id\n", *id)
	fmt.Printf("      rm -f /tmp/loom.new /tmp/platform-signing.pub /tmp/node.env\n")
	fmt.Printf("      loom pull -url %s -dns %s'\n\n", nonEmptyOr(s.DistributionURL(), "<分发点>"), firstDNS(s, n))
	fmt.Printf("最后那次 pull 会把其余全部装好,包括它自己的定时器。\n")
	fmt.Printf("还要在新机器上放 TLS 材料(%s / node.crt / node.key,见 deploy/README)。\n", "ca.crt")
	return nil
}

func optFlag(name, v string) string {
	if v == "" {
		return ""
	}
	return " " + name + " " + v
}

func nonEmptyOr(v, alt string) string {
	if v == "" {
		return alt
	}
	return v
}

func firstDNS(s *model.SSOT, n *model.Node) string {
	if d := s.DNSFor(n); len(d) > 0 {
		return d[0]
	}
	return "223.5.5.5"
}
