package render

import (
	"fmt"
	"strings"

	"loom/internal/model"
)

const header = "# 由 loom render 生成 —— 不要手工编辑(§12)\n" +
	"# 改配置请改 SSOT 再重新渲染;手工修改会被下次收敛覆盖(§15.3)\n"

// renderWireGuardPair 一次生成一条隧道的两个文件。
//
// 两端在同一个函数里产生,是为了让"必须严格对应"的字段在代码上就无法
// 分开演化:公钥互指、AllowedIPs 互为对方地址、Endpoint 只出现在发起方、
// ListenPort 只出现在接受方。§20.1 说的 24 个文件两两吻合,靠的就是这里
// 只有一处实现。
func renderWireGuardPair(t *model.ResolvedTunnel) (acceptor, initiator File) {
	return File{
		Path:    "wireguard/" + model.IfaceName(t.Initiator.ID) + ".conf",
		Content: acceptorConf(t),
	}, File{
		Path:    "wireguard/" + model.IfaceName(t.Acceptor.ID) + ".conf",
		Content: initiatorConf(t),
	}
}

// acceptorConf 是接受方的配置:监听端口,不写 Endpoint。
func acceptorConf(t *model.ResolvedTunnel) string {
	var b strings.Builder
	b.WriteString(header)
	fmt.Fprintf(&b, "# 隧道 %s ← %s(%s),本端为接受方\n", t.Acceptor.ID, t.Initiator.ID, t.Protocol)
	fmt.Fprintf(&b, "# 发起方由两端 direction 推导:%s=%s, %s=%s(§2.2)\n\n",
		t.Initiator.ID, t.Initiator.Direction, t.Acceptor.ID, t.Acceptor.Direction)

	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "Address = %s\n", t.AcceptorAddr)
	fmt.Fprintf(&b, "ListenPort = %d\n", t.ListenPort)
	// 私钥属于秘密层,渲染层只写引用(§12.1)。
	fmt.Fprintf(&b, "PostUp = wg set %%i private-key %s\n", model.SecretPath)

	b.WriteString("\n[Peer]\n")
	fmt.Fprintf(&b, "# %s\n", t.Initiator.ID)
	fmt.Fprintf(&b, "PublicKey = %s\n", t.Initiator.WGPublicKey)
	fmt.Fprintf(&b, "AllowedIPs = %s\n", t.InitiatorAddr)
	// 接受方不写 Endpoint:对端可能是 reverse_only,主动拨号会违反其方向约束。
	return b.String()
}

// initiatorConf 是发起方的配置:写 Endpoint 与 keepalive,不监听。
func initiatorConf(t *model.ResolvedTunnel) string {
	var b strings.Builder
	b.WriteString(header)
	fmt.Fprintf(&b, "# 隧道 %s → %s(%s),本端为发起方\n", t.Initiator.ID, t.Acceptor.ID, t.Protocol)
	fmt.Fprintf(&b, "# 发起方由两端 direction 推导:%s=%s, %s=%s(§2.2)\n\n",
		t.Initiator.ID, t.Initiator.Direction, t.Acceptor.ID, t.Acceptor.Direction)

	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "Address = %s\n", t.InitiatorAddr)
	fmt.Fprintf(&b, "PostUp = wg set %%i private-key %s\n", model.SecretPath)

	b.WriteString("\n[Peer]\n")
	fmt.Fprintf(&b, "# %s\n", t.Acceptor.ID)
	fmt.Fprintf(&b, "PublicKey = %s\n", t.Acceptor.WGPublicKey)
	fmt.Fprintf(&b, "AllowedIPs = %s\n", t.AcceptorAddr)
	fmt.Fprintf(&b, "Endpoint = %s:%d\n", t.Acceptor.PublicEndpoint, t.ListenPort)
	// PersistentKeepalive 由发起方维持。对 reverse_only 这是隧道存活的
	// 唯一依靠 —— 接受方永远不会主动重连(§6.1)。
	b.WriteString("PersistentKeepalive = 25\n")
	return b.String()
}
