// Package render 把 SSOT 变成每节点的配置包。
//
// 渲染是纯函数(§12):同样的输入必然产生同样的字节。这里不含随机数、
// 不含当前时间、不做外部查询,map 一律排序后遍历。dry-run diff、漂移
// 检测和回滚这三个产物全都建立在这个性质上(§12.1)。
package render

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"loom/internal/model"
)

// File 是配置包里的一个文件。Path 相对于节点的配置根。
type File struct {
	Path    string
	Content string
}

// Bundle 是单个节点的完整配置包。Files 按 Path 排序。
type Bundle struct {
	Owner string
	Files []File
}

// Hash 是配置包的内容哈希,用于 §15.3 的漂移检测与 §19 的
// Snapshot.rendered_bundles。它只覆盖渲染层 —— 秘密层不在其中(§12.1)。
func (b *Bundle) Hash() string {
	h := sha256.New()
	for _, f := range b.Files {
		fmt.Fprintf(h, "%s\x00%d\x00%s\x00", f.Path, len(f.Content), f.Content)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Skip 记录一条被跳过的隧道及原因。
//
// 它存在是为了不静默截断:渲染少生成了东西,调用方必须看得见,否则
// "全绿"会被误读成"全都覆盖到了"。
type Skip struct {
	Where  string
	Reason string
}

// Result 是一次渲染的全部产物。
type Result struct {
	Bundles []Bundle // 按 Owner 排序
	Skipped []Skip   // 按 Where 排序
}

// Render 渲染整份 SSOT。
//
// 调用方应先跑 validate:Render 假定输入已经过校验,只对自己无法表达
// 的输入报错(如要求混淆参数但渲染器尚未实现)。
func Render(s *model.SSOT) (*Result, error) {
	tunnels, err := s.ResolveAll()
	if err != nil {
		return nil, err
	}

	byNode := map[string][]File{}
	var skipped []Skip

	// 被下线的节点不产出任何配置 —— 给一台正在停机的机器发新配置没有意义,
	// 而且会让"它到底该不该跑"变得含糊。停机指令走签名过的 manifest。
	decommissioned := map[string]bool{}
	for i := range s.Nodes {
		if s.Nodes[i].Decommission {
			decommissioned[s.Nodes[i].ID] = true
			skipped = append(skipped, Skip{
				Where:  "node:" + s.Nodes[i].ID,
				Reason: "已标记下线(decommission),不渲染任何配置;停机指令在签名过的快照里",
			})
		}
	}

	for _, t := range tunnels {
		// 一端下线,两端都不再渲染这条隧道 —— 对端不该继续配一个正在停机的
		// 邻居。下线节点靠公网 HTTPS 取快照,不依赖隧道,所以断得起。
		if decommissioned[t.Initiator.ID] || decommissioned[t.Acceptor.ID] {
			continue
		}
		switch t.Protocol {
		case model.WG, model.AWG:
			// 继续
		default:
			skipped = append(skipped, Skip{
				Where:  t.Pair(),
				Reason: fmt.Sprintf("协议 %s 的渲染尚未实现", t.Protocol),
			})
			continue
		}

		// 混淆参数是接口级的,且"全部置零 = 标准 WireGuard"(§17.2)。
		// 在参数渲染实现之前默默输出一份不带参数的配置,等于让人以为
		// 开了混淆而实际没开 —— 这必须是硬错误,不是跳过。
		if t.Obfuscation != "" {
			return nil, fmt.Errorf(
				"隧道 %s 引用了混淆参数集 %q,但渲染器尚未实现 §17 参数输出;"+
					"静默输出无参数配置会退化为标准 WireGuard", t.Pair(), t.Obfuscation)
		}

		af, bf := renderWireGuardPair(t)
		byNode[t.Acceptor.ID] = append(byNode[t.Acceptor.ID], af)
		byNode[t.Initiator.ID] = append(byNode[t.Initiator.ID], bf)
	}

	// 上报者装在**每个**节点上,服务器也要 —— DDNS 重解析、隧道断连、
	// 有人手工改配置,这些只有节点自己知道(§16.1)。
	for i := range s.Nodes {
		if decommissioned[s.Nodes[i].ID] {
			continue
		}
		if !usesLinuxLifecycle(&s.Nodes[i]) {
			continue
		}
		f, sk := renderReport(s, &s.Nodes[i])
		byNode[s.Nodes[i].ID] = append(byNode[s.Nodes[i].ID], f...)
		skipped = append(skipped, sk...)
	}

	// 节点侧的控制通道:自己去分发点取配置(§14.2)。
	for i := range s.Nodes {
		if decommissioned[s.Nodes[i].ID] {
			continue
		}
		if !usesLinuxLifecycle(&s.Nodes[i]) {
			continue
		}
		f, sk := renderPull(s, &s.Nodes[i])
		byNode[s.Nodes[i].ID] = append(byNode[s.Nodes[i].ID], f...)
		skipped = append(skipped, sk...)
	}

	// 对端走 DDNS 的发起方需要定时重解析(§12:这也是渲染产物,不该手写)。
	for i := range s.Nodes {
		if decommissioned[s.Nodes[i].ID] {
			continue
		}
		if !usesLinuxLifecycle(&s.Nodes[i]) {
			continue
		}
		if fs := renderReresolve(s, &s.Nodes[i]); fs != nil {
			byNode[s.Nodes[i].ID] = append(byNode[s.Nodes[i].ID], fs...)
		}
	}

	// sing-box:一台机器一份配置。同时持有两种能力的机器合并渲染 ——
	// 分成两份会让后写的静默覆盖先写的(§1.3)。
	for i := range s.Nodes {
		n := &s.Nodes[i]
		if decommissioned[n.ID] {
			continue
		}
		if !runsSingBox(n) {
			continue
		}
		f, sk, err := renderSingBox(s, n)
		if err != nil {
			return nil, err
		}
		skipped = append(skipped, sk...)
		byNode[n.ID] = append(byNode[n.ID], f)
		if usesLinuxLifecycle(n) {
			byNode[n.ID] = append(byNode[n.ID], renderSingBoxUnit(s, n))

			// Agent 的配置与 sing-box 的配置必须同源:两边枚举出的声明和候选
			// 一旦分叉,Agent 会去切一个不存在的 selector。
			af, ask := renderAgent(s, n)
			byNode[n.ID] = append(byNode[n.ID], af...)
			skipped = append(skipped, ask...)
		} else {
			skipped = append(skipped, Skip{
				Where: "lifecycle:" + n.ID,
				Reason: fmt.Sprintf("platform=%s 只渲染平台无关的 sing-box 配置；"+
					"Windows Service/Android VpnService、配置 pull、Agent 与 report 由平台宿主交付，"+
					"禁止回退为 systemd 或 /etc/loom 安装", n.Access.Platform),
			})
		}
	}

	ids := make([]string, 0, len(byNode))
	for id := range byNode {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	res := &Result{Skipped: skipped}
	for _, id := range ids {
		files := byNode[id]
		sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
		// 同一个包里两个文件抢同一个路径,写盘时后者覆盖前者 —— 而渲染
		// 报告的文件数仍然对得上,所以完全看不出来。宁可整体失败。
		for i := 1; i < len(files); i++ {
			if files[i].Path == files[i-1].Path {
				return nil, fmt.Errorf("节点 %s 渲染出两个 %s —— 后者会静默覆盖前者",
					id, files[i].Path)
			}
		}
		res.Bundles = append(res.Bundles, Bundle{Owner: id, Files: files})
	}
	sort.Slice(res.Skipped, func(i, j int) bool { return res.Skipped[i].Where < res.Skipped[j].Where })
	return res, nil
}

// runsSingBox 是“这个节点是否实际得到 sing-box workload”的唯一判据。
// report 的组件版本期望必须复用它；仅有 server 角色但 inbound_port=0 的
// 隧道端点不会安装 sing-box，不能被版本检查误报为缺组件。
func runsSingBox(n *model.Node) bool {
	return n != nil && (n.IsAccess() || (n.IsServer() && n.Server.InboundPort > 0))
}

// usesLinuxLifecycle 是渲染层对平台安装产物的唯一分流点。
// 纯服务器节点当前都是 Linux；接入节点则必须由显式 platform 决定。
func usesLinuxLifecycle(n *model.Node) bool {
	return n != nil && (!n.IsAccess() || n.Access.Platform.UsesLinuxLifecycle())
}

// Diff 逐文件比较两次渲染,返回人可读的变更摘要。
// 这是 §12.1 的第一个产物:部署前看到会改哪些文件。
func Diff(old, new *Result) string {
	type key struct{ node, path string }
	index := func(r *Result) map[key]string {
		m := map[key]string{}
		if r == nil {
			return m
		}
		for _, b := range r.Bundles {
			for _, f := range b.Files {
				m[key{b.Owner, f.Path}] = f.Content
			}
		}
		return m
	}
	o, n := index(old), index(new)

	var keys []key
	seen := map[key]bool{}
	for k := range o {
		keys, seen[k] = append(keys, k), true
	}
	for k := range n {
		if !seen[k] {
			keys = append(keys, k)
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].node != keys[j].node {
			return keys[i].node < keys[j].node
		}
		return keys[i].path < keys[j].path
	})

	var b strings.Builder
	for _, k := range keys {
		ov, had := o[k]
		nv, has := n[k]
		switch {
		case had && !has:
			fmt.Fprintf(&b, "- %s/%s\n", k.node, k.path)
		case !had && has:
			fmt.Fprintf(&b, "+ %s/%s\n", k.node, k.path)
		case ov != nv:
			fmt.Fprintf(&b, "~ %s/%s\n", k.node, k.path)
			b.WriteString(lineDiff(ov, nv))
		}
	}
	return b.String()
}

func lineDiff(old, new string) string {
	ol, nl := strings.Split(old, "\n"), strings.Split(new, "\n")
	var b strings.Builder
	max := len(ol)
	if len(nl) > max {
		max = len(nl)
	}
	for i := 0; i < max; i++ {
		var o, n string
		if i < len(ol) {
			o = ol[i]
		}
		if i < len(nl) {
			n = nl[i]
		}
		if o == n {
			continue
		}
		if i < len(ol) && o != "" {
			fmt.Fprintf(&b, "    - %s\n", o)
		}
		if i < len(nl) && n != "" {
			fmt.Fprintf(&b, "    + %s\n", n)
		}
	}
	return b.String()
}
