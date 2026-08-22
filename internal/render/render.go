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

	for _, t := range tunnels {
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

	// sing-box:接入档案、中继、落地目标。
	for i := range s.Profiles {
		p := &s.Profiles[i]
		f, sk, err := renderProfile(s, p)
		if err != nil {
			return nil, err
		}
		skipped = append(skipped, sk...)
		// 客户端档案在 Node 里没有对应条目(见 status.md 记的模型赘余),
		// 这里合成一个只带 access 能力的临时节点给 unit 渲染用。
		byNode[p.ID] = append(byNode[p.ID], f,
			renderSingBoxUnit(s, &model.Node{ID: p.ID, Capabilities: []model.Capability{model.Access}}))
	}
	// 服务器只有一种渲染。中继与出口不是两类节点,是同一台机器在不同
	// 路径上的两种位置(§1.1)。
	for i := range s.Nodes {
		n := &s.Nodes[i]
		if !n.Has(model.Server) || n.InboundPort == 0 {
			continue
		}
		f, err := renderServer(s, n)
		if err != nil {
			return nil, err
		}
		byNode[n.ID] = append(byNode[n.ID], f, renderSingBoxUnit(s, n))
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
		res.Bundles = append(res.Bundles, Bundle{Owner: id, Files: files})
	}
	sort.Slice(res.Skipped, func(i, j int) bool { return res.Skipped[i].Where < res.Skipped[j].Where })
	return res, nil
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
