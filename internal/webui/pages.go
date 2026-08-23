package webui

import (
	"fmt"
	"html"
	"sort"
	"strings"
)

// 页面是服务端渲染的纯 HTML,**没有任何外部资源、没有 JavaScript**。
//
// 不是极简主义:这些机器不一定能出网,而通过 ssh 端口转发进来时更不能。
// 一个依赖 CDN 的界面在最需要它的时候(隧道断了、机器出问题了)恰好打不开。

const style = `<style>
:root{--fg:#1a1a1a;--dim:#666;--line:#ddd;--ok:#0a7;--bad:#c33;--warn:#c80;--bg:#fff;--card:#fafafa}
@media(prefers-color-scheme:dark){:root{--fg:#e8e8e8;--dim:#999;--line:#333;--ok:#3c9;--bad:#f66;--warn:#fa4;--bg:#151515;--card:#1e1e1e}}
*{box-sizing:border-box}
body{margin:0;padding:1.5rem;font:14px/1.6 ui-monospace,SFMono-Regular,Menlo,monospace;color:var(--fg);background:var(--bg)}
h1{font-size:1.1rem;margin:0 0 .3rem}h2{font-size:.95rem;margin:1.6rem 0 .5rem;color:var(--dim);font-weight:600}
a{color:inherit}
.bar{display:flex;gap:1rem;align-items:baseline;flex-wrap:wrap;border-bottom:1px solid var(--line);padding-bottom:.8rem;margin-bottom:1rem}
.dim{color:var(--dim)}.ok{color:var(--ok)}.bad{color:var(--bad)}.warn{color:var(--warn)}
table{border-collapse:collapse;width:100%;margin:.3rem 0}
td,th{text-align:left;padding:.3rem .8rem .3rem 0;border-bottom:1px solid var(--line);vertical-align:top;white-space:nowrap}
th{color:var(--dim);font-weight:600;font-size:.85rem}
td.w{white-space:normal}
.card{background:var(--card);border:1px solid var(--line);padding:.8rem 1rem;margin:.5rem 0}
form{display:inline}
button{font:inherit;padding:.3rem .8rem;border:1px solid var(--line);background:var(--card);color:var(--fg);cursor:pointer}
button:hover{border-color:var(--fg)}
input{font:inherit;padding:.35rem .6rem;border:1px solid var(--line);background:var(--bg);color:var(--fg)}
pre{background:var(--card);border:1px solid var(--line);padding:.8rem;overflow-x:auto;white-space:pre-wrap;margin:.5rem 0}
.sp{margin-left:auto}
</style>`

func shell(d Deps, title, body string, isAuthed bool) string {
	role := "节点"
	if d.Publisher != nil {
		role = "节点 · 签发者"
	}
	auth := `<a href="/login">登录以操作</a>`
	if isAuthed {
		auth = `已登录 · <a href="/logout">退出</a>`
	}
	return fmt.Sprintf(`<!doctype html><meta charset=utf-8><title>%s · Loom</title>
<meta name=viewport content="width=device-width,initial-scale=1">%s
<div class=bar><h1>%s</h1><span class=dim>%s</span><span class="dim sp">%s</span></div>%s`,
		esc(title), style, esc(d.Node), esc(role), auth, body)
}

func pageLogin(d Deps, errMsg string) string {
	msg := ""
	if errMsg != "" {
		msg = `<p class=bad>` + esc(errMsg) + `</p>`
	}
	return shell(d, "登录", fmt.Sprintf(`
<div class=card>
%s<form method=post action=/login>
<input type=password name=password placeholder="运维口令" autofocus> <button>登录</button>
</form>
<p class=dim>口令来自本机秘密层的 <code>ui/%s</code>。<br>
读页面不需要登录 —— 能连到这里,你已经过了 WireGuard 或 ssh 那一关。<br>
<b>写操作需要</b>:任何节点都能到任何节点的隧道地址,一台被拿下就能去动别人。</p>
</div>`, msg, esc(d.Node)), false)
}

func pageResult(d Deps, name, out string, err error) string {
	status := `<p class=ok>✅ 完成</p>`
	if err != nil {
		status = `<p class=bad>❌ ` + esc(err.Error()) + `</p>`
	}
	body := status
	if out != "" {
		body += "<pre>" + esc(out) + "</pre>"
	}
	return shell(d, name, body+`<p><a href="/">← 回到总览</a></p>`, true)
}

func pagePublish(d Deps, out string, err error) string {
	content, findings, cerr := d.Publisher.Current()
	dist, derr := d.Publisher.Distributed()

	var b strings.Builder
	b.WriteString(`<h2>分发点</h2><div class=card>`)
	switch {
	case derr != nil:
		fmt.Fprintf(&b, `<span class=bad>取不到:%s</span>`, esc(derr.Error()))
	default:
		fmt.Fprintf(&b, `当前指向 <b>%s</b>`, esc(short(dist)))
	}
	b.WriteString(`</div>`)

	b.WriteString(`<h2>校验</h2><div class=card>`)
	switch {
	case cerr != nil:
		fmt.Fprintf(&b, `<span class=bad>%s</span>`, esc(cerr.Error()))
	case findings != "":
		fmt.Fprintf(&b, `<span class=bad>不通过:</span><pre>%s</pre>`, esc(findings))
	default:
		b.WriteString(`<span class=ok>✅ 通过</span>`)
	}
	b.WriteString(`</div>`)

	if cerr == nil && findings == "" {
		b.WriteString(`<form method=post action=/publish><button>渲染 · 签名 · 分发</button></form>
<p class=dim>签名私钥只在这一步用到,不上任何服务器。分发出去的全是占位符,凭据在各节点本地。</p>`)
	} else {
		b.WriteString(`<p class=dim>校验不通过,不给发布 —— 渲染一份自相矛盾的配置出去,
比不发布糟得多。</p>`)
	}

	if out != "" || err != nil {
		b.WriteString(`<h2>本次发布</h2>`)
		if err != nil {
			fmt.Fprintf(&b, `<p class=bad>❌ %s</p>`, esc(err.Error()))
		}
		if out != "" {
			fmt.Fprintf(&b, `<pre>%s</pre>`, esc(out))
		}
	}

	fmt.Fprintf(&b, `<h2>SSOT <span class=dim>%s</span></h2><pre>%s</pre>`,
		esc(d.Publisher.SSOTPath), esc(content))
	b.WriteString(`<p><a href="/">← 回到总览</a></p>`)
	return shell(d, "发布", b.String(), true)
}

func pageOverview(d Deps, isAuthed bool) string {
	v := d.Snapshot()
	var b strings.Builder

	// 全网是不是同一版。落后的那台往往正是出问题的那台。
	vers := map[string][]string{}
	for _, n := range v.Nodes {
		k := n.Applied
		if k == "" {
			k = "(未记录)"
		}
		vers[k] = append(vers[k], n.ID)
	}
	if len(vers) > 1 {
		b.WriteString(`<div class=card><span class=warn>⚠️ 全网不是同一个快照</span><table>`)
		var keys []string
		for k := range vers {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			sort.Strings(vers[k])
			fmt.Fprintf(&b, `<tr><td>%s</td><td class=w>%s</td></tr>`, esc(short(k)), esc(strings.Join(vers[k], " ")))
		}
		b.WriteString(`</table></div>`)
	} else if len(vers) == 1 {
		for k := range vers {
			fmt.Fprintf(&b, `<div class=card>快照 <b>%s</b> <span class=dim>(全网一致)</span></div>`, esc(short(k)))
		}
	}
	for _, w := range v.Warnings {
		fmt.Fprintf(&b, `<div class=card><span class=warn>⚠️ %s</span></div>`, esc(w))
	}

	b.WriteString(`<h2>节点</h2><table><tr><th>节点<th>隧道<th>快照<th>观测</tr>`)
	for _, n := range v.Nodes {
		self := ""
		if n.Self {
			self = ` <span class=dim>(本机)</span>`
		}
		src := `<span class=dim>转述</span>`
		if n.Reached {
			src = `<span class=dim>直连</span>`
		}
		var tl []string
		for _, t := range n.Tunnels {
			cls := "ok"
			if !t.OK {
				cls = "bad"
			}
			label := fmt.Sprintf("%s=%ds", t.Interface, t.AgeSec)
			if t.State != "" && t.State != "active" {
				label = fmt.Sprintf("%s=%s", t.Interface, t.State)
			}
			tl = append(tl, fmt.Sprintf(`<span class=%s>%s</span>`, cls, esc(label)))
		}
		if len(tl) == 0 {
			tl = []string{`<span class=dim>—</span>`}
		}
		age := ""
		if n.AgeSec > 90 {
			age = fmt.Sprintf(` <span class=warn>%d 分钟前</span>`, n.AgeSec/60)
		}
		fmt.Fprintf(&b, `<tr><td><b>%s</b>%s<td class=w>%s<td>%s<td>%s%s</tr>`,
			esc(n.ID), self, strings.Join(tl, "  "), esc(short(n.Applied)), src, age)
		for _, p := range n.Problems {
			fmt.Fprintf(&b, `<tr><td><td class="w bad" colspan=3>%s</tr>`, esc(p))
		}
	}
	b.WriteString(`</table>`)

	// 各节点直接访问每个目标 —— 这张表是按段测量的产出(§16.1.2)。
	targets := map[string]bool{}
	for _, n := range v.Nodes {
		for _, t := range n.Targets {
			targets[t.Target] = true
		}
	}
	var ts []string
	for t := range targets {
		ts = append(ts, t)
	}
	sort.Strings(ts)
	for _, t := range ts {
		fmt.Fprintf(&b, `<h2>各节点直接访问 %s</h2><table>`, esc(t))
		for _, n := range v.Nodes {
			cell := `<span class=dim>(没量)</span>`
			for _, r := range n.Targets {
				if r.Target != t {
					continue
				}
				if r.Err == "" {
					cell = fmt.Sprintf(`<span class=ok>✅ %dms</span>`, r.MS)
				} else {
					cell = fmt.Sprintf(`<span class=bad>❌ %s</span>`, esc(r.Err))
				}
			}
			fmt.Fprintf(&b, `<tr><td>%s<td class=w>%s</tr>`, esc(n.ID), cell)
		}
		b.WriteString(`</table>`)
	}

	b.WriteString(`<h2>节点之间(隧道内 RTT)</h2><table>`)
	for _, n := range v.Nodes {
		if len(n.Edges) == 0 {
			continue
		}
		var parts []string
		for _, e := range n.Edges {
			if e.Err != "" {
				parts = append(parts, fmt.Sprintf(`<span class=bad>%s=❌</span>`, esc(e.To)))
			} else {
				parts = append(parts, fmt.Sprintf("%s=%dms", esc(e.To), e.MS))
			}
		}
		fmt.Fprintf(&b, `<tr><td>%s<td class=w>%s</tr>`, esc(n.ID), strings.Join(parts, "  "))
	}
	b.WriteString(`</table>`)

	b.WriteString(`<h2>本机操作</h2>`)
	if !isAuthed {
		b.WriteString(`<p class=dim>需要<a href="/login">登录</a>。</p>`)
	} else {
		var names []string
		for k := range d.Actions {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, k := range names {
			fmt.Fprintf(&b, `<form method=post action="/act/%s"><button>%s</button></form> `, esc(k), esc(k))
		}
		if d.Publisher != nil {
			b.WriteString(` <a href="/publish"><button>发布…</button></a>`)
		}
	}
	return shell(d, "总览", b.String(), isAuthed)
}

func esc(s string) string { return html.EscapeString(s) }

func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	if s == "" {
		return "—"
	}
	return s
}
