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
textarea{width:100%;height:60vh;font:inherit;padding:.6rem;border:1px solid var(--line);background:var(--card);color:var(--fg);white-space:pre;overflow-wrap:normal;overflow-x:auto}
.sp{margin-left:auto}
</style>`

func shell(d Deps, title, body string, isAuthed bool) string {
	role := "节点"
	if d.Control != nil {
		role = "节点 · 中控"
	}
	// 这台机器上没有任何写操作时不显示登录入口 —— 一个点进去只会说
	// "没配口令"的链接,只会让人以为自己配错了。
	auth := `<span class=dim>只读</span>`
	switch {
	case isAuthed:
		auth = `已登录 · <a href="/logout">退出</a>`
	case d.Operator != "" && (len(d.Actions) > 0 || d.Control != nil):
		auth = `<a href="/login">登录以操作</a>`
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

func pageSSOT(d Deps, content, findings string, err error, saved bool) string {
	var b strings.Builder

	dist, derr := d.Control.Distributed()
	b.WriteString(`<div class=card>`)
	if derr != nil {
		fmt.Fprintf(&b, `<span class=bad>问不到分发点:%s</span>`, esc(brief(derr.Error())))
	} else {
		fmt.Fprintf(&b, `分发点当前指向 <b>%s</b>`, esc(short(dist)))
	}
	b.WriteString(`<br><span class=dim>发布是自动的:存盘之后发布器会校验、渲染、签名、分发。
这里没有"发布"按钮 —— 唯一的写操作就是改 SSOT。</span></div>`)

	switch {
	case saved:
		b.WriteString(`<div class=card><span class=ok>✅ 已保存。发布器会在下一轮接管(约 30 秒)。</span></div>`)
	case err != nil:
		fmt.Fprintf(&b, `<div class=card><span class=bad>❌ %s</span></div>`, esc(err.Error()))
	case findings != "":
		fmt.Fprintf(&b, `<div class=card><span class=bad>校验不通过,未保存:</span><pre>%s</pre></div>`, esc(findings))
	}

	fmt.Fprintf(&b, `<h2>%s</h2>
<form method=post action=/ssot>
<textarea name=content spellcheck=false>%s</textarea><br>
<button name=action value=check>只校验</button>
<button name=action value=save>校验并保存</button>
</form>
<p class=dim>校验不过就不会保存 —— 存一份自相矛盾的 SSOT 进去,发布器会拒绝发布,
而线上停在旧快照。宁可在这里挡住。</p>
<p><a href="/">← 回到总览</a></p>`, esc(d.Control.SSOTPath), esc(content))
	return shell(d, "改 SSOT", b.String(), true)
}

func pageEvents(d Deps, isAuthed bool) string {
	evs := d.Events(200)
	var b strings.Builder
	b.WriteString(`<p class=dim>只记<b>状态变化</b>,不记状态 —— "每分钟一条 cn-a 正常"没有价值,
有价值的是什么时候坏的、什么时候好的、坏了多久。</p>`)
	if len(evs) == 0 {
		b.WriteString(`<div class=card>还没有记录到任何变化。<br>
<span class=dim>中控刚起来时只播种不产生事件 —— 否则每次重启都会看起来像全网同时变了一次。</span></div>`)
		return shell(d, "事件", b.String()+`<p><a href="/">← 回到总览</a></p>`, isAuthed)
	}
	b.WriteString(`<table><tr><th>时间<th>节点<th>什么<th>变化<th>持续</tr>`)
	for _, e := range evs {
		cls := ""
		switch e.Level {
		case "problem":
			cls = " class=bad"
		case "ok":
			cls = " class=ok"
		case "pending":
			cls = " class=warn"
		}
		last := esc(e.Lasted)
		switch {
		case e.Ongoing && e.Level == "problem":
			// 还在持续的**问题**必须一眼看出来 —— 它需要人现在就管。
			last = `<b class=bad>` + last + ` 至今</b>`
		case e.Ongoing:
			last += ` <span class=dim>至今</span>`
		}
		subj := e.Subject
		if subj == "" {
			subj = e.Kind
		} else {
			subj = e.Kind + " " + subj
		}
		fmt.Fprintf(&b, `<tr><td class=dim>%s<td>%s<td class=w>%s<td class=w%s>%s → %s<td>%s</tr>`,
			esc(shortTS(e.TS)), esc(e.Node), esc(subj), cls, esc(e.From), esc(e.To), last)
		if e.Detail != "" {
			fmt.Fprintf(&b, `<tr><td><td><td class="w dim" colspan=3>%s</tr>`, esc(brief(e.Detail)))
		}
	}
	b.WriteString(`</table><p><a href="/">← 回到总览</a></p>`)
	return shell(d, "事件", b.String(), isAuthed)
}

// shortTS 去掉日期里没信息量的部分,表格窄一些。
func shortTS(ts string) string {
	if len(ts) >= 19 {
		return ts[5:19]
	}
	return ts
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

	if d.Unresolved != nil {
		// 待处理放最前面。**"没有"也要说出来** —— 一个空白的面板分不出
		// "一切正常"和"这功能坏了"。
		var live, pending []UnresolvedView
		for _, e := range d.Unresolved() {
			switch e.Level {
			case "problem":
				live = append(live, e)
			case "pending":
				pending = append(pending, e)
			}
		}
		switch {
		case len(live) > 0:
			b.WriteString(`<div class=card><span class=bad>⚠️ 未解决(` +
				fmt.Sprint(len(live)) + `)</span><table>`)
			for _, e := range live {
				fmt.Fprintf(&b, `<tr><td>%s<td class=w>%s %s<td class=bad>%s<td><b>%s</b></tr>`,
					esc(e.Node), esc(e.Kind), esc(e.Subject), esc(e.State), esc(e.LastedText()))
			}
			b.WriteString(`</table></div>`)
		default:
			b.WriteString(`<div class=card><span class=ok>✅ 没有未解决的问题</span></div>`)
		}
		for _, e := range pending {
			fmt.Fprintf(&b, `<div class=card><span class=warn>⏳ %s %s %s —— %s</span><br>
<span class=dim>%s</span></div>`,
				esc(e.Node), esc(e.Kind), esc(e.Subject), esc(e.LastedText()), esc(e.Detail))
		}
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
					cell = fmt.Sprintf(`<span class=bad>❌ %s</span>`, esc(brief(r.Err)))
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

	if d.Events != nil {
		b.WriteString(`<h2>事件</h2><p><a href="/events">看状态变化历史 →</a></p>`)
	}
	if d.Operator == "" && len(d.Actions) == 0 && d.Control == nil {
		return shell(d, "总览", b.String(), isAuthed)
	}
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
		if d.Control != nil {
			b.WriteString(` <a href="/ssot"><button>改 SSOT…</button></a>`)
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

// brief 把网络错误压成一行能看的。
//
// Go 的网络错误带着完整的拨号上下文(`Get "https://…": dial tcp 1.2.3.4:443: …`),
// 在表格里会把整行撑爆,而真正有信息量的是最后那一小截。
func brief(s string) string {
	if i := strings.LastIndex(s, ": "); i > 0 {
		s = s[i+2:]
	}
	if len(s) > 44 {
		s = s[:44] + "…"
	}
	return s
}
