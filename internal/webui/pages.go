package webui

import (
	"fmt"
	"html"
	"math"
	"sort"
	"strings"
	"time"
)

// 页面是服务端渲染的纯 HTML,**没有任何外部资源、没有 JavaScript**。
//
// 不是极简主义:这些机器不一定能出网,而通过 ssh 端口转发进来时更不能。
// 一个依赖 CDN 的界面在最需要它的时候(隧道断了、机器出问题了)恰好打不开。

const style = `<style>
:root{--fg:#eef4f2;--dim:#94a3a1;--line:#465153;--ok:#4ed3b0;--bad:#ff727c;--warn:#f6c76b;--info:#72b7ff;--route:#ffd166;--bg:#22292b;--side:#293133;--card:#30393b;--card2:#354043;--ink:#13191a}
*{box-sizing:border-box}
body{margin:0;font:14px/1.55 Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:var(--fg);background:var(--bg)}
a{color:inherit;text-decoration:none}a:hover{color:var(--ok)}
.app{min-height:100vh;display:grid;grid-template-columns:230px minmax(0,1fr)}
.side{background:var(--side);border-right:1px solid var(--line);padding:24px 18px;position:sticky;top:0;height:100vh}
.brand{display:flex;align-items:center;gap:11px;font-size:18px;font-weight:750;letter-spacing:.04em;margin-bottom:28px}.mark{display:grid;place-items:center;width:31px;height:31px;border:2px solid var(--ok);border-radius:7px;color:var(--ok);font-weight:850;line-height:1}
.role{font-size:11px;color:var(--dim);font-weight:500;letter-spacing:.08em;text-transform:uppercase}
.nav{display:grid;gap:6px}.nav a{padding:9px 11px;border-radius:8px;color:var(--dim)}.nav a:first-child,.nav a:hover{background:var(--card);color:var(--fg)}
.sidefoot{position:absolute;left:18px;right:18px;bottom:22px;color:var(--dim);font-size:12px}
.main{min-width:0;padding:26px 30px 50px}.top{display:flex;align-items:flex-start;gap:16px;margin-bottom:22px}.top h1{font-size:22px;line-height:1.25;margin:0 0 4px}.sp{margin-left:auto}
h2{font-size:13px;margin:0 0 12px;color:var(--dim);font-weight:700;letter-spacing:.08em;text-transform:uppercase}
.dim{color:var(--dim)}.ok{color:var(--ok)}.bad{color:var(--bad)}.warn{color:var(--warn)}.info{color:var(--info)}
.badge{display:inline-flex;align-items:center;gap:6px;border:1px solid var(--line);border-radius:999px;padding:4px 9px;font-size:12px}.dot{width:7px;height:7px;border-radius:50%;background:currentColor}
.grid{display:grid;grid-template-columns:repeat(12,minmax(0,1fr));gap:14px;margin-bottom:14px}.span3{grid-column:span 3}.span4{grid-column:span 4}.span5{grid-column:span 5}.span6{grid-column:span 6}.span7{grid-column:span 7}.span8{grid-column:span 8}.span12{grid-column:1/-1}
.card{background:linear-gradient(145deg,var(--card),#2d3537);border:1px solid var(--line);border-radius:12px;padding:16px;min-width:0;box-shadow:0 8px 24px rgba(0,0,0,.08)}
.metric{font-size:25px;font-weight:760;line-height:1.15;margin:5px 0}.metric small{font-size:13px;color:var(--dim);font-weight:500}.label{font-size:12px;color:var(--dim)}
.section{margin-top:18px}.sectionhead{display:flex;align-items:center;gap:12px;margin:0 0 10px}.sectionhead h2{margin:0}
table{border-collapse:collapse;width:100%;margin:0}
td,th{text-align:left;padding:9px 10px 9px 0;border-bottom:1px solid rgba(148,163,161,.19);vertical-align:top;white-space:nowrap}
tr:last-child td{border-bottom:0}th{color:var(--dim);font-weight:650;font-size:11px;letter-spacing:.04em;text-transform:uppercase}td.w{white-space:normal}
.topology{width:100%;min-height:330px;display:block;background:rgba(18,24,25,.27);border-radius:9px;border:1px solid rgba(148,163,161,.14)}
.topology .tunnel{stroke:var(--ok);stroke-width:2.2;opacity:.78}.topology .candidate{stroke:var(--dim);stroke-width:1.8;stroke-dasharray:2 7;opacity:.72}.topology .degraded{stroke:var(--warn)}.topology .failed{stroke:var(--bad)}.topology .unknown{stroke:var(--dim);stroke-dasharray:3 7;opacity:.58}.topology .route{stroke:var(--route);stroke-width:5;opacity:.78}.topology .node{fill:var(--card2);stroke:var(--ok);stroke-width:1.5}.topology .node.problem{stroke:var(--bad)}.topology .node.unknown{stroke:var(--dim);stroke-dasharray:3 3}.topology .selected{stroke:var(--route);stroke-width:3}.topology text{fill:var(--fg);font:600 13px ui-sans-serif,system-ui}.topology .sub{fill:var(--dim);font-size:10px;font-weight:500}
.legend{display:flex;gap:16px;flex-wrap:wrap;margin-top:10px;color:var(--dim);font-size:11px}.key{display:inline-block;width:26px;border-top:2px solid var(--ok);vertical-align:middle;margin-right:6px}.key.candidate{border-color:var(--dim);border-top-style:dotted}.key.route{border-color:var(--route);border-width:4px}.key.degraded{border-color:var(--warn)}.key.failed{border-color:var(--bad)}
.nodegrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(205px,1fr));gap:10px}.nodecard{border:1px solid rgba(148,163,161,.22);background:rgba(21,28,29,.24);border-radius:9px;padding:12px}.nodehead{display:flex;align-items:center;gap:7px;margin-bottom:8px}.nodehead b{font-size:15px}.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}.tiny{font-size:11px}.clip{overflow:hidden;text-overflow:ellipsis;max-width:100%}
.notice{border-left:3px solid var(--warn)}.notice.badline{border-left-color:var(--bad)}.empty{padding:18px;text-align:center;color:var(--dim);border:1px dashed var(--line);border-radius:9px}
form{display:inline}
button{font:inherit;padding:7px 11px;border:1px solid var(--line);border-radius:7px;background:var(--card2);color:var(--fg);cursor:pointer}button:hover{border-color:var(--ok)}
input{font:inherit;padding:8px 10px;border:1px solid var(--line);border-radius:7px;background:var(--bg);color:var(--fg)}
pre{background:rgba(17,23,24,.45);border:1px solid var(--line);border-radius:8px;padding:12px;overflow-x:auto;white-space:pre-wrap;margin:8px 0}
textarea{width:100%;height:60vh;font:13px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;padding:12px;border:1px solid var(--line);border-radius:8px;background:#1d2425;color:var(--fg);white-space:pre;overflow-wrap:normal;overflow-x:auto}
@media(max-width:950px){.app{grid-template-columns:1fr}.side{position:static;height:auto;padding:14px 18px}.brand{margin-bottom:12px}.nav{display:flex;overflow-x:auto}.sidefoot{position:static;margin-top:10px}.main{padding:20px 16px}.span3,.span4,.span5,.span6,.span7,.span8{grid-column:1/-1}}
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
	eventsLink := ""
	if d.Events != nil {
		eventsLink = `<a href="/events">事件</a>`
	}
	configLink := ""
	if d.Control != nil {
		configLink = `<a href="/ssot">配置与密钥</a>`
	}
	refresh := ""
	if title == "总览" {
		// 纯 SSR 不靠 JavaScript；只让实时总览定时重取。编辑、登录和结果页
		// 不能自动刷新，否则会丢表单或重复操作。
		refresh = `<meta http-equiv=refresh content=30>`
	}
	return fmt.Sprintf(`<!doctype html><meta charset=utf-8><title>%s · Loom</title>
<meta name=viewport content="width=device-width,initial-scale=1">%s%s
<div class=app><aside class=side><div class=brand>
<span class=mark aria-hidden=true>L</span>
<span>Loom<div class=role>%s</div></span></div><nav class=nav>
<a href="/#overview">总览</a><a href="/#topology">隧道与路径</a><a href="/#nodes">节点</a><a href="/#routes">Agent 路由</a><a href="/#release">发布与收敛</a>%s%s
</nav><div class=sidefoot>%s · %s</div></aside><main class=main>
<div class=top><div><h1>%s</h1><div class=dim>节点 %s</div></div><div class=sp>%s</div></div>%s</main></div>`,
		esc(title), refresh, style, esc(role), eventsLink, configLink, esc(d.Node), esc(role),
		esc(title), esc(d.Node), auth, body)
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
	now := d.Now().UTC()
	var b strings.Builder

	// 顶部坐标与健康摘要。
	vers := map[string][]string{}
	unknownApplied := 0
	for _, n := range v.Nodes {
		k := n.Applied
		if k == "" {
			unknownApplied++
			continue
		}
		vers[k] = append(vers[k], n.ID)
	}
	healthyNodes, problemNodes, unknownNodes := 0, 0, 0
	for _, n := range v.Nodes {
		switch n.Health {
		case "healthy":
			healthyNodes++
		case "problem":
			problemNodes++
		default:
			unknownNodes++
		}
	}
	activeLinks, tunnelLinks := 0, 0
	for _, l := range v.Links {
		if l.Kind != "tunnel" {
			continue
		}
		tunnelLinks++
		if l.State == "active" {
			activeLinks++
		}
	}
	freshRoutes := 0
	for _, r := range v.Routes {
		if !r.Stale {
			freshRoutes++
		}
	}
	healthClass, healthText := "warn", fmt.Sprintf("%d 故障 · %d 未知", problemNodes, unknownNodes)
	if problemNodes > 0 {
		healthClass = "bad"
	} else if unknownNodes == 0 {
		healthClass, healthText = "ok", "全部节点已核验健康"
	}
	fmt.Fprintf(&b, `<div id=overview class=grid>
<div class="card span3"><div class=label>节点健康</div><div class=metric>%d <small>/ %d</small></div><div class=%s>%s</div></div>
<div class="card span3"><div class=label>常驻 WG 链路</div><div class=metric>%d <small>/ %d</small></div><div class=dim>SSOT 底图 + 承载可达性观测</div></div>
<div class="card span3"><div class=label>Agent 当前选择</div><div class=metric>%d <small>/ %d 新鲜</small></div><div class=dim>来自 selector 实读</div></div>
<div class="card span3"><div class=label>当前快照</div><div class="metric mono">%s</div><div class=dim>页面观测 %s</div></div>
</div>`, healthyNodes, len(v.Nodes), healthClass, healthText,
		activeLinks, tunnelLinks, freshRoutes, len(v.Routes), esc(short(v.Applied)), esc(ageText(v.ObservedAt, now)))

	if len(vers) > 1 {
		b.WriteString(`<div class="card notice"><span class=warn>全网不是同一个快照</span><table>`)
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
	} else if len(vers) == 1 && unknownApplied == 0 {
		for k := range vers {
			fmt.Fprintf(&b, `<div class="badge ok"><span class=dot></span>快照 %s · 全网一致</div>`, esc(short(k)))
		}
	} else if len(vers) == 1 {
		for k := range vers {
			fmt.Fprintf(&b, `<div class="badge warn"><span class=dot></span>已观测节点为快照 %s · %d 个节点未核验</div>`, esc(short(k)), unknownApplied)
		}
	} else if unknownApplied > 0 {
		fmt.Fprintf(&b, `<div class="badge warn"><span class=dot></span>%d 个节点没有快照观测</div>`, unknownApplied)
	}
	for _, w := range v.Warnings {
		fmt.Fprintf(&b, `<div class="card notice"><span class=warn>%s</span></div>`, esc(w))
	}

	var unresolved []UnresolvedView
	if d.Unresolved != nil {
		unresolved = d.Unresolved()
	}

	// 近实时拓扑：底图和 route overlay 都由 View 数据生成，不写死节点或边。
	// 观测本来就是分钟级 gossip，页面是 30 秒 SSR 刷新；直接写清采样节奏，
	// 不把周期数据包装成流式实时。
	b.WriteString(`<div id=topology class=section><div class=sectionhead><h2>近实时拓扑</h2><span class=dim>采样约 1 分钟 · 页面每 30 秒刷新 · 每条数据保留观测年龄</span></div><div class=grid>`)
	b.WriteString(`<div class="card span8">` + topologySVG(v) + `<div class=legend>
	<span><i class=key></i>常驻 WG</span><span><i class="key candidate"></i>候选跳（未核验）</span>
	<span><i class="key route"></i>Agent 当前 RouteCandidate</span><span><i class="key degraded"></i>部分失败</span><span><i class="key failed"></i>故障</span>
</div><div class="tiny dim">候选跳只表示 SSOT 可选，不表示在线；黄色路径只采用 sing-box selector 实读状态。</div>`)
	if len(v.Links) > 0 {
		b.WriteString(`<table><tr><th>边<th>类型 / 状态<th>观测时间<th>来源</tr>`)
		for _, l := range v.Links {
			fmt.Fprintf(&b, `<tr><td class=mono>%s ↔ %s<td>%s / %s<td>%s<td class="w tiny dim">%s</tr>`,
				esc(l.From), esc(l.To), esc(l.Kind), esc(l.State), esc(ageText(l.ObservedAt, now)), esc(l.Source))
		}
		b.WriteString(`</table>`)
	}
	b.WriteString(`</div>`)
	b.WriteString(`<div class="card span4"><h2>待处理</h2>`)
	if len(unresolved) == 0 {
		if unknownNodes > 0 {
			fmt.Fprintf(&b, `<div class=empty><span class=warn>没有已确认故障，但 %d 个节点状态未知</span><br><span class=tiny>unknown 不等于 healthy</span></div>`, unknownNodes)
		} else {
			b.WriteString(`<div class=empty><span class=ok>没有未解决的问题</span><br><span class=tiny>现状来自 state.json，非事件历史倒推</span></div>`)
		}
	} else {
		for _, e := range unresolved {
			cls := "notice"
			if e.Level == "problem" {
				cls += " badline"
			}
			fmt.Fprintf(&b, `<div class="card %s"><b>%s · %s %s</b><br><span class=%s>%s · %s</span><br><span class="tiny dim">%s</span></div>`,
				cls, esc(e.Node), esc(e.Kind), esc(e.Subject),
				map[bool]string{true: "bad", false: "warn"}[e.Level == "problem"],
				esc(e.State), esc(e.LastedText()), esc(e.Detail))
		}
	}
	b.WriteString(`</div></div></div>`)

	// 节点卡片保留所有已有目标、隧道和错误细节。
	b.WriteString(`<div id=nodes class=section><div class=sectionhead><h2>节点</h2><span class=dim>版本、快照、rollout 与数据来源</span></div><div class=nodegrid>`)
	for _, n := range v.Nodes {
		dotClass := "warn"
		if n.Health == "healthy" {
			dotClass = "ok"
		} else if n.Health == "problem" {
			dotClass = "bad"
		}
		fmt.Fprintf(&b, `<div class=nodecard><div class=nodehead><span class="%s dot"></span><b>%s</b>`,
			dotClass, esc(n.ID))
		if n.Self {
			b.WriteString(`<span class="tiny dim">本机</span>`)
		}
		b.WriteString(`</div>`)
		healthLabel := "状态未知"
		if n.Health == "healthy" {
			healthLabel = "已核验健康"
		} else if n.Health == "problem" {
			healthLabel = "已确认有问题"
		}
		fmt.Fprintf(&b, `<div class="tiny %s">%s</div>`, dotClass, healthLabel)
		fmt.Fprintf(&b, `<div class="tiny dim">%s · %s</div><div>快照 <span class=mono>%s</span></div>`,
			esc(n.Source), esc(ageText(n.ObservedAt, now)), esc(short(n.Applied)))
		if n.Version != nil {
			fmt.Fprintf(&b, `<div class="tiny clip">commit <span class=mono>%s</span> · bin <span class=mono>%s</span></div>`,
				esc(short(n.Version.Commit)), esc(short(n.Version.Binary)))
		}
		if n.Rollout != nil {
			cls := rolloutCSS(n.Rollout)
			fmt.Fprintf(&b, `<div class="tiny %s">rollout %s · %s</div>`, cls, esc(n.Rollout.Stage), esc(short(n.Rollout.Snapshot)))
		}
		for _, c := range n.Components {
			cls := "ok"
			actual := c.Actual
			if !c.OK {
				cls = "bad"
				if c.Error != "" {
					actual = "无法核对"
				}
			}
			fmt.Fprintf(&b, `<div class="tiny %s clip">%s %s / 期望 %s</div>`,
				cls, esc(c.Name), esc(actual), esc(c.Expected))
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
			tl = append(tl, fmt.Sprintf(`<span class="tiny %s">%s</span>`, cls, esc(label)))
		}
		if len(tl) > 0 {
			b.WriteString(`<div>` + strings.Join(tl, ` · `) + `</div>`)
		}
		for _, r := range n.Targets {
			observed := ageText(r.ObservedAt, now)
			if r.Err == "" {
				kind := "target"
				if r.Uplink {
					kind = "uplink"
				}
				fmt.Fprintf(&b, `<div class="tiny ok clip">%s · %s · %dms · %s</div>`,
					esc(kind), esc(r.Target), r.MS, esc(observed))
			} else if r.Uplink {
				fmt.Fprintf(&b, `<div class="tiny bad clip">uplink · %s · %s · %s</div>`,
					esc(r.Target), esc(brief(r.Err)), esc(observed))
			} else {
				fmt.Fprintf(&b, `<div class="tiny info clip">target · %s · 不可达（剪枝数据） · %s · %s</div>`,
					esc(r.Target), esc(brief(r.Err)), esc(observed))
			}
		}
		for _, p := range n.Problems {
			fmt.Fprintf(&b, `<div class="tiny bad clip">%s</div>`, esc(p))
		}
		b.WriteString(`</div>`)
	}
	b.WriteString(`</div></div>`)

	// 业务候选路径来自 SSOT RouteCandidate.ServerChain。它与 WG 承载边是两层：
	// 没有直连 WG 不等于没有业务路径；声明存在也不等于路径已实时在线。
	b.WriteString(`<div class=section><div class=sectionhead><h2>业务候选路径</h2><span class=dim>无直边 ≠ 无路径；未选中的候选不冒充在线</span></div><div class=card>`)
	if len(v.Candidates) == 0 {
		b.WriteString(`<div class=empty>本节点没有可展示的 RouteCandidate.ServerChain。</div>`)
	} else {
		b.WriteString(`<table><tr><th>接入节点<th>声明 / 服务<th>候选路径<th>状态<th>更新时间 / 来源</tr>`)
		for _, p := range v.Candidates {
			path := strings.Join(p.Chain, " → ")
			if len(p.Chain) <= 1 {
				path = p.Node + " → direct"
			}
			cls, label := "warn", "候选（未核验）"
			if p.State == "selected" {
				cls, label = "ok", "当前选中"
			}
			observed := "未实时核验"
			if p.ObservedAt != "" {
				observed = ageText(p.ObservedAt, now)
			}
			fmt.Fprintf(&b, `<tr><td>%s<td>%s<td class="w mono %s">%s<td class=%s>%s<td class="w tiny">%s<br><span class=dim>%s</span></tr>`,
				esc(p.Node), esc(p.Declaration), cls, esc(path), cls, label,
				esc(observed), esc(p.Source))
		}
		b.WriteString(`</table>`)
	}
	b.WriteString(`</div></div>`)

	// 当前 Agent 选择来自 selector 实读文件，按每条 declaration 独立标时间。
	b.WriteString(`<div id=routes class=section><div class=sectionhead><h2>Agent 路由</h2><span class=dim>当前实际 RouteCandidate</span></div><div class=card>`)
	if len(v.Routes) == 0 {
		b.WriteString(`<div class=empty>没有可验证的 Agent 当前选路数据；不会用历史事件冒充现状。</div>`)
	} else {
		b.WriteString(`<table><tr><th>节点<th>声明<th>当前路径<th>候选健康<th>更新时间 / 来源<th>理由</tr>`)
		for _, r := range v.Routes {
			path := strings.Join(r.Chain, " → ")
			if len(r.Chain) <= 1 {
				path = r.Node + " → direct"
			}
			cls := "ok"
			if r.Stale {
				cls = "warn"
			}
			health := `<span class=warn>未上报（旧 Agent）</span>`
			if h := r.Health; h != nil {
				hcls := "ok"
				if h.RecentSuccess+h.RecentDegraded == 0 {
					hcls = "warn"
				}
				if h.Candidates > 0 && h.RecentFailed == h.Candidates {
					hcls = "bad"
				}
				health = fmt.Sprintf(`<span class=%s>%d 正常 · %d 波动 · %d 失败 · %d 过期 · %d 未知</span>`,
					hcls, h.RecentSuccess, h.RecentDegraded, h.RecentFailed, h.Stale, h.Unknown)
				if h.SelectedState != "" {
					stateClass, stateLabel := "warn", h.SelectedState
					switch h.SelectedState {
					case "success":
						stateClass, stateLabel = "ok", "正常"
					case "degraded":
						stateLabel = "波动"
					case "failed":
						stateClass, stateLabel = "bad", "失败"
					case "stale":
						stateLabel = "过期"
					case "unknown":
						stateLabel = "未知"
					}
					detail := "当前候选 " + stateLabel
					if h.SelectedMetrics != "" {
						detail += " · " + h.SelectedMetrics
					}
					health += `<br><span class="tiny ` + stateClass + `">` + esc(detail) + `</span>`
				}
				if h.BestMetrics != "" {
					health += `<br><span class="tiny dim">窗口最佳 ` + esc(h.BestMetrics) + `</span>`
				}
			}
			fmt.Fprintf(&b, `<tr><td>%s<td>%s<td class="w mono %s">%s<td class=w>%s<td class=w>%s<br><span class="tiny dim">%s</span><td class=w>%s</tr>`,
				esc(r.Node), esc(r.Declaration), cls, esc(path), health,
				esc(ageText(r.ObservedAt, now)), esc(r.Source), esc(r.Reason))
		}
		b.WriteString(`</table>`)
	}
	b.WriteString(`</div></div>`)

	// 发布器与各节点 rollout 使用和 /status 相同的 View 字段。
	b.WriteString(`<div id=release class=section><div class=sectionhead><h2>发布与收敛</h2></div><div class=grid><div class="card span5">`)
	if v.Publisher == nil {
		b.WriteString(`<h2>发布器</h2><div class=empty>本节点不是中控，或 /status 未提供发布器状态。</div>`)
	} else {
		cls, label := "ok", "心跳正常"
		if !v.Publisher.Healthy {
			cls, label = "bad", "发布器不健康"
		}
		fmt.Fprintf(&b, `<h2>发布器</h2><div class="badge %s"><span class=dot></span>%s</div>
<div class=metric>PID %d</div><div class="tiny dim">heartbeat %s · %s · interval %ds</div>
<table><tr><td>commit<td class=mono>%s<tr><td>binary<td class=mono>%s<tr><td>上次成功<td>%s<tr><td>快照<td class=mono>%s</table>`,
			cls, label, v.Publisher.PID, esc(v.Publisher.UpdatedAt), esc(ageText(v.Publisher.UpdatedAt, now)), v.Publisher.IntervalSeconds,
			esc(short(v.Publisher.Commit)), esc(short(v.Publisher.Binary)), esc(v.Publisher.LastSuccess), esc(short(v.Publisher.LastSnapshot)))
		if v.Publisher.LastError != "" {
			fmt.Fprintf(&b, `<div class="tiny %s">最近错误 %s · %s</div>`,
				map[bool]string{true: "bad", false: "dim"}[!v.Publisher.Healthy], esc(v.Publisher.LastErrorAt), esc(v.Publisher.LastError))
		}
	}
	b.WriteString(`</div><div class="card span7"><h2>节点 rollout</h2><table><tr><th>节点<th>目标快照<th>阶段<th>进入时间<th>回退点</tr>`)
	for _, n := range v.Nodes {
		if n.Rollout == nil {
			continue
		}
		cls := rolloutCSS(n.Rollout)
		fmt.Fprintf(&b, `<tr><td>%s<td class=mono>%s<td class=%s>%s<td>%s<td class=mono>%s</tr>`,
			esc(n.ID), esc(short(n.Rollout.Snapshot)), cls, esc(n.Rollout.Stage), esc(n.Rollout.EnteredAt), esc(short(n.Rollout.LastGood)))
		if n.Rollout.Error != "" {
			fmt.Fprintf(&b, `<tr><td><td class="bad w" colspan=4>%s</tr>`, esc(n.Rollout.Error))
		}
	}
	b.WriteString(`</table></div></div></div>`)

	if d.Events != nil {
		b.WriteString(`<div class=section><div class=sectionhead><h2>最近事件</h2><a class="sp tiny" href="/events">全部事件 →</a></div><div class=card><table>`)
		for _, e := range d.Events(8) {
			cls := "dim"
			if e.Level == "problem" {
				cls = "bad"
			} else if e.Level == "ok" {
				cls = "ok"
			}
			fmt.Fprintf(&b, `<tr><td class=dim>%s<td>%s<td class=w>%s %s<td class=%s>%s → %s</tr>`,
				esc(shortTS(e.TS)), esc(e.Node), esc(e.Kind), esc(e.Subject), cls, esc(e.From), esc(e.To))
		}
		b.WriteString(`</table></div></div>`)
	}
	if d.Operator == "" && len(d.Actions) == 0 && d.Control == nil {
		return shell(d, "总览", b.String(), isAuthed)
	}
	b.WriteString(`<div class=section><div class=sectionhead><h2>本机操作</h2></div><div class=card>`)
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
	b.WriteString(`</div></div>`)
	return shell(d, "总览", b.String(), isAuthed)
}

func rolloutCSS(r *RolloutView) string {
	if r == nil {
		return "warn"
	}
	if r.Problem {
		return "bad"
	}
	switch r.Stage {
	case "verified", "decommissioned":
		return "ok"
	default:
		return "warn"
	}
}

func ageText(ts string, now time.Time) string {
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		if ts == "" {
			return "时间未记录"
		}
		return ts
	}
	d := now.Sub(t)
	if d < 0 {
		d = 0
	}
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%d 秒前", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%d 分钟前", int(d.Minutes()))
	default:
		return fmt.Sprintf("%.1f 小时前", d.Hours())
	}
}

type svgPoint struct{ x, y float64 }

func topologySVG(v View) string {
	ids := make([]string, 0, len(v.Nodes))
	for _, n := range v.Nodes {
		ids = append(ids, n.ID)
	}
	sort.Strings(ids)
	pos := map[string]svgPoint{}
	for i, id := range ids {
		angle := -math.Pi/2 + 2*math.Pi*float64(i)/float64(maxInt(1, len(ids)))
		pos[id] = svgPoint{x: 380 + 270*math.Cos(angle), y: 190 + 135*math.Sin(angle)}
	}
	selected := map[string]bool{}
	for _, r := range v.Routes {
		if r.Stale {
			continue
		}
		for _, id := range r.Chain {
			selected[id] = true
		}
	}
	var b strings.Builder
	b.WriteString(`<svg class=topology viewBox="0 0 760 380" role=img aria-label="近实时网络拓扑"><defs><marker id=arrow viewBox="0 0 10 10" refX=8 refY=5 markerWidth=5 markerHeight=5 orient=auto-start-reverse><path d="M 0 0 L 10 5 L 0 10 z" fill="#ffd166"/></marker></defs>`)
	for _, l := range v.Links {
		a, aok := pos[l.From]
		z, zok := pos[l.To]
		if !aok || !zok {
			continue
		}
		cls := l.Kind
		if cls != "candidate" {
			cls = "tunnel"
		}
		if l.State == "failed" {
			cls += " failed"
		} else if l.State == "degraded" {
			cls += " degraded"
		} else if l.State == "unknown" {
			cls += " unknown"
		}
		fmt.Fprintf(&b, `<line class="%s" x1="%.1f" y1="%.1f" x2="%.1f" y2="%.1f"/>`, cls, a.x, a.y, z.x, z.y)
		if l.MS > 0 {
			fmt.Fprintf(&b, `<text class=sub x="%.1f" y="%.1f">%dms</text>`, (a.x+z.x)/2, (a.y+z.y)/2-4, l.MS)
		}
	}
	for _, r := range v.Routes {
		if r.Stale {
			continue
		}
		for i := 0; i+1 < len(r.Chain); i++ {
			a, aok := pos[r.Chain[i]]
			z, zok := pos[r.Chain[i+1]]
			if aok && zok {
				fmt.Fprintf(&b, `<line class=route marker-end="url(#arrow)" x1="%.1f" y1="%.1f" x2="%.1f" y2="%.1f"/>`, a.x, a.y, z.x, z.y)
			}
		}
	}
	health := map[string]string{}
	for _, n := range v.Nodes {
		health[n.ID] = n.Health
	}
	for _, id := range ids {
		p := pos[id]
		cls := "node"
		if health[id] == "problem" {
			cls += " problem"
		} else if health[id] != "healthy" {
			cls += " unknown"
		}
		if selected[id] {
			cls += " selected"
		}
		fmt.Fprintf(&b, `<circle class="%s" cx="%.1f" cy="%.1f" r="31"/><text text-anchor=middle x="%.1f" y="%.1f">%s</text>`, cls, p.x, p.y, p.x, p.y+5, esc(id))
	}
	if len(ids) == 0 {
		b.WriteString(`<text class=sub text-anchor=middle x=380 y=190>暂无拓扑观测</text>`)
	}
	b.WriteString(`</svg>`)
	return b.String()
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
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
