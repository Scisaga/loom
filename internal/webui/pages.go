package webui

import (
	"fmt"
	"html"
	"math"
	"net/url"
	"sort"
	"strings"
	"time"
)

// 页面是服务端渲染的纯 HTML,**没有任何外部资源、没有 JavaScript**。
//
// 不是极简主义:这些机器不一定能出网,而通过 ssh 端口转发进来时更不能。
// 一个依赖 CDN 的界面在最需要它的时候(隧道断了、机器出问题了)恰好打不开。

const style = `<style>
:root{--fg:#181b1a;--dim:#717674;--faint:#9ba09e;--line:#e2e6e3;--line2:#ccd2ce;--ok:#239b68;--oksoft:#eef8f3;--bad:#b84c4c;--badsoft:#fff3f2;--warn:#a66a14;--warnsoft:#fff8eb;--info:#477d9c;--route:#239b68;--bg:#fcfcfb;--card:#fff;--card2:#f7f8f7;--ink:#181b1a}
*{box-sizing:border-box}
html{background:var(--bg)}body{margin:0;font:14px/1.55 Inter,"Atkinson Hyperlegible Next",ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:var(--fg);background:var(--bg)}
a{color:inherit;text-decoration:none}a:hover{color:var(--ok)}code,.mono{font-family:"Intel One Mono",ui-monospace,SFMono-Regular,Menlo,monospace}
.app{min-height:100vh}.header{height:58px;background:#fff;border-bottom:1px solid var(--line);display:flex;align-items:stretch;padding:0 20px;gap:24px;position:sticky;top:0;z-index:4}
.brand{display:flex;align-items:center;gap:9px;font-size:17px;font-weight:760;letter-spacing:.09em;white-space:nowrap}.brandmark{width:34px;height:34px;color:#252927}.brandmark path{fill:currentColor}
.role{font-size:10px;color:var(--dim);font-weight:550;letter-spacing:.08em;text-transform:uppercase}.nav{display:flex;align-items:stretch;gap:2px;min-width:0;overflow-x:auto}.nav a{display:flex;align-items:center;padding:0 10px;color:var(--dim);white-space:nowrap;border-bottom:2px solid transparent}.nav a:hover,.nav a.active{color:var(--fg);border-bottom-color:var(--ok)}.navgroup{display:flex;align-items:stretch;position:relative;padding:13px 3px 0;margin-left:5px;border-left:1px solid var(--line)}.navgroup:before{content:attr(data-label);position:absolute;top:2px;left:10px;font-size:8px;line-height:1;color:var(--faint);letter-spacing:.09em;text-transform:uppercase}.navgroup a{padding:0 7px}
.headmeta{margin-left:auto;display:flex;align-items:center;gap:18px;white-space:nowrap;font-size:12px}.headmeta .env{display:flex;align-items:center;gap:7px}.headmeta .dot{width:7px;height:7px}.main{min-width:0;max-width:1580px;margin:0 auto;padding:32px 22px 56px}
.top{display:flex;align-items:flex-start;gap:18px;margin-bottom:22px}.eyebrow{font-size:11px;letter-spacing:.13em;font-weight:700;text-transform:uppercase;margin-bottom:3px}.top h1{font-size:28px;letter-spacing:-.025em;line-height:1.2;margin:0 0 5px}.subtitle{color:var(--dim);font-size:13px}.sp{margin-left:auto}
h2{font-size:13px;margin:0 0 12px;color:var(--dim);font-weight:700;letter-spacing:.08em;text-transform:uppercase}h3{font-size:15px;margin:0 0 5px}
.dim{color:var(--dim)}.faint{color:var(--faint)}.ok{color:var(--ok)}.bad{color:var(--bad)}.warn{color:var(--warn)}.info{color:var(--info)}
.badge{display:inline-flex;align-items:center;gap:7px;border:1px solid var(--line);border-radius:999px;padding:4px 9px;font-size:12px}.dot{display:inline-block;width:7px;height:7px;border-radius:50%;background:currentColor;flex:0 0 auto}
.grid{display:grid;grid-template-columns:repeat(12,minmax(0,1fr));gap:14px;margin-bottom:14px}.span3{grid-column:span 3}.span4{grid-column:span 4}.span5{grid-column:span 5}.span6{grid-column:span 6}.span7{grid-column:span 7}.span8{grid-column:span 8}.span9{grid-column:span 9}.span12{grid-column:1/-1}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:16px;min-width:0}.card.soft{background:var(--card2)}.metric{font-size:24px;font-weight:720;line-height:1.15;margin:5px 0}.metric small{font-size:13px;color:var(--dim);font-weight:500}.label{font-size:11px;color:var(--dim);letter-spacing:.04em;text-transform:uppercase}
.section{margin-top:22px}.sectionhead{display:flex;align-items:center;gap:12px;margin:0 0 10px}.sectionhead h2{margin:0}.toolbar{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.split{display:grid;grid-template-columns:minmax(280px,1fr) minmax(0,2fr);gap:14px}.stack{display:grid;gap:14px}
table{border-collapse:collapse;width:100%;margin:0}td,th{text-align:left;padding:10px 10px 10px 0;border-bottom:1px solid var(--line);vertical-align:top;white-space:nowrap}tr:last-child td{border-bottom:0}th{color:var(--dim);font-weight:650;font-size:10px;letter-spacing:.06em;text-transform:uppercase}td.w{white-space:normal}.rowlink:hover{background:#fafcfb}
.topology{width:100%;min-height:330px;display:block;background:transparent}.topology .tunnel{stroke:#a5aaa8;stroke-width:1.6;opacity:.95}.topology .candidate{stroke:#b9bebc;stroke-width:1.4;stroke-dasharray:5 6;opacity:.9}.topology .degraded{stroke:#d79b3b}.topology .failed{stroke:#c65a5a}.topology .unknown{stroke:#a5aaa8;stroke-dasharray:3 7;opacity:.7}.topology .route{stroke:var(--route);stroke-width:3;opacity:.9}.topology .node{fill:#fff;stroke:var(--ok);stroke-width:1.8}.topology .node.problem{stroke:var(--bad)}.topology .node.unknown{stroke:#a5aaa8;stroke-dasharray:3 3}.topology .node.undeclared{fill:var(--warnsoft);stroke:var(--warn);stroke-dasharray:2 4}.topology .selected{stroke:var(--route);stroke-width:3}.topology text{fill:var(--fg);font:600 13px ui-sans-serif,system-ui}.topology .sub{fill:var(--dim);font-size:10px;font-weight:500}
.legend{display:flex;gap:16px;flex-wrap:wrap;margin-top:10px;color:var(--dim);font-size:11px}.key{display:inline-block;width:26px;border-top:2px solid #a5aaa8;vertical-align:middle;margin-right:6px}.key.candidate{border-color:#b9bebc;border-top-style:dashed}.key.route{border-color:var(--route);border-width:3px}.key.degraded{border-color:#d79b3b}.key.failed{border-color:#c65a5a}
.nodegrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:10px}.nodecard{border:1px solid var(--line);background:#fff;border-radius:7px;padding:13px}.nodehead{display:flex;align-items:center;gap:7px;margin-bottom:8px}.nodehead b{font-size:15px}.catalogrow{display:block;padding:13px 11px;border-bottom:1px solid var(--line);border-left:3px solid transparent}.catalogrow:last-child{border-bottom:0}.catalogrow.selected{background:var(--oksoft);border-left-color:var(--ok)}.issue{padding:10px 0;border-bottom:1px solid var(--line)}.issue:last-child{border-bottom:0}.issue.problem{border-left:3px solid var(--bad);padding-left:10px}.tiny{font-size:11px}.small{font-size:12px}.clip{overflow:hidden;text-overflow:ellipsis;max-width:100%}
.notice{border-left:3px solid var(--warn);background:var(--warnsoft)}.notice.badline{border-left-color:var(--bad);background:var(--badsoft)}.empty{padding:20px;text-align:center;color:var(--dim);border:1px dashed var(--line2);border-radius:7px}.callout{padding:12px 14px;border-radius:7px;background:var(--oksoft);border:1px solid #cce7d8}.callout.warnline{background:var(--warnsoft);border-color:#ead7b2}
form{display:inline}.blockform{display:block}.checkline{display:flex;align-items:flex-start;gap:9px}.checkline input{margin-top:3px}button,.button{font:inherit;padding:8px 12px;border:1px solid var(--line2);border-radius:6px;background:#fff;color:var(--fg);cursor:pointer;display:inline-flex;align-items:center;justify-content:center;gap:7px}button:hover,.button:hover{border-color:var(--ok);color:var(--fg)}button.primary,.button.primary{background:var(--fg);border-color:var(--fg);color:#fff}button.green,.button.green{background:var(--ok);border-color:var(--ok);color:#fff}button[disabled]{cursor:not-allowed;color:var(--faint);background:#f1f3f2;border-color:var(--line)}
input,select{font:inherit;padding:9px 10px;border:1px solid var(--line2);border-radius:6px;background:#fff;color:var(--fg)}input:focus,select:focus,textarea:focus{outline:2px solid #cce7d8;outline-offset:1px}.field{display:grid;gap:5px}.field label{font-size:11px;color:var(--dim);text-transform:uppercase}.fields{display:grid;grid-template-columns:repeat(12,minmax(0,1fr));gap:12px}.field.span2{grid-column:span 2}.field.span3{grid-column:span 3}.field.span4{grid-column:span 4}.field.span6{grid-column:span 6}.field.span8{grid-column:span 8}.field.span12{grid-column:1/-1}
pre{background:var(--card2);border:1px solid var(--line);border-radius:7px;padding:12px;overflow-x:auto;white-space:pre-wrap;margin:8px 0}textarea{width:100%;height:58vh;font:13px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;padding:12px;border:1px solid var(--line2);border-radius:7px;background:#fff;color:var(--fg);white-space:pre;overflow-wrap:normal;overflow-x:auto}
textarea.compact{height:118px;white-space:pre-wrap}
.bars{height:112px;display:flex;align-items:end;gap:5px;padding:9px 0 20px;border-bottom:1px solid var(--line);position:relative}.bar{flex:1;min-width:4px;background:#73c39d;border-radius:2px 2px 0 0}.bar.alt{background:#6f96ad}.bar.idle{background:#cbd0cd}.barlabel{display:flex;justify-content:space-between;font-size:10px;color:var(--dim);margin-top:5px}.kv{display:grid;grid-template-columns:minmax(110px,.6fr) minmax(0,1.5fr);gap:8px 15px}.kv dt{color:var(--dim);font-size:11px;text-transform:uppercase}.kv dd{margin:0;min-width:0}.steps{display:flex;border:1px solid var(--line);border-radius:7px;background:#fff}.step{flex:1;padding:14px 17px;border-right:1px solid var(--line)}.step:last-child{border-right:0}.step b{display:block;margin-top:3px}
.counterchart{height:150px;display:flex;align-items:stretch;gap:12px;padding:12px 6px 0;border-bottom:1px solid var(--line);background:linear-gradient(to top,transparent 32%,var(--line) 33%,transparent 34%,transparent 65%,var(--line) 66%,transparent 67%)}.countergroup{flex:1;min-width:58px;display:grid;grid-template-rows:1fr 25px;gap:5px;text-align:center}.counterbars{display:flex;align-items:end;justify-content:center;gap:4px}.counterbars i{display:block;width:min(22px,38%);min-height:2px;border-radius:2px 2px 0 0}.counterrx{background:#73c39d}.countertx{background:#6f96ad}.counterbars i.idle{background:#cbd0cd}.counterkey{display:inline-block;width:10px;height:8px;border-radius:1px;margin-right:5px}.counterkey.rx{background:#73c39d}.counterkey.tx{background:#6f96ad}
.historychart{height:176px;display:flex;align-items:stretch;gap:4px;overflow-x:auto;padding:10px 4px 0;border-bottom:1px solid var(--line);background:linear-gradient(to top,transparent 32%,var(--line) 33%,transparent 34%,transparent 65%,var(--line) 66%,transparent 67%)}.historybucket{flex:1;min-width:12px;display:grid;grid-template-rows:1fr 19px;gap:3px;text-align:center}.historybars{display:flex;align-items:end;justify-content:center;gap:2px;min-height:0}.historybars i{display:block;min-height:1px;border-radius:2px 2px 0 0}.historytotal{width:min(24px,72%);background:#4ba477}.historyrx,.historytx{width:min(13px,42%)}.historyrx{background:#73c39d}.historytx{background:#6f96ad}.historymissing{height:100%!important;width:1px;border-radius:0!important;background:repeating-linear-gradient(to bottom,var(--line2) 0 3px,transparent 3px 7px)}.historyflag{font-size:8px;color:var(--warn);white-space:nowrap}.linkchart{display:grid;gap:0;border-top:1px solid var(--line);margin-top:8px}.linkcharthead,.linkchartrow{display:grid;grid-template-columns:minmax(170px,.8fr) minmax(220px,1.4fr) minmax(190px,.8fr);gap:18px;align-items:center;padding:9px 0;border-bottom:1px solid var(--line)}.linkcharthead{color:var(--dim);font-size:10px;font-weight:650;letter-spacing:.06em;text-transform:uppercase}.linkbartrack{display:block;height:12px;background:var(--card2);border:1px solid var(--line);border-radius:2px;margin-bottom:3px}.linkbarfill{display:block;height:100%;min-width:1px;background:#4ba477;border-radius:1px}
@media(max-width:1180px){.nav a{padding:0 7px}.headmeta .env{display:none}.span3{grid-column:span 6}.split{grid-template-columns:1fr}}
@media(max-width:760px){.header{height:auto;min-height:51px;flex-wrap:wrap;padding:8px 12px;gap:5px 14px}.nav{order:3;width:100%;height:46px}.navgroup{padding-top:12px}.headmeta{margin-left:auto}.main{padding:22px 13px 44px}.top{display:block}.top .sp{margin:12px 0 0}.span3,.span4,.span5,.span6,.span7,.span8,.span9{grid-column:1/-1}.fields{grid-template-columns:1fr}.field.span2,.field.span3,.field.span4,.field.span6,.field.span8,.field.span12{grid-column:auto}.steps{display:grid}.step{border-right:0;border-bottom:1px solid var(--line)}td,th{white-space:normal}.hide-mobile{display:none}.linkcharthead{display:none}.linkchartrow{grid-template-columns:1fr;gap:5px}.historybucket{min-width:10px}}
</style>`

func shell(d Deps, title, body string, isAuthed bool, evidence ...View) string {
	role := "Local node"
	if d.Control != nil {
		role = "Control plane"
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
	active := navActive(title)
	nav := primaryNavigation(d)
	var navHTML strings.Builder
	group := ""
	for _, item := range nav {
		if item.group != group {
			if group != "" {
				navHTML.WriteString(`</span>`)
			}
			group = item.group
			if group != "" {
				fmt.Fprintf(&navHTML, `<span class=navgroup data-label="%s">`, esc(group))
			}
		}
		cls := ""
		if item.key == active {
			cls = ` class=active`
		}
		fmt.Fprintf(&navHTML, `<a%s href="%s">%s</a>`, cls, esc(item.href), esc(item.label))
	}
	if group != "" {
		navHTML.WriteString(`</span>`)
	}
	refresh := ""
	if title == "总览" {
		// 纯 SSR 不靠 JavaScript；只让实时总览定时重取。编辑、登录和结果页
		// 不能自动刷新，否则会丢表单或重复操作。
		refresh = `<meta http-equiv=refresh content=30>`
	}
	eyebrow, heading, subtitle := pageHeading(d, title)
	if len(evidence) > 0 {
		body = evidenceBanner(evidence[0]) + body
	}
	return fmt.Sprintf(`<!doctype html><meta charset=utf-8><title>%s · LOOM</title>
<meta name=viewport content="width=device-width,initial-scale=1">%s%s
<div class=app><header class=header><a class=brand href="/" aria-label="LOOM overview">%s<span>LOOM</span></a>
<nav class=nav aria-label="Primary">%s</nav><div class=headmeta><span class="env dim"><span class=dot></span>Live evidence</span><span>%s</span></div></header>
<main class=main><div class=top><div><div class=eyebrow>%s</div><h1>%s</h1><div class=subtitle>%s</div></div><div class=sp>%s</div></div>%s</main></div>`,
		esc(heading), refresh, style, logoSVG(), navHTML.String(), auth,
		esc(eyebrow), esc(heading), esc(subtitle), esc(d.Node)+` · `+esc(role), body)
}

// evidenceBanner keeps control-plane read failures visible on every page that
// renders a View. Otherwise an SSOT enrichment failure can look like a valid
// empty catalog on Services/Nodes/Topology even though Overview contains the
// warning. The caller passes the View it already rendered, so this does not
// trigger a second collection with a different timestamp.
func evidenceBanner(v View) string {
	seen := map[string]bool{}
	var warnings []string
	for _, warning := range v.Warnings {
		warning = strings.TrimSpace(warning)
		if warning == "" || seen[warning] {
			continue
		}
		seen[warning] = true
		warnings = append(warnings, warning)
	}
	if v.TrafficHistoryStatus == "unavailable" && v.TrafficHistoryError != "" {
		warning := "中控流量历史不可用:" + v.TrafficHistoryError
		if !seen[warning] {
			warnings = append(warnings, warning)
		}
	}
	if len(warnings) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString(`<div class="card notice badline"><b>Evidence is incomplete</b><ul>`)
	for _, warning := range warnings {
		fmt.Fprintf(&b, `<li>%s</li>`, esc(warning))
	}
	b.WriteString(`</ul><span class="small dim">Unavailable evidence stays unavailable; this page does not turn it into an empty or healthy state.</span></div><div class=section></div>`)
	return b.String()
}

type navigationItem struct {
	label, href, key, group string
}

// primaryNavigation follows capabilities, not deployment convention. Every
// node serves the UI, but only a node with ControlDeps owns desired-state,
// enrollment, deployment and event-journal surfaces. A regular node keeps a
// deliberately small diagnostic navigation and links "This node" directly to
// its own detail page instead of presenting the fleet inventory as a local
// management capability.
func primaryNavigation(d Deps) []navigationItem {
	if d.Control == nil {
		return []navigationItem{
			{label: "Local overview", href: "/", key: "overview"},
			{label: "This node", href: "/nodes/" + url.PathEscape(d.Node), key: "nodes"},
			{label: "Topology", href: "/topology", key: "topology"},
			{label: "Live paths", href: "/routing", key: "routing"},
		}
	}
	return []navigationItem{
		{label: "Overview", href: "/", key: "overview"},
		{label: "Nodes", href: "/nodes", key: "nodes", group: "Network"},
		{label: "Topology", href: "/topology", key: "topology", group: "Network"},
		{label: "Services", href: "/services", key: "services", group: "Traffic"},
		{label: "Live paths", href: "/routing", key: "routing", group: "Traffic"},
		{label: "Deployments", href: "/deployments", key: "deployments", group: "Operations"},
		{label: "Events", href: "/events", key: "events", group: "Operations"},
		{label: "SSOT", href: "/settings", key: "settings", group: "Advanced"},
	}
}

func navActive(title string) string {
	t := strings.ToLower(title)
	switch {
	case title == "总览" || strings.Contains(t, "overview"):
		return "overview"
	case strings.Contains(t, "node") || strings.Contains(title, "节点"):
		return "nodes"
	case strings.Contains(t, "topology") || strings.Contains(title, "拓扑"):
		return "topology"
	case strings.Contains(t, "service") || strings.Contains(title, "服务"):
		return "services"
	case strings.Contains(t, "routing") || strings.Contains(t, "live path") || strings.Contains(title, "路由"):
		return "routing"
	case strings.Contains(t, "deployment") || strings.Contains(title, "发布"):
		return "deployments"
	case strings.Contains(t, "event") || strings.Contains(title, "事件"):
		return "events"
	case strings.Contains(t, "setting") || strings.Contains(title, "ssot") || strings.Contains(title, "配置"):
		return "settings"
	default:
		return ""
	}
}

func pageHeading(d Deps, title string) (string, string, string) {
	if d.Control == nil {
		switch title {
		case "总览":
			return "LOCAL NODE / STATUS", "Local overview", d.Node + " · direct local status with newest trusted network observations"
		case "登录":
			return "LOCAL NODE / ACCESS", "Operator sign in", "Local maintenance actions require an authenticated node session"
		case "事件":
			return "LOCAL NODE / UNAVAILABLE", "Events unavailable", "The event journal is retained on the control node"
		case "改 SSOT", "Settings":
			return "LOCAL NODE / READ ONLY", "Settings unavailable", "This node has no desired-state write capability"
		default:
			return strings.ToUpper(strings.ReplaceAll(title, " ", " / ")), title, d.Node + " · local diagnostic view"
		}
	}
	switch title {
	case "总览":
		return "LIVE NETWORK", "Network overview", d.Node + " control plane · newest trusted observations"
	case "事件":
		return "OPERATIONS / EVENTS", "Events", "State transitions recorded by the control plane"
	case "改 SSOT":
		return "ADVANCED / SSOT", "Advanced / SSOT", "Validate and atomically save the declarative source of truth"
	case "登录":
		return "CONTROL / ACCESS", "Operator sign in", "Write operations require a local control-plane session"
	default:
		return strings.ToUpper(strings.ReplaceAll(title, " ", " / ")), title, d.Node + " control plane"
	}
}

// logoSVG embeds the same approved compound geometry used by the SVG prototypes.
// It stays transparent and uses currentColor so the white header always gets a
// visible graphite mark without masks or external assets.
func logoSVG() string {
	return `<svg class=brandmark viewBox="127 112 1000 1000" role=img aria-label="Loom mark"><g transform="translate(0 1254) scale(1 -1)"><path fill=currentColor fill-rule=evenodd clip-rule=evenodd d="` + approvedLogoPath + `"/></g></svg>`
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

func pageSSOT(d Deps, content, revision, findings string, err error, saved bool) string {
	var b strings.Builder

	dist, derr := "", error(nil)
	if d.Control.Distributed == nil {
		derr = fmt.Errorf("distribution status callback is unavailable")
	} else {
		dist, derr = d.Control.Distributed()
	}
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

	fmt.Fprintf(&b, `<div class=section><div class=sectionhead><h2>Source of truth</h2><span class="mono tiny dim">%s</span></div>
<form method=post action=/ssot>
<input type=hidden name=revision value="%s">
<textarea name=content spellcheck=false>%s</textarea><br>
<button name=action value=check>只校验</button>
<button class=green name=action value=save>校验并保存</button>
</form>
<p class=dim>校验不过就不会保存 —— 存一份自相矛盾的 SSOT 进去,发布器会拒绝发布,
而线上停在旧快照。revision 变化也会拒绝旧表单覆盖新内容。</p></div>
<p><a href="/">← 回到总览</a></p>`, esc(d.Control.SSOTPath), esc(revision), esc(content))
	return shell(d, "改 SSOT", b.String(), true)
}

type eventFilter struct {
	Node, Kind, Level, Query string
}

func (f eventFilter) values() string {
	v := url.Values{}
	if f.Node != "" {
		v.Set("node", f.Node)
	}
	if f.Kind != "" {
		v.Set("kind", f.Kind)
	}
	if f.Level != "" {
		v.Set("level", f.Level)
	}
	if f.Query != "" {
		v.Set("q", f.Query)
	}
	return v.Encode()
}

func filterEvents(evs []EventView, f eventFilter) []EventView {
	out := make([]EventView, 0, len(evs))
	needle := strings.ToLower(f.Query)
	for _, e := range evs {
		if f.Node != "" && e.Node != f.Node || f.Kind != "" && e.Kind != f.Kind || f.Level != "" && e.Level != f.Level {
			continue
		}
		if needle != "" && !strings.Contains(strings.ToLower(strings.Join([]string{e.Node, e.Kind, e.Subject, e.From, e.To, e.Detail}, " ")), needle) {
			continue
		}
		out = append(out, e)
	}
	return out
}

func pageEvents(d Deps, filter eventFilter, isAuthed bool) string {
	if d.Events == nil {
		return shell(d, "事件", `<div class=empty>This node does not retain the control-plane event journal. Open Events on the control node.</div>`, isAuthed)
	}
	all := d.Events(200)
	evs := filterEvents(all, filter)
	var b strings.Builder
	var unresolved []UnresolvedView
	if d.Unresolved != nil {
		unresolved = d.Unresolved()
	}
	b.WriteString(`<div class=card><div class=sectionhead><h2>Current unresolved state</h2><span class=dim>Current truth · not reconstructed from transition history</span></div>`)
	if len(unresolved) == 0 {
		b.WriteString(`<div class=callout><b class=ok>No unresolved problems</b><br><span class=small>A quiet history is not used as proof; this comes from the current state tracker.</span></div>`)
	} else {
		b.WriteString(`<table><tr><th>Node<th>Kind / subject<th>State<th>Duration<th>Detail</tr>`)
		for i := range unresolved {
			issue := &unresolved[i]
			cls := "warn"
			if issue.Level == "problem" {
				cls = "bad"
			}
			fmt.Fprintf(&b, `<tr><td class=mono>%s<td class=w>%s · %s<td class=%s>%s<td>%s<td class=w>%s</tr>`, esc(issue.Node), esc(issue.Kind), esc(issue.Subject), cls, esc(issue.State), esc(issue.LastedText()), esc(issue.Detail))
		}
		b.WriteString(`</table>`)
	}
	b.WriteString(`</div><div class=section></div>`)
	export := "/events.csv"
	if values := filter.values(); values != "" {
		export += "?" + values
	}
	fmt.Fprintf(&b, `<div class=card><form method=get action=/events><div class=fields><div class="field span3"><label>Node</label><input name=node value="%s" placeholder="all nodes"></div><div class="field span3"><label>Kind</label><input name=kind value="%s" placeholder="all kinds"></div><div class="field span2"><label>Level</label><select name=level><option value="">All</option>%s</select></div><div class="field span3"><label>Search</label><input name=q value="%s" placeholder="subject or detail"></div><div class="field"><label>&nbsp;</label><button>Filter</button></div></div></form></div>
<div class=sectionhead><span class=dim>Showing %d of the newest %d transitions. Current state remains in Overview and Nodes.</span><span class=sp><a class=button href="%s">Export filtered CSV</a></span></div>`,
		esc(filter.Node), esc(filter.Kind), eventLevelOptions(filter.Level), esc(filter.Query), len(evs), len(all), esc(export))
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

func eventLevelOptions(selected string) string {
	var b strings.Builder
	for _, level := range []string{"problem", "ok", "pending", "info"} {
		attr := ""
		if selected == level {
			attr = " selected"
		}
		fmt.Fprintf(&b, `<option value="%s"%s>%s</option>`, level, attr, level)
	}
	return b.String()
}

// shortTS 去掉日期里没信息量的部分,表格窄一些。
func shortTS(ts string) string {
	if len(ts) >= 19 {
		return ts[5:19]
	}
	return ts
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

func topologySVG(v View, routeOverlay ...RouteView) string {
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
	for _, r := range routeOverlay {
		if r.Stale {
			continue
		}
		for _, id := range r.Chain {
			selected[id] = true
		}
	}
	var b strings.Builder
	b.WriteString(`<svg class=topology viewBox="0 0 760 380" role=img aria-label="近实时网络拓扑"><defs><marker id=arrow viewBox="0 0 10 10" refX=8 refY=5 markerWidth=5 markerHeight=5 orient=auto-start-reverse><path d="M 0 0 L 10 5 L 0 10 z" fill="#239b68"/></marker></defs>`)
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
	for _, r := range routeOverlay {
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
	declared := map[string]bool{}
	for _, n := range v.Nodes {
		health[n.ID] = n.Health
		declared[n.ID] = n.Declared
	}
	for _, id := range ids {
		p := pos[id]
		cls := "node"
		if health[id] == "problem" {
			cls += " problem"
		} else if health[id] != "healthy" {
			cls += " unknown"
		}
		if !declared[id] {
			cls += " undeclared"
		}
		if selected[id] {
			cls += " selected"
		}
		fmt.Fprintf(&b, `<circle class="%s" cx="%.1f" cy="%.1f" r="31"/><text text-anchor=middle x="%.1f" y="%.1f">%s</text>`, cls, p.x, p.y, p.x, p.y+5, esc(id))
		if !declared[id] {
			fmt.Fprintf(&b, `<text class=sub text-anchor=middle x="%.1f" y="%.1f">undeclared observed</text>`, p.x, p.y+47)
		}
	}
	if len(ids) == 0 {
		b.WriteString(`<text class=sub text-anchor=middle x=380 y=190>暂无拓扑观测</text>`)
	}
	b.WriteString(`</svg>`)
	return b.String()
}

// intentSourceLabel prevents a regular node from presenting its last-applied
// report inventory as the control node's current SSOT. The source is attached
// by the report adapter and deliberately remains visible in operator copy.
func intentSourceLabel(v View) string {
	switch strings.TrimSpace(v.IntentSource) {
	case "current SSOT":
		return "current SSOT"
	case "serving node applied inventory":
		return "serving node applied inventory"
	case "":
		return "attached inventory"
	default:
		return strings.TrimSpace(v.IntentSource)
	}
}

func carrierTunnelCount(tunnels []TunnelView) (total, active int) {
	for _, tunnel := range tunnels {
		if !tunnel.CarrierPresent {
			continue
		}
		total++
		if tunnel.OK {
			active++
		}
	}
	return total, active
}

func hasCarrierTunnel(tunnels []TunnelView) bool {
	for _, tunnel := range tunnels {
		if tunnel.CarrierPresent {
			return true
		}
	}
	return false
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
