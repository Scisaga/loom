package webui

import (
	"fmt"
	"html"
	"net/url"
	"sort"
	"strings"
	"time"
)

// 页面是服务端渲染的纯 HTML,不依赖任何外部资源。节点接入页只有一段
// CSP hash 锁定的本地脚本，用来在同步 SSH 提交期间禁止重复操作并反馈进度。
//
// 不是极简主义:这些机器不一定能出网,而通过 ssh 端口转发进来时更不能。
// 一个依赖 CDN 的界面在最需要它的时候(隧道断了、机器出问题了)恰好打不开。

const progressSubmitScript = `document.querySelectorAll("form[data-submit-progress]").forEach(function(form){form.addEventListener("submit",function(event){if(!form.checkValidity())return;if(form.dataset.submitting==="true"){event.preventDefault();return}form.dataset.submitting="true";form.setAttribute("aria-busy","true");var submitter=event.submitter;if(submitter&&submitter.name){var preserved=document.createElement("input");preserved.type="hidden";preserved.name=submitter.name;preserved.value=submitter.value;form.appendChild(preserved)}form.classList.add("is-submitting");form.querySelectorAll("button").forEach(function(button){button.disabled=true})})});`

const style = `<style>
:root{--fg:#181b1a;--dim:#717674;--faint:#9ba09e;--line:#e2e6e3;--line2:#ccd2ce;--ok:#239b68;--oksoft:#eef8f3;--bad:#b84c4c;--badsoft:#fff3f2;--warn:#a66a14;--warnsoft:#fff8eb;--info:#477d9c;--route:#239b68;--bg:#fcfcfb;--card:#fff;--card2:#f7f8f7;--ink:#181b1a;--font-mono:"SFMono-Regular","Roboto Mono","IBM Plex Mono",Consolas,"Liberation Mono",ui-monospace,monospace}
*{box-sizing:border-box}
html{background:var(--bg)}body{margin:0;font:14px/1.55 Inter,"Atkinson Hyperlegible Next",ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:var(--fg);background:var(--bg)}
a{color:inherit;text-decoration:none;transition:color .14s ease}a:hover{color:var(--ok)}code,.mono{font-family:var(--font-mono);font-weight:400;font-synthesis:none;font-variant-ligatures:none;font-variant-numeric:tabular-nums;font-feature-settings:"zero" 1}
.app{min-height:100vh}.header{height:50px;background:#fff;border-bottom:1px solid var(--line);display:flex;align-items:stretch;padding:0 20px;gap:20px;position:sticky;top:0;z-index:4}
.brand{display:flex;align-items:center;gap:9px;flex:0 0 253px;font-size:17px;font-weight:760;letter-spacing:.09em;white-space:nowrap}.brandmark{width:34px;height:34px;color:#252927}.brandmark path{fill:currentColor}
.role{font-size:10px;color:var(--dim);font-weight:550;letter-spacing:.08em;text-transform:uppercase}.nav{display:flex;align-items:stretch;gap:0;min-width:0;overflow-x:auto;scrollbar-width:none}.nav::-webkit-scrollbar{display:none}.nav a{position:relative;display:flex;align-items:center;gap:7px;padding:0 10px;color:var(--dim);white-space:nowrap;font-size:13px;transition:color .14s ease,background-color .14s ease}.nav a:after{content:"";position:absolute;right:8px;bottom:0;left:8px;height:2px;background:var(--ok);transform:scaleX(0);transform-origin:center;transition:transform .18s ease}.nav a:before{content:"";width:14px;height:14px;flex:0 0 auto;background:50%/14px 14px no-repeat;transition:filter .14s ease}.nav a[data-key=overview]:before{background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16' fill='none' stroke='%237d8280' stroke-width='1.35'%3E%3Crect x='1.5' y='1.5' width='5' height='5' rx='1'/%3E%3Crect x='9.5' y='1.5' width='5' height='5' rx='1'/%3E%3Crect x='1.5' y='9.5' width='5' height='5' rx='1'/%3E%3Crect x='9.5' y='9.5' width='5' height='5' rx='1'/%3E%3C/svg%3E")}.nav a[data-key=nodes]:before{background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16' fill='none' stroke='%237d8280' stroke-width='1.35'%3E%3Crect x='2' y='2' width='12' height='5' rx='1.4'/%3E%3Crect x='2' y='9' width='12' height='5' rx='1.4'/%3E%3C/svg%3E")}.nav a[data-key=topology]:before{background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16' fill='none' stroke='%237d8280' stroke-width='1.35'%3E%3Cpath d='M4.2 4.2L8 8m3.8-3.8L8 8m0 0v4.4'/%3E%3Ccircle cx='3' cy='3' r='1.8'/%3E%3Ccircle cx='13' cy='3' r='1.8'/%3E%3Ccircle cx='8' cy='13.5' r='1.8'/%3E%3C/svg%3E")}.nav a[data-key=services]:before{background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16' fill='none' stroke='%237d8280' stroke-width='1.35'%3E%3Crect x='2' y='2' width='12' height='12' rx='2'/%3E%3Cpath d='M5 5h6M5 8h6M5 11h4'/%3E%3C/svg%3E")}.nav a[data-key=routing]:before{background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16' fill='none' stroke='%237d8280' stroke-width='1.35'%3E%3Cpath d='M2 4h4.2C9 4 8.2 12 11 12h2.5M2 12h3.5C8.4 12 7.7 4 10.7 4h2.8'/%3E%3C/svg%3E")}.nav a[data-key=deployments]:before{background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16' fill='none' stroke='%237d8280' stroke-width='1.35'%3E%3Crect x='2' y='3' width='12' height='10.5' rx='2'/%3E%3Cpath d='M8 6v4m-2-2 2 2 2-2'/%3E%3C/svg%3E")}.nav a[data-key=events]:before{background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16' fill='none' stroke='%237d8280' stroke-width='1.35'%3E%3Ccircle cx='8' cy='8' r='6.2'/%3E%3Cpath d='M8 4.5V8l2.5 1.5'/%3E%3C/svg%3E")}.nav a[data-key=settings]:before{background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16' fill='none' stroke='%237d8280' stroke-width='1.35'%3E%3Cpath d='M2 4h5m3 0h4M2 8h2m3 0h7M2 12h7m3 0h2'/%3E%3C/svg%3E")}.nav a:hover{color:var(--fg);background:#f7f9f8}.nav a:hover:before,.nav a.active:before{filter:brightness(.3)}.nav a.active{color:var(--fg);font-weight:600}.nav a.active:after{transform:scaleX(1)}.nav a:focus-visible{outline:2px solid #b9dfcd;outline-offset:-4px}.navgroup{display:contents}.navgroup:before{display:none}
.headmeta{margin-left:auto;display:flex;align-items:center;gap:18px;white-space:nowrap;font-size:12px}.headmeta .env{display:flex;align-items:center;gap:7px}.headmeta .dot{width:7px;height:7px}.main{min-width:0;max-width:1586px;margin:0 auto;padding:28px 20px 56px;animation:loom-page-in .16s cubic-bezier(.2,.7,.3,1) both}
@keyframes loom-page-in{from{opacity:.82}to{opacity:1}}@keyframes loom-spin{to{transform:rotate(360deg)}}
.top{display:flex;align-items:flex-start;gap:18px;margin-bottom:22px}.eyebrow{font-size:11px;letter-spacing:.13em;font-weight:700;text-transform:uppercase;margin-bottom:3px}.top h1{font-size:28px;letter-spacing:-.025em;line-height:1.2;margin:0 0 5px}.subtitle{color:var(--dim);font-size:13px}.sp{margin-left:auto}
h2{font-size:13px;margin:0 0 12px;color:var(--dim);font-weight:700;letter-spacing:.08em;text-transform:uppercase}h3{font-size:15px;margin:0 0 5px}
.dim{color:var(--dim)}.faint{color:var(--faint)}.ok{color:var(--ok)}.bad{color:var(--bad)}.warn{color:var(--warn)}.info{color:var(--info)}
.sr-only{position:absolute!important;width:1px!important;height:1px!important;padding:0!important;margin:-1px!important;overflow:hidden!important;clip:rect(0,0,0,0)!important;white-space:nowrap!important;border:0!important}
.badge{display:inline-flex;align-items:center;gap:7px;border:1px solid var(--line);border-radius:999px;padding:4px 9px;font-size:12px}.dot{display:inline-block;width:7px;height:7px;border-radius:50%;background:currentColor;flex:0 0 auto}
.grid{display:grid;grid-template-columns:repeat(12,minmax(0,1fr));gap:14px;margin-bottom:14px}.span3{grid-column:span 3}.span4{grid-column:span 4}.span5{grid-column:span 5}.span6{grid-column:span 6}.span7{grid-column:span 7}.span8{grid-column:span 8}.span9{grid-column:span 9}.span12{grid-column:1/-1}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:16px;min-width:0}.card.soft{background:var(--card2)}.metric{font-size:24px;font-weight:720;line-height:1.15;margin:5px 0}.metric small{font-size:13px;color:var(--dim);font-weight:500}.label{font-size:11px;color:var(--dim);letter-spacing:.04em;text-transform:uppercase}
.section{margin-top:22px}.sectionhead{display:flex;align-items:center;gap:12px;margin:0 0 10px}.sectionhead h2{margin:0}.toolbar{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.split{display:grid;grid-template-columns:minmax(280px,1fr) minmax(0,2fr);gap:14px}.stack{display:grid;gap:14px}
table{border-collapse:collapse;width:100%;margin:0}td,th{text-align:left;padding:10px 10px 10px 0;border-bottom:1px solid var(--line);vertical-align:top;white-space:nowrap}tr:last-child td{border-bottom:0}th{color:var(--dim);font-weight:650;font-size:10px;letter-spacing:.06em;text-transform:uppercase}td.w{white-space:normal}.rowlink:hover{background:#fafcfb}
.topology{width:100%;min-height:330px;display:block;background:transparent}.topology .tunnel{stroke:#a5aaa8;stroke-width:1.25;opacity:.95}.topology .candidate{stroke:#b9bebc;stroke-width:1.35;stroke-dasharray:5 6;opacity:.9}.topology .degraded{stroke:#d79b3b}.topology .failed{stroke:#c65a5a}.topology .unknown{stroke:#a5aaa8;stroke-dasharray:3 7;opacity:.7}.topology .route{stroke:var(--route);stroke-width:2;opacity:.95}.topology .route-ring{fill:none;stroke:var(--route);stroke-width:2;opacity:.3}.topology .node{fill:var(--ok);stroke:#fff;stroke-width:3}.topology .node.problem{fill:var(--bad)}.topology .node.unknown{fill:#a5aaa8;stroke:#fff;stroke-dasharray:none}.topology .node.undeclared{fill:var(--warn);stroke:#fff}.topology .node.selected{fill:var(--ok);stroke:#fff;stroke-width:3}.topology text{fill:var(--fg);font:500 13px var(--font-mono)}.topology .sub{fill:var(--dim);font:400 11px/1.4 Inter,ui-sans-serif,system-ui}
.legend{display:flex;gap:16px;flex-wrap:wrap;margin-top:10px;color:var(--dim);font-size:11px}.key{display:inline-block;width:26px;border-top:2px solid #a5aaa8;vertical-align:middle;margin-right:6px}.key.candidate{border-color:#b9bebc;border-top-style:dashed}.key.route{border-color:var(--route);border-width:3px}.key.degraded{border-color:#d79b3b}.key.failed{border-color:#c65a5a}
.topology-layer-note{display:flex;align-items:flex-start;gap:8px;margin:11px 0 0;padding:9px 11px;border:1px solid var(--line);border-radius:6px;background:var(--card2);color:var(--dim);font-size:11px}.topology-layer-note:before{content:"i";display:inline-flex;align-items:center;justify-content:center;flex:0 0 auto;width:16px;height:16px;border:1px solid var(--line2);border-radius:50%;color:var(--fg);font-size:10px;font-weight:700}.topology-edge-grid{display:grid;grid-template-columns:minmax(0,1.65fr) minmax(340px,.85fr);gap:14px}.topology-edge-card{padding:0;overflow:hidden}.edge-panel-head{display:flex;align-items:flex-start;gap:14px;min-height:72px;padding:14px 16px 12px}.edge-panel-head h3{margin:0;font-size:15px}.edge-panel-head p{margin:2px 0 0;color:var(--dim);font-size:11px}.edge-panel-head .badge{margin-left:auto;white-space:nowrap}.badge.intent{border-color:#d6e1e7;background:#f5f9fb;color:var(--info)}.topology-edge-card table{border-top:1px solid var(--line)}.topology-edge-card th:first-child,.topology-edge-card td:first-child{padding-left:16px}.topology-edge-card th:last-child,.topology-edge-card td:last-child{padding-right:16px}.edge-status{display:inline-flex;align-items:center;gap:7px;white-space:nowrap}.edge-status .dot{width:6px;height:6px}.edge-source{max-width:380px;white-space:normal;color:var(--dim);font-size:11px;line-height:1.45}.route-hop-list{border-top:1px solid var(--line)}.route-hop{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:4px 12px;padding:12px 16px;border-bottom:1px solid var(--line)}.route-hop:last-child{border-bottom:0}.route-hop-pair{font-size:13px}.route-hop-state{display:inline-flex;align-items:center;gap:6px;color:var(--info);font-size:11px;white-space:nowrap}.route-hop-state .dot{width:6px;height:6px}.route-hop-meta{grid-column:1/-1;color:var(--dim);font-size:11px;line-height:1.45}.route-hop-note{margin:0 16px 14px;padding:9px 10px;border-radius:6px;background:var(--card2);color:var(--dim);font-size:11px;line-height:1.45}
.enrollment-access{padding:0;overflow:hidden}.enrollment-summary{display:flex;align-items:center;gap:12px;min-height:54px;padding:13px 17px;cursor:pointer;list-style:none}.enrollment-summary::-webkit-details-marker{display:none}.enrollment-summary:before{content:"›";display:inline-flex;align-items:center;justify-content:center;width:18px;height:18px;border-radius:5px;background:var(--card2);color:var(--dim);font-size:18px;line-height:1;transition:transform .16s ease}.enrollment-access[open]>.enrollment-summary:before{transform:rotate(90deg)}.enrollment-summary-copy{display:flex;align-items:baseline;gap:9px;min-width:0}.enrollment-summary-copy b{font-size:14px}.enrollment-summary-copy span{overflow:hidden;color:var(--dim);font-size:12px;text-overflow:ellipsis;white-space:nowrap}.enrollment-summary-hint{margin-left:auto;color:var(--dim);font-size:11px}.enrollment-access[open]>.enrollment-summary{border-bottom:1px solid var(--line)}.enrollment-access-body{padding:17px}.enrollment-access-grid{display:grid;grid-template-columns:minmax(0,1.72fr) minmax(320px,.78fr);gap:18px}.enrollment-identity-panel{min-width:0}.enrollment-panel-head{display:flex;align-items:flex-start;justify-content:space-between;gap:14px}.enrollment-panel-head h3,.enrollment-boundary-panel h3{margin:3px 0 0;font-size:16px}.enrollment-intro{max-width:850px;margin:9px 0 15px;color:var(--dim);font-size:12px}.enrollment-identity-meta{display:grid;grid-template-columns:minmax(190px,.8fr) minmax(260px,1.25fr) minmax(220px,1fr);gap:10px;margin-bottom:12px}.enrollment-identity-meta>div{display:grid;align-content:start;gap:5px;min-width:0;padding:10px 12px;border:1px solid var(--line);border-radius:7px;background:var(--card2)}.enrollment-identity-meta .mono{overflow:hidden;font-size:11px;text-overflow:ellipsis;white-space:nowrap}.enrollment-public-key{overflow:hidden;border:1px solid var(--line);border-radius:7px;background:#fff}.enrollment-public-key-head{display:flex;align-items:center;gap:12px;min-height:46px;padding:8px 10px 8px 12px;border-bottom:1px solid var(--line);background:var(--card2)}.enrollment-public-key-head>div{display:flex;align-items:baseline;gap:9px}.enrollment-public-key-head .button{margin-left:auto;padding:6px 10px;background:#fff;font-size:11px}.enrollment-public-key code{display:block;overflow-x:auto;padding:12px;font-size:11px;line-height:1.5;white-space:nowrap}.enrollment-state{margin:12px 0 0;padding:12px 14px}.enrollment-state-action{margin-top:10px}.enrollment-boundary-panel{padding-left:18px;border-left:1px solid var(--line)}.enrollment-boundary-list{display:grid;gap:0;margin:12px 0 15px}.enrollment-boundary-list>div{display:grid;grid-template-columns:105px minmax(0,1fr);gap:12px;padding:8px 0;border-bottom:1px solid var(--line)}.enrollment-boundary-list>div:last-child{border-bottom:0}.enrollment-boundary-list span{color:var(--dim);font-size:10px;letter-spacing:.04em;text-transform:uppercase}.enrollment-boundary-list b{font-size:12px;font-weight:500}.enrollment-workflow{width:100%;justify-content:space-between}.enrollment-key-note{display:flex;align-items:flex-start;gap:10px;margin-top:16px;padding:10px 12px;border:1px solid #cce7d8;border-radius:7px;background:var(--oksoft)}.enrollment-key-note-icon{display:inline-flex;align-items:center;justify-content:center;flex:0 0 auto;width:22px;height:22px;border-radius:50%;background:#dcefe5;color:var(--ok);font-size:9px}.enrollment-key-note div{display:grid;gap:1px}.enrollment-key-note b{font-size:12px}.enrollment-key-note span:last-child{color:var(--dim);font-size:11px}
.nodegrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:10px}.nodecard{border:1px solid var(--line);background:#fff;border-radius:7px;padding:13px}.nodehead{display:flex;align-items:center;gap:7px;margin-bottom:8px}.nodehead b{font-size:15px}.catalogrow{display:block;padding:13px 11px;border-bottom:1px solid var(--line);border-left:3px solid transparent}.catalogrow:last-child{border-bottom:0}.catalogrow.selected{background:var(--oksoft);border-left-color:var(--ok)}.issue{padding:10px 0;border-bottom:1px solid var(--line)}.issue:last-child{border-bottom:0}.issue.problem{border-left:3px solid var(--bad);padding-left:10px}.tiny{font-size:11px}.small{font-size:12px}.clip{overflow:hidden;text-overflow:ellipsis;max-width:100%}
.node-inventory-help{display:flex;flex-wrap:wrap;gap:5px 20px;margin:-5px 0 10px;padding:9px 12px;border:1px solid var(--line);border-radius:7px;background:var(--card2);color:var(--dim);font-size:11px}.node-inventory-help span{white-space:nowrap}.node-inventory-help b{color:var(--fg);font-weight:650}.attention-summary{margin-bottom:6px}
.notice{border-left:3px solid var(--warn);background:var(--warnsoft)}.notice.badline{border-left-color:var(--bad);background:var(--badsoft)}.empty{padding:20px;text-align:center;color:var(--dim);border:1px dashed var(--line2);border-radius:7px}.callout{padding:12px 14px;border-radius:7px;background:var(--oksoft);border:1px solid #cce7d8}.callout.warnline{background:var(--warnsoft);border-color:#ead7b2}
.status-alert{display:grid;grid-template-columns:26px minmax(0,1fr) auto;gap:11px;align-items:center;min-height:58px;padding:9px 13px;border:1px solid var(--line);border-radius:8px;background:#fff}.status-alert.problem{border-color:#efd9d7;background:#fff9f8}.status-alert.warning{border-color:#eadfc9;background:#fffbf4}.status-alert-icon{display:inline-flex;align-items:center;justify-content:center;width:24px;height:24px;border-radius:50%;font-size:13px;font-weight:750}.status-alert.problem .status-alert-icon{color:var(--bad);background:#f8e7e5}.status-alert.warning .status-alert-icon{color:var(--warn);background:#f7ead3}.status-alert-body{min-width:0}.status-alert-title{display:flex;align-items:baseline;gap:9px;line-height:1.3}.status-alert-title strong{font-size:13px}.status-alert-title span{color:var(--dim);font-size:11px}.status-alert-items{display:flex;flex-wrap:wrap;gap:2px 15px;margin-top:2px;color:var(--fg);font-size:12px}.status-alert-items>span{min-width:0}.status-alert-items>span:before{content:"";display:inline-block;width:4px;height:4px;margin:0 7px 2px 0;border-radius:50%;background:currentColor;opacity:.45}.status-alert-note{max-width:330px;color:var(--dim);font-size:11px;line-height:1.4;text-align:right}.evidence-alert{margin-bottom:18px}.snapshot-alert{margin-top:10px}.snapshot-groups{display:flex;flex-wrap:wrap;gap:5px 8px;margin-top:4px}.snapshot-group{display:inline-flex;align-items:center;gap:8px;min-width:0;padding:3px 8px;border:1px solid #e5dccb;border-radius:5px;background:rgba(255,255,255,.68);font-size:11px}.snapshot-group.current{border-color:#cce3d7;background:#f6fbf8}.snapshot-group .mono{color:var(--fg)}.snapshot-group-nodes{color:var(--dim)}
form{display:inline}.blockform{display:block}.checkline{display:flex;align-items:flex-start;gap:9px}.checkline input{margin-top:3px}button,.button{font:inherit;padding:8px 12px;border:1px solid var(--line2);border-radius:6px;background:#fff;color:var(--fg);cursor:pointer;display:inline-flex;align-items:center;justify-content:center;gap:7px}button:hover,.button:hover{border-color:var(--ok);color:var(--fg)}button.primary,.button.primary{background:var(--fg);border-color:var(--fg);color:#fff}button.green,.button.green{background:var(--ok);border-color:var(--ok);color:#fff}button[disabled]{cursor:not-allowed;color:var(--faint);background:#f1f3f2;border-color:var(--line)}
.progress-submit{min-width:188px}.button-busy{display:none;align-items:center;gap:8px}.button-spinner{width:13px;height:13px;border:2px solid currentColor;border-right-color:transparent;border-radius:50%;animation:loom-spin .7s linear infinite}.blockform:valid .progress-submit:focus{cursor:wait}.blockform:valid .progress-submit:focus .button-idle,.blockform.is-submitting .progress-submit .button-idle{display:none}.blockform:valid .progress-submit:focus .button-busy,.blockform.is-submitting .progress-submit .button-busy{display:inline-flex}.blockform.is-submitting .progress-submit,.blockform.is-submitting .progress-submit[disabled]{cursor:wait;background:#8a918d;border-color:#8a918d;color:#fff;opacity:.82}.blockform.is-submitting a.button{pointer-events:none;opacity:.45}
input,select{font:inherit;padding:9px 10px;border:1px solid var(--line2);border-radius:6px;background:#fff;color:var(--fg)}input:focus,select:focus,textarea:focus{outline:2px solid #cce7d8;outline-offset:1px}.field{display:grid;gap:5px}.field label{font-size:11px;color:var(--dim);text-transform:uppercase}.fields{display:grid;grid-template-columns:repeat(12,minmax(0,1fr));gap:12px}.field.span2{grid-column:span 2}.field.span3{grid-column:span 3}.field.span4{grid-column:span 4}.field.span6{grid-column:span 6}.field.span8{grid-column:span 8}.field.span12{grid-column:1/-1}
pre{background:var(--card2);border:1px solid var(--line);border-radius:7px;padding:12px;overflow-x:auto;white-space:pre-wrap;margin:8px 0}textarea{width:100%;height:58vh;font:13px/1.5 var(--font-mono);padding:12px;border:1px solid var(--line2);border-radius:7px;background:#fff;color:var(--fg);white-space:pre;overflow-wrap:normal;overflow-x:auto}
textarea.compact{height:118px;white-space:pre-wrap}
.barlabel{display:flex;justify-content:space-between;font-size:10px;color:var(--dim);margin-top:5px}.kv{display:grid;grid-template-columns:minmax(110px,.6fr) minmax(0,1.5fr);gap:8px 15px}.kv dt{color:var(--dim);font-size:11px;text-transform:uppercase}.kv dd{margin:0;min-width:0}.steps{display:flex;border:1px solid var(--line);border-radius:7px;background:#fff}.step{flex:1;padding:14px 17px;border-right:1px solid var(--line)}.step:last-child{border-right:0}.step b{display:block;margin-top:3px}
.current-counters{border-top:1px solid var(--line)}.current-counter-head,.current-counter-row{display:grid;grid-template-columns:minmax(190px,1.45fr) repeat(3,minmax(110px,.65fr));column-gap:28px;align-items:center}.current-counter-head{padding:7px 0 5px;color:var(--dim);font-size:10px;font-weight:650;letter-spacing:.06em;text-transform:uppercase}.current-counter-row{position:relative;padding:9px 0 13px;border-top:1px solid var(--line)}.current-counter-head+.current-counter-row{border-top:0}.current-counter-interface{display:flex;align-items:baseline;gap:10px;min-width:0}.current-counter-interface .mono{overflow:hidden;text-overflow:ellipsis}.current-counter-value{display:flex;align-items:baseline;justify-content:space-between;gap:8px;min-width:0}.current-counter-value small{display:none;color:var(--dim);font-size:9px;text-transform:uppercase}.current-counter-value b{font-size:12px;font-weight:400}.current-counter-value.total b{color:var(--fg)}.current-counter-track{grid-column:2/-1;height:3px;margin-top:6px;overflow:hidden;border-radius:2px;background:var(--card2)}.current-counter-track i{display:block;height:100%;border-radius:2px;background:#73c39d}.current-counter-row.idle .current-counter-track i{width:3px!important;background:var(--line2)}.current-counter-summary{display:flex;justify-content:space-between;gap:18px;padding-top:6px;color:var(--dim);font-size:10px}.current-counter-summary strong{color:var(--fg);font-weight:400}.current-counter-summary+p{margin:10px 0 0}
.counterchart{height:150px;display:flex;align-items:stretch;gap:12px;padding:12px 6px 0;border-bottom:1px solid var(--line);background:linear-gradient(to top,transparent 32%,var(--line) 33%,transparent 34%,transparent 65%,var(--line) 66%,transparent 67%)}.countergroup{flex:1;min-width:58px;display:grid;grid-template-rows:1fr 25px;gap:5px;text-align:center}.counterbars{display:flex;align-items:end;justify-content:center;gap:4px}.counterbars i{display:block;width:min(22px,38%);min-height:2px;border-radius:2px 2px 0 0}.counterrx{background:#73c39d}.countertx{background:#6f96ad}.counterbars i.idle{background:#cbd0cd}.counterkey{display:inline-block;width:10px;height:8px;border-radius:1px;margin-right:5px}.counterkey.rx{background:#73c39d}.counterkey.tx{background:#6f96ad}
.historychart{height:176px;display:flex;align-items:stretch;gap:4px;overflow-x:auto;padding:10px 4px 0;border-bottom:1px solid var(--line);background:linear-gradient(to top,transparent 32%,var(--line) 33%,transparent 34%,transparent 65%,var(--line) 66%,transparent 67%)}.historybucket{flex:1;min-width:12px;display:grid;grid-template-rows:1fr 19px;gap:3px;text-align:center}.historybars{display:flex;align-items:end;justify-content:center;gap:2px;min-height:0}.historybars i{display:block;min-height:1px;border-radius:2px 2px 0 0}.historytotal{width:min(24px,72%);background:#4ba477}.historyrx,.historytx{width:min(13px,42%)}.historyrx{background:#73c39d}.historytx{background:#6f96ad}.historymissing{height:100%!important;width:1px;border-radius:0!important;background:repeating-linear-gradient(to bottom,var(--line2) 0 3px,transparent 3px 7px)}.historyflag{font-size:8px;color:var(--warn);white-space:nowrap}.linkchart{display:grid;gap:0;border-top:1px solid var(--line);margin-top:8px}.linkcharthead,.linkchartrow{display:grid;grid-template-columns:minmax(170px,.8fr) minmax(220px,1.4fr) minmax(190px,.8fr);gap:18px;align-items:center;padding:9px 0;border-bottom:1px solid var(--line)}.linkcharthead{color:var(--dim);font-size:10px;font-weight:650;letter-spacing:.06em;text-transform:uppercase}.linkbartrack{display:block;height:12px;background:var(--card2);border:1px solid var(--line);border-radius:2px;margin-bottom:3px}.linkbarfill{display:block;height:100%;min-width:1px;background:#4ba477;border-radius:1px}
/* Overview follows the approved 1586 x 992 control-center composition. */
.page-overview .top{margin-bottom:0}.page-overview .top>.sp{display:none}.overview-health{display:flex;align-items:center;gap:8px;height:22px;margin:7px 0 19px;font-size:13px}.status-check{display:inline-flex;align-items:center;justify-content:center;width:14px;height:14px;border:1.5px solid currentColor;border-radius:50%;color:var(--ok);font-size:10px;font-weight:800;line-height:1}.status-check.warn{color:var(--warn)}.status-check.bad{color:var(--bad)}.page-overview .steps{height:82px}.page-overview .step{padding:15px 32px}.page-overview .step .label{color:var(--fg);font-size:13px;letter-spacing:0;text-transform:none}.page-overview .step b{font-size:17px;line-height:1.25;margin-top:2px}.page-overview .step b small{font-size:13px;font-weight:400}.page-overview .step .tiny{display:block;margin-top:1px}.page-overview .snapshot-verdict.converged{display:none}.overview-primary{display:grid;grid-template-columns:minmax(0,1.868fr) minmax(340px,1fr);gap:16px;height:330px;margin-top:18px}.overview-topology-card{height:330px;padding:12px 15px}.overview-card-head{display:flex;align-items:center;gap:18px;height:25px}.overview-card-head h2,.overview-compact-card h2,.overview-list-card h2,.overview-events h2{margin:0;color:var(--fg);font-size:16px;font-weight:700;letter-spacing:-.01em;text-transform:none}.overview-card-head .legend{margin:0 0 0 auto;gap:14px}.overview-topology-card .topology{height:275px;min-height:0}.overview-side{display:grid;grid-template-rows:143px 1fr;gap:14px}.overview-compact-card{padding:11px 17px;overflow:hidden}.overview-compact-card .sectionhead{height:23px;margin:0 0 6px}.traffic-compact-body{display:grid;grid-template-columns:165px minmax(0,1fr);gap:18px;align-items:end}.traffic-compact-body .metric{font-size:18px;margin:1px 0}.traffic-spark{height:59px;display:flex;align-items:end;gap:5px;padding:3px 3px 12px;border-top:1px solid var(--line);border-bottom:1px solid var(--line);background:linear-gradient(to top,transparent 48%,var(--line) 49%,transparent 50%)}.traffic-spark span{position:relative;flex:1;min-width:3px;max-width:18px;height:var(--height);min-height:2px;background:#73c39d;border-radius:2px 2px 0 0}.traffic-spark span:last-child{background:var(--ok)}.traffic-spark span.missing{height:100%;min-height:0;width:1px;flex:0 0 1px;border-radius:0;background:repeating-linear-gradient(to bottom,var(--line2) 0 3px,transparent 3px 7px)}.traffic-spark span.flagged{outline:1px dashed #d79b3b;outline-offset:2px}.traffic-spark span.flagged:after{content:attr(data-flag);position:absolute;top:-13px;left:50%;transform:translateX(-50%);font-size:8px;color:var(--warn)}.traffic-compact-scale{display:flex;justify-content:space-between;margin-top:2px;color:var(--dim);font-size:9px}.rollout-summary{font-size:13px}.rollout-summary b{font-size:14px}.rollout-stages{display:grid;grid-template-columns:repeat(4,1fr);margin-top:13px;position:relative}.rollout-stages:before{content:"";position:absolute;top:4px;left:7%;right:7%;height:1.5px;background:var(--ok)}.rollout-stage{position:relative;padding-top:15px;text-align:center;color:var(--dim);font-size:11px}.rollout-stage:before{content:"";position:absolute;top:0;left:calc(50% - 4px);width:8px;height:8px;border-radius:50%;background:var(--ok)}.overview-secondary{display:grid;grid-template-columns:minmax(0,1.185fr) minmax(0,1fr);gap:16px;height:203px;margin-top:12px}.overview-list-card{height:203px;padding:11px 18px;overflow:hidden}.overview-list-card .sectionhead{height:24px;margin:0}.overview-list-card table{font-size:12px}.overview-list-card th{padding:3px 7px 4px 0;font-size:10px;text-transform:none;letter-spacing:0}.overview-list-card td{height:27px;padding:3px 7px 3px 0}.overview-list-card .dot{width:7px;height:7px;margin-right:10px;color:#72c69f}.overview-events{height:111px;margin-top:12px;padding:11px 18px}.overview-events .sectionhead{height:22px;margin:0 0 3px}.overview-event-row{display:grid;grid-template-columns:46px 9px minmax(0,1fr);gap:7px;align-items:center;height:23px;font-size:12px}.overview-event-row .dot{width:7px;height:7px;color:#72c69f}.overview-event-row time{color:var(--dim);font-family:var(--font-mono)}.overview-attention{margin-top:12px}.overview-attention .issue{padding:8px 10px}.page-overview>.section{margin-top:22px}
@media(max-width:1180px){.brand{flex-basis:auto}.nav a{padding:0 7px}.headmeta .env{display:none}.span3{grid-column:span 6}.split{grid-template-columns:1fr}}
@media(max-width:1180px){.overview-primary{grid-template-columns:minmax(0,1.5fr) minmax(320px,1fr)}.overview-card-head .legend{display:none}.overview-secondary{grid-template-columns:1fr 1fr}}
@media(max-width:960px){.topology-edge-grid,.enrollment-access-grid{grid-template-columns:1fr}.enrollment-boundary-panel{padding:17px 0 0;border-top:1px solid var(--line);border-left:0}.enrollment-identity-meta{grid-template-columns:1fr 1fr}.enrollment-identity-meta>div:first-child{grid-column:1/-1}}
@media(max-width:760px){.header{height:auto;min-height:51px;flex-wrap:wrap;padding:8px 12px;gap:5px 14px}.nav{order:3;width:100%;height:42px}.headmeta{margin-left:auto}.main{padding:22px 13px 44px}.top{display:block}.top .sp{margin:12px 0 0}.span3,.span4,.span5,.span6,.span7,.span8,.span9{grid-column:1/-1}.fields{grid-template-columns:1fr}.field.span2,.field.span3,.field.span4,.field.span6,.field.span8,.field.span12{grid-column:auto}.steps{display:grid}.step{border-right:0;border-bottom:1px solid var(--line)}td,th{white-space:normal}.hide-mobile{display:none}.linkcharthead{display:none}.linkchartrow{grid-template-columns:1fr;gap:5px}.historybucket{min-width:10px}.current-counter-head{display:none}.current-counter-row{grid-template-columns:1fr repeat(3,minmax(62px,auto));column-gap:12px}.current-counter-row:first-of-type{border-top:0}.current-counter-interface{display:grid;gap:0}.current-counter-value{display:grid;justify-items:end;gap:0}.current-counter-value small{display:block}.current-counter-track{grid-column:1/-1}.current-counter-summary{display:grid;gap:2px}.current-counter-summary strong{grid-row:1}.page-overview .steps,.overview-primary,.overview-secondary{height:auto;display:grid;grid-template-columns:1fr}.page-overview .step{padding:12px 15px}.overview-topology-card{height:auto;overflow-x:auto}.overview-topology-card .topology{width:650px;height:260px}.overview-side{grid-template-rows:auto}.overview-secondary{height:auto}.overview-list-card{height:auto;max-height:300px}.overview-events{height:auto}.traffic-compact-body{grid-template-columns:130px minmax(0,1fr)}.edge-panel-head{min-height:0}.topology-edge-card{overflow-x:auto}.route-hop{grid-template-columns:1fr}.route-hop-state,.route-hop-meta{grid-column:1}.enrollment-summary-copy{display:grid;gap:0}.enrollment-summary-hint{display:none}.enrollment-access-body{padding:13px}.enrollment-identity-meta{grid-template-columns:1fr}.enrollment-identity-meta>div:first-child{grid-column:auto}.enrollment-public-key-head>div{display:grid;gap:0}.enrollment-boundary-list>div{grid-template-columns:90px minmax(0,1fr)}}
@media(max-width:760px){.status-alert{grid-template-columns:26px minmax(0,1fr);align-items:start}.status-alert-note{grid-column:2;max-width:none;text-align:left}.status-alert-title{display:block}.status-alert-title span{display:block;margin-top:1px}.snapshot-group{align-items:flex-start;flex-direction:column;gap:0}}
@media(prefers-reduced-motion:reduce){*,*:before,*:after{scroll-behavior:auto!important;animation-duration:.01ms!important;animation-iteration-count:1!important;transition-duration:.01ms!important}}
</style>`

func shell(d Deps, title, body string, isAuthed bool, evidence ...View) string {
	role := "Local node"
	if d.Control != nil {
		role = "Control plane"
	}
	// 这台机器上没有任何写操作时不显示登录入口 —— 一个点进去只会说
	// "没配口令"的链接,只会让人以为自己配错了。
	auth := `<span class=dim>Read-only view<span class=sr-only>只读</span></span>`
	switch {
	case isAuthed:
		auth = `Signed in · <a href="/logout">Sign out</a>`
	case d.Operator != "" && (len(d.Actions) > 0 || d.Control != nil):
		auth = `<a href="/login">Operator sign in</a>`
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
		fmt.Fprintf(&navHTML, `<a data-key=%s%s href="%s">%s</a>`, esc(item.key), cls, esc(item.href), esc(item.label))
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
	progressScript := ""
	if strings.Contains(body, "data-submit-progress") {
		progressScript = `<script>` + progressSubmitScript + `</script>`
	}
	pageClass := "page-" + active
	return fmt.Sprintf(`<!doctype html><meta charset=utf-8><title>%s · LOOM</title><link rel=icon href="/favicon.svg?v=2" type="image/svg+xml">
<meta name=viewport content="width=device-width,initial-scale=1">%s%s
<div class=app><header class=header><a class=brand href="/" aria-label="LOOM overview">%s<span>LOOM</span></a>
<nav class=nav aria-label="Primary">%s</nav><div class=headmeta><span class="env dim"><span class=dot></span>Live evidence</span><span>%s</span></div></header>
<main class="main %s"><div class=top><div><div class=eyebrow>%s</div><h1>%s</h1><div class=subtitle>%s</div></div><div class=sp>%s</div></div>%s</main></div>%s`,
		esc(heading), refresh, style, logoSVG(), navHTML.String(), auth,
		esc(pageClass), esc(eyebrow), esc(heading), esc(subtitle), esc(d.Node)+` · `+esc(role), body, progressScript)
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
	fmt.Fprintf(&b, `<aside class="status-alert problem evidence-alert" role=alert><span class=status-alert-icon aria-hidden=true>!</span><div class=status-alert-body><div class=status-alert-title><strong>Evidence is incomplete</strong><span>%d source warning`, len(warnings))
	if len(warnings) != 1 {
		b.WriteByte('s')
	}
	b.WriteString(`</span></div><div class=status-alert-items>`)
	for _, warning := range warnings {
		fmt.Fprintf(&b, `<span>%s</span>`, esc(warning))
	}
	b.WriteString(`</div></div><span class=status-alert-note>Unavailable evidence is never treated as empty or healthy.</span></aside>`)
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

func faviconSVG() string {
	return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="127 112 1000 1000"><rect x="127" y="112" width="1000" height="1000" fill="#fff"/><g transform="translate(0 1254) scale(1 -1)"><path fill="#111" fill-rule="evenodd" clip-rule="evenodd" d="` + approvedLogoPath + `"/></g></svg>`
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
	// Keep the inventory order: the control adapter already follows SSOT order,
	// which is more useful to an operator than an arbitrary alphabetical orbit.
	// Reverse-only nodes form the accepting side of the carrier diagram. If a
	// view has no direction metadata (older/local reporters), split it in two so
	// the graph still reads left-to-right instead of collapsing into one column.
	ids := make([]string, 0, len(v.Nodes))
	left, right := []string{}, []string{}
	nodes := map[string]NodeView{}
	selected := map[string]bool{}
	for _, route := range routeOverlay {
		if route.Stale {
			continue
		}
		// A direct route has no server-to-server edge, but it still selects the
		// access node as the local egress. Highlight that node instead of making
		// the overlay appear to do nothing.
		if len(route.Chain) == 0 && route.Node != "" {
			selected[route.Node] = true
		}
		for _, id := range route.Chain {
			selected[id] = true
		}
	}
	for _, n := range v.Nodes {
		if n.ID == "" {
			continue
		}
		ids = append(ids, n.ID)
		nodes[n.ID] = n
		if n.Direction == "reverse_only" {
			right = append(right, n.ID)
		} else {
			left = append(left, n.ID)
		}
	}
	sort.SliceStable(left, func(i, j int) bool {
		a, z := nodes[left[i]], nodes[left[j]]
		if a.Self != z.Self {
			return a.Self
		}
		if selected[a.ID] != selected[z.ID] {
			return selected[a.ID]
		}
		return a.ID < z.ID
	})
	sort.SliceStable(right, func(i, j int) bool {
		if selected[right[i]] != selected[right[j]] {
			return selected[right[i]]
		}
		return right[i] < right[j]
	})
	if len(right) == 0 && len(left) > 1 {
		cut := (len(left) + 1) / 2
		right = append(right, left[cut:]...)
		left = left[:cut]
	}
	pos := map[string]svgPoint{}
	for i, id := range left {
		pos[id] = svgPoint{x: 300, y: topologyColumnY(i, len(left))}
	}
	for i, id := range right {
		pos[id] = svgPoint{x: 730, y: topologyColumnY(i, len(right))}
	}
	var b strings.Builder
	b.WriteString(`<svg class=topology viewBox="0 0 960 275" role=img aria-label="Near-real-time network topology"><defs><marker id=arrow viewBox="0 0 10 10" refX=8 refY=5 markerWidth=5 markerHeight=5 orient=auto-start-reverse><path d="M 0 0 L 10 5 L 0 10 z" fill="#239b68"/></marker></defs>`)
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
	for _, id := range ids {
		p := pos[id]
		n := nodes[id]
		cls := "node"
		if n.Health == "problem" {
			cls += " problem"
		} else if n.Health != "healthy" {
			cls += " unknown"
		}
		if !n.Declared {
			cls += " undeclared"
		}
		if selected[id] {
			cls += " selected"
			fmt.Fprintf(&b, `<circle class=route-ring cx="%.1f" cy="%.1f" r="11"/>`, p.x, p.y)
		}
		fmt.Fprintf(&b, `<circle class="%s" cx="%.1f" cy="%.1f" r="6"/>`, cls, p.x, p.y)
		if p.x < 500 {
			fmt.Fprintf(&b, `<text text-anchor=end x="%.1f" y="%.1f">%s</text><text class=sub text-anchor=end x="%.1f" y="%.1f">%s</text>`, p.x-18, p.y+1, esc(id), p.x-18, p.y+22, esc(topologyNodeSubtitle(n)))
		} else {
			fmt.Fprintf(&b, `<text x="%.1f" y="%.1f">%s</text><text class=sub x="%.1f" y="%.1f">%s</text>`, p.x+18, p.y+1, esc(id), p.x+18, p.y+22, esc(topologyNodeSubtitle(n)))
		}
	}
	if len(ids) == 0 {
		b.WriteString(`<text class=sub text-anchor=middle x=480 y=138>No topology observations</text>`)
	}
	b.WriteString(`</svg>`)
	return b.String()
}

func topologyColumnY(index, count int) float64 {
	switch count {
	case 0:
		return 138
	case 1:
		return 138
	case 2:
		return []float64{82, 205}[index]
	case 3:
		return []float64{48, 138, 238}[index]
	default:
		return 36 + float64(index)*204/float64(count-1)
	}
}

func topologyNodeSubtitle(n NodeView) string {
	place := strings.TrimSpace(n.City)
	if place == "" {
		place = strings.TrimSpace(n.Name)
	}
	var traits []string
	if n.Self {
		traits = append(traits, "control")
	}
	for _, role := range n.Roles {
		if role != "control" {
			traits = append(traits, role)
		}
	}
	if len(traits) == 0 && n.Direction != "" {
		traits = append(traits, strings.ReplaceAll(n.Direction, "_", "-"))
	}
	if n.EgressCapable && !containsString(traits, "egress") {
		traits = append(traits, "egress")
	}
	detail := strings.Join(traits, " + ")
	if !n.Declared {
		detail = "undeclared observed"
	}
	if place == "" {
		return detail
	}
	if detail == "" {
		return place
	}
	return place + " · " + detail
}

func containsString(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
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
