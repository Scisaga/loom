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

// 页面是服务端渲染的纯 HTML,不依赖任何外部资源。节点接入页只有一段
// CSP hash 锁定的本地脚本，用来在同步 SSH 提交期间禁止重复操作并反馈进度。
//
// 不是极简主义:这些机器不一定能出网,而通过 ssh 端口转发进来时更不能。
// 一个依赖 CDN 的界面在最需要它的时候(隧道断了、机器出问题了)恰好打不开。

const progressSubmitScript = `document.querySelectorAll("form[data-submit-progress]").forEach(function(form){form.addEventListener("submit",function(event){if(!form.checkValidity())return;if(form.dataset.submitting==="true"){event.preventDefault();return}form.dataset.submitting="true";form.setAttribute("aria-busy","true");var submitter=event.submitter;if(submitter&&submitter.name){var preserved=document.createElement("input");preserved.type="hidden";preserved.name=submitter.name;preserved.value=submitter.value;form.appendChild(preserved)}form.classList.add("is-submitting");form.querySelectorAll("button").forEach(function(button){button.disabled=true})})});`

const deviceEnrollmentScript = `document.querySelectorAll("form[data-device-enrollment-form]").forEach(function(form){var platform=form.querySelector("[data-enrollment-platform]"),use=form.querySelector("[data-enrollment-use]"),forward=form.querySelector("[data-enrollment-forward]"),egress=form.querySelector("[data-enrollment-egress]"),grants=form.querySelector("[data-enrollment-grants]"),direction=form.querySelector("[data-enrollment-direction]");function setInputs(container,enabled){if(!container)return;container.hidden=!enabled;container.querySelectorAll("input,select").forEach(function(input){input.disabled=!enabled})}function update(){var linux=platform&&platform.value==="linux-server";if(!linux)use.checked=true;forward.disabled=!linux;if(!linux)forward.checked=false;egress.disabled=!linux||!forward.checked;if(!forward.checked)egress.checked=false;setInputs(direction,forward.checked);setInputs(grants,use.checked)}[platform,use,forward,egress].forEach(function(input){if(input)input.addEventListener("change",update)});update()});`

const copyValueScript = `document.querySelectorAll("[data-copy-target]").forEach(function(button){button.addEventListener("click",async function(){var target=document.getElementById(button.dataset.copyTarget),feedback=button.closest(".client-invite-qr").querySelector("[data-copy-feedback]");try{await navigator.clipboard.writeText(target.value);feedback.textContent="Join link copied"}catch(error){feedback.textContent="Copy failed — use the join-link field"}})});`

const topologyInteractionScript = `document.querySelectorAll("svg.topology").forEach(function(svg){var lockedNode="";function apply(nodeID,edgeFocus,locked){var active=Boolean(nodeID||edgeFocus),visibleNodes={};if(nodeID)visibleNodes[nodeID]=true;svg.classList.toggle("has-focus",active);svg.querySelectorAll(".topology-edge").forEach(function(edge){var related=edgeFocus?edge===edgeFocus:Boolean(nodeID&&(edge.dataset.from===nodeID||edge.dataset.to===nodeID));edge.classList.toggle("is-related",related);edge.classList.toggle("is-muted",active&&!related);if(related){visibleNodes[edge.dataset.from]=true;visibleNodes[edge.dataset.to]=true}});svg.querySelectorAll(".edge-metric").forEach(function(metric){var related=edgeFocus?metric.dataset.from===edgeFocus.dataset.from&&metric.dataset.to===edgeFocus.dataset.to:Boolean(nodeID&&(metric.dataset.from===nodeID||metric.dataset.to===nodeID));metric.classList.toggle("is-related",related)});svg.querySelectorAll(".topology-node").forEach(function(node){var id=node.dataset.node,same=id===nodeID;node.classList.toggle("is-selected",same&&locked);node.classList.toggle("is-preview",same&&!locked);node.classList.toggle("is-muted",active&&!visibleNodes[id]);node.setAttribute("aria-pressed",String(same&&locked))})}function clearTransient(){if(!lockedNode)apply("",null,false)}svg.querySelectorAll(".topology-node").forEach(function(node){var id=node.dataset.node;node.addEventListener("pointerenter",function(){if(!lockedNode)apply(id,null,false)});node.addEventListener("pointerleave",clearTransient);node.addEventListener("focus",function(){if(!lockedNode)apply(id,null,false)});node.addEventListener("blur",clearTransient);node.addEventListener("click",function(event){event.stopPropagation();lockedNode=lockedNode===id?"":id;apply(lockedNode,null,Boolean(lockedNode))});node.addEventListener("keydown",function(event){if(event.key==="Enter"||event.key===" "){event.preventDefault();lockedNode=lockedNode===id?"":id;apply(lockedNode,null,Boolean(lockedNode))}})});svg.querySelectorAll(".topology-edge").forEach(function(edge){edge.addEventListener("pointerenter",function(){if(!lockedNode)apply("",edge,false)});edge.addEventListener("pointerleave",clearTransient)});svg.addEventListener("click",function(event){if(event.target.closest(".topology-node"))return;if(lockedNode){lockedNode="";apply("",null,false)}});svg.addEventListener("keydown",function(event){if(event.key==="Escape"&&lockedNode){event.preventDefault();lockedNode="";apply("",null,false)}});apply("",null,false)});`

const style = `<style>
:root{--fg:#181b1a;--dim:#717674;--faint:#9ba09e;--line:#e2e6e3;--line2:#ccd2ce;--ok:#239b68;--oksoft:#eef8f3;--bad:#b84c4c;--badsoft:#fff3f2;--warn:#a66a14;--warnsoft:#fff8eb;--info:#477d9c;--route:#466fc2;--traffic-rx:#73c39d;--traffic-tx:#6f96ad;--bg:#fcfcfb;--card:#fff;--card2:#f7f8f7;--ink:#181b1a;--font-mono:"SFMono-Regular","Roboto Mono","IBM Plex Mono",Consolas,"Liberation Mono",ui-monospace,monospace}
*{box-sizing:border-box}
html{background:var(--bg)}body{margin:0;font:14px/1.55 Inter,"Atkinson Hyperlegible Next",ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:var(--fg);background:var(--bg)}
a{color:inherit;text-decoration:none;transition:color .14s ease}a:hover{color:var(--ok)}code,.mono{font-family:var(--font-mono);font-weight:400;font-synthesis:none;font-variant-ligatures:none;font-variant-numeric:tabular-nums;font-feature-settings:"zero" 1}
.app{min-height:100vh}.header{height:50px;background:#fff;border-bottom:1px solid var(--line);display:flex;align-items:stretch;padding:0 20px;gap:20px;position:sticky;top:0;z-index:4}
.brand{display:flex;align-items:center;gap:9px;flex:0 0 253px;font-size:17px;font-weight:760;letter-spacing:.09em;white-space:nowrap}.brandmark{width:34px;height:34px;color:#252927}.brandmark path{fill:currentColor}
.role{font-size:10px;color:var(--dim);font-weight:550;letter-spacing:.08em;text-transform:uppercase}.nav{display:flex;align-items:stretch;gap:0;min-width:0;overflow-x:auto;scrollbar-width:none}.nav::-webkit-scrollbar{display:none}.nav a{position:relative;display:flex;align-items:center;gap:7px;padding:0 10px;color:var(--dim);white-space:nowrap;font-size:13px;transition:color .14s ease,background-color .14s ease}.nav a:after{content:"";position:absolute;right:8px;bottom:0;left:8px;height:2px;background:var(--ok);transform:scaleX(0);transform-origin:center;transition:transform .18s ease}.nav a:before{content:"";width:14px;height:14px;flex:0 0 auto;background:50%/14px 14px no-repeat;transition:filter .14s ease}.nav a[data-key=overview]:before{background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16' fill='none' stroke='%237d8280' stroke-width='1.35'%3E%3Crect x='1.5' y='1.5' width='5' height='5' rx='1'/%3E%3Crect x='9.5' y='1.5' width='5' height='5' rx='1'/%3E%3Crect x='1.5' y='9.5' width='5' height='5' rx='1'/%3E%3Crect x='9.5' y='9.5' width='5' height='5' rx='1'/%3E%3C/svg%3E")}.nav a[data-key=nodes]:before{background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16' fill='none' stroke='%237d8280' stroke-width='1.35'%3E%3Crect x='2' y='2' width='12' height='5' rx='1.4'/%3E%3Crect x='2' y='9' width='12' height='5' rx='1.4'/%3E%3C/svg%3E")}.nav a[data-key=topology]:before{background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16' fill='none' stroke='%237d8280' stroke-width='1.35'%3E%3Cpath d='M4.2 4.2L8 8m3.8-3.8L8 8m0 0v4.4'/%3E%3Ccircle cx='3' cy='3' r='1.8'/%3E%3Ccircle cx='13' cy='3' r='1.8'/%3E%3Ccircle cx='8' cy='13.5' r='1.8'/%3E%3C/svg%3E")}.nav a[data-key=services]:before{background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16' fill='none' stroke='%237d8280' stroke-width='1.35'%3E%3Crect x='2' y='2' width='12' height='12' rx='2'/%3E%3Cpath d='M5 5h6M5 8h6M5 11h4'/%3E%3C/svg%3E")}.nav a[data-key=routing]:before{background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16' fill='none' stroke='%237d8280' stroke-width='1.35'%3E%3Cpath d='M2 4h4.2C9 4 8.2 12 11 12h2.5M2 12h3.5C8.4 12 7.7 4 10.7 4h2.8'/%3E%3C/svg%3E")}.nav a[data-key=deployments]:before{background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16' fill='none' stroke='%237d8280' stroke-width='1.35'%3E%3Crect x='2' y='3' width='12' height='10.5' rx='2'/%3E%3Cpath d='M8 6v4m-2-2 2 2 2-2'/%3E%3C/svg%3E")}.nav a[data-key=events]:before{background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16' fill='none' stroke='%237d8280' stroke-width='1.35'%3E%3Ccircle cx='8' cy='8' r='6.2'/%3E%3Cpath d='M8 4.5V8l2.5 1.5'/%3E%3C/svg%3E")}.nav a[data-key=settings]:before{background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16' fill='none' stroke='%237d8280' stroke-width='1.35'%3E%3Cpath d='M2 4h5m3 0h4M2 8h2m3 0h7M2 12h7m3 0h2'/%3E%3C/svg%3E")}.nav a:hover{color:var(--fg);background:#f7f9f8}.nav a:hover:before,.nav a.active:before{filter:brightness(.3)}.nav a.active{color:var(--fg);font-weight:600}.nav a.active:after{transform:scaleX(1)}.nav a:focus-visible{outline:2px solid #b9dfcd;outline-offset:-4px}.navgroup{display:contents}.navgroup:before{display:none}
.nav a[data-key=devices]:before{background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16' fill='none' stroke='%237d8280' stroke-width='1.35'%3E%3Crect x='1.8' y='2.5' width='8.8' height='7.3' rx='1.3'/%3E%3Cpath d='M4.2 12.7h4M6.2 9.8v2.9'/%3E%3Crect x='11.5' y='5.8' width='2.8' height='7.3' rx='.8'/%3E%3C/svg%3E")}
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
.topology{width:100%;min-height:390px;display:block;background:transparent;overflow:visible}.topology path,.topology ellipse{vector-effect:non-scaling-stroke}.topology .topology-ring{fill:none;stroke:#edf0ee;stroke-width:1}.topology .topology-ring.inner{stroke-dasharray:3 5}.topology .ring-key{fill:var(--dim);font:500 9px Inter,ui-sans-serif,system-ui;letter-spacing:.035em}.topology .ring-dot{fill:#dfe5e1}.topology .topology-edge path{fill:none}.topology .topology-edge,.topology .topology-node,.topology .edge-metric{transition:opacity .16s ease}.topology .tunnel{stroke:#a5aaa8;stroke-width:1.25;opacity:.88;transition:stroke .16s ease,stroke-width .16s ease,opacity .16s ease}.topology .direct-hy2{stroke:#4f9b74;stroke-width:1.45;opacity:.9;transition:stroke .16s ease,stroke-width .16s ease,opacity .16s ease}.topology .candidate{stroke:#b9bebc;stroke-width:1.25;stroke-dasharray:5 6;opacity:.82;transition:stroke .16s ease,stroke-width .16s ease,opacity .16s ease}.topology .degraded{stroke:#d79b3b}.topology .failed{stroke:#c65a5a}.topology .unknown{stroke:#a5aaa8;stroke-dasharray:3 7;opacity:.62}.topology .edge-hit{stroke:transparent;stroke-width:13;pointer-events:stroke}.topology .topology-edge:hover .tunnel,.topology .topology-edge.is-related .tunnel,.topology .topology-edge:hover .direct-hy2,.topology .topology-edge.is-related .direct-hy2{stroke:#247b53;stroke-width:2.35;opacity:1}.topology .topology-edge.is-related .candidate{stroke:#69716d;stroke-width:1.8;opacity:1}.topology.has-focus .topology-edge.is-muted{opacity:.1}.topology.has-focus .topology-node.is-muted{opacity:.2}.topology .edge-metric{opacity:0;pointer-events:none}.topology .edge-metric.is-related{opacity:1}.topology .edge-metric text{fill:#4e5652;stroke:rgba(255,255,255,.96);stroke-width:4px;stroke-linejoin:round;paint-order:stroke;display:block;font:500 8.8px var(--font-mono);font-variant-numeric:tabular-nums}.topology .route{fill:none;stroke:var(--route);stroke-width:2.5;opacity:.96}.topology .route-ring{fill:none;stroke:var(--route);stroke-width:2;opacity:.3}.topology .topology-node{cursor:pointer;outline:none}.topology .node-focus{fill:none;stroke:var(--ok);stroke-width:2;opacity:0;transform-box:fill-box;transform-origin:center;transform:scale(.72);transition:opacity .16s ease,transform .16s ease}.topology .topology-node:hover .node-focus,.topology .topology-node:focus .node-focus,.topology .topology-node.is-preview .node-focus,.topology .topology-node.is-selected .node-focus{opacity:.28;transform:scale(1)}.topology .topology-node.is-selected .node-focus{opacity:.48}.topology .node{fill:var(--ok);stroke:#fff;stroke-width:3}.topology .node.problem{fill:var(--bad)}.topology .node.unknown{fill:#a5aaa8;stroke:#fff;stroke-dasharray:none}.topology .node.undeclared{fill:var(--warn);stroke:#fff}.topology .node.selected{fill:var(--ok);stroke:#fff;stroke-width:3}.topology .node-label{paint-order:stroke;stroke:#fff;stroke-width:4px;stroke-linejoin:round}.topology text{fill:var(--fg);font:500 12px var(--font-mono)}.topology .sub{fill:var(--dim);font:400 10px/1.4 Inter,ui-sans-serif,system-ui}
.topology .node-hit{fill:transparent;stroke:none;pointer-events:all}
.topology .topology-edge.is-related .tunnel.degraded,.topology .topology-edge.is-related .direct-hy2.degraded{stroke:#d79b3b}.topology .topology-edge.is-related .tunnel.failed,.topology .topology-edge.is-related .direct-hy2.failed{stroke:#c65a5a}.topology.has-focus .route{opacity:.14}.topology.has-focus .route-ring{opacity:.08}
.legend{display:flex;gap:16px;flex-wrap:wrap;margin-top:10px;color:var(--dim);font-size:11px}.key{display:inline-block;width:26px;border-top:2px solid #a5aaa8;vertical-align:middle;margin-right:6px}.key.direct-hy2{border-color:#4f9b74}.key.candidate{border-color:#b9bebc;border-top-style:dashed}.key.route{border-color:var(--route);border-width:3px}.key.degraded{border-color:#d79b3b}.key.failed{border-color:#c65a5a}
.topology-layer-note{display:flex;align-items:flex-start;gap:8px;margin:11px 0 0;padding:9px 11px;border:1px solid var(--line);border-radius:6px;background:var(--card2);color:var(--dim);font-size:11px}.topology-layer-note:before{content:"i";display:inline-flex;align-items:center;justify-content:center;flex:0 0 auto;width:16px;height:16px;border:1px solid var(--line2);border-radius:50%;color:var(--fg);font-size:10px;font-weight:700}.topology-edge-grid{display:grid;grid-template-columns:minmax(0,1.65fr) minmax(340px,.85fr);gap:14px}.topology-edge-card{padding:0;overflow:hidden}.edge-panel-head{display:flex;align-items:flex-start;gap:14px;min-height:72px;padding:14px 16px 12px}.edge-panel-head h3{margin:0;font-size:15px}.edge-panel-head p{margin:2px 0 0;color:var(--dim);font-size:11px}.edge-panel-head .badge{margin-left:auto;white-space:nowrap}.badge.intent{border-color:#d6e1e7;background:#f5f9fb;color:var(--info)}.topology-edge-card table{border-top:1px solid var(--line)}.topology-edge-card th:first-child,.topology-edge-card td:first-child{padding-left:16px}.topology-edge-card th:last-child,.topology-edge-card td:last-child{padding-right:16px}.edge-status{display:inline-flex;align-items:center;gap:7px;white-space:nowrap}.edge-status .dot{width:6px;height:6px}.edge-source{max-width:380px;white-space:normal;color:var(--dim);font-size:11px;line-height:1.45}.route-hop-list{border-top:1px solid var(--line)}.route-hop{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:4px 12px;padding:12px 16px;border-bottom:1px solid var(--line)}.route-hop:last-child{border-bottom:0}.route-hop-pair{font-size:13px}.route-hop-state{display:inline-flex;align-items:center;gap:6px;color:var(--info);font-size:11px;white-space:nowrap}.route-hop-state .dot{width:6px;height:6px}.route-hop-meta{grid-column:1/-1;color:var(--dim);font-size:11px;line-height:1.45}.route-hop-note{margin:0 16px 14px;padding:9px 10px;border-radius:6px;background:var(--card2);color:var(--dim);font-size:11px;line-height:1.45}
.topology .route{stroke-width:3;opacity:.94}.topology .route-ring{stroke-width:2.4;opacity:.72}.topology .node.selected{stroke:var(--route);stroke-width:3.5}.topology .node.problem.selected{fill:var(--bad)}.topology .node.unknown.selected{fill:#a5aaa8}.topology .route-direct-label{fill:var(--route);stroke:#fff;stroke-width:3px;paint-order:stroke;font:650 9px Inter,ui-sans-serif,system-ui}.topology-side{display:grid;align-content:start;gap:14px}.topology-route-focus{display:flex;align-items:center;gap:16px;margin:-3px -3px 10px;padding:10px 12px;border:1px solid #d8e1f4;border-radius:7px;background:#f5f7fc}.topology-route-focus>div{display:grid;grid-template-columns:auto minmax(0,1fr);align-items:baseline;gap:1px 12px;min-width:0}.topology-route-focus .label{grid-column:1/-1;color:var(--route)}.topology-route-focus b{font-size:13px}.topology-route-focus .mono{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.topology-route-focus .tiny{grid-column:1/-1}.topology-route-focus .button{margin-left:auto;white-space:nowrap}.automatic-routing-card{padding:14px}.automatic-routing-head{display:flex;align-items:center;gap:10px}.automatic-routing-head h2{margin:0}.automatic-routing-head .tiny{margin-left:auto}.automatic-routing-card>p{margin:5px 0 10px;color:var(--dim);font-size:10px;line-height:1.45}.automatic-route-list{display:grid;border-top:1px solid var(--line)}.automatic-route-row{display:grid;gap:3px;padding:10px 0;border-bottom:1px solid var(--line)}.automatic-route-row.active{margin:0 -8px;padding:10px 8px;border-radius:6px;background:#f5f7fc}.automatic-route-heading,.automatic-route-meta{display:flex;align-items:center;gap:8px}.automatic-route-heading b{min-width:0;overflow:hidden;font-size:12px;text-overflow:ellipsis;white-space:nowrap}.automatic-route-heading .tiny{margin-left:auto}.automatic-route-row>.mono{overflow:hidden;color:var(--route);font-size:11px;text-overflow:ellipsis;white-space:nowrap}.automatic-route-meta{flex-wrap:wrap;color:var(--dim);font-size:9px}.automatic-route-meta span:first-child{min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.automatic-route-meta a,.automatic-route-meta .info{margin-left:auto}.automatic-routing-all{display:block;margin-top:10px;color:var(--info);font-size:10px}.routing-entry-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(245px,1fr));gap:9px}.routing-entry-card{display:grid;gap:5px;min-width:0;padding:11px 12px;border:1px solid var(--line);border-radius:7px;background:#fff}.routing-entry-card:hover{border-color:var(--line2);background:var(--card2);color:inherit}.routing-entry-card.active{border-color:#b9c9e9;background:#f5f7fc;box-shadow:inset 3px 0 0 var(--route)}.routing-entry-card>span:first-child{display:grid;min-width:0}.routing-entry-card b,.routing-entry-card small,.routing-entry-card>.mono{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.routing-entry-card b{font-size:13px}.routing-entry-card small{color:var(--dim);font-size:9px}.routing-entry-card>.mono{color:var(--route);font-size:11px}
/* Services keeps Service controls and policy context together. Local ingress
   inventory belongs to the access-node detail where that configuration runs. */
.page-services .top{margin-bottom:16px}.services-summary{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));margin-bottom:10px;overflow:hidden;border:1px solid var(--line);border-radius:8px;background:#fff}.services-summary-item{min-width:0;padding:12px 17px;border-right:1px solid var(--line)}.services-summary-item:last-child{border-right:0}.services-summary-item .metric{font-size:21px;margin:3px 0}.services-summary-item>.dim{overflow:hidden;font-size:11px;text-overflow:ellipsis;white-space:nowrap}.services-flow{display:flex;align-items:center;gap:9px;min-height:38px;margin-bottom:14px;padding:8px 13px;border:1px solid var(--line);border-radius:7px;background:var(--card2);color:var(--dim);font-size:12px}.services-flow b{color:var(--fg);font-weight:650}.services-flow-label{margin-right:5px;color:var(--fg);font-size:10px;font-weight:700;letter-spacing:.07em;text-transform:uppercase}.services-workspace{display:grid;grid-template-columns:minmax(260px,310px) minmax(0,1fr);gap:14px;align-items:start}.service-catalog,.service-editor{padding:0;overflow:hidden}.service-catalog{align-self:start}.service-catalog-head{display:flex;align-items:center;gap:10px;min-height:62px;padding:12px 14px;border-bottom:1px solid var(--line)}.service-catalog-head h2,.service-editor-head h2{margin:0;color:var(--fg);font-size:15px;letter-spacing:0;text-transform:none}.service-catalog-head .dim,.service-editor-head .dim{font-size:11px}.service-catalog-head .button{padding:6px 9px;font-size:12px}.service-catalog-list .catalogrow{padding:12px 14px}.service-catalog-name{margin-bottom:3px;font-size:13px;font-weight:650}.service-catalog-id{display:flex;align-items:center;gap:8px;margin-bottom:3px}.service-catalog-id .mono{min-width:0;overflow:hidden;text-overflow:ellipsis}.service-catalog-id .badge{margin-left:auto;padding:2px 7px;overflow:hidden;max-width:125px;font-size:10px;text-overflow:ellipsis;white-space:nowrap}.service-editor-head{display:flex;align-items:center;gap:14px;min-height:62px;padding:12px 17px;border-bottom:1px solid var(--line);background:#fff}.service-editor-body{padding:16px 17px}.service-editor-empty{padding:16px}.service-primary-fields{display:grid;grid-template-columns:minmax(170px,.72fr) minmax(210px,1fr) minmax(230px,1.08fr);gap:12px;align-items:start}.service-primary-fields .field{grid-template-rows:auto 40px minmax(14px,auto);align-content:start}.service-primary-fields input,.service-primary-fields select,.service-primary-fields .readonly-value{width:100%;height:40px;min-height:40px}.field-hint{color:var(--dim);font-size:10px;line-height:1.4}.readonly-value{min-height:40px;padding:9px 10px;border:1px solid var(--line);border-radius:6px;background:var(--card2)}.service-host-rules{margin-top:15px}.service-subhead{display:flex;align-items:flex-end;gap:12px;margin-bottom:7px}.service-subhead>div{display:grid;gap:1px}.service-subhead label{color:var(--fg);font-size:12px;font-weight:650}.service-subhead span:not(.badge){color:var(--dim);font-size:11px}.service-subhead>.badge{margin-left:auto;padding:3px 8px;font-size:10px}.service-host-rules textarea.compact{height:126px}.service-rule-help{display:flex;flex-wrap:wrap;gap:4px 18px;margin-top:6px;color:var(--dim);font-size:10px}.service-rule-help span:before{content:"·";margin-right:5px;color:var(--faint)}.service-rule-list{overflow:hidden;border:1px solid var(--line);border-radius:7px}.service-rule-list>div{display:flex;align-items:center;gap:10px;min-height:39px;padding:7px 10px;border-bottom:1px solid var(--line)}.service-rule-list>div:last-child{border-bottom:0}.service-rule-list code{min-width:0;overflow:hidden;text-overflow:ellipsis}.service-rule-list .badge{margin-left:auto;padding:2px 7px;font-size:10px}.service-form-actions{display:flex;align-items:center;gap:14px;margin-top:14px;padding-top:13px;border-top:1px solid var(--line)}.service-form-actions>.toolbar{margin-left:auto}.service-form-actions .progress-submit{min-width:142px}.service-danger{display:flex;align-items:center;gap:14px;margin-top:15px;padding:10px 12px;border:1px solid #efd9d7;border-radius:7px;background:#fff9f8}.service-danger>div{display:grid;gap:1px}.service-danger b{font-size:11px;color:var(--bad)}.service-danger span{color:var(--dim);font-size:10px}.service-danger form{margin-left:auto}.danger-button{border-color:#dfb5b2;color:var(--bad);background:#fff}.danger-button:hover{border-color:var(--bad);color:var(--bad)}.service-state-note{display:flex;align-items:center;gap:8px;margin-top:12px;color:var(--dim);font-size:10px}.service-state-icon{display:inline-flex;align-items:center;justify-content:center;flex:0 0 auto;width:17px;height:17px;border:1px solid var(--line2);border-radius:50%;color:var(--fg);font-size:9px;font-weight:700}.service-state-note a{color:var(--fg);text-decoration:underline;text-decoration-color:var(--line2)}.service-editor-access{margin:12px 0 0}.services-policy-library{margin-top:20px;padding:0;overflow:hidden}.services-policy-library>summary{display:flex;align-items:center;gap:12px;min-height:58px;padding:11px 15px;cursor:pointer;list-style:none}.services-policy-library>summary::-webkit-details-marker{display:none}.services-policy-library>summary:before{content:"›";display:inline-flex;align-items:center;justify-content:center;width:18px;height:18px;border-radius:5px;background:var(--card2);color:var(--dim);font-size:18px;line-height:1;transition:transform .16s ease}.services-policy-library[open]>summary:before{transform:rotate(90deg)}.services-policy-library>summary>span:first-of-type{display:grid}.services-policy-library>summary b{font-size:13px}.services-policy-library>summary small{color:var(--dim);font-size:10px}.services-policy-library>summary>.sp{color:var(--dim);font-size:11px}.services-policy-library[open]>summary{border-bottom:1px solid var(--line)}.policy-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:10px;padding:12px}.policy-card{min-width:0;padding:12px;border:1px solid var(--line);border-radius:7px;background:var(--card2)}.policy-card-head{display:flex;align-items:flex-start;gap:10px}.policy-card-head>div{display:grid}.policy-card-head>div span{color:var(--dim);font-size:10px}.policy-card-head>.badge{margin-left:auto;padding:2px 7px;font-size:10px}.policy-card-servers{display:grid;gap:3px;margin:10px 0}.policy-card-servers span{color:var(--dim);font-size:9px;text-transform:uppercase}.policy-card-servers code{overflow:hidden;font-size:10px;text-overflow:ellipsis;white-space:nowrap}.policy-card-meta{display:flex;flex-wrap:wrap;gap:4px 13px;padding-top:8px;border-top:1px solid var(--line);color:var(--dim);font-size:9px}.policy-card-meta b{color:var(--fg);font-weight:600}
.node-ingress-managed,.node-ingress-primary{padding:13px 14px;border-radius:7px}.node-ingress-managed{border:1px solid #cce7d8;background:var(--oksoft)}.node-ingress-primary{margin-top:12px;border:1px solid #d6e1e7;background:#f8fafb}.node-ingress-heading{display:flex;align-items:center;gap:14px}.node-ingress-heading>div{display:flex;align-items:center;gap:10px}.node-ingress-heading h3{margin:0}.node-ingress-heading>.small{margin-left:auto}.node-ingress-managed table,.node-ingress-primary table{margin-top:9px}.node-ingress-legacy{margin-top:12px;border:1px solid var(--line);border-radius:7px;overflow:hidden}.node-ingress-legacy>summary{display:flex;align-items:center;gap:12px;min-height:54px;padding:10px 13px;cursor:pointer;list-style:none}.node-ingress-legacy>summary::-webkit-details-marker{display:none}.node-ingress-legacy>summary:before{content:"›";display:inline-flex;align-items:center;justify-content:center;width:18px;height:18px;border-radius:5px;background:var(--card2);color:var(--dim);font-size:18px;line-height:1;transition:transform .16s ease}.node-ingress-legacy[open]>summary:before{transform:rotate(90deg)}.node-ingress-legacy>summary>span:first-of-type{display:grid}.node-ingress-legacy>summary small{color:var(--dim);font-size:10px}.node-ingress-legacy[open]>summary{border-bottom:1px solid var(--line)}.node-ingress-legacy-body{padding:0 13px 4px}
.nodegrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:10px}.nodecard{border:1px solid var(--line);background:#fff;border-radius:7px;padding:13px}.nodehead{display:flex;align-items:center;gap:7px;margin-bottom:8px}.nodehead b{font-size:15px}.catalogrow{display:block;padding:13px 11px;border-bottom:1px solid var(--line);border-left:3px solid transparent}.catalogrow:last-child{border-bottom:0}.catalogrow.selected{background:var(--oksoft);border-left-color:var(--ok)}.issue{padding:10px 0;border-bottom:1px solid var(--line)}.issue:last-child{border-bottom:0}.issue.problem{border-left:3px solid var(--bad);padding-left:10px}.tiny{font-size:11px}.small{font-size:12px}.clip{overflow:hidden;text-overflow:ellipsis;max-width:100%}
.node-inventory-help{display:flex;flex-wrap:wrap;gap:5px 20px;margin:-5px 0 10px;padding:9px 12px;border:1px solid var(--line);border-radius:7px;background:var(--card2);color:var(--dim);font-size:11px}.node-inventory-help span{white-space:nowrap}.node-inventory-help b{color:var(--fg);font-weight:650}.node-inventory-card{overflow-x:auto}.attention-summary{margin-bottom:6px}
.notice{border-left:3px solid var(--warn);background:var(--warnsoft)}.notice.badline{border-left-color:var(--bad);background:var(--badsoft)}.empty{padding:20px;text-align:center;color:var(--dim);border:1px dashed var(--line2);border-radius:7px}.callout{padding:12px 14px;border-radius:7px;background:var(--oksoft);border:1px solid #cce7d8}.callout.warnline{background:var(--warnsoft);border-color:#ead7b2}
.status-alert{display:grid;grid-template-columns:26px minmax(0,1fr) auto;gap:11px;align-items:center;min-height:58px;padding:9px 13px;border:1px solid var(--line);border-radius:8px;background:#fff}.status-alert.problem{border-color:#efd9d7;background:#fff9f8}.status-alert.warning{border-color:#eadfc9;background:#fffbf4}.status-alert-icon{display:inline-flex;align-items:center;justify-content:center;width:24px;height:24px;border-radius:50%;font-size:13px;font-weight:750}.status-alert.problem .status-alert-icon{color:var(--bad);background:#f8e7e5}.status-alert.warning .status-alert-icon{color:var(--warn);background:#f7ead3}.status-alert-body{min-width:0}.status-alert-title{display:flex;align-items:baseline;gap:9px;line-height:1.3}.status-alert-title strong{font-size:13px}.status-alert-title span{color:var(--dim);font-size:11px}.status-alert-items{display:flex;flex-wrap:wrap;gap:2px 15px;margin-top:2px;color:var(--fg);font-size:12px}.status-alert-items>span{min-width:0}.status-alert-items>span:before{content:"";display:inline-block;width:4px;height:4px;margin:0 7px 2px 0;border-radius:50%;background:currentColor;opacity:.45}.status-alert-note{max-width:330px;color:var(--dim);font-size:11px;line-height:1.4;text-align:right}.evidence-alert{margin-bottom:18px}.snapshot-alert{margin-top:10px}.snapshot-groups{display:flex;flex-wrap:wrap;gap:5px 8px;margin-top:4px}.snapshot-group{display:inline-flex;align-items:center;gap:8px;min-width:0;padding:3px 8px;border:1px solid #e5dccb;border-radius:5px;background:rgba(255,255,255,.68);font-size:11px}.snapshot-missing{margin-top:7px;overflow-wrap:anywhere}.snapshot-group.current{border-color:#cce3d7;background:#f6fbf8}.snapshot-group .mono{color:var(--fg)}.snapshot-group-nodes{color:var(--dim)}
form{display:inline}.blockform{display:block}.checkline{display:flex;align-items:flex-start;gap:9px}.checkline input{margin-top:3px}button,.button{font:inherit;padding:8px 12px;border:1px solid var(--line2);border-radius:6px;background:#fff;color:var(--fg);cursor:pointer;display:inline-flex;align-items:center;justify-content:center;gap:7px}button:hover,.button:hover{border-color:var(--ok);color:var(--fg)}button.primary,.button.primary{background:var(--fg);border-color:var(--fg);color:#fff}button.green,.button.green{background:var(--ok);border-color:var(--ok);color:#fff}button[disabled]{cursor:not-allowed;color:var(--faint);background:#f1f3f2;border-color:var(--line)}
.progress-submit{min-width:188px}.button-busy{display:none;align-items:center;gap:8px}.button-spinner{width:13px;height:13px;border:2px solid currentColor;border-right-color:transparent;border-radius:50%;animation:loom-spin .7s linear infinite}.blockform:valid .progress-submit:focus{cursor:wait}.blockform:valid .progress-submit:focus .button-idle,.blockform.is-submitting .progress-submit .button-idle{display:none}.blockform:valid .progress-submit:focus .button-busy,.blockform.is-submitting .progress-submit .button-busy{display:inline-flex}.blockform.is-submitting .progress-submit,.blockform.is-submitting .progress-submit[disabled]{cursor:wait;background:#8a918d;border-color:#8a918d;color:#fff;opacity:.82}.blockform.is-submitting a.button{pointer-events:none;opacity:.45}
input,select{font:inherit;padding:9px 10px;border:1px solid var(--line2);border-radius:6px;background:#fff;color:var(--fg)}input:focus,select:focus,textarea:focus{outline:2px solid #cce7d8;outline-offset:1px}.field{display:grid;gap:5px}.field label{font-size:11px;color:var(--dim);text-transform:uppercase}.fields{display:grid;grid-template-columns:repeat(12,minmax(0,1fr));gap:12px}.field.span2{grid-column:span 2}.field.span3{grid-column:span 3}.field.span4{grid-column:span 4}.field.span6{grid-column:span 6}.field.span8{grid-column:span 8}.field.span12{grid-column:1/-1}
pre{background:var(--card2);border:1px solid var(--line);border-radius:7px;padding:12px;overflow-x:auto;white-space:pre-wrap;margin:8px 0}textarea{width:100%;height:58vh;font:13px/1.5 var(--font-mono);padding:12px;border:1px solid var(--line2);border-radius:7px;background:#fff;color:var(--fg);white-space:pre;overflow-wrap:normal;overflow-x:auto}
textarea.compact{height:118px;white-space:pre-wrap}
.barlabel{display:flex;justify-content:space-between;font-size:10px;color:var(--dim);margin-top:5px}.kv{display:grid;grid-template-columns:minmax(110px,.6fr) minmax(0,1.5fr);gap:8px 15px}.kv dt{color:var(--dim);font-size:11px;text-transform:uppercase}.kv dd{margin:0;min-width:0}.kv dd.mono{overflow-wrap:anywhere;word-break:break-word}.steps{display:flex;border:1px solid var(--line);border-radius:7px;background:#fff}.step{flex:1;padding:14px 17px;border-right:1px solid var(--line)}.step:last-child{border-right:0}.step b{display:block;margin-top:3px}
.current-counters{border-top:1px solid var(--line)}.current-counter-head,.current-counter-row{display:grid;grid-template-columns:minmax(190px,1.45fr) repeat(3,minmax(110px,.65fr));column-gap:28px;align-items:center}.current-counter-head{padding:7px 0 5px;color:var(--dim);font-size:10px;font-weight:650;letter-spacing:.06em;text-transform:uppercase}.current-counter-row{position:relative;padding:9px 0 13px;border-top:1px solid var(--line)}.current-counter-head+.current-counter-row{border-top:0}.current-counter-interface{display:flex;align-items:baseline;gap:10px;min-width:0}.current-counter-interface .mono{overflow:hidden;text-overflow:ellipsis}.current-counter-value{display:flex;align-items:baseline;justify-content:space-between;gap:8px;min-width:0}.current-counter-value small{display:none;color:var(--dim);font-size:9px;text-transform:uppercase}.current-counter-value b{font-size:12px;font-weight:400}.current-counter-value.total b{color:var(--fg)}.current-counter-track{grid-column:2/-1;height:4px;margin-top:6px;overflow:hidden;border-radius:2px;background:var(--card2)}.current-counter-fill{display:flex;height:100%;min-width:1px;overflow:hidden;border-radius:2px}.current-counter-fill i{display:block;height:100%}.current-counter-rx{background:var(--traffic-rx)}.current-counter-tx{background:var(--traffic-tx)}.current-counter-row.idle .current-counter-fill{width:3px!important;background:var(--line2)}.current-counter-row.idle .current-counter-fill i{display:none}.current-counter-summary{display:flex;justify-content:space-between;gap:18px;padding-top:6px;color:var(--dim);font-size:10px}.current-counter-legend{display:flex;align-items:center;gap:12px;flex-wrap:wrap}.current-counter-legend>span{white-space:nowrap}.current-counter-summary strong{color:var(--fg);font-weight:400}.current-counter-summary+p{margin:10px 0 0}
.counterchart{height:150px;display:flex;align-items:stretch;gap:12px;padding:12px 6px 0;border-bottom:1px solid var(--line);background:linear-gradient(to top,transparent 32%,var(--line) 33%,transparent 34%,transparent 65%,var(--line) 66%,transparent 67%)}.countergroup{flex:1;min-width:58px;display:grid;grid-template-rows:1fr 25px;gap:5px;text-align:center}.counterbars{display:flex;align-items:end;justify-content:center;gap:4px}.counterbars i{display:block;width:min(22px,38%);min-height:2px;border-radius:2px 2px 0 0}.counterrx{background:var(--traffic-rx)}.countertx{background:var(--traffic-tx)}.counterbars i.idle{background:#cbd0cd}.counterkey{display:inline-block;width:10px;height:8px;border-radius:1px;margin-right:5px}.counterkey.rx{background:var(--traffic-rx)}.counterkey.tx{background:var(--traffic-tx)}
.historychart{height:176px;display:flex;align-items:stretch;gap:4px;overflow-x:auto;padding:10px 4px 0;border-bottom:1px solid var(--line);background:linear-gradient(to top,transparent 32%,var(--line) 33%,transparent 34%,transparent 65%,var(--line) 66%,transparent 67%)}.historybucket{flex:1;min-width:12px;display:grid;grid-template-rows:1fr 19px;gap:3px;text-align:center}.historybars{display:flex;align-items:end;justify-content:center;gap:2px;min-height:0}.historybars i{display:block;min-height:1px;border-radius:2px 2px 0 0}.historytotal{width:min(24px,72%);background:#4ba477}.historyrx,.historytx{width:min(13px,42%)}.historyrx{background:var(--traffic-rx)}.historytx{background:var(--traffic-tx)}.historymissing{height:100%!important;width:1px;border-radius:0!important;background:repeating-linear-gradient(to bottom,var(--line2) 0 3px,transparent 3px 7px)}.historyflag{font-size:8px;color:var(--warn);white-space:nowrap}.linkchart{display:grid;gap:0;border-top:1px solid var(--line);margin-top:8px}.linkcharthead,.linkchartrow{display:grid;grid-template-columns:minmax(170px,.8fr) minmax(220px,1.4fr) minmax(190px,.8fr);gap:18px;align-items:center;padding:9px 0;border-bottom:1px solid var(--line)}.linkcharthead{color:var(--dim);font-size:10px;font-weight:650;letter-spacing:.06em;text-transform:uppercase}.linkbartrack{display:block;height:12px;background:var(--card2);border:1px solid var(--line);border-radius:2px;margin-bottom:3px}.linkbarfill{display:block;height:100%;min-width:1px;background:#4ba477;border-radius:1px}
/* Overview follows the approved 1586 x 992 control-center composition. */
.page-overview .top{margin-bottom:0}.page-overview .top>.sp{display:none}.overview-health{display:flex;align-items:center;gap:8px;height:22px;margin:7px 0 19px;font-size:13px}.status-check{display:inline-flex;align-items:center;justify-content:center;width:14px;height:14px;border:1.5px solid currentColor;border-radius:50%;color:var(--ok);font-size:10px;font-weight:800;line-height:1}.status-check.warn{color:var(--warn)}.status-check.bad{color:var(--bad)}.page-overview .steps{height:82px}.page-overview .step{padding:15px 32px}.page-overview .step .label{color:var(--fg);font-size:13px;letter-spacing:0;text-transform:none}.page-overview .step b{font-size:17px;line-height:1.25;margin-top:2px}.page-overview .step b small{font-size:13px;font-weight:400}.page-overview .step .tiny{display:block;margin-top:1px}.page-overview .snapshot-verdict.converged{display:none}.overview-primary{display:grid;grid-template-columns:minmax(0,1.868fr) minmax(340px,1fr);gap:16px;height:380px;margin-top:18px}.overview-topology-card{height:380px;padding:12px 15px}.overview-card-head{display:flex;align-items:center;gap:18px;height:25px}.overview-card-head h2,.overview-compact-card h2,.overview-list-card h2,.overview-events h2{margin:0;color:var(--fg);font-size:16px;font-weight:700;letter-spacing:-.01em;text-transform:none}.overview-card-head .legend{margin:0 0 0 auto;gap:14px}.overview-topology-card .topology{height:325px;min-height:0}.overview-side{display:grid;grid-template-rows:155px 1fr;gap:14px}.overview-compact-card{padding:11px 17px;overflow:hidden}.overview-compact-card .sectionhead{height:23px;margin:0 0 6px}.traffic-compact-body{display:grid;grid-template-columns:165px minmax(0,1fr);gap:18px;align-items:end}.traffic-compact-body .metric{font-size:18px;margin:1px 0}.traffic-spark{height:59px;display:flex;align-items:end;gap:5px;padding:3px 3px 12px;border-top:1px solid var(--line);border-bottom:1px solid var(--line);background:linear-gradient(to top,transparent 48%,var(--line) 49%,transparent 50%)}.traffic-spark span{position:relative;flex:1;min-width:3px;max-width:18px;height:var(--height);min-height:2px;background:#73c39d;border-radius:2px 2px 0 0}.traffic-spark span:last-child{background:var(--ok)}.traffic-spark span.missing{height:100%;min-height:0;width:1px;flex:0 0 1px;border-radius:0;background:repeating-linear-gradient(to bottom,var(--line2) 0 3px,transparent 3px 7px)}.traffic-spark span.flagged{outline:1px dashed #d79b3b;outline-offset:2px}.traffic-spark span.flagged:after{content:attr(data-flag);position:absolute;top:-13px;left:50%;transform:translateX(-50%);font-size:8px;color:var(--warn)}.traffic-compact-scale{display:flex;justify-content:space-between;margin-top:2px;color:var(--dim);font-size:9px}.rollout-summary{font-size:13px}.rollout-summary b{font-size:14px}.rollout-stages{display:grid;grid-template-columns:repeat(4,1fr);margin-top:13px;position:relative}.rollout-stages:before{content:"";position:absolute;top:4px;left:7%;right:7%;height:1.5px;background:var(--ok)}.rollout-stage{position:relative;padding-top:15px;text-align:center;color:var(--dim);font-size:11px}.rollout-stage:before{content:"";position:absolute;top:0;left:calc(50% - 4px);width:8px;height:8px;border-radius:50%;background:var(--ok)}.overview-secondary{display:grid;grid-template-columns:minmax(0,1.185fr) minmax(0,1fr);gap:16px;height:203px;margin-top:12px}.overview-list-card{height:203px;padding:11px 18px;overflow:hidden}.overview-list-card .sectionhead{height:24px;margin:0}.overview-list-card table{font-size:12px}.overview-list-card th{padding:3px 7px 4px 0;font-size:10px;text-transform:none;letter-spacing:0}.overview-list-card td{height:27px;padding:3px 7px 3px 0}.overview-list-card .dot{width:7px;height:7px;margin-right:10px;color:#72c69f}.overview-events{height:111px;margin-top:12px;padding:11px 18px}.overview-events .sectionhead{height:22px;margin:0 0 3px}.overview-event-row{display:grid;grid-template-columns:46px 9px minmax(0,1fr);gap:7px;align-items:center;height:23px;font-size:12px}.overview-event-row .dot{width:7px;height:7px;color:#72c69f}.overview-event-row time{color:var(--dim);font-family:var(--font-mono)}.overview-attention{margin-top:12px}.overview-attention .issue{padding:8px 10px}.page-overview>.section{margin-top:22px}
.overview-events .sectionhead>a{white-space:nowrap}.overview-event-row{min-width:0;overflow:hidden}.overview-event-row .clip{display:block;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
@media(max-width:1180px){.brand{flex-basis:auto}.nav a{padding:0 7px}.headmeta .env{display:none}.span3{grid-column:span 6}.split{grid-template-columns:1fr}}
@media(max-width:1180px){.overview-primary{grid-template-columns:minmax(0,1.5fr) minmax(320px,1fr)}.overview-card-head .legend{display:none}.overview-secondary{grid-template-columns:1fr 1fr}}
@media(max-width:1040px){.services-summary{grid-template-columns:repeat(2,minmax(0,1fr))}.services-summary-item:nth-child(2){border-right:0}.services-summary-item:nth-child(-n+2){border-bottom:1px solid var(--line)}.services-workspace{grid-template-columns:1fr}.service-catalog-list{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr))}.service-catalog-list>a{min-width:0;border-right:1px solid var(--line)}.service-catalog-list .catalogrow{height:100%;border-bottom:0}.service-primary-fields{grid-template-columns:minmax(160px,.8fr) minmax(190px,1fr) minmax(210px,1fr)}}
@media(max-width:960px){.topology-edge-grid{grid-template-columns:1fr}}
@media(max-width:760px){.header{height:auto;min-height:51px;flex-wrap:wrap;padding:8px 12px;gap:5px 14px}.nav{order:3;width:100%;height:42px}.headmeta{margin-left:auto}.main{padding:22px 13px 44px}.top{display:block}.top .sp{margin:12px 0 0}.span3,.span4,.span5,.span6,.span7,.span8,.span9{grid-column:1/-1}.fields{grid-template-columns:1fr}.field.span2,.field.span3,.field.span4,.field.span6,.field.span8,.field.span12{grid-column:auto}.steps{display:grid}.step{border-right:0;border-bottom:1px solid var(--line)}td,th{white-space:normal}.hide-mobile{display:none}.linkcharthead{display:none}.linkchartrow{grid-template-columns:1fr;gap:5px}.historybucket{min-width:10px}.current-counter-head{display:none}.current-counter-row{grid-template-columns:1fr repeat(3,minmax(62px,auto));column-gap:12px}.current-counter-row:first-of-type{border-top:0}.current-counter-interface{display:grid;gap:0}.current-counter-value{display:grid;justify-items:end;gap:0}.current-counter-track{grid-column:1/-1}.current-counter-summary{display:grid;gap:2px}.current-counter-summary strong{grid-row:1}.page-overview .steps,.overview-primary,.overview-secondary{height:auto;display:grid;grid-template-columns:1fr}.page-overview .step{padding:12px 15px}.overview-topology-card{height:auto;overflow-x:auto}.overview-topology-card .topology{width:780px;height:300px}.overview-side{grid-template-rows:auto}.overview-secondary{height:auto}.overview-list-card{height:auto;max-height:300px}.overview-events{height:auto}.traffic-compact-body{grid-template-columns:130px minmax(0,1fr)}.edge-panel-head{min-height:0}.topology-edge-card{overflow-x:auto}.route-hop{grid-template-columns:1fr}.route-hop-state,.route-hop-meta{grid-column:1}}
@media(max-width:760px){.services-summary{grid-template-columns:repeat(2,minmax(0,1fr))}.services-summary-item{padding:10px 12px}.services-summary-item .metric{font-size:18px}.services-summary-item>.dim{white-space:normal}.services-flow{flex-wrap:wrap;gap:4px 7px}.services-flow-label{flex-basis:100%}.service-catalog-list{display:flex;overflow-x:auto;scroll-snap-type:x proximity}.service-catalog-list>a{flex:0 0 235px;scroll-snap-align:start}.service-primary-fields{grid-template-columns:1fr}.service-editor-body{padding:14px}.service-form-actions{display:grid}.service-form-actions>.toolbar{width:100%;margin-left:0}.service-form-actions .button,.service-form-actions button{flex:1;min-height:42px}.service-danger{align-items:flex-start;flex-direction:column}.service-danger form{margin-left:0}.services-policy-library>summary small{display:none}.services-policy-library>summary>.sp{font-size:10px}.policy-grid{grid-template-columns:1fr}.node-ingress-heading{align-items:flex-start;flex-direction:column;gap:5px}.node-ingress-heading>.small{margin-left:0}}
@media(max-width:760px){.status-alert{grid-template-columns:26px minmax(0,1fr);align-items:start}.status-alert-note{grid-column:2;max-width:none;text-align:left}.status-alert-title{display:block}.status-alert-title span{display:block;margin-top:1px}.snapshot-group{align-items:flex-start;flex-direction:column;gap:0}}
.topology-layout{align-items:start}.topology-stage{align-self:start}.topology-layer-note{display:grid;grid-template-columns:auto minmax(0,1fr) auto;align-items:start;column-gap:9px;row-gap:0}.topology-layer-summary{display:grid;gap:1px;min-width:0}.topology-layer-summary b{color:var(--fg);font-size:11px;font-weight:650}.topology-layer-summary span{line-height:1.45}.topology-evidence-details{min-width:0}.topology-evidence-details>summary{display:flex;align-items:center;gap:5px;cursor:pointer;list-style:none;color:var(--info);font-size:10px;white-space:nowrap}.topology-evidence-details>summary::-webkit-details-marker{display:none}.topology-evidence-details>summary:after{content:"＋";font-size:11px}.topology-evidence-details[open]{grid-column:2/-1;margin-top:4px}.topology-evidence-details[open]>summary{margin-bottom:4px}.topology-evidence-details[open]>summary:after{content:"−"}.topology-evidence-details p{margin:0;line-height:1.55}.topology-status-card{padding:14px}.topology-status-head{display:flex;align-items:flex-start;gap:10px;padding-bottom:11px;border-bottom:1px solid var(--line)}.topology-status-head h2{margin:0}.topology-status-head>div{display:grid;gap:2px;min-width:0}.topology-status-head>div>span{color:var(--dim);font-size:9px;line-height:1.35}.topology-status-head>.badge{margin-left:auto;padding:3px 7px;white-space:nowrap;font-size:9px}.topology-status-head>.badge .dot{width:6px;height:6px}.topology-carrier-status{display:grid;grid-template-columns:minmax(0,1fr) auto;align-items:end;gap:12px;padding:12px 0 11px}.topology-carrier-status .metric{margin:3px 0 0;font-size:22px}.topology-status-source{display:grid;justify-items:end;padding-bottom:3px;text-align:right}.topology-status-source b{font-size:11px}.topology-status-source span{color:var(--dim);font-size:9px}.topology-status-grid{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);border-top:1px solid var(--line)}.topology-status-item{min-width:0;padding:11px 10px 0 0}.topology-status-item+div{padding-right:0;padding-left:12px;border-left:1px solid var(--line)}.topology-status-item .metric{margin:3px 0;font-size:18px}.topology-status-item .metric small{font-size:10px}.topology-status-item>.dim{font-size:9px;line-height:1.4}.automatic-routing-card{padding:14px 14px 11px}.automatic-routing-card>p{margin:4px 0 8px}.automatic-route-row{padding:9px 0}.automatic-routing-all{margin-top:8px}.automatic-routing-card .empty{margin-top:8px}.automatic-routing-card .automatic-route-list+.automatic-routing-all{margin-top:8px}
.routing-summary .card{padding:14px 16px}.routing-scopes{margin-top:20px}.routing-entry-grid{margin-bottom:16px}.routing-decision-card{padding:0;overflow-x:auto}.routing-decision-head{margin:0;padding:14px 16px 11px;border-bottom:1px solid var(--line)}.routing-decision-table{min-width:980px}.routing-decision-table th:first-child,.routing-decision-table td:first-child{padding-left:16px}.routing-decision-table th:last-child,.routing-decision-table td:last-child{padding-right:16px}.routing-decision-table td{padding-top:12px;padding-bottom:12px}.route-text{color:var(--route)}.routing-candidate-card{overflow-x:auto}.routing-candidate-card table{min-width:720px}
.topology .route-local-exit{pointer-events:none;transition:opacity .16s ease}.topology .route-local-exit rect{stroke-width:1}.topology .route-local-exit text{fill:var(--route);stroke:none;font-family:Inter,ui-sans-serif,system-ui;font-size:8px;font-weight:700;letter-spacing:.045em}.topology.has-focus .route-local-exit{opacity:.12}
.clients-summary{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));overflow:hidden;margin-bottom:14px;padding:0}.clients-summary-item{padding:14px 18px;border-right:1px solid var(--line)}.clients-summary-item:last-child{border-right:0}.clients-summary-item .metric{font-size:21px}.clients-layout{display:grid;grid-template-columns:minmax(0,1fr);align-items:start;gap:14px}.clients-list-card{padding:0;overflow:hidden}.clients-card-head{display:flex;align-items:center;gap:12px;padding:14px 16px;border-bottom:1px solid var(--line)}.clients-card-head h2{margin:0;color:var(--fg);font-size:15px;letter-spacing:-.01em;text-transform:none}.clients-card-head p{margin:1px 0 0;font-size:10px}.clients-table-scroll{overflow-x:auto}.clients-table{min-width:960px;table-layout:fixed}.clients-table th,.clients-table td{padding:12px 16px;white-space:normal;overflow-wrap:anywhere}.client-col-device{width:22%}.client-col-membership{width:11%}.client-col-responsibilities{width:14%}.client-col-grants{width:22%}.client-col-seen{width:112px}.client-time{display:inline-block;white-space:nowrap;font-size:11px;line-height:1.6}.client-time-zone{display:block;font-size:9px;font-weight:400;letter-spacing:0}.client-runtime-detail{display:block;margin-top:4px}.clients-table th:first-child,.clients-table td:first-child{padding-left:16px}.clients-table th:last-child,.clients-table td:last-child{padding-right:16px}.client-name{display:grid;min-width:0;gap:3px}.client-name b{font-size:12px}.client-name span{font-size:10px}.client-status{display:inline-flex;align-items:center;gap:6px}.client-status .dot{width:6px;height:6px;flex-shrink:0}.client-platform{display:inline-flex;align-items:center;min-width:65px}.device-tag-list{display:flex;flex-wrap:wrap;gap:4px;white-space:normal}.device-tag{display:inline-flex;align-items:center;padding:3px 7px;border:1px solid var(--line);border-radius:999px;background:var(--card2);color:var(--fg);font:500 10px var(--font-mono);line-height:1.2;white-space:nowrap}.device-membership{display:flex;align-items:center;gap:8px;white-space:nowrap}.device-pause-action{display:flex;flex-shrink:0;margin:0}.device-pause-action .button{display:inline-flex;align-items:center;justify-content:center;width:28px;height:28px;padding:0}.device-pause-action svg{display:block;flex-shrink:0}.device-archive-notice{margin-bottom:14px}.device-join-actions{margin-top:14px}.device-join-actions p{max-width:760px}.device-join-actions summary{cursor:pointer;font-weight:650}.device-rejoin-confirm{display:flex;align-items:flex-start;gap:8px;margin:14px 0}.device-rejoin-confirm input{width:auto;margin-top:4px;flex-shrink:0}.device-delete-form{display:flex;align-items:center;gap:10px}.device-delete-confirm{display:flex;align-items:flex-start;gap:7px;max-width:480px}.device-delete-confirm input{width:auto;margin-top:2px;flex-shrink:0}.client-empty{padding:34px 18px;text-align:center}.client-empty b{display:block;margin-bottom:3px}.linux-delivery{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}.linux-package{display:grid;gap:12px}.linux-package-head{display:flex;align-items:flex-start;gap:12px}.linux-package-head h2{margin:0 0 3px;color:var(--fg);font-size:15px;letter-spacing:-.01em;text-transform:none}.linux-package-meta{display:grid;grid-template-columns:auto minmax(0,1fr);gap:5px 12px;padding-top:10px;border-top:1px solid var(--line);font-size:10px}.linux-package-meta dt{color:var(--dim);text-transform:uppercase}.linux-package-meta dd{min-width:0;margin:0;overflow-wrap:anywhere}.linux-install summary{cursor:pointer;list-style:none;font-weight:650}.linux-install summary::-webkit-details-marker{display:none}.linux-install summary:after{content:"＋";float:right;color:var(--dim)}.linux-install[open] summary:after{content:"−"}.linux-install ol{margin:12px 0 0;padding-left:18px}.linux-install li{margin:9px 0}.command-block{display:block;margin-top:5px;padding:8px 10px;overflow-x:auto;border:1px solid var(--line);border-radius:5px;background:var(--card2);font-size:10px;line-height:1.55;white-space:pre}.client-add-grid,.client-invite-grid{display:grid;grid-template-columns:minmax(320px,.8fr) minmax(0,1.2fr);gap:14px}.client-add-grid{align-items:start}.client-invite-grid{align-items:stretch}.client-form-card h2,.client-invite-copy h2{color:var(--fg);font-size:15px;letter-spacing:-.01em;text-transform:none}.client-form-card p{margin:0 0 15px}.client-form-actions{display:flex;align-items:center;gap:8px;margin-top:18px}.client-boundary{display:grid;gap:0}.client-boundary>div{display:grid;grid-template-columns:105px minmax(0,1fr);gap:12px;padding:10px 0;border-bottom:1px solid var(--line);font-size:11px}.client-boundary>div:last-child{border-bottom:0}.client-boundary span{color:var(--dim)}.client-invite-qr{display:grid;justify-items:center;gap:11px;text-align:center}.client-invite-qr img{display:block;width:min(100%,250px);aspect-ratio:1;padding:10px;border:1px solid var(--line);border-radius:8px;background:#fff}.client-invite-qr p{max-width:300px;margin:0}.client-invite-copy{display:grid;align-content:start;gap:14px}.invite-link{display:flex;align-items:stretch;gap:8px}.invite-link input{flex:1 1 auto;width:100%;min-width:0;font:11px var(--font-mono)}.invite-link .button{display:flex;align-items:center;white-space:nowrap}.client-invite-expiry{display:flex;align-items:flex-start;gap:9px;padding:10px;border-radius:6px;background:var(--warnsoft);color:var(--warn);font-size:11px}.client-invite-expiry .dot{margin-top:5px}.client-invite-actions{display:flex;flex-wrap:wrap;align-items:stretch;gap:8px}.client-done-form{display:flex;margin:0}.client-done-form .button{height:100%}.client-setup{display:grid;gap:14px;margin-top:14px}.client-setup-head{display:flex;align-items:flex-end;justify-content:space-between;gap:20px;padding-bottom:12px;border-bottom:1px solid var(--line)}.client-setup-head h2{margin:1px 0 0;color:var(--fg);font-size:16px;letter-spacing:-.01em;text-transform:none}.client-setup-head p{max-width:560px;margin:0;text-align:right}.client-setup-prepare{display:grid;grid-template-columns:minmax(230px,.55fr) minmax(0,1.45fr);align-items:center;gap:16px}.client-setup-prepare>div,.client-method-title{display:flex;align-items:flex-start;gap:10px}.client-setup-prepare b,.client-setup-prepare span{display:block}.client-step{display:inline-flex!important;align-items:center;justify-content:center;min-width:28px;height:28px;border-radius:999px;background:var(--oksoft);color:var(--ok);font:700 10px var(--font-mono)}.client-setup-methods{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));overflow:hidden;border:1px solid var(--line);border-radius:7px}.client-setup-method{min-width:0;padding:14px}.client-setup-method+ .client-setup-method{border-left:1px solid var(--line)}.client-setup-method h3{display:inline-block;margin:0 8px 0 0;font-size:13px}.client-setup-method p{margin:8px 0 0}.client-method-title>div{min-width:0}.client-setup-boundary{display:flex;align-items:baseline;gap:9px;padding-top:12px;border-top:1px solid var(--line);font-size:11px}.client-setup-boundary span{color:var(--dim)}.client-invite-qr{display:grid;justify-items:center;gap:11px;text-align:center}.client-invite-qr img{display:block;width:min(100%,250px);aspect-ratio:1;padding:10px;border:1px solid var(--line);border-radius:8px;background:#fff}.client-invite-copy{display:grid;align-content:start;gap:14px}.invite-link{display:flex;align-items:stretch;gap:8px}.invite-link input{flex:1 1 auto;width:100%;min-width:0;font:11px var(--font-mono)}.invite-link .button{display:flex;align-items:center;white-space:nowrap}.client-invite-expiry{display:flex;align-items:flex-start;gap:9px;padding:10px;border-radius:6px;background:var(--warnsoft);color:var(--warn);font-size:11px}.client-invite-expiry .dot{margin-top:5px}.client-invite-actions{display:flex;flex-wrap:wrap;align-items:stretch;gap:8px}.client-done-form{display:flex;margin:0}.client-done-form .button{height:100%}.client-setup{display:grid;gap:14px;margin-top:14px}.client-setup-head{display:flex;align-items:flex-end;justify-content:space-between;gap:20px;padding-bottom:12px;border-bottom:1px solid var(--line)}.client-setup-head h2{margin:1px 0 0;color:var(--fg);font-size:16px;letter-spacing:-.01em;text-transform:none}.client-setup-head p{max-width:560px;margin:0;text-align:right}.client-setup-prepare{display:grid;grid-template-columns:minmax(230px,.55fr) minmax(0,1.45fr);align-items:center;gap:16px}.client-setup-prepare>div,.client-method-title{display:flex;align-items:flex-start;gap:10px}.client-setup-prepare b,.client-setup-prepare span{display:block}.client-step{display:inline-flex!important;align-items:center;justify-content:center;min-width:28px;height:28px;border-radius:999px;background:var(--oksoft);color:var(--ok);font:700 10px var(--font-mono)}.client-setup-methods{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));overflow:hidden;border:1px solid var(--line);border-radius:7px}.client-setup-method{min-width:0;padding:14px}.client-setup-method+ .client-setup-method{border-left:1px solid var(--line)}.client-setup-method h3{display:inline-block;margin:0 8px 0 0;font-size:13px}.client-setup-method p{margin:8px 0 0}.client-method-title>div{min-width:0}.client-setup-boundary{display:flex;align-items:baseline;gap:9px;padding-top:12px;border-top:1px solid var(--line);font-size:11px}.client-setup-boundary span{color:var(--dim)}.client-setup-blocked{margin:0}
.client-invite-qr-copy{display:block;justify-self:center;width:min(100%,250px);padding:0;border:0;background:transparent;color:inherit}.client-invite-qr-copy:hover{border:0;background:transparent}.client-invite-qr-copy:focus-visible{outline:2px solid #b9dfcd;outline-offset:4px}.client-invite-qr-copy img{display:block;width:100%;aspect-ratio:1;padding:10px;border:1px solid var(--line);border-radius:8px;background:#fff}
@media(max-width:760px){.device-delete-form{display:grid;width:100%}.device-delete-form .danger-button{min-height:42px}}
@media(max-width:1180px) and (min-width:761px){.topology-layout>.topology-stage,.topology-layout>.topology-side{grid-column:1/-1}.topology-layout>.topology-side{grid-template-columns:minmax(280px,.82fr) minmax(0,1.18fr)}}
.client-choice-group{display:grid;gap:8px;padding:0;border:0}.client-choice-group legend{margin-bottom:5px;font-weight:650}.client-choice-group label{display:flex;align-items:flex-start;gap:8px;padding:8px 10px;border:1px solid var(--line);border-radius:6px;background:var(--card2);font:500 11px var(--font-mono)}.client-choice-group input{width:auto;margin-top:3px}.client-choice-group label span{display:grid}.client-choice-group small{font-size:9px}
@media(max-width:960px){.clients-layout,.client-invite-grid{grid-template-columns:1fr}.linux-delivery{grid-template-columns:1fr 1fr}.client-add-grid{grid-template-columns:1fr}}
@media(max-width:760px){.topology-layer-note{grid-template-columns:auto minmax(0,1fr)}.topology-evidence-details{grid-column:2}.topology-status-head{align-items:flex-start}.topology-status-grid{grid-template-columns:1fr 1fr}}
@media(max-width:760px){.clients-summary{grid-template-columns:1fr}.clients-summary-item{border-right:0;border-bottom:1px solid var(--line)}.clients-summary-item:last-child{border-bottom:0}.clients-list-card{overflow-x:auto}.linux-delivery{grid-template-columns:1fr}.client-form-actions,.client-invite-actions{display:grid}.client-form-actions .button,.client-form-actions button,.client-invite-actions .button{justify-content:center;min-height:42px}.client-done-form,.client-done-form .button{width:100%}.invite-link{display:grid}.invite-link .button{justify-content:center}.client-invite-qr img{width:190px}.client-setup-head{display:grid;gap:5px}.client-setup-head p{text-align:left}.client-setup-prepare{grid-template-columns:1fr}.client-setup-methods{grid-template-columns:1fr}.client-setup-method+ .client-setup-method{border-top:1px solid var(--line);border-left:0}.client-setup-boundary{display:grid;gap:3px}}
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
	case title == "登录":
		auth = `<span class=dim>Operator access</span>`
	case d.Operator != "" && (len(d.Actions) > 0 || d.Control != nil):
		auth = `<a href="` + esc(loginURL(shellLoginReturnTo(d, title))) + `">Operator sign in</a>`
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
	pageScripts := ""
	if strings.Contains(body, "data-submit-progress") {
		pageScripts += `<script>` + progressSubmitScript + `</script>`
	}
	if strings.Contains(body, "data-device-enrollment-form") {
		pageScripts += `<script>` + deviceEnrollmentScript + `</script>`
	}
	if strings.Contains(body, "data-copy-target") {
		pageScripts += `<script>` + copyValueScript + `</script>`
	}
	if strings.Contains(body, `<svg class=topology`) {
		pageScripts += `<script>` + topologyInteractionScript + `</script>`
	}
	pageClass := "page-" + active
	return fmt.Sprintf(`<!doctype html><meta charset=utf-8><title>%s · LOOM</title><link rel=icon href="/favicon.svg?v=9" type="image/svg+xml">
<meta name=viewport content="width=device-width,initial-scale=1">%s%s
<div class=app><header class=header><a class=brand href="/" aria-label="LOOM overview">%s<span>LOOM</span></a>
<nav class=nav aria-label="Primary">%s</nav><div class=headmeta><span class="env dim"><span class=dot></span>Live evidence</span><span>%s</span></div></header>
<main class="main %s"><div class=top><div><div class=eyebrow>%s</div><h1>%s</h1><div class=subtitle>%s</div></div><div class=sp>%s</div></div>%s</main></div>%s`,
		esc(heading), refresh, style, logoSVG(), navHTML.String(), auth,
		esc(pageClass), esc(eyebrow), esc(heading), esc(subtitle), esc(d.Node)+` · `+esc(role), body, pageScripts)
}

func shellLoginReturnTo(d Deps, title string) string {
	if strings.HasPrefix(title, "Node · ") {
		nodeID := strings.TrimSpace(strings.TrimPrefix(title, "Node · "))
		if nodeID != "" {
			return "/nodes/" + url.PathEscape(nodeID)
		}
	}
	active := navActive(title)
	for _, item := range primaryNavigation(d) {
		if item.key == active {
			return item.href
		}
	}
	return "/"
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
			{label: "This device", href: "/nodes/" + url.PathEscape(d.Node), key: "devices"},
			{label: "Topology", href: "/topology", key: "topology"},
			{label: "Live paths", href: "/routing", key: "routing"},
		}
	}
	return []navigationItem{
		{label: "Overview", href: "/", key: "overview"},
		{label: "Devices", href: "/devices", key: "devices", group: "Network"},
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
	case strings.Contains(t, "device") || strings.Contains(t, "node") || strings.Contains(t, "client") || strings.Contains(title, "设备") || strings.Contains(title, "节点") || strings.Contains(title, "客户端"):
		return "devices"
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
	case strings.Contains(t, "setting") || strings.Contains(t, "ssot") || strings.Contains(title, "配置"):
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
	case "Devices":
		return "FLEET / DEVICES", "Devices", "Identity, membership, responsibilities and runtime evidence in one inventory"
	case "Clients":
		return "FLEET / DEVICES", "Devices", "Compatibility view for the unified Device inventory"
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
	return faviconAsset
}

func pageLogin(d Deps, errMsg, returnTo string) string {
	msg := ""
	if errMsg != "" {
		msg = `<p class=bad>` + esc(errMsg) + `</p>`
	}
	return shell(d, "登录", fmt.Sprintf(`
<div class=card>
%s<form method=post action=/login>
<input type=hidden name=next value="%s">
<input type=password name=password placeholder="运维口令" autofocus> <button>登录</button>
</form>
<p class=small>Sign-in will return to <code>%s</code>.</p>
<p class=dim>口令来自本机秘密层的 <code>ui/%s</code>。<br>
读页面不需要登录 —— 能连到这里,你已经过了 WireGuard 或 ssh 那一关。<br>
<b>写操作需要</b>:任何节点都能到任何节点的隧道地址,一台被拿下就能去动别人。</p>
</div>`, msg, esc(returnTo), esc(returnTo), esc(d.Node)), false)
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

type svgRect struct {
	minX, minY, maxX, maxY float64
}

type topologyObstacle struct {
	node   string
	bounds svgRect
}

type topologyPoint struct {
	x, y, angle float64
	ring        string
}

type topologyCurve struct {
	d     string
	label svgPoint
}

func topologySVG(v View, routeOverlay ...RouteView) string {
	// Nodes that can accept a reverse connection form the inner anchor ring;
	// reverse-only nodes form the outer egress ring. The half-step rotation keeps
	// equal-sized rings from stacking on the same radial axes. If an old/local
	// reporter has no direction metadata, keep a deterministic fallback split.
	ids := make([]string, 0, len(v.Nodes))
	inner, outer := []string{}, []string{}
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
			outer = append(outer, n.ID)
		} else {
			inner = append(inner, n.ID)
		}
	}
	sort.SliceStable(inner, func(i, j int) bool {
		a, z := nodes[inner[i]], nodes[inner[j]]
		if a.Self != z.Self {
			return a.Self
		}
		return a.ID < z.ID
	})
	sort.SliceStable(outer, func(i, j int) bool {
		return outer[i] < outer[j]
	})
	if len(outer) == 0 && len(inner) > 1 {
		cut := (len(inner) + 1) / 2
		outer = append(outer, inner[cut:]...)
		inner = inner[:cut]
	}
	pos := map[string]topologyPoint{}
	topologyRingPositions(pos, inner, "inner", -90, 170, 75)
	outerOffset := -90.0
	if len(outer) > 0 {
		outerOffset += 180 / float64(len(outer))
	}
	topologyRingPositions(pos, outer, "outer", outerOffset, 310, 130)

	var b strings.Builder
	b.WriteString(`<svg class=topology viewBox="0 0 960 360" role=group aria-label="Near-real-time interactive concentric network topology"><defs><marker id=arrow viewBox="0 0 10 10" refX=8 refY=5 markerWidth=5 markerHeight=5 orient=auto-start-reverse><path d="M 0 0 L 10 5 L 0 10 z" fill="#466fc2"/></marker></defs>`)
	b.WriteString(`<ellipse class="topology-ring outer" cx=480 cy=180 rx=310 ry="130"/><ellipse class="topology-ring inner" cx=480 cy=180 rx=170 ry="75"/>`)
	b.WriteString(`<circle class=ring-dot cx=18 cy=18 r="3"/><text class=ring-key x=28 y=21>内圈：可接受反向建连的锚点</text><circle class=ring-dot cx=18 cy=35 r="3"/><text class=ring-key x=28 y=38>外圈：反向接入的出口节点</text><text class=ring-key text-anchor=end x=942 y=21>悬停预览 · 点击锁定 · Esc 取消</text>`)
	curves := map[string]topologyCurve{}
	curveStarts := map[string]string{}
	metricPositions := topologyMetricPositions(v.Links, pos, nodes)
	var metricLabels strings.Builder
	for _, l := range v.Links {
		a, aok := pos[l.From]
		z, zok := pos[l.To]
		if !aok || !zok {
			continue
		}
		edgeKind := "tunnel"
		switch l.Kind {
		case "candidate", "direct-hy2":
			edgeKind = l.Kind
		}
		cls := edgeKind
		if l.State == "failed" {
			cls += " failed"
		} else if l.State == "degraded" {
			cls += " degraded"
		} else if l.State == "unknown" {
			cls += " unknown"
		}
		key := topologyLinkKey(l.From, l.To)
		curve := topologyEdgeCurve(a, z, key, l.Kind)
		labelPosition := curve.label
		if metricPosition, ok := metricPositions[key]; ok && edgeKind != "candidate" {
			labelPosition = metricPosition
		}
		curves[key] = curve
		curveStarts[key] = l.From
		if edgeKind == "candidate" {
			fmt.Fprintf(&b, `<g class="topology-edge edge-candidate" data-from="%s" data-to="%s"><title>%s ↔ %s；按需候选关系，不做连续 RTT 或流量观测；%s</title><path class="%s" d="%s"/><path class=edge-hit d="%s"/></g>`, esc(l.From), esc(l.To), esc(l.From), esc(l.To), esc(l.Source), cls, curve.d, curve.d)
			continue
		}
		metric, detail := topologyLinkMetric(l)
		fmt.Fprintf(&b, `<g class="topology-edge edge-%s" data-from="%s" data-to="%s"><title>%s</title><path class="%s" d="%s"/><path class=edge-hit d="%s"/></g>`, esc(edgeKind), esc(l.From), esc(l.To), esc(detail), cls, curve.d, curve.d)
		fmt.Fprintf(&metricLabels, `<g class=edge-metric data-from="%s" data-to="%s" transform="translate(%.1f %.1f)"><title>%s</title><text text-anchor=middle y=3>%s</text></g>`, esc(l.From), esc(l.To), labelPosition.x, labelPosition.y, esc(detail), esc(metric))
	}
	seenRouteEdges := map[string]bool{}
	directNodes := map[string]bool{}
	for _, r := range routeOverlay {
		if r.Stale {
			continue
		}
		if len(r.Chain) <= 1 && r.Node != "" {
			directNodes[r.Node] = true
			continue
		}
		for i := 0; i+1 < len(r.Chain); i++ {
			from, to := r.Chain[i], r.Chain[i+1]
			directedKey := from + "\x00" + to
			if seenRouteEdges[directedKey] {
				continue
			}
			seenRouteEdges[directedKey] = true
			a, aok := pos[from]
			z, zok := pos[to]
			if aok && zok {
				key := topologyLinkKey(from, to)
				curve, ok := curves[key]
				if !ok {
					curve = topologyEdgeCurve(a, z, key, "tunnel")
				}
				marker := `marker-end="url(#arrow)"`
				if ok && curveStarts[key] != from {
					marker = `marker-start="url(#arrow)"`
				}
				fmt.Fprintf(&b, `<path class=route %s d="%s"/>`, marker, curve.d)
			}
		}
	}
	directIDs := make([]string, 0, len(directNodes))
	for id := range directNodes {
		directIDs = append(directIDs, id)
	}
	sort.Strings(directIDs)
	for _, id := range directIDs {
		p, ok := pos[id]
		if !ok {
			continue
		}
		// A zero-hop decision has no topology edge. Mark the access node with a
		// compact endpoint badge instead of drawing a synthetic short arrow: a
		// local exit is a terminal state, not another hop or hidden target node.
		fmt.Fprintf(&b, `<g class=route-local-exit transform="translate(%.1f %.1f)"><title>%s exits locally</title><rect width=82 height=19 rx=9.5 fill="#f5f7fc" stroke="#b9c9e9"/><circle cx=10 cy=9.5 r=3 fill="#466fc2"/><text x=18 y=13 fill="#466fc2" font-family="Inter,ui-sans-serif,system-ui" font-size=8 font-weight=700>LOCAL EXIT</text></g>`, p.x+14, p.y+10, esc(id))
	}
	b.WriteString(metricLabels.String())
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
		nodeLabel := id + " · " + topologyNodeSubtitle(n)
		fmt.Fprintf(&b, `<g class=topology-node data-node="%s" data-ring="%s" data-angle="%.1f" role=button tabindex="0" aria-pressed="false" aria-label="%s，点击聚焦相邻链路"><title>%s</title><circle class=node-hit cx="%.1f" cy="%.1f" r="16"/><circle class=node-focus cx="%.1f" cy="%.1f" r="11"/><circle class="%s" cx="%.1f" cy="%.1f" r="6"/>`, esc(id), p.ring, p.angle, esc(nodeLabel), esc(nodeLabel), p.x, p.y, p.x, p.y, cls, p.x, p.y)
		x, titleY, subY, anchor := topologyLabelPosition(p)
		fmt.Fprintf(&b, `<text class=node-label text-anchor=%s x="%.1f" y="%.1f">%s</text><text class="sub node-label" text-anchor=%s x="%.1f" y="%.1f">%s</text></g>`, anchor, x, titleY, esc(id), anchor, x, subY, esc(topologyNodeSubtitle(n)))
	}
	if len(ids) == 0 {
		b.WriteString(`<text class=sub text-anchor=middle x=480 y=183>No topology observations</text>`)
	}
	b.WriteString(`</svg>`)
	return b.String()
}

func topologyRingPositions(pos map[string]topologyPoint, ids []string, ring string, offset, rx, ry float64) {
	if len(ids) == 0 {
		return
	}
	for i, id := range ids {
		angle := offset + float64(i)*360/float64(len(ids))
		radians := angle * math.Pi / 180
		pos[id] = topologyPoint{
			x: 480 + rx*math.Cos(radians), y: 180 + ry*math.Sin(radians),
			angle: angle, ring: ring,
		}
	}
}

func topologyLinkKey(from, to string) string {
	if to < from {
		from, to = to, from
	}
	return from + "\x00" + to
}

func topologyEdgeCurve(a, z topologyPoint, key, kind string) topologyCurve {
	if kind == "candidate" && a.ring == z.ring {
		rx, ry := 170.0, 75.0
		if a.ring == "outer" {
			rx, ry = 310, 130
		}
		delta := math.Mod(z.angle-a.angle+360, 360)
		sweep := 1
		if delta > 180 {
			delta = 360 - delta
			sweep = 0
		}
		large := 0
		if delta > 180 {
			large = 1
		}
		return topologyCurve{d: fmt.Sprintf("M %.1f %.1f A %.1f %.1f 0 %d %d %.1f %.1f", a.x, a.y, rx, ry, large, sweep, z.x, z.y)}
	}

	dx, dy := z.x-a.x, z.y-a.y
	distance := math.Hypot(dx, dy)
	if distance == 0 {
		return topologyCurve{d: fmt.Sprintf("M %.1f %.1f", a.x, a.y), label: svgPoint{x: a.x, y: a.y}}
	}
	hash := topologyStringHash(key)
	bend := float64(int(hash%7)-3) * 7
	if bend == 0 {
		bend = 4
	}
	cx := (a.x+z.x)/2 - dy/distance*bend
	cy := (a.y+z.y)/2 + dx/distance*bend
	t := .31 + float64((hash/7)%3)*.19
	x := (1-t)*(1-t)*a.x + 2*(1-t)*t*cx + t*t*z.x
	y := (1-t)*(1-t)*a.y + 2*(1-t)*t*cy + t*t*z.y
	tx := 2*(1-t)*(cx-a.x) + 2*t*(z.x-cx)
	ty := 2*(1-t)*(cy-a.y) + 2*t*(z.y-cy)
	tangent := math.Hypot(tx, ty)
	offset := 8.0
	if (hash/21)%2 == 0 {
		offset = -offset
	}
	if tangent > 0 {
		x += -ty / tangent * offset
		y += tx / tangent * offset
	}
	return topologyCurve{
		d:     fmt.Sprintf("M %.1f %.1f Q %.1f %.1f %.1f %.1f", a.x, a.y, cx, cy, z.x, z.y),
		label: svgPoint{x: x, y: y},
	}
}

// topologyMetricPositions keeps labels close to their continuous carrier
// curves without turning labels into routing vertices. It treats node markers,
// node labels and already placed metrics as obstacles, then tries several
// positions on both sides of the carrier. Verified direct Hy2 probes take the
// same collision-avoidance path as WG tunnels; candidate edges still have no
// metric.
func topologyMetricPositions(links []LinkView, positions map[string]topologyPoint, nodes map[string]NodeView) map[string]svgPoint {
	type lane struct {
		key, hubID string
		a, z       topologyPoint
		other      topologyPoint
		hubAtStart bool
		halfWidth  float64
	}
	groups := map[string][]lane{}
	for _, link := range links {
		if link.Kind != "tunnel" && link.Kind != "direct-hy2" {
			continue
		}
		a, aok := positions[link.From]
		z, zok := positions[link.To]
		if !aok || !zok {
			continue
		}
		metric, _ := topologyLinkMetric(link)
		item := lane{
			key: topologyLinkKey(link.From, link.To), a: a, z: z,
			halfWidth: topologyMetricHalfWidth(metric),
		}
		switch {
		case a.ring == "outer" && z.ring != "outer":
			item.hubID, item.other, item.hubAtStart = link.From, z, true
		case z.ring == "outer" && a.ring != "outer":
			item.hubID, item.other = link.To, a
		default:
			// A same-ring measured link still needs a stable hub for arranging its
			// labels. This does not change the probe or carrier direction.
			if link.From < link.To {
				item.hubID, item.other, item.hubAtStart = link.From, z, true
			} else {
				item.hubID, item.other = link.To, a
			}
		}
		groups[item.hubID] = append(groups[item.hubID], item)
	}
	hubIDs := make([]string, 0, len(groups))
	for hubID := range groups {
		hubIDs = append(hubIDs, hubID)
	}
	sort.Strings(hubIDs)
	out := map[string]svgPoint{}
	type placedMetric struct {
		bounds svgRect
	}
	placed := []placedMetric{}
	obstacles := topologyNodeObstacles(positions, nodes)
	for _, hubID := range hubIDs {
		lanes := groups[hubID]
		sort.Slice(lanes, func(i, j int) bool {
			if lanes[i].other.angle == lanes[j].other.angle {
				return lanes[i].key < lanes[j].key
			}
			return lanes[i].other.angle < lanes[j].other.angle
		})
		fractions := make([]float64, len(lanes))
		for i := range fractions {
			fractions[i] = .5
			if len(fractions) > 1 {
				// Keep the label centre away from both endpoint markers. Normal
				// offsets provide the remaining separation for a dense fan.
				fractions[i] = .32 + .36*float64(i)/float64(len(fractions)-1)
			}
		}
		maxInt := int(^uint(0) >> 1)
		bestNodeScore, bestMetricScore, bestPenalty := maxInt, maxInt, maxInt
		best := make([]svgPoint, len(lanes))
		normalOffsets := [...]float64{14, -14, 26, -26}
		normalVariants := 1
		for range lanes {
			if normalVariants > 1024/len(normalOffsets) {
				normalVariants = 1024
				break
			}
			normalVariants *= len(normalOffsets)
		}
		// Rotations in both directions cover all six permutations for the
		// current three-link fan while remaining bounded for larger degrees.
		for reverse := 0; reverse < 2; reverse++ {
			for shift := 0; shift < len(lanes); shift++ {
				for normalVariant := 0; normalVariant < normalVariants; normalVariant++ {
					candidate := make([]svgPoint, len(lanes))
					bounds := make([]svgRect, len(lanes))
					nodeScore, metricScore, penalty := 0, 0, 0
					normalCode := normalVariant
					for i, item := range lanes {
						fractionIndex := (i + shift) % len(lanes)
						if reverse == 1 {
							fractionIndex = len(lanes) - 1 - fractionIndex
						}
						penalty += int(math.Abs(float64(fractionIndex-i))) * 10
						t := 1 - fractions[fractionIndex]
						if item.hubAtStart {
							t = fractions[fractionIndex]
						}
						offsetIndex := normalCode % len(normalOffsets)
						normalCode /= len(normalOffsets)
						offset := normalOffsets[offsetIndex]
						penalty += int(math.Abs(offset))
						candidate[i] = topologyMetricPoint(item.a, item.z, item.key, t, offset)
						bounds[i] = topologyMetricBounds(candidate[i], item.halfWidth)
						for _, obstacle := range obstacles {
							if topologyRectsOverlap(bounds[i], obstacle.bounds) {
								nodeScore++
							}
						}
						for _, prior := range placed {
							if topologyRectsOverlap(bounds[i], prior.bounds) {
								metricScore++
							}
						}
					}
					for i := range candidate {
						for j := i + 1; j < len(candidate); j++ {
							if topologyRectsOverlap(bounds[i], bounds[j]) {
								metricScore++
							}
						}
					}
					if nodeScore < bestNodeScore ||
						nodeScore == bestNodeScore && metricScore < bestMetricScore ||
						nodeScore == bestNodeScore && metricScore == bestMetricScore && penalty < bestPenalty {
						bestNodeScore, bestMetricScore, bestPenalty = nodeScore, metricScore, penalty
						copy(best, candidate)
					}
				}
			}
		}
		for i, item := range lanes {
			out[item.key] = best[i]
			placed = append(placed, placedMetric{bounds: topologyMetricBounds(best[i], item.halfWidth)})
		}
	}
	return out
}

func topologyMetricPoint(a, z topologyPoint, key string, t, offset float64) svgPoint {
	dx, dy := z.x-a.x, z.y-a.y
	distance := math.Hypot(dx, dy)
	if distance == 0 {
		return svgPoint{x: a.x, y: a.y}
	}
	hash := topologyStringHash(key)
	bend := float64(int(hash%7)-3) * 7
	if bend == 0 {
		bend = 4
	}
	cx := (a.x+z.x)/2 - dy/distance*bend
	cy := (a.y+z.y)/2 + dx/distance*bend
	x := (1-t)*(1-t)*a.x + 2*(1-t)*t*cx + t*t*z.x
	y := (1-t)*(1-t)*a.y + 2*(1-t)*t*cy + t*t*z.y
	tx := 2*(1-t)*(cx-a.x) + 2*t*(z.x-cx)
	ty := 2*(1-t)*(cy-a.y) + 2*t*(z.y-cy)
	tangent := math.Hypot(tx, ty)
	if tangent > 0 {
		x += -ty / tangent * offset
		y += tx / tangent * offset
	}
	return svgPoint{x: x, y: y}
}

func topologyMetricHalfWidth(metric string) float64 {
	return topologyApproxTextWidth(metric, 8.8, true)/2 + 4
}

func topologyMetricBounds(point svgPoint, halfWidth float64) svgRect {
	// The text baseline is y=3 inside the translated group. This includes its
	// four-pixel white paint-order halo and a small scaling allowance.
	return svgRect{minX: point.x - halfWidth, minY: point.y - 9, maxX: point.x + halfWidth, maxY: point.y + 10}
}

func topologyNodeObstacles(positions map[string]topologyPoint, nodes map[string]NodeView) []topologyObstacle {
	obstacles := make([]topologyObstacle, 0, len(positions)*3)
	for id, point := range positions {
		obstacles = append(obstacles, topologyObstacle{node: id, bounds: svgRect{
			minX: point.x - 17, minY: point.y - 17, maxX: point.x + 17, maxY: point.y + 17,
		}})
		node, ok := nodes[id]
		if !ok {
			continue
		}
		x, titleY, subY, anchor := topologyLabelPosition(point)
		obstacles = append(obstacles,
			topologyObstacle{node: id, bounds: topologyTextBounds(x, titleY, topologyApproxTextWidth(id, 12, true), 12, anchor)},
			topologyObstacle{node: id, bounds: topologyTextBounds(x, subY, topologyApproxTextWidth(topologyNodeSubtitle(node), 10, false), 10, anchor)},
		)
	}
	return obstacles
}

func topologyTextBounds(x, baseline, width, fontSize float64, anchor string) svgRect {
	minX, maxX := x, x+width
	switch anchor {
	case "middle":
		minX, maxX = x-width/2, x+width/2
	case "end":
		minX, maxX = x-width, x
	}
	return svgRect{minX: minX - 3, minY: baseline - fontSize - 3, maxX: maxX + 3, maxY: baseline + 4}
}

func topologyApproxTextWidth(value string, fontSize float64, mono bool) float64 {
	width := 0.0
	for _, r := range value {
		if mono {
			width += fontSize * .61
			continue
		}
		switch {
		case r > 127:
			width += fontSize
		case r == ' ':
			width += fontSize * .34
		default:
			width += fontSize * .56
		}
	}
	return width
}

func topologyRectsOverlap(a, z svgRect) bool {
	return a.minX < z.maxX && a.maxX > z.minX && a.minY < z.maxY && a.maxY > z.minY
}

func topologyStringHash(value string) uint32 {
	var hash uint32 = 2166136261
	for _, r := range value {
		hash ^= uint32(r)
		hash *= 16777619
	}
	return hash
}

func topologyLabelPosition(p topologyPoint) (x, titleY, subY float64, anchor string) {
	radians := p.angle * math.Pi / 180
	cosine := math.Cos(radians)
	if math.Abs(cosine) < .35 {
		x, anchor = p.x, "middle"
		if math.Sin(radians) < 0 {
			return x, p.y - 20, p.y - 7, anchor
		}
		return x, p.y + 25, p.y + 40, anchor
	}
	if cosine < 0 {
		return p.x - 17, p.y - 2, p.y + 15, "end"
	}
	return p.x + 17, p.y - 2, p.y + 15, "start"
}

func topologyLinkMetric(l LinkView) (string, string) {
	latency := "—"
	if l.Samples > l.Failures && l.ObservedAt != "" {
		latency = fmt.Sprintf("%dms", l.MS)
	}
	variation := "Δ—"
	successfulQuality := l.QualityObservations - l.QualityFailed
	if successfulQuality >= 2 && l.QualityP95MS >= l.QualityP50MS {
		variation = fmt.Sprintf("Δ%dms", l.QualityP95MS-l.QualityP50MS)
	}
	if l.Kind == "direct-hy2" {
		rate := "—"
		if l.ProbeSamples > 0 && l.ProbeBytes > 0 && l.ProbeDurationMS > 0 {
			rate = topologyProbeBitRate(l.ProbeBytes, l.ProbeDurationMS)
		}
		from, to := strings.TrimSpace(l.ObservedFrom), strings.TrimSpace(l.ObservedTo)
		if from == "" {
			from = l.From
		}
		if to == "" {
			to = l.To
		}
		compact := latency + " · " + variation + " · " + rate
		detail := fmt.Sprintf("方向 %s→%s；公网 Hysteria2 单跳主动探测；Hy2 单跳响应延迟 %s；近 15 分钟探测延迟波动 %s（P95−P50；P50 %dms / P95 %dms，%d 次观测，%d 次失败）；主动探测速率 %s（固定响应 %d bytes / %dms，%d 个探测样本）；速率为固定响应的 achieved probe throughput，不是业务流量/容量；%s；%s",
			from, to, latency, variation,
			l.QualityP50MS, l.QualityP95MS, l.QualityObservations, l.QualityFailed,
			rate, l.ProbeBytes, l.ProbeDurationMS, l.ProbeSamples, l.Source, l.MetricsSource)
		return compact, detail
	}
	rate := "—"
	if l.RateSamples > 0 && l.RateWindowSeconds > 0 {
		rate = topologyBitRate(l.RecentTXBytes, l.RateWindowSeconds)
	}
	compact := latency + " · " + variation + " · " + rate
	detail := fmt.Sprintf("%s ↔ %s；当前 RTT %s；近 15 分钟 RTT 波动 %s（P95−P50；P50 %dms / P95 %dms，%d 次观测，%d 次完全失败）；近 5 分钟实际传输速率 %s（%d 个相邻样本，%d/2 端点上报）；%s；%s",
		l.From, l.To, latency, variation,
		l.QualityP50MS, l.QualityP95MS, l.QualityObservations, l.QualityFailed,
		rate, l.RateSamples, l.RateReportingEndpoints, l.Source, l.MetricsSource)
	return compact, detail
}

func topologyBitRate(bytes, seconds int64) string {
	if bytes <= 0 || seconds <= 0 {
		return "0bit/s"
	}
	rate := float64(bytes) * 8 / float64(seconds)
	return topologyFormattedBitRate(rate)
}

func topologyProbeBitRate(bytes, durationMS int64) string {
	if bytes <= 0 || durationMS <= 0 {
		return "0bit/s"
	}
	rate := float64(bytes) * 8 * 1000 / float64(durationMS)
	return topologyFormattedBitRate(rate)
}

func topologyFormattedBitRate(rate float64) string {
	switch {
	case rate >= 1_000_000_000:
		return fmt.Sprintf("%.1fGb/s", rate/1_000_000_000)
	case rate >= 1_000_000:
		return fmt.Sprintf("%.1fMb/s", rate/1_000_000)
	case rate >= 1_000:
		return fmt.Sprintf("%.1fkb/s", rate/1_000)
	default:
		return fmt.Sprintf("%.0fbit/s", rate)
	}
}

func topologyNodeSubtitle(n NodeView) string {
	place := nodeCountryCityLabel(n)
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

func nodeCountryCityLabel(n NodeView) string {
	city, country := strings.TrimSpace(n.City), strings.TrimSpace(n.Country)
	switch {
	case city == "":
		return country
	case country == "":
		return city
	default:
		return city + " · " + country
	}
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
// Go 的网络错误带着完整的拨号上下文(`Get "https://…": dial tcp 192.0.2.44:443: …`),
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
