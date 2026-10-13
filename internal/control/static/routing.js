import {linkRoundTripText} from './link-history.js';
// Read-only navigation and rendering. Authority and reports enter as projections.
import {reportIsCurrent,nodeRuntimeState} from './model.js';
import {icon} from './icons.js';
import {hy2TransferRateText} from './hy2-transfer.js';
import {trafficSummary,trafficRatesHTML} from './traffic-history.js';
const list=value=>Array.isArray(value)?value:[];
const esc=value=>String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const ordered=values=>[...values].sort((a,b)=>{const left=a.name||a.id,right=b.name||b.id;return left<right?-1:left>right?1:a.id<b.id?-1:a.id>b.id?1:0});
const stamp=value=>value?new Date(value).toISOString().replace('T',' ').replace('Z',' UTC'):'Not reported';
const url=params=>'/routing'+(params.size?'?'+params:'');
function link(params,changes){const result=new URLSearchParams(params);for(const [key,value]of Object.entries(changes)){if(value==null||value==='')result.delete(key);else result.set(key,String(value))}return url(result)}
const table=(headers,rows)=>`<div class="table-wrap"><table><thead><tr>${headers.map(h=>`<th>${esc(h)}</th>`).join('')}</tr></thead><tbody>${rows||`<tr><td colspan="${headers.length}" class="empty">No matching devices.</td></tr>`}</tbody></table></div>`;
const nav=(href,label,attrs='')=>`<a href="${esc(href)}" data-nav ${attrs}>${label}</a>`;

export function routingContext(projection,params,now=Infinity){
 const services=ordered([...list(projection.services),...list(projection.targets).filter(t=>t.target_kind==='service'&&t.conflicted&&!list(projection.services).some(s=>s.id===t.target_id)).map(t=>({id:t.target_id,name:t.target_id,suspended:true}))]),requested=params.get('service');
 const service=requested?services.find(s=>s.id===requested):services[0];
 const allPolicies=list(projection.policies),devices=ordered(list(projection.devices));
 const records=service?devices.flatMap(device=>{
  const policies=allPolicies.filter(p=>list(device.policy_ids).includes(p.id)&&p.service_id===service.id);
  return device.authorized&&policies.length?[record(projection,service,device,policies,now)]:[];
 }):[];
 const device=params.has('device')?devices.find(d=>d.id===params.get('device')):null;
 const detail=device&&service?record(projection,service,device,allPolicies.filter(p=>list(device.policy_ids).includes(p.id)&&p.service_id===service.id),now):null;
 return {services,service,records,detail,requested,unresolved:devices.some(d=>d.authorized&&list(d.policy_ids).some(id=>!allPolicies.some(p=>p.id===id)))};
}
function record(projection,service,device,policies,now){
 const policy=policies.length===1?policies[0]:null;
 const allowed=device.authorized&&!service.suspended&&list(device.roles).includes('access')&&policy?.action==='allow';
 const paths=allowed?list(projection.paths).filter(p=>p.device===device.id&&p.service_id===service.id):[];
 const selected=paths.find(p=>p.selected),evidence=device.evidence;
 const current=reportIsCurrent(evidence,now)?selected:null;
 const reason=service.suspended?'Service suspended by conflicting changes':!device.authorized?'Device is not authorized':!policy?'No available Policy assigned':policy.action==='deny'?'Access denied by Policy':!list(device.roles).includes('access')?'Device has no access responsibility':!paths.length?'No authorized candidate':!evidence?(device.last_report_at?'Waiting for device confirmation':'No device report'):evidence.freshness==='clock_unknown'?'Report time needs checking':!reportIsCurrent(evidence,now)?'Runtime report expired':!selected?'No selection reported':'Current selection confirmed';
 const values=current?list(evidence?.measurements).filter(v=>v.level==='service'&&v.service_id===service.id&&v.candidate_id===current.candidate_id&&v.spec_digest===current.spec_digest&&v.network_generation===evidence.network_generation&&list(current.targets).includes(v.target)&&v.current_until>now):[];
 const targetState=values.some(v=>v.result==='unavailable')?'unavailable':values.some(v=>v.result==='available')?'available':'unknown';
 return {device,service,policy,allowed,paths,selected,current,evidence,reason,targetState};
}
function routeKey(path,device,projection){
 if(!path)return null;
 if(path.final_exit==='direct')return 'direct';
 const chain=list(path.chain),nodes=chain[0]===device.id?chain.slice(1):chain;
 return JSON.stringify([path.first_transport,path.first_resource_id,nodes,list(path.link_ids).map(id=>[id,list(projection.links).find(l=>l.id===id)?.spec_digest||null]),path.final_exit]);
}
export function routingSummary(records,projection){
 const groups=new Map();
 for(const row of records){if(!row.current)continue;const key=routeKey(row.current,row.device,projection),value=groups.get(key)||{key,path:row.current,count:0};value.count++;groups.set(key,value)}
 return {groups:[...groups.values()].sort((a,b)=>a.key<b.key?-1:a.key>b.key?1:0),unconfirmed:records.filter(r=>r.allowed&&!r.current).length,failed:records.filter(r=>r.targetState==='unavailable').length,unknown:records.filter(r=>r.allowed&&r.targetState==='unknown').length};
}
function preferenceLabel(evidence,projection){
 const value=evidence?.preference;
 if(!value)return 'not reported';
 if(value.mode==='auto')return 'Auto';
 if(value.mode==='direct')return 'Direct';
 if(value.mode==='fixed_exit')return 'Fixed exit · '+(list(projection.devices).find(d=>d.id===value.exit)?.name||value.exit);
 return 'not reported';
}
function pathLabel(path,projection){
 const name=id=>list(projection.devices).find(d=>d.id===id)?.name||id;
 if(path.final_exit==='direct')return 'Direct';
 if(!list(path.chain).length)return 'Local egress · '+name(path.final_exit);
 return `${path.first_transport==='wireguard'?'WG':path.first_transport==='hysteria2'?'Hy2':path.first_transport} · ${path.chain.map(name).join(' → ')}`;
}
function hidden(params,omit){return [...params].filter(([key])=>!omit.includes(key)).map(([key,value])=>`<input type="hidden" name="${esc(key)}" value="${esc(value)}">`).join('')}
function searchForm(params,key,label,placeholder){return `<form data-page-filter class="paths-search">${hidden(params,[key,'page'])}<label>${icon('search')}<input aria-label="${label}" type="search" name="${key}" value="${esc(params.get(key)||'')}" placeholder="${placeholder}"></label><button type="submit" class="paths-search-submit" aria-label="Search">Search</button></form>`}
function policySummary(row){
 const p=row.policy;if(!p)return '<p>No effective Policy is assigned to this device for this Service.</p>';
 const scope=value=>value?.mode==='any'?'Any eligible node':value?.mode==='none'?'No nodes permitted':value?.mode==='only'?list(value.node_ids).join(', '):'Unknown';
 return `<div class="paths-policy"><span class="${p.action==='allow'?'ok':'bad'}">Access ${p.action==='allow'?'allowed':'denied'}</span><span>${row.service.kind==='internet'?`Direct ${p.allow_direct?'allowed':'not allowed'} · `:''}Entry: ${esc(scope(p.entry_scope))} · Relay: ${esc(scope(p.relay_scope))} · ${row.service.kind==='internet'?`Final exit: ${esc(scope(p.exit_scope))}${list(p.local_egress_devices).length?' · Local egress: '+esc(p.local_egress_devices.join(', ')):''}`:`Fixed LAN gateway: ${esc(row.service.local_network?.gateway_node_id||'Unavailable')} · ${esc(row.service.local_network?.virtual_prefix)} → ${esc(row.service.local_network?.local_prefix)}`}${p.max_hops?' · Managed nodes: '+esc(p.max_hops):''}</span>${nav('/services?service='+encodeURIComponent(row.service.id),'Service details →')}</div>`;
}
function sampleText(sample,now){
 if(!sample)return 'No target sample';
 const result=sample.result==='available'?'Target succeeded':sample.result==='unavailable'?'Target failed':'Target result unknown';
 return `${result} · reported ${stamp(sample.observed_at)}${sample.current_until>now?' · current sample':sample.observed_at>now?' · future sample time':now>=sample.valid_until?' · expired':' · current validity unconfirmed'}`;
}
function samples(row,path){return list(row.evidence?.measurements).filter(v=>v.level==='service'&&v.service_id===row.service.id&&v.candidate_id===path.candidate_id&&v.spec_digest===path.spec_digest&&v.network_generation===row.evidence?.network_generation&&list(path.targets).includes(v.target))}
function sharedRate(linkID,projection,histories,now){
 const scope='link:'+linkID,summary=trafficSummary(projection,scope,histories?.get('traffic:'+scope));
 return `<span data-traffic-scope="${esc(summary.scope||'')}"><small>Shared WG peer · ${esc(linkID)}</small>${trafficRatesHTML(summary,now)}</span>`;
}
function candidateRows(row,projection,params,now,traffic){return row.paths.map(path=>{
 const observations=samples(row,path),chosen=params.has('candidate')?path.candidate_id===params.get('candidate'):path===row.current;
 return `<tr data-candidate="${esc(path.candidate_id)}" ${chosen?'class="selected-path"':''}><td>${nav(link(params,{candidate:path.candidate_id,target:null}),esc(pathLabel(path,projection)))}<small class="mono">${esc(path.first_resource_id||'No shared first hop')}${path.link_ids.length?' · '+esc(path.link_ids.join(' → ')):''}</small><details><summary>Scope and measurements</summary><dl class="device-facts"><dt>Candidate</dt><dd class="mono">${esc(path.candidate_id)}</dd><dt>Specification</dt><dd class="mono">${esc(path.spec_digest)}</dd><dt>First hop RTT</dt><dd>Unknown</dd><dt>Shared link rate</dt><dd>${list(path.link_ids).map(id=>sharedRate(id,projection,traffic,now)).join('')||'No shared relay Link'}</dd></dl>${observations.map(v=>`<p>${esc(v.target)}<br>${esc(sampleText(v,now))}${v.result==='available'&&v.duration_ms!=null?`<br>Complete HTTPS request: ${esc(v.duration_ms)} ms`:''}</p>`).join('')||'<p>No target samples in the current View report.</p>'}</details></td><td>${observations.map(v=>`<p>${esc(v.target)}<small>${esc(sampleText(v,now))}</small></p>`).join('')||'No target report'}</td><td>${path===row.current?'Current selection · Reported selection':path.selected?'Reported selection · historical':'Not selected in this report'}<small>${esc(stamp(row.evidence?.reported_at))}</small></td></tr>`;
 }).join('')}
function routeDiagram(row,path,projection,target,now,traffic){
 if(!path)return '<p class="empty">No authorized route preview.</p>';
 const current=path===row.current;
 const device=id=>list(projection.devices).find(d=>d.id===id)?.name||id;
 const startsHere=path.chain[0]===row.device.id,chain=startsHere?path.chain.slice(1):path.chain;
 const nodes=[{name:row.device.name||row.device.id,role:'Source device',icon:row.device.platform?.startsWith('android')?'phone':'devices'}];
 for(const id of chain)nodes.push({name:device(id),role:id===path.final_exit?(row.service.kind==='local_network'?'LAN gateway':'Final exit'):'Relay',icon:id===path.final_exit?'devices':'ssot'});
 if(!chain.length&&path.final_exit!=='direct')nodes[0].role=row.service.kind==='local_network'?'Source · LAN gateway':'Source · local egress';
 let targetName=target||'Service target';try{targetName=new URL(target).hostname||targetName}catch{}
 nodes.push({name:targetName,role:row.service.kind==='internet'?'Business target':'LAN target',icon:'globe'});
 const edge=index=>{
  if(!index)return '';
  const linkIndex=index-(startsHere?1:2),linkID=linkIndex>=0&&index<nodes.length-1?path.link_ids[linkIndex]:null;
  const resource=index===1&&!startsHere&&path.first_resource_id?path.first_transport+' · '+path.first_resource_id:'';
  const label=resource||(linkID?(list(projection.links).find(l=>l.id===linkID)?.transport||'Transport unknown')+' · '+linkID:path.final_exit==='direct'?'Direct':'');
  const check=resource&&reportIsCurrent(row.evidence,now)?list(row.evidence?.measurements).find(v=>v.level==='resource'&&v.resource_id===path.first_resource_id&&v.network_generation===row.evidence.network_generation&&v.current_until>now):null;
  const firstHop=check?`<small title="${esc(stamp(check.observed_at))}">First-hop ${esc(check.result)}${check.duration_ms!=null?' · '+esc(check.duration_ms)+' ms exchange':''}</small>${path.first_transport==='hysteria2'?`<small title="Small UDP authentication exchange; includes QUIC/TLS overhead and retransmissions; not capacity or business usage">${esc(hy2TransferRateText(check,now))}</small>`:''}`:'<small>First-hop timing unknown</small>';
  return `<span class="paths-edge"><span class="paths-edge-metrics">${label?`<small>${esc(label)}</small>`:''}${linkID?`<small>${esc(linkRoundTripText(list(projection.links).find(v=>v.id===linkID),now))}</small>`:resource?firstHop:'<small>Segment timing unknown</small>'}${linkID?sharedRate(linkID,projection,traffic,now):''}</span><span class="paths-arrow" aria-hidden="true"></span></span>`;
 };
 return `<div class="paths-route nodes-${nodes.length} ${current?'current':'preview'}" aria-label="${current?'Current reported route':'Authorized route preview; current route unconfirmed'}">${nodes.map((v,i)=>`${edge(i)}<div class="paths-hop"><span class="paths-node-icon">${icon(v.icon)}</span><b class="mono">${esc(v.name)}</b><small>${esc(v.role)}</small></div>`).join('')}</div><p class="tiny dim">${current?'Current selection':path.selected?'Last reported selection':'Authorized candidate preview'} · ${esc(stamp(row.evidence?.reported_at))}. ${current?'':row.current?'This candidate is not the current selection. ':'Current route remains unconfirmed. '}Shared-link measurements are not this Service’s traffic.</p>`;

}
export function routingHistoryRequest(projection,params){
 if(params.get('tab')!=='history')return null;
 const row=routingContext(projection,params).detail;if(!row?.allowed)return null;
 const path=row.paths.find(p=>p.candidate_id===params.get('candidate'))||(!params.has('candidate')&&(row.selected||row.paths[0]));
 if(!path)return null;
 const target=params.get('target')||path.targets[0];if(!path.targets.includes(target))return null;
 const query=new URLSearchParams({device:row.device.id,service:row.service.id,candidate:path.candidate_id,target});
 return {key:JSON.stringify([query.toString(),path.spec_digest,row.device.last_report_at,list(projection.fact_frontier)]),url:'/api/control/ui/path-history?'+query,spec:path.spec_digest};
}
function historyHTML(value,request,now){
 if(!request)return '<p>No applicable target or authorized candidate for history.</p>';
 if(!value||value.key!==request.key)return '<p role="status">Loading original target samples…</p>';
 if(value.error)return `<p role="status">History unavailable: ${esc(value.error)}</p><button type="button" data-paths-history-retry>Retry history</button>`;
 const data=value.data;if(data.spec_digest!==request.spec)return '<p>Authorization changed. Reload this Service to inspect its current scope.</p>';
 const buckets=list(data.buckets),maximum=Math.max(1,...buckets.map(b=>b.observation?.result==='available'?b.observation.duration_ms||0:0));
 return `<p>Historical samples · ${esc(stamp(data.from))} — ${esc(stamp(data.until))}</p><button type="button" data-paths-history-retry>Refresh history</button><p class="mono">${esc(data.target)}</p><div class="paths-history">${buckets.map(bucket=>{const v=bucket.observation,result=v?.result||'unknown',label=bucket.ambiguous?'Conflicting samples at the same time':sampleText(v,now),duration=v?.result==='available'?v.duration_ms:null;return `<div class="paths-hour" title="${esc(stamp(bucket.hour)+' · '+label+(duration!=null?' · '+duration+' ms':'')+(v?' · network '+v.network_generation:''))}"><div class="paths-duration">${duration!=null?`<svg viewBox="0 0 10 100" preserveAspectRatio="none" aria-hidden="true"><rect x="0" width="10" y="${100-Math.max(1,Math.round(duration/maximum*100))}" height="${Math.max(1,Math.round(duration/maximum*100))}"/></svg>`:''}</div><span class="paths-sample ${esc(result)}" aria-label="${esc(label)}"></span><small>${new Date(bucket.hour).getUTCHours()}</small></div>`}).join('')}</div><p class="tiny dim">UTC hours · last distinct matching sample in each hour. An empty hour is unknown; a failed request has no successful response time. A sample does not prove availability for the entire hour.</p>`;
}
function detailHTML(context,projection,params,now,history,traffic){
 const row=context.detail,back=link(params,{device:null,candidate:null,target:null,tab:null});
 if(!context.service||!row)return `<div class="paths-back">${nav(back,'← Back to Service devices','data-paths-back')}</div><h2>Service or device unavailable</h2><p>This link has no current authorized device / Service context.</p>`;
 const candidate=row.paths.find(p=>p.candidate_id===params.get('candidate'))||(!params.has('candidate')&&(row.selected||row.paths[0]));
 const requestedTarget=candidate&&(params.get('target')||candidate.targets[0]),target=candidate&&candidate.targets.includes(requestedTarget)?requestedTarget:null,tab=params.get('tab')==='history'?'history':'candidates';
 const route=row.current||row.selected||candidate,routeTarget=route?.targets.includes(target)?target:route?.targets[0];
 const observed=route&&samples(row,route).find(v=>v.target===routeTarget),currentSample=row.current&&observed?.current_until>now?observed:null;
 const runtime=nodeRuntimeState(row.device,now),management='/devices/'+encodeURIComponent(row.device.id)+'?service='+encodeURIComponent(row.service.id),name=row.service.name||row.service.id;
 return `<div class="paths-back">${nav(back,'← '+esc(name)+' devices','data-paths-back')}</div><div class="paths-identity"><div><span class="label">DEVICE</span><b>${nav(management,esc(row.device.name||row.device.id))}</b></div><div><span class="label">SERVICE</span><b>${esc(name)}</b></div><div><span class="label">POLICY FOR THIS DEVICE</span>${row.policy?nav('/policies?policy='+encodeURIComponent(row.policy.id),esc(row.policy.name||row.policy.id)+' ↗'):'<span>No assigned Policy</span>'}</div><div><span class="label">DEVICE MODE</span><b data-routing-preference>${row.service.kind==='local_network'?'Fixed LAN gateway':`Mode: ${esc(preferenceLabel(row.evidence,projection))}`}</b><small>${row.evidence?.preference?'Reported by device':'No mode report'}</small></div></div>${policySummary(row)}<section class="paths-current"><div class="sectionhead"><h2>${row.current?'Current route':'Current route unknown'}</h2><span class="dim">${esc(row.reason)} · ${esc(stamp(row.evidence?.reported_at))}</span></div><div class="paths-target-state ${currentSample?.result==='available'?'ok':currentSample?.result==='unavailable'?'bad':'unknown'}">${currentSample?.result==='available'?'Target succeeded':currentSample?.result==='unavailable'?'Target failed':'Target unknown'} · <span class="mono">${esc(routeTarget||'No applicable business target')}</span>${nav('/topology?device='+encodeURIComponent(row.device.id)+'&service='+encodeURIComponent(row.service.id),'Open topology →')}</div>${routeDiagram(row,route,projection,routeTarget,now,traffic)}<div class="paths-readbacks"><div><span class="label">END-TO-END HTTPS</span><b data-end-to-end>${observed?.result==='available'&&observed.duration_ms!=null?esc(observed.duration_ms)+' ms':'Unknown'}</b></div><div><span class="mono">${esc(routeTarget||'No applicable HTTPS target')}</span><small>${observed?'Original sample · '+esc(sampleText(observed,now)):'No matching target sample'}</small></div><div><span class="label">DEVICE RUNTIME</span><span data-paths-runtime class="${runtime==='running'?'ok':runtime==='error'?'bad':'unknown'}">${esc(runtime)}</span><small>${esc(stamp(row.evidence?.reported_at))}</small></div>${nav(management,'View device →')}</div></section><div class="service-tabs paths-tabs" role="tablist">${['candidates','history'].map(v=>nav(link(params,{tab:v==='candidates'?null:v}),v==='candidates'?'Candidate routes':'History',`role="tab" aria-selected="${tab===v}" class="${tab===v?'selected':''}"`)).join('')}<span>${row.paths.length} authorized candidates · read only</span></div><section class="paths-tab-content">${tab==='candidates'?table(['Route','Target result','Device selection'],candidateRows(row,projection,params,now,traffic)):`<div class="paths-history-select">${row.paths.map(p=>nav(link(params,{candidate:p.candidate_id,target:null}),esc(pathLabel(p,projection)),`class="button ${p===candidate?'selected':''}"`)).join('')}${candidate?candidate.targets.map(t=>nav(link(params,{target:t}),esc(t),`class="button ${t===target?'selected':''}"`)).join(''):''}</div>${historyHTML(history,routingHistoryRequest(projection,params),now)}`}</section><p class="tiny dim">Viewing candidates does not change device traffic. Only a fresh device report confirms its selection.</p>`;
}
function serviceDescription(service){
 if(service.suspended)return 'Service suspended';
 if(service.kind==='local_network')return 'LAN · '+(service.local_network?.gateway_node_id||'No gateway');
 return 'Internet'+(list(service.matchers).length?' · '+service.matchers.map(m=>m.value).join(' + '):'');
}
function resultHTML(row,now){
 const current=row.current&&samples(row,row.current).filter(v=>v.current_until>now),sample=current?.find(v=>v.result===row.targetState)||null;
 return `<div class="paths-result-head"><span class="${row.targetState==='available'?'ok':row.targetState==='unavailable'?'bad':'unknown'}">${row.policy?.action==='deny'?'Access denied':row.targetState==='unavailable'?'Current target failure':row.targetState==='available'?'Current target success':'Current result unknown'}</span><small>${esc(stamp(row.device.last_report_at))}</small></div><small>${sample?esc(sample.target):esc(row.current?'No current target sample':row.reason)}</small>`;
}
export function routingHTML(projection,params,now,history=null,traffic=null){
 const context=routingContext(projection,params,now),isDetail=params.has('device');
 const allRecords=context.services.flatMap(service=>routingContext(projection,new URLSearchParams({service:service.id}),now).records),totalDevices=new Set(allRecords.map(r=>r.device.id)).size;
 const title=`<div class="network-heading paths-heading"><span class="eyebrow">NETWORK / PATHS</span><h1>${isDetail?'Path detail':'Live paths'}</h1><p class="dim">${isDetail?'Inspect this device’s route, policy and observations for a specific target.':'Choose a service to see its devices. Open a device for path details.'}</p>${isDetail?'':`<span class="dim" data-routing-total>${context.services.length} services · ${totalDevices} devices in active services · ${allRecords.length} ${context.unresolved?'known ':''}access records</span>`}</div>`;
 if(isDetail)return title+`<section class="paths-detail">${detailHTML(context,projection,params,now,history,traffic)}</section>`;
 const selected=context.service,base=new URLSearchParams(params);if(selected)base.set('service',selected.id);
 const needle=(params.get('s')||'').toLowerCase(),search=(params.get('q')||'').toLowerCase(),rawFilter=params.get('filter')||'',summary=routingSummary(context.records,projection);
 const permittedFilters=['','failed','unknown','no_route','denied','waiting',...summary.groups.map(g=>'route:'+g.key)],filter=permittedFilters.includes(rawFilter)?rawFilter:'';
 const serviceRows=context.services.filter(s=>(s.name+' '+s.id).toLowerCase().includes(needle)).map(service=>{
  const scoped=routingContext(projection,new URLSearchParams({service:service.id}),now),value=routingSummary(scoped.records,projection);
  return nav(link(new URLSearchParams(params.has('s')?{s:params.get('s')}:{}),{service:service.id}),`<div class="paths-service-title"><b>${esc(service.name||service.id)}</b><span>${service.suspended?'Unknown':scoped.records.length}</span></div><small>${esc(serviceDescription(service))}</small><small class="${value.failed?'bad':value.unknown||service.suspended?'unknown':''}">${service.suspended?'Conflicting changes · projection suspended':scoped.unresolved?'Assignment total unknown · '+scoped.records.length+' known':scoped.records.length?(value.failed+' failed · '+value.unknown+' unknown'):'No devices assigned'}</small><small>${service.suspended?'No current authorized routes':value.groups.map(g=>esc(pathLabel(g.path,projection))+' '+g.count).join(' · ')+(value.unconfirmed?' · Unconfirmed '+value.unconfirmed:'')||'No current confirmed selections'}${!service.suspended?' · '+scoped.records.length+' assigned':''}</small>`,`class="paths-service ${selected?.id===service.id?'selected':''}" data-service="${esc(service.id)}" aria-current="${selected?.id===service.id?'true':'false'}"`);
 }).join('');
 const records=context.records.filter(r=>(r.device.name+' '+r.device.id).toLowerCase().includes(search)&&(!filter||filter==='unknown'&&r.allowed&&r.targetState==='unknown'||filter==='failed'&&r.targetState==='unavailable'||filter==='no_route'&&r.allowed&&!r.current||filter==='denied'&&r.policy?.action==='deny'||filter==='waiting'&&r.allowed&&!r.evidence&&!!r.device.last_report_at||filter.startsWith('route:')&&routeKey(r.current,r.device,projection)===filter.slice(6)));
 const pageSize=20,total=Math.max(1,Math.ceil(records.length/pageSize)),page=Math.min(total,Math.max(1,Number.parseInt(params.get('page'),10)||1));
 const rows=records.slice((page-1)*pageSize,page*pageSize).map(row=>`<tr data-paths-device="${esc(row.device.id)}"><td>${nav(link(base,{device:row.device.id}),`<span class="mono">${esc(row.device.name||row.device.id)}</span><small class="paths-open">Open path details →</small>`)}<small class="mono paths-device-id">${esc(row.device.id)}</small></td><td class="mono">${esc(row.policy?.name||row.policy?.id||'Unavailable Policy')}</td><td>${row.current?esc(pathLabel(row.current,projection)):'No confirmed route'}<small>${esc(row.reason)}</small>${row.selected&&!row.current?`<small>Historical: ${esc(pathLabel(row.selected,projection))}</small>`:''}</td><td>${resultHTML(row,now)}</td></tr>`).join('');
 const options=[['','All · '+context.records.length],['failed','Failed · '+summary.failed],['unknown','Unknown · '+summary.unknown],...summary.groups.map(g=>['route:'+g.key,pathLabel(g.path,projection)+' · '+g.count]),['no_route','No confirmed route · '+summary.unconfirmed]];
 if(context.records.some(r=>r.policy?.action==='deny'))options.push(['denied','Denied']);if(context.records.some(r=>r.allowed&&!r.evidence&&r.device.last_report_at))options.push(['waiting','Waiting for device']);
 const filters=options.map(([value,label])=>nav(link(base,{filter:value,page:null}),esc(label),`class="${filter===value?'selected':''}" aria-current="${filter===value?'true':'false'}"`)).join('');
 return title+`<div class="paths-layout"><aside class="paths-services"><div class="sectionhead"><h2>Services</h2><span class="dim">Devices</span></div>${searchForm(new URLSearchParams(params.has('service')?{service:params.get('service')}:{}),'s','Find a Service','Find a service')}${serviceRows||'<p class="empty">No matching Services.</p>'}${context.unresolved?'<p class="note">Some assigned Policies are unavailable; Service counts may be incomplete.</p>':''}</aside><section class="paths-devices"><div class="paths-device-heading"><div class="sectionhead"><h2>${esc(selected?.name||selected?.id||'Service unavailable')}</h2><span>${context.unresolved?'Assignment total unknown · '+context.records.length+' known devices':context.records.length+' devices · '+new Set(context.records.map(r=>r.policy?.id).filter(Boolean)).size+' policies'}</span></div><p class="dim">${esc(selected?serviceDescription(selected):'No available Service')}</p></div>${selected?`<div class="paths-device-search">${searchForm(base,'q','Find a device','Find a device')}<span class="dim">${records.length} of ${context.records.length} devices</span></div><div class="paths-filters">${filters}</div>${table(['Device','Policy','Current route','Target / updated'],rows)}<div class="inventory-foot"><span>${records.length} devices · page ${page} of ${total}</span><div>${page>1?nav(link(base,{page:page-1}),'← Previous','class="button"'):''}${page<total?nav(link(base,{page:page+1}),'Next →','class="button"'):''}</div></div><p class="tiny dim">Target results apply to the observed target only. Missing device reports remain unknown.</p>`:'<p>This Service is unavailable. Choose an existing Service; no old route is retained.</p>'}</section></div>`;
}
