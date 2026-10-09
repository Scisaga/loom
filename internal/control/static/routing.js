// Read-only navigation and rendering. Authority and reports enter as projections.
import {reportIsCurrent} from './model.js';
const list=value=>Array.isArray(value)?value:[];
const esc=value=>String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const ordered=values=>[...values].sort((a,b)=>{const left=a.name||a.id,right=b.name||b.id;return left<right?-1:left>right?1:a.id<b.id?-1:a.id>b.id?1:0});
const stamp=value=>value?new Date(value).toISOString().replace('T',' ').replace('Z',' UTC'):'Not reported';
const url=params=>'/routing'+(params.size?'?'+params:'');
function link(params,changes){const result=new URLSearchParams(params);for(const [key,value]of Object.entries(changes)){if(value==null||value==='')result.delete(key);else result.set(key,String(value))}return url(result)}
const table=(headers,rows)=>`<div class="table-wrap"><table><thead><tr>${headers.map(h=>`<th>${esc(h)}</th>`).join('')}</tr></thead><tbody>${rows||`<tr><td colspan="${headers.length}" class="empty">No matching devices.</td></tr>`}</tbody></table></div>`;
const nav=(href,label,attrs='')=>`<a href="${esc(href)}" data-nav ${attrs}>${label}</a>`;

export function routingContext(projection,params,now=Infinity){
 const services=ordered(list(projection.services)),requested=params.get('service');
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
 const allowed=device.authorized&&list(device.roles).includes('access')&&policy?.action==='allow';
 const paths=allowed?list(projection.paths).filter(p=>p.device===device.id&&p.service_id===service.id):[];
 const selected=paths.find(p=>p.selected),evidence=device.evidence;
 const current=reportIsCurrent(evidence,now)?selected:null;
 const reason=!device.authorized?'Device is not authorized':!policy?'No available Policy assigned':policy.action==='deny'?'Access denied by Policy':!list(device.roles).includes('access')?'Device has no access responsibility':!paths.length?'No authorized candidate':!evidence?(device.last_report_at?'Waiting for device confirmation':'No device report'):evidence.freshness==='clock_unknown'?'Report time needs checking':!reportIsCurrent(evidence,now)?'Runtime report expired':evidence.runtime?.state!=='running'?'Runtime reported '+(evidence.runtime?.state||'unknown'):!selected?'No selection reported':'Current selection confirmed';
 const values=current?list(evidence?.measurements).filter(v=>v.level==='service'&&v.service_id===service.id&&v.candidate_id===current.candidate_id&&v.spec_digest===current.spec_digest&&v.network_generation===evidence.network_generation&&list(current.targets).includes(v.target)&&v.current_until>now):[];
 const targetState=values.some(v=>v.result==='unavailable')?'unavailable':values.some(v=>v.result==='available')?'available':'unknown';
 return {device,service,policy,allowed,paths,selected,current,evidence,reason,targetState};
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
 return `${path.first_transport} · ${path.chain.map(name).join(' → ')}`;
}
function hidden(params,omit){return [...params].filter(([key])=>!omit.includes(key)).map(([key,value])=>`<input type="hidden" name="${esc(key)}" value="${esc(value)}">`).join('')}
function searchForm(params,key,label,placeholder){return `<form data-page-filter class="paths-search">${hidden(params,[key,'page'])}<label>${label}<input type="search" name="${key}" value="${esc(params.get(key)||'')}" placeholder="${placeholder}"></label><button type="submit">Search</button></form>`}
function policySummary(row){
 const p=row.policy;if(!p)return '<p>No effective Policy is assigned to this device for this Service.</p>';
 const scope=value=>value?.mode==='any'?'Any eligible node':value?.mode==='none'?'No nodes permitted':value?.mode==='only'?list(value.node_ids).join(', '):'Unknown';
 return `<dl class="paths-policy"><dt>Access</dt><dd>${esc(p.action)}</dd><dt>Entry</dt><dd>${esc(scope(p.entry_scope))}</dd><dt>Relay</dt><dd>${esc(scope(p.relay_scope))}</dd>${row.service.kind==='internet'?`<dt>Direct</dt><dd>${p.allow_direct?'Allowed':'Not allowed'}</dd><dt>Final exit</dt><dd>${esc(scope(p.exit_scope))}</dd><dt>Local egress</dt><dd>${esc(list(p.local_egress_devices).join(', ')||'Not allowed')}</dd>`:`<dt>LAN gateway</dt><dd>${esc(row.service.local_network?.gateway_node_id||'Unavailable')}</dd><dt>Address mapping</dt><dd>${esc(row.service.local_network?.virtual_prefix)} → ${esc(row.service.local_network?.local_prefix)}</dd>`}<dt>Managed nodes</dt><dd>${esc(p.max_hops||'No additional limit')}</dd></dl>`;
}
function sampleText(sample,now){
 if(!sample)return 'No target sample';
 const result=sample.result==='available'?'Target succeeded':sample.result==='unavailable'?'Target failed':'Target result unknown';
 return `${result} · reported ${stamp(sample.observed_at)}${sample.current_until>now?' · current sample':sample.observed_at>now?' · future sample time':now>=sample.valid_until?' · expired':' · current validity unconfirmed'}`;
}
function samples(row,path){return list(row.evidence?.measurements).filter(v=>v.level==='service'&&v.service_id===row.service.id&&v.candidate_id===path.candidate_id&&v.spec_digest===path.spec_digest&&v.network_generation===row.evidence?.network_generation&&list(path.targets).includes(v.target))}
function candidateRows(row,projection,params,now){return row.paths.map(path=>{
 const observations=samples(row,path),chosen=path.candidate_id===params.get('candidate');
 return `<tr data-candidate="${esc(path.candidate_id)}" ${chosen?'class="selected-path"':''}><td>${nav(link(params,{candidate:path.candidate_id,target:null}),esc(pathLabel(path,projection)))}<small class="mono">${esc(path.first_resource_id||'No shared first hop')}${path.link_ids.length?' · '+esc(path.link_ids.join(' → ')):''}</small><details><summary>Scope and measurements</summary><dl class="device-facts"><dt>Candidate</dt><dd class="mono">${esc(path.candidate_id)}</dd><dt>Specification</dt><dd class="mono">${esc(path.spec_digest)}</dd><dt>First hop RTT</dt><dd>Unknown</dd><dt>Shared link rate</dt><dd>Unknown</dd></dl>${observations.map(v=>`<p>${esc(v.target)}<br>${esc(sampleText(v,now))}${v.result==='available'&&v.duration_ms!=null?`<br>Complete HTTPS request: ${esc(v.duration_ms)} ms`:''}</p>`).join('')||'<p>No target samples in the current View report.</p>'}</details></td><td>${observations.map(v=>`<p>${esc(v.target)}<small>${esc(sampleText(v,now))}</small></p>`).join('')||'No target report'}</td><td>${path===row.current?'Current selection · Reported selection':path.selected?'Reported selection · historical':'Not selected in this report'}<small>${esc(stamp(row.evidence?.reported_at))}</small></td></tr>`;
 }).join('')}
function routeDiagram(row,path,projection,target){
 if(!path)return '<p class="empty">No authorized route preview.</p>';
 const current=path===row.current;
 const device=id=>list(projection.devices).find(d=>d.id===id)?.name||id;
 const nodes=[{name:row.device.name||row.device.id,role:'Source device'}];
 for(const id of path.chain)nodes.push({name:device(id),role:id===path.final_exit?(row.service.kind==='local_network'?'LAN gateway':'Final exit'):'Relay'});
 if(!path.chain.length&&path.final_exit!=='direct')nodes[0].role=row.service.kind==='local_network'?'Source · LAN gateway':'Source · local egress';
 nodes.push({name:target||'Service target',role:row.service.kind==='internet'?'Business target':'LAN target'});
 const edge=index=>{
  if(!index)return '';
  const linkID=index>1&&index<nodes.length-1?path.link_ids[index-2]:null;
  const resource=index===1&&path.first_resource_id?path.first_transport+' · '+path.first_resource_id:'';
  const label=resource||(linkID?(list(projection.links).find(l=>l.id===linkID)?.transport||'Transport unknown')+' · '+linkID:path.final_exit==='direct'?'Direct':'');
  return `<span class="paths-edge"><span class="paths-arrow" aria-hidden="true">→</span>${label?`<small>${esc(label)}</small>`:''}${resource||linkID?'<small>RTT unknown</small>':''}</span>`;
 };
 return `<div class="paths-route" aria-label="${current?'Current reported route':'Authorized route preview; current route unconfirmed'}">${nodes.map((v,i)=>`${edge(i)}<div class="paths-hop"><b>${esc(v.name)}</b><small>${esc(v.role)}</small></div>`).join('')}</div><p class="tiny dim">${current?'Current selection':path.selected?'Last reported selection':'Authorized candidate preview'} · ${esc(stamp(row.evidence?.reported_at))}. ${current?'':row.current?'This candidate is not the current selection. ':'Current route remains unconfirmed. '}Shared-link measurements are not this Service’s traffic.</p>`;

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
function detailHTML(context,projection,params,now,history){
 const row=context.detail,back=link(params,{device:null,candidate:null,target:null,tab:null});
 if(!context.service||!row)return nav(back,'← Back to Service devices')+'<h2>Service or device unavailable</h2><p>This link has no current authorized device / Service context.</p>';
 const candidate=row.paths.find(p=>p.candidate_id===params.get('candidate'))||(!params.has('candidate')&&(row.selected||row.paths[0]));
 const requestedTarget=candidate&&(params.get('target')||candidate.targets[0]),target=candidate&&candidate.targets.includes(requestedTarget)?requestedTarget:null,tab=params.get('tab')==='history'?'history':'candidates';
 const management=nav('/devices/'+encodeURIComponent(row.device.id)+'?service='+encodeURIComponent(row.service.id),'Manage device')+' · '+nav('/services?service='+encodeURIComponent(row.service.id),'Service')+(row.policy?' · '+nav('/policies?policy='+encodeURIComponent(row.policy.id),esc(row.policy.name||row.policy.id)):'');
 return `<div class="paths-back">${nav(back,'← Back to Service devices','data-paths-back')}</div><div class="sectionhead"><div><h2>${esc(row.device.name||row.device.id)} → ${esc(row.service.name||row.service.id)}</h2><p>${management}</p></div><span class="badge unknown">${esc(row.reason)}</span></div>${policySummary(row)}<section class="paths-current"><h3>${row.current?'Current route':'Current route unknown'}</h3><p>${esc(row.reason)}. ${row.selected?'The last signed selection is shown below with its original report time.':''}</p><div class="paths-readbacks"><span>Runtime reported: ${esc(row.evidence?.runtime?.state||'not reported')}<small>${esc(stamp(row.evidence?.reported_at))}</small></span>${row.service.kind==='local_network'?'<span>Fixed LAN gateway · automatic path selection</span>':`<span data-routing-preference>Mode: ${esc(preferenceLabel(row.evidence,projection))}<small>${row.evidence?.preference?'Reported setting · '+esc(stamp(row.evidence.reported_at)):''}</small></span>`}<span>Current target result: ${esc(candidate&&samples(row,candidate).find(v=>v.target===target&&v.current_until>now)?.result||'unknown')}</span></div>${routeDiagram(row,candidate,projection,target)}${candidate?`<p>Complete HTTPS request time: ${esc((samples(row,candidate).find(v=>v.target===target&&v.result==='available')?.duration_ms??'Unknown'))}${samples(row,candidate).some(v=>v.target===target&&v.result==='available'&&v.duration_ms!=null)?' ms (reported)':''}</p>`:''}</section><div class="service-tabs" role="tablist">${['candidates','history'].map(v=>nav(link(params,{tab:v==='candidates'?null:v}),v==='candidates'?'Candidate paths':'Historical samples',`role="tab" aria-selected="${tab===v}" class="${tab===v?'selected':''}"`)).join('')}</div>${tab==='candidates'?table(['Route','Latest target report','Device selection'],candidateRows(row,projection,params,now)):`<div class="paths-history-select">${row.paths.map(p=>nav(link(params,{candidate:p.candidate_id,target:null}),esc(pathLabel(p,projection)),`class="button ${p===candidate?'selected':''}"`)).join('')}${candidate?candidate.targets.map(t=>nav(link(params,{target:t}),esc(t),`class="button ${t===target?'selected':''}"`)).join(''):''}</div>${historyHTML(history,routingHistoryRequest(projection,params),now)}`}`;
}
export function routingHTML(projection,params,now,history=null){
 const context=routingContext(projection,params,now),title='<div class="network-heading"><span class="eyebrow">NETWORK / SERVICE ACCESS</span><h1>Live paths</h1><p class="dim">Service assignments, reported paths and target samples</p></div>';
 if(params.has('device'))return title+`<section class="card paths-detail">${detailHTML(context,projection,params,now,history)}</section>`;
 const selected=context.service,base=new URLSearchParams(params);if(selected)base.set('service',selected.id);
 const needle=(params.get('s')||'').toLowerCase(),search=(params.get('q')||'').toLowerCase(),filter=['unconfirmed','denied','waiting'].includes(params.get('filter'))?params.get('filter'):'';
 const serviceRows=context.services.filter(s=>(s.name+' '+s.id).toLowerCase().includes(needle)).map(service=>{
  const scoped=routingContext(projection,new URLSearchParams({service:service.id}),now),denied=scoped.records.filter(r=>r.policy?.action==='deny').length;
  return nav(link(new URLSearchParams(params.has('s')?{s:params.get('s')}:{}),{service:service.id}),`<b>${esc(service.name||service.id)}</b><small>${scoped.unresolved?'Assignment total unknown · '+scoped.records.length+' known':scoped.records.length+' assigned'} · ${denied} denied</small><span>${scoped.records.filter(r=>r.current).length} current paths · ${scoped.records.filter(r=>r.targetState==='unavailable').length} target failures · ${scoped.records.filter(r=>r.allowed&&(!r.current||r.current.availability==='unknown')).length} unconfirmed</span>`,`class="paths-service ${selected?.id===service.id?'selected':''}" data-service="${esc(service.id)}"`);
 }).join('');
 const records=context.records.filter(r=>(r.device.name+' '+r.device.id).toLowerCase().includes(search)&&(!filter||filter==='unconfirmed'&&r.allowed&&(!r.current||r.current.availability==='unknown')||filter==='denied'&&r.policy?.action==='deny'||filter==='waiting'&&r.allowed&&!r.evidence&&!!r.device.last_report_at));
 const pageSize=20,total=Math.max(1,Math.ceil(records.length/pageSize)),page=Math.min(total,Math.max(1,Number.parseInt(params.get('page'),10)||1));
 const rows=records.slice((page-1)*pageSize,page*pageSize).map(row=>`<tr data-paths-device="${esc(row.device.id)}"><td>${nav(link(base,{device:row.device.id}),`<b>${esc(row.device.name||row.device.id)}</b>`)}<small class="mono">${esc(row.device.id)}</small></td><td>${esc(row.policy?.name||row.policy?.id||'Unavailable Policy')}</td><td>${esc(row.reason)}${row.selected?`<small>Reported: ${esc(pathLabel(row.selected,projection))}</small>`:''}</td><td>${row.policy?.action==='deny'?'Access denied':row.targetState==='unavailable'?'Current target failure':row.targetState==='available'?'Current target success':'Current result unknown'}<small>${esc(stamp(row.device.last_report_at))}</small></td></tr>`).join('');
 const filters=[['','All'],['unconfirmed','Unconfirmed route / target'],['waiting','Waiting for device'],['denied','Denied']].map(([value,label])=>nav(link(base,{filter:value,page:null}),label,`class="button ${filter===value?'selected':''}" aria-current="${filter===value?'true':'false'}"`)).join('');
 return title+`<div class="paths-layout"><aside class="card paths-services"><h2>Services</h2>${searchForm(new URLSearchParams(params.has('service')?{service:params.get('service')}:{}),'s','Find a Service','Service name or ID')}${serviceRows||'<p class="empty">No matching Services.</p>'}${context.unresolved?'<p class="note">Some assigned Policies are unavailable; Service counts may be incomplete.</p>':''}</aside><section class="card paths-devices"><div class="sectionhead"><h2>${esc(selected?.name||selected?.id||'Service unavailable')}</h2><span>${context.unresolved?'Assignment total unknown · '+context.records.length+' known devices':context.records.length+' assigned devices'}</span></div>${selected?`${searchForm(base,'q','Find a device','Device name or ID')}<div class="paths-filters">${filters}</div>${table(['Device','Policy','Path','Target result / reported'],rows)}<div class="inventory-foot"><span>${records.length} devices · page ${page} of ${total}</span><div>${page>1?nav(link(base,{page:page-1}),'← Previous','class="button"'):''}${page<total?nav(link(base,{page:page+1}),'Next →','class="button"'):''}</div></div>`:'<p>This Service is unavailable. Choose an existing Service; no old route is retained.</p>'}</section></div>`;
}
