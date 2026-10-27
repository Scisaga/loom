import {canonical,esc,list,reportIsCurrent} from './model.js';

// Per-device business-path observations, never a shared Policy health flag.
export function policyPathOptions(projection,deviceID,policy,now,reviewedTargets){
 let href='';const unknown=reason=>({state:'unknown',reason,href});
 const device=list(projection?.devices).find(v=>v.id===deviceID);
 if(!device)return unknown('No joined device runtime yet.');
 if(!device.authorized||device.conflicted)return unknown('Device is not currently authorized.');
 const current=list(projection.policies).find(v=>v.id===policy.id),service=list(projection.services).find(v=>v.id===current?.service_id);
 if(!current||!service||list(projection.targets).some(v=>(v.target_kind==='policy'&&v.target_id===policy.id||v.target_kind==='service'&&v.target_id===current.service_id)&&(v.deleted||v.conflicted)))return unknown('Policy or Service reference is unavailable.');
 if(canonical(current)!==canonical(policy))return unknown('Policy changed since this draft was opened.');
 if(reviewedTargets&&[['policy',policy.id],['service',current.service_id]].some(([kind,id])=>{
  const reviewed=reviewedTargets.find(v=>v.target_kind===kind&&v.target_id===id),latest=list(projection.targets).find(v=>v.target_kind===kind&&v.target_id===id);
  return !reviewed||!latest||canonical(list(reviewed.material_ids))!==canonical(list(latest.material_ids));
 }))return unknown('Policy or Service changed since this draft was opened.');
 if(!list(device.policy_ids).includes(policy.id))return unknown('This Policy is not applied to this device.');
 href='/routing?'+new URLSearchParams({service:current.service_id,device:deviceID});
 if(current.action!=='allow')return unknown('Access is denied by this Policy.');
 const report=device.evidence;
 if(!report)return unknown('No current device report.');
 if(report.freshness==='clock_unknown'||Date.parse(report.reported_at)>now+5000)return unknown('Device report time needs checking.');
 if(!reportIsCurrent(report,now))return unknown('Device report has expired.');
 if(report.runtime?.state!=='running'||!report.view_digest||report.runtime.applied_view_digest!==report.view_digest)return unknown('No running, applied configuration report.');
 const choices=report.policy_choices;
 if(!Array.isArray(choices))return unknown('Client policy choice was not reported.');
 const choice=choices.find(v=>v.service_id===current.service_id);
 if(!choice?.policy_id)return unknown('Waiting for the client to select a policy for this Service.');
 if(choice.policy_id!==policy.id)return unknown('This Policy is available but is not selected by this client.');
 const mode=current.name||current.id;
 const paths=list(projection.paths).filter(v=>v.device===deviceID&&v.service_id===current.service_id&&v.policy_id===policy.id);
 if(!paths.length)return unknown(mode+': no candidate in the current projection.');
 if(paths.every(v=>!list(v.targets).length))return unknown(mode+': no matching business probe targets.');
 const counts={available:0,unavailable:0,unknown:0};
 for(const path of paths)counts[list(path.targets).length&&path.current_until>now&&['available','unavailable'].includes(path.availability)?path.availability:'unknown']++;
 const state=counts.available?'available':counts.unavailable===paths.length?'unavailable':'unknown';
 return {state,counts,href,reason:`${mode}: ${counts.available} available · ${counts.unavailable} failed · ${counts.unknown} unknown paths.`};
}

function runtimeContents(value,details,inDraft){
 const label=value.state==='available'?'Available':value.state==='unavailable'?'Unavailable':'Unknown';
 return `<span class="badge ${value.state}" title="Path options: ${label}">${details?'Path options: ':''}${label}</span><small title="${esc(value.reason)}">${esc(value.reason)}</small>${details&&value.href?`<a href="${esc(value.href)}" ${inDraft?'target="_blank" rel="noopener"':'data-nav=""'}>View live paths ${inDraft?'↗':'→'}</a>`:''}`;
}
export function policyRuntimeHTML(policy,context={},details=true,inDraft=false){
 const {projection,deviceID='',now=0,reviewedTargets}=context,value=policyPathOptions(projection,deviceID,policy,now,reviewedTargets);
 return `<span class="policy-runtime" data-policy-runtime="${esc(policy.id)}" data-policy-device="${esc(deviceID)}" data-policy-details="${details}" data-policy-state="${value.state}" role="status">${runtimeContents(value,details,inDraft)}</span>`;
}

// Read-only hints inside retained drafts must not replace their reviewed inputs.
export function refreshPolicyRuntime(root,projection,now){
 for(const node of root.querySelectorAll('[data-policy-runtime]')){
  const form=node.closest('form[data-policies]'),policies=form?JSON.parse(form.dataset.policies):list(projection.policies),policy=policies.find(v=>v.id===node.dataset.policyRuntime)||{id:node.dataset.policyRuntime};
  const value=policyPathOptions(projection,node.dataset.policyDevice,policy,now,form?JSON.parse(form.dataset.targets):undefined),contents=runtimeContents(value,node.dataset.policyDetails==='true',!!form);
  node.dataset.policyState=value.state;
  if(node.innerHTML!==contents)node.innerHTML=contents;
 }
}

const policyLabel=(policy,service)=>`${policy.name||policy.id} · ${service?.name||policy.service_id}`;
const selectedTag=(id,label)=>`<span class="selected-node-tag">${esc(label)}<button type="button" data-policy-remove="${esc(id)}" aria-label="Remove ${esc(label)}">×</button></span>`;
export function policyChoicesHTML(selected,policies,services,targets,context={}){
 const values=[...policies].sort((a,b)=>(a.name||a.id).localeCompare(b.name||b.id));
 for(const id of selected)if(!values.some(p=>p.id===id))values.push({id,name:id,service_id:'',unavailable:true});
 const rows=values.map(p=>{
  const service=services.find(s=>s.id===p.service_id),unavailable=p.unavailable||p.action!=='allow'||!service||targets.some(t=>((t.target_kind==='policy'&&t.target_id===p.id)||(t.target_kind==='service'&&t.target_id===p.service_id))&&(t.deleted||t.conflicted)),label=policyLabel(p,service),name=p.name||p.id,description=[service?.name||p.service_id,service?(service.kind==='local_network'?'Shared LAN':'Internet'):''].filter(Boolean).join(' · ');
  return `<label data-policy-option="${esc([label,service?.local_network?.gateway_node_id||'',p.id].join(' '))}" data-policy-label="${esc(label)}"><input type="checkbox" name="policy_id" value="${esc(p.id)}" ${selected.includes(p.id)?'checked':''} ${unavailable?'disabled data-policy-unavailable':''}><span class="policy-option-identity"><span title="${esc(name)}">${esc(name)}</span><small title="${esc(description)}">${esc(description)}</small></span>${unavailable?'<span class="policy-option-unavailable"><span title="Unavailable reference">Unavailable reference</span><small title="Remove the selected tag explicitly.">Remove the selected tag explicitly.</small></span>':policyRuntimeHTML(p,context,false,true)}</label>`;
 }).join('');
 return `<div class="policy-picker"><div class="policy-tags">${selected.map(id=>{const p=values.find(p=>p.id===id);return selectedTag(id,policyLabel(p,services.find(s=>s.id===p.service_id)))}).join('')}</div><details><summary><span data-policy-picker-label aria-live="polite">Find a policy…</span><span aria-hidden="true">⌄</span></summary><div class="node-picker-popup"><div class="policy-picker-toolbar"><input type="search" data-policy-search aria-label="Find a policy or service" placeholder="Policy, service or gateway"><button type="button" data-policy-select-all disabled>Select all policies</button></div>${rows||'<p>No policies. Joining without business access is allowed.</p>'}</div></details></div><p class="tiny dim">Authorize the policies this device may choose. The client selects one policy for each service.</p><div data-selected-policy-summary></div>`;
}
export function syncPolicyChoices(form,services,canCopy=false,context={}){
 const picker=form.querySelector('.policy-picker');if(!picker)return;
 context={...context,reviewedTargets:form.dataset.targets?JSON.parse(form.dataset.targets):undefined};
 const policies=JSON.parse(form.dataset.policies),selected=[...picker.querySelectorAll('[name=policy_id]:checked')];
 const eligible=[...picker.querySelectorAll('[name=policy_id]:enabled')],remaining=eligible.some(input=>!input.checked),all=eligible.length>0&&!remaining,button=picker.querySelector('[data-policy-select-all]');
 button.disabled=!remaining;button.textContent=all?'All '+eligible.length+' selected':'Select all policies';
 picker.querySelector('[data-policy-picker-label]').textContent=all&&selected.length===eligible.length?'All '+selected.length+' policies selected':selected.length?selected.length+' policies selected':'Find a policy…';
 picker.querySelector('.policy-tags').innerHTML=selected.map(input=>selectedTag(input.value,input.closest('label').dataset.policyLabel)).join('');
 const summary=form.querySelector('[data-selected-policy-summary]'),summaries=selected.map(input=>{
  const p=policies.find(p=>p.id===input.value),s=services.find(s=>s.id===p?.service_id);
  if(!p||!s||input.hasAttribute('data-policy-unavailable'))return `<section class="selected-policy-summary bad">${esc(input.closest('label').dataset.policyLabel)} · unavailable. Remove or review this reference before submitting.</section>`;
  const scope=v=>v?.mode==='any'?'unrestricted':v?.mode==='none'?'none':list(v?.node_ids).join(', '),rule=p.action==='deny'?'Deny this service':s.kind==='local_network'?`Fixed LAN gateway ${s.local_network.gateway_node_id} · entry ${scope(p.entry_scope)} · transit ${scope(p.relay_scope)}`:`${p.allow_direct?'Direct, or ':''}entry ${scope(p.entry_scope)} · transit ${scope(p.relay_scope)} · exit ${scope(p.exit_scope)}`,targets=s.kind==='local_network'?s.local_network.virtual_prefix+' → '+s.local_network.local_prefix:list(s.matchers).map(v=>(v.kind==='dns_suffix'?'.':'')+v.value).join(' + ');
  return `<section class="selected-policy-summary"><div class="sectionhead"><span class="mono">${esc(p.name||p.id)}</span><span>${esc(s.name||s.id)} · ${s.kind==='local_network'?'Shared LAN':'Internet'}</span><a href="/policies?policy=${encodeURIComponent(p.id)}" data-nav>View rules →</a></div><p>${esc(rule)}</p><small class="mono">${esc(targets)}</small>${policyRuntimeHTML(p,context,true,true)}${canCopy?`<button type="button" data-copy-policy="${esc(p.id)}">Copy for this device</button>`:''}</section>`;
 }).join('');
 summary.innerHTML=summaries?`<div class="policy-summary-heading"><h3>Selected policy details</h3><span class="tiny dim" data-policy-summary-range></span></div><div class="policy-summary-list" data-policy-summary-list role="region" aria-label="Selected policy details" tabindex="0">${summaries}</div><nav class="policy-summary-pagination" aria-label="Selected policy pages"><button type="button" data-policy-summary-page="-1">Previous</button><span data-policy-summary-page-status role="status" aria-live="polite"></span><button type="button" data-policy-summary-page="1">Next</button></nav>`:'<p class="dim policy-empty">Join only · no business access.</p>';
 showPolicySummaryPage(summary,Number(summary.dataset.page)||0);
 const count=form.querySelector('[data-device-selection-count]');if(count){const roles=[...form.querySelectorAll('[name=responsibility]:checked')].length,serviceIDs=new Set(selected.map(input=>policies.find(p=>p.id===input.value)?.service_id).filter(Boolean));count.textContent=roles+' roles · '+selected.length+' policies · '+serviceIDs.size+' services'}
}
function showPolicySummaryPage(summary,page){
 const rows=[...summary.querySelectorAll('.selected-policy-summary')],pages=Math.max(1,Math.ceil(rows.length/3)),current=Math.max(0,Math.min(Math.floor(page)||0,pages-1));
 summary.dataset.page=String(current);if(!rows.length)return;
 const start=current*3,end=Math.min(start+3,rows.length);
 rows.forEach((row,index)=>row.hidden=index<start||index>=end);
 summary.querySelector('[data-policy-summary-range]').textContent=`${start+1}–${end} of ${rows.length}`;
 summary.querySelector('[data-policy-summary-page-status]').textContent=`Page ${current+1} of ${pages}`;
 summary.querySelector('[data-policy-summary-page="-1"]').disabled=current===0;
 summary.querySelector('[data-policy-summary-page="1"]').disabled=current===pages-1;
 summary.querySelector('.policy-summary-pagination').hidden=pages===1;
 summary.querySelector('[data-policy-summary-list]').scrollTop=0;
}
export function policyPickerOutsideClick(event){
 for(const details of document.querySelectorAll('.policy-picker>details[open]'))if(!details.parentElement.contains(event.target))details.open=false;
}
export function policyPickerInput(event){const input=event.target.closest('[data-policy-search]');if(!input)return;for(const row of input.closest('.policy-picker').querySelectorAll('[data-policy-option]'))row.hidden=!row.dataset.policyOption.toLowerCase().includes(input.value.toLowerCase())}
export function policyPickerClick(event){
 const button=event.target.closest('[data-policy-remove],[data-policy-select-all],[data-policy-summary-page]');if(!button)return false;
 if(button.hasAttribute('data-policy-summary-page')){const summary=button.closest('[data-selected-policy-summary]');showPolicySummaryPage(summary,Number(summary.dataset.page)+Number(button.dataset.policySummaryPage));return true}
 const picker=button.closest('.policy-picker');
 if(button.hasAttribute('data-policy-select-all')){
  const inputs=[...picker.querySelectorAll('[name=policy_id]:enabled:not(:checked)')];
  for(const input of inputs)input.checked=true;
  inputs[0]?.dispatchEvent(new Event('change',{bubbles:true}));
 }else{
  const input=[...picker.querySelectorAll('[name=policy_id]')].find(input=>input.value===button.dataset.policyRemove);input.checked=false;input.dispatchEvent(new Event('change',{bubbles:true}));
 }
 return true;
}
export function policyPickerKey(event){const picker=event.target.closest('.policy-picker');if(!picker)return;if(event.key==='Escape'){picker.querySelector('details').open=false;picker.querySelector('summary').focus();event.preventDefault()}else if(event.key==='Enter'&&event.target.matches('[data-policy-search]')){event.preventDefault();const input=[...picker.querySelectorAll('[data-policy-option]')].find(v=>{const input=v.querySelector('input');return !v.hidden&&!input.disabled&&!input.checked})?.querySelector('input');input?.click()}}
