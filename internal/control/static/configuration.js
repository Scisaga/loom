// A disposable public review and browser draft. Authority, conflict references
// and completion remain the existing signed originals and ordinary operation.
export function createConfigurationReview({api,esc,table,canonical,canOperate,redraw,refresh,toast}){
 let review=null,error='',loading=false,frontier='',dirty=false,onlyConflicts=false,search='';
 const drafts=new Map;
 const key=row=>row.target.target_kind+':'+row.target.target_id;
 const state=row=>row.target.conflicted?'Conflict · paused':row.target.deleted?'Deleted':'Effective here';
 const label=name=>name.replaceAll('_',' ');
 const sourceValue=source=>source.value&&!['.delete','.revoke'].some(v=>source.operation.endsWith(v))?source.value:null;
 function fields(value){return Object.entries(value).map(([name,entry])=>{
  const immutable=name==='id';
  if(typeof entry==='boolean')return `<div class="field"><label>${esc(label(name))}</label><select data-value-field="${esc(name)}" data-type="boolean"><option value="true" ${entry?'selected':''}>true</option><option value="false" ${entry?'':'selected'}>false</option></select></div>`;
  if(entry&&typeof entry==='object')return `<div class="field"><label>${esc(label(name))}</label><textarea data-value-field="${esc(name)}" data-type="json" rows="${Math.min(8,Math.max(2,JSON.stringify(entry,null,2).split('\n').length))}">${esc(JSON.stringify(entry,null,2))}</textarea></div>`;
  return `<div class="field"><label>${esc(label(name))}</label><input data-value-field="${esc(name)}" data-type="${typeof entry}" ${typeof entry==='number'?'type="number" step="1"':''} ${immutable?'readonly':''} value="${esc(entry)}"></div>`;
 }).join('')}
 function differences(sources){
  const values=sources.map(sourceValue),names=[...new Set(values.flatMap(v=>Object.keys(v||{})))].sort();
  const changed=names.filter(name=>new Set(values.map(v=>canonical(v?.[name]??null))).size>1);
  return table(['FIELD',...sources.map(v=>v.control_id||'Unavailable')],changed.map(name=>`<tr><td>${esc(label(name))}</td>${values.map(v=>`<td class="configuration-value">${esc(v?.[name]===undefined?'Unavailable':typeof v[name]==='string'?v[name]:JSON.stringify(v[name]))}</td>`).join('')}</tr>`).join(''));
 }
 function references(row){return `<section data-configuration-impact><h4>Known references on ${esc(review.local_control_id)}</h4><p>Read ${esc(new Date(review.observed_at).toLocaleString())}. Includes paused public settings. Unavailable originals and other controls may contain further references.</p>${row.references.length?table(['OBJECT','CURRENT RESULT','POLICIES / RESPONSIBILITIES'],row.references.map(v=>`<tr><td><a href="${v.kind==='device'?'/devices/'+encodeURIComponent(v.id):v.kind==='invite'?'/devices/invites/'+encodeURIComponent(v.id):'/policies?policy='+encodeURIComponent(v.id)}" data-nav>${esc(v.name||v.id)}</a><small>${esc(v.kind)} · ${esc(v.id)}</small></td><td>${esc(v.state.replaceAll('_',' '))}${v.effect?`<small>${esc(v.effect)}</small>`:''}${v.expires_at?`<small>Expires ${esc(new Date(v.expires_at).toLocaleString())}</small>`:''}</td><td>${esc([...(v.policy_ids||[]),...(v.responsibilities||[])].join(', '))}</td></tr>`).join('')):'<p>No confirmed references in the currently available public originals.</p>'}</section>`}
 function rowHTML(row){
  const id=key(row),draft=drafts.get(id),t=row.target;
  const sources=row.sources.map(source=>`<article class="configuration-source"><h4>${esc(source.control_id||'Unavailable')} · ${esc(source.status)}</h4><small>${esc(source.operation)} · sequence ${esc(source.sequence)}</small><p class="mono">${esc(source.material_id)}</p>${source.reason?`<p>${esc(source.reason)}</p>`:''}${sourceValue(source)?`<details><summary>Public value</summary><pre>${esc(JSON.stringify(source.value,null,2))}</pre></details>`:''}${row.resolvable&&sourceValue(source)&&canOperate('conflict.resolve')?`<button type="button" data-configuration-choice="${esc(id)}" data-source="${esc(source.material_id)}">Use this value as a draft</button>`:''}</article>`).join('');
  let editor='';
  if(draft&&canOperate('conflict.resolve'))editor=`<form id="configuration-resolution-${esc(id)}" data-configuration-form data-key="${esc(id)}" data-request-id="${esc(draft.requestId)}" data-review="${esc(JSON.stringify(draft.review))}"><h4>${draft.action==='put'?'Review final '+esc(label(t.target_kind))+' value':'Review deletion'}</h4>${draft.action==='put'?fields(draft.value):`<p>Delete ${esc(t.target_kind)} ${esc(t.target_id)}. Referencing permissions and routes will close. Device deletion keeps a permanent tombstone.</p>`}<div class="field"><label>Additional reviewed dependencies</label><input name="additional_dependencies" placeholder="Optional fact IDs, comma separated"><small>Required object references are included from this reviewed view.</small></div><label class="choice"><input type="checkbox" name="reviewed" required> I reviewed all ${draft.review.conflicts.length} conflict facts and the known references above.</label><div class="service-save"><span role="alert"></span><button class="primary" type="submit">Submit reviewed resolution</button></div></form>`;
  return `<details data-key="${esc(id)}" data-configuration-target="${esc(id)}" ${draft?'open':''}><summary><b>${esc(t.target_id)}<small>${esc(label(t.target_kind))}</small></b><span>${esc(state(row))}</span><span>${t.conflicted?'Review competing signed changes':t.deleted?'Historical originals retained':'Current value verified here'}</span></summary>${t.conflicted?differences(row.sources):''}<div class="configuration-sources">${sources}</div>${references(row)}${row.reason?`<p role="status">${esc(row.reason)}</p>`:''}${row.resolvable&&canOperate('conflict.resolve')?`<button class="danger" type="button" data-configuration-delete="${esc(id)}">Resolve by deleting this object</button>`:''}${editor}</details>`;
 }
 async function load(redrawWhenDone=true){
  if(loading)return;loading=true;error='';
  try{const next=await api('/api/control/ui/configuration');if(next.schema!==3)throw Error('Unsupported configuration review.');review=next;dirty=false;return true}catch(e){error=e.message;return false}finally{loading=false;if(redrawWhenDone)redraw()}
 }
 function html(projection){
  const current=canonical([projection.control_config_id,projection.targets]);
  if(frontier!==current){frontier=current;dirty=!!review&&current!==canonical([review.control_config_id,review.targets]);if(dirty&&!drafts.size&&!loading)queueMicrotask(load)}
  if(!review&&!loading&&!error)queueMicrotask(load);
  return `<section class="card" id="configuration-state"><h2>Configuration state</h2><p>Current results on this control. Local acceptance, peer reception and device application are separate.</p><div class="configuration-toolbar"><input type="search" data-configuration-search placeholder="Find a service, policy or device" value="${esc(search)}" aria-label="Find a configuration object"><button type="button" data-configuration-filter>${onlyConflicts?'Show all objects':'Show conflicts'}</button><button type="button" data-configuration-refresh>Refresh sources and references</button></div>${dirty?'<p role="status">New facts may have arrived. The draft retains the sources you reviewed; refresh and review again before submitting.</p>':''}${error?`<p role="alert">${esc(error)}</p>`:''}${!review?'<p>Loading verified public sources…</p>':review.rows.filter(row=>!onlyConflicts||row.target.conflicted).map(rowHTML).join('')||'<p>No currently known conflicts.</p>'}</section>`;
 }
 function pick(id,source,action){
  const row=review.rows.find(v=>key(v)===id);if(!row?.resolvable)return;
  const old=document.querySelector('[data-configuration-form][data-key="'+CSS.escape(id)+'"]'),prior=old?readValue(old):drafts.get(id)?.value;
  if(old)old.remove();
  drafts.set(id,{action,value:source?structuredClone(source.value):prior,requestId:crypto.randomUUID(),review:{kind:row.target.target_kind,id:row.target.target_id,conflicts:[...row.target.material_ids],targets:structuredClone(review.targets),policies:structuredClone(review.policies)}});redraw();
 }
 function click(event){
  const button=event.target.closest('[data-configuration-choice],[data-configuration-delete],[data-configuration-refresh],[data-configuration-filter]');return button?handleClick(button):false;
 }
 async function handleClick(button){
  if(button.hasAttribute('data-configuration-filter')){onlyConflicts=!onlyConflicts;redraw();return true}
  if(button.hasAttribute('data-configuration-refresh')){
   const forms=[...document.querySelectorAll('[data-configuration-form]')];try{const values=forms.map(form=>drafts.get(form.dataset.key)?.action==='put'?readValue(form):null);forms.forEach((form,i)=>{const d=drafts.get(form.dataset.key);if(d&&d.action==='put')d.value=values[i];form.remove()})}catch(e){toast('The final value contains invalid structured fields. Correct them before refreshing.',true);return true}
   if(!await load(false)){redraw();return true}for(const[id,draft]of drafts){const row=review?.rows.find(v=>key(v)===id);if(row?.resolvable){draft.review={kind:row.target.target_kind,id:row.target.target_id,conflicts:[...row.target.material_ids],targets:structuredClone(review.targets),policies:structuredClone(review.policies)};draft.requestId=crypto.randomUUID()}else drafts.delete(id)}redraw();return true;
  }
  if(button.hasAttribute('data-configuration-delete')){pick(button.dataset.configurationDelete,null,'delete');return true}
  const row=review.rows.find(v=>key(v)===button.dataset.configurationChoice),source=row?.sources.find(v=>v.material_id===button.dataset.source);if(source)pick(key(row),source,'put');return true;
 }
 function readValue(form){const value={};for(const field of form.querySelectorAll('[data-value-field]'))value[field.dataset.valueField]=field.dataset.type==='json'?JSON.parse(field.value):field.dataset.type==='number'?Number(field.value):field.dataset.type==='boolean'?field.value==='true':field.value;return value}
 function dependencies(draft,value){
  const ids=[...draft.conflicts],add=(kind,id)=>{if(!id)return;const target=draft.targets.find(v=>v.target_kind===kind&&v.target_id===id);if(!target||target.deleted||target.conflicted)throw Error(`The reviewed ${kind} ${id} is unavailable. Refresh its references.`);ids.push(...target.material_ids)};
  const policy=id=>{const p=draft.policies.find(v=>v.id===id);if(!p)throw Error('A selected Policy was not available in this review.');add('policy',id);add('service',p.service_id)};
  if(draft.kind==='policy'){add('service',value.service_id);for(const scope of [value.entry_scope,value.relay_scope,value.exit_scope])for(const id of scope?.node_ids||[])add('device',id);for(const id of value.local_egress_devices||[])add('device',id)}
  if(draft.kind==='device')for(const id of value.policy_ids||[])policy(id);
  if(draft.kind==='service'&&value.local_network)add('device',value.local_network.gateway_node_id);
  if(draft.kind==='resource')add('device',value.owner_node_id);
  if(draft.kind==='link'){for(const id of [value.from_resource_id,value.resource_id,value.probe_target?.resource_id])add('resource',id);for(const id of [value.from_node_id,value.to_node_id])add('device',id)}
  if(draft.kind==='expected_component')add('device',value.node_id);
  if(draft.kind==='dns_record'&&value.service_id)add('service',value.service_id);
  return ids;
 }
 async function submit(form){
  if(!form.matches('[data-configuration-form]'))return false;
  if(form.submitting)return true;form.submitting=true;const output=form.querySelector('[role=alert]');output.textContent='Submitting…';
  try{
   if(!form.elements.reviewed.checked)throw Error('Review all current source facts and their known references first.');
   const draft=JSON.parse(form.dataset.review),current=drafts.get(form.dataset.key),value=current.action==='put'?readValue(form):null,payload={conflicts:draft.conflicts,action:current.action};if(value)payload.value=value;
   const refs=current.action==='put'?dependencies(draft,value):draft.conflicts;
   refs.push(...String(form.elements.additional_dependencies.value).split(',').map(v=>v.trim()).filter(Boolean));
   const command={schema:3,request_id:form.dataset.requestId,operation:'conflict.resolve',target_kind:draft.kind,target_id:draft.id,dependencies:[...new Set(refs)].sort(),payload};
   const contents=canonical({...command,request_id:''});if(form.submittedContents&&form.submittedContents!==contents)command.request_id=form.dataset.requestId=crypto.randomUUID();form.submittedContents=contents;
   const result=await api('/api/control/operations',{method:'POST',headers:{'Content-Type':'application/json'},body:canonical(command)});
   drafts.delete(form.dataset.key);form.remove();await refresh(false);await load();toast('Resolution accepted locally. Peer reception and device application need their own readback.');return true;
  }catch(e){output.textContent=e.message;toast(e.message,true);return true}finally{form.submitting=false}
 }
 function filter(value){search=value;redraw()}
 return {html,click,submit,filter};
}
