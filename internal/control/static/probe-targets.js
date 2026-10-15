import {list,esc} from './model.js';

const compareID=(left,right)=>left.id<right.id?-1:left.id>right.id?1:0;
const configurationLink='<a href="/ssot?section=configuration" data-nav>Review the current conflict →</a>';

// This is the shared pool, including targets without a matching Service or a
// device assignment. Path reports cannot supply or restore its current values.
export function probeTargetsHTML(snapshot,params,{canOperate=()=>false,draftAttributes=()=>''}={}){
  const pool=[...list(snapshot.business_probe_targets)].sort(compareID);
  const states=list(snapshot.targets).filter(value=>value.target_kind==='probe_target');
  const stateByID=new Map(states.map(value=>[value.target_id,value]));
  const services=new Map(list(snapshot.services).map(value=>[value.id,value]));
  const serviceStates=new Map(list(snapshot.targets).filter(value=>value.target_kind==='service').map(value=>[value.target_id,value]));
  const creating=params.get('new')==='1',selected=params.get('target');
  const query=params.get('q')||'',search=query.toLowerCase();
  const writable=canOperate('probe_target.put'),deletable=canOperate('probe_target.delete');
  const href=(id='',newDraft=false)=>'/services?'+new URLSearchParams({tab:'probes',...(query?{q:query}:{}),...(id?{target:id}:{}),...(newDraft?{new:'1'}:{})});
  const conflicts=states.filter(value=>value.conflicted&&!pool.some(target=>target.id===value.target_id));
  const records=[...pool,...conflicts.map(value=>({id:value.target_id,url:'',matched_service_ids:[]}))].sort(compareID);
  const matches=value=>[value.id,value.url,...list(value.matched_service_ids).flatMap(id=>[id,services.get(id)?.name||''])].join(' ').toLowerCase().includes(search);
  const visible=records.filter(value=>matches(value)||!creating&&value.id===selected);
  const unavailable=stateByID.get(selected);
  const current=pool.find(value=>value.id===selected);
  const selectedConflict=!!unavailable?.conflicted;
  const validSelection=!creating&&!!current&&!selectedConflict&&!unavailable?.deleted;
  const close=`<a class="button" href="${esc(href())}" data-nav>Close</a>`;

  const matchingServices=value=>{
    const ids=[...new Set(list(value.matched_service_ids))].sort();
    if(!ids.length)return '<span class="dim">No matching service</span><small>Kept in the shared pool</small>';
    return `<ul class="probe-match-list">${ids.map(id=>{
      const service=services.get(id),state=serviceStates.get(id);
      if(state?.conflicted)return `<li><span>${esc(service?.name||id)} · suspended</span> ${configurationLink}</li>`;
      if(!service||state?.deleted)return `<li><span class="dim">${esc(id)} · unavailable</span></li>`;
      return `<li><a href="/services?service=${encodeURIComponent(id)}" data-nav>${esc(service.name||id)} →</a></li>`;
    }).join('')}</ul>`;
  };

  const deleteButton=value=>deletable?`<button type="button" class="danger" data-delete-kind="probe_target" data-delete-id="${esc(value.id)}" data-delete-message="${esc(`Delete probe target ${value.id} (${value.url})? Future probes stop using this target after the change reaches each device. Service destinations and selected policies stay unchanged.`)}" ${draftAttributes()}>Delete</button>`:'';

  const editor=value=>{
    if(!writable)return `<section class="probe-editor"><div class="sectionhead"><h3>Inspect probe target</h3><span class="tiny dim">Read only</span></div><p class="mono">${esc(value.id)}</p><p class="probe-url mono">${esc(value.url)}</p><div class="intent-actions">${close}</div></section>`;
    return `<section class="probe-editor"><div class="sectionhead"><h3>${creating?'Add probe target':'Edit probe target'}</h3><span class="tiny dim">Draft · not saved</span></div>${!creating?`<p class="tiny dim">Current URL · <span class="probe-url mono">${esc(value.url)}</span></p>`:''}<form id="probe-target-form" data-creating="${creating}" ${draftAttributes()}><div class="probe-editor-fields"><div class="field"><label for="probe-target-id">Target ID${creating?'':' · read only'}</label>${creating?'<input id="probe-target-id" name="id" data-probe-target-id required autocomplete="off"><small>Use a new ID. Existing, deleted and conflicting IDs cannot create a new target.</small>':`<input type="hidden" name="id" value="${esc(value.id)}"><p id="probe-target-id" class="mono">${esc(value.id)}</p>`}</div><div class="field"><label for="probe-target-url">HTTPS URL</label><input id="probe-target-url" name="url" type="url" pattern="https://.*" required value="${esc(value.url)}" placeholder="https://service.example/health" autocomplete="off"><small>Use an exact HTTPS URL, including its path.</small></div></div>${!creating?`<div class="probe-editor-matches"><span class="tiny dim">Matching services · saved URL</span>${matchingServices(value)}</div>`:''}<p class="tiny dim">${creating?'Saving adds a shared target.':'Saving updates this shared target.'} Each device still uses only the targets allowed by its service and selected policy.</p><div class="intent-actions service-save"><span id="operation-status" role="alert"></span><a class="button" href="${esc(href())}" data-nav>Discard</a><button class="primary" type="submit">${creating?'Add target':'Save target'}</button></div></form></section>`;
  };

  let selectionNotice='';
  if(creating&&params.has('target'))selectionNotice=`<p class="note" role="alert">${current||unavailable?'This target ID is already known. A new target needs an unused ID.':'Choose either a new target or an existing target to edit.'} No target was changed.</p>`;
  else if(!creating&&params.has('target')&&!validSelection)selectionNotice=`<div class="note" role="status"><p>${selectedConflict?'This target has conflicting signed values. Probing with it is suspended.':unavailable?.deleted?'This target was deleted and cannot be edited.':'This probe target is unavailable. No other target has been opened.'}</p>${selectedConflict?configurationLink:''}</div>`;
  else if(creating&&!writable)selectionNotice='<p class="note" role="status">This connection cannot add probe targets.</p>';

  const rows=visible.map(value=>{
    const state=stateByID.get(value.id),suspended=!!state?.conflicted,deleted=!!state?.deleted;
    const opened=validSelection&&value.id===selected;
    const actions=suspended?configurationLink:deleted?'<span class="dim">Deleted</span>':`<a class="button" href="${esc(href(value.id))}" data-nav>${writable?'Edit':'Inspect'}</a>${deleteButton(value)}`;
    const row=`<tr data-key="probe-target:${esc(value.id)}" data-probe-target="${esc(value.id)}" ${opened?'class="selected" aria-selected="true"':''}><td><b class="mono">${esc(value.id)}</b><small>${suspended?'Suspended · conflicting signed changes':'Shared target'}</small></td><td class="probe-url mono">${suspended?'<span class="dim">No effective URL</span>':esc(value.url)}</td><td>${suspended?'<span class="dim">Matching paused</span>':matchingServices(value)}</td><td><div class="intent-actions">${actions}</div></td></tr>`;
    return row+(opened?`<tr class="probe-expanded" data-key="probe-editor:${esc(value.id)}"><td colspan="4">${editor(value)}</td></tr>`:'');
  }).join('');
  const newEditor=creating&&!params.has('target')&&writable?`<tr class="probe-expanded" data-key="probe-editor:new"><td colspan="4">${editor({id:'',url:'',matched_service_ids:[]})}</td></tr>`:'';
  const conflictCount=states.filter(value=>value.conflicted).length;
  return `<form class="probe-filters" data-page-filter><input type="hidden" name="tab" value="probes"><label><input type="search" name="q" value="${esc(query)}" aria-label="Search probe target ID, URL or matching service" placeholder="Search target ID, URL or matching service"></label><button type="submit">Search</button>${query?'<a class="button" href="/services?tab=probes" data-nav>Clear</a>':''}<span class="tiny dim">${search?`${visible.length} shown · `:''}${pool.length} shared targets${conflictCount?` · ${conflictCount} suspended conflicts`:''} · includes unused targets</span></form>${selectionNotice}<section class="card probe-pool"><div class="panel-heading"><h2>Shared HTTPS pool</h2><span class="tiny dim">Matching services do not grant access</span></div><div class="table-wrap"><table><thead><tr><th scope="col">Target ID</th><th scope="col">HTTPS URL</th><th scope="col">Matching services</th><th scope="col">Actions</th></tr></thead><tbody>${rows||'<tr data-key="probe-empty"><td colspan="4" class="empty">'+(search?'No targets match this search.':'No shared probe targets have been configured.')+'</td></tr>'}${newEditor}</tbody></table></div></section><section class="intent-section"><div class="sectionhead"><h2>Probe results</h2><a href="/routing" data-nav>View Live paths →</a></div><p class="dim">Inspect results for a device, service and candidate in Live paths.</p><p class="tiny dim">An unused or unmatched target stays available here. Saving never grants device access.</p></section>`;
}
