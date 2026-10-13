import {icon} from './icons.js';
const kinds=['authority','membership','enrollment','revocation','conflict','runtime'];
const colors={authority:'#7085bf',membership:'#986db5',enrollment:'#4f9e96',revocation:'#cb765b',conflict:'#c45c7a',runtime:'#a28c54'};
const esc=value=>String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const stamp=value=>value?new Date(value).toISOString().replace('T',' ').replace('Z',' UTC'):'Unknown';

// One deletable page query. Its fixed cutoff, list and draft are presentation
// values; every request still enters the normal authenticated control handler.
export function eventsView({api,redraw}){
 let state=null,observer=null,token=0;
 function current(){return location.pathname==='/events'}
 function reset(){state?.request?.abort();observer?.disconnect();state=null}
 function query(params){const q=new URLSearchParams;for(const key of ['from','until','q','kind','source','object','interval'])if(params.get(key))q.set(key,params.get(key));return q}
 function ensure(){
  if(!current()){reset();return null}
  const key=location.search;
  if(state?.key!==key){reset();state={key,token:++token,params:query(new URLSearchParams(key)),data:null,rows:[],loading:false,error:'',request:null,draft:null}}
  return state;
 }
 async function load(){
  const s=ensure();if(!s||s.loading||s.data&&!s.data.next_cursor)return;
  const params=new URLSearchParams(s.params);if(s.data?.next_cursor)params.set('cursor',s.data.next_cursor);
  s.loading=true;s.error='';s.request=new AbortController;redraw();
  try{
   const data=await api('/api/control/ui/events?'+params,{signal:s.request.signal});
   if(state!==s||!current())return;
   if(data.schema!==3||!Array.isArray(data.events)||!Array.isArray(data.buckets))throw Error('Invalid event response.');
   const seen=new Set(s.rows.map(v=>v.id));for(const row of data.events)if(!seen.has(row.id)){s.rows.push(row);seen.add(row.id)}
   s.data=data;s.params=new URLSearchParams;
   for(const [key,value]of Object.entries(data.query)){if(key==='result_digest'){s.params.set('result',value)}else if(key==='interval_minutes')s.params.set('interval',String(value));else if(value)s.params.set(key,value)}
  }catch(error){if(state===s&&error.name!=='AbortError')s.error=error.message||'Event query failed.'}
  finally{if(state===s){s.loading=false;s.request=null;if(current())redraw()}}
 }
 function draft(){
  const form=document.querySelector('#events-filter');
  if(form&&form.dataset.eventsKey===String(state?.token))state.draft=Object.fromEntries(new FormData(form));
  return state.draft||Object.fromEntries(new URLSearchParams(location.search));
 }
 function chart(data){
  if(!data)return '<p class="empty">Loading the complete query window…</p>';
  const buckets=data.buckets,max=Math.max(4,Math.ceil(Math.max(1,...buckets.map(v=>v.total))/4)*4),width=1200,h=150,axis=36,top=12,step=(width-axis)/buckets.length;
  const bars=buckets.map((bucket,i)=>{
   const title=`${stamp(bucket.from)} – ${stamp(bucket.until)}\n${bucket.covered?'Complete local reception coverage':'Uncovered reception interval'}\n${kinds.map(k=>`${k}: ${bucket.counts[k]||0}`).join('\n')}\nObserved total: ${bucket.total}`;
   let y=h+top;const parts=[];
   for(const kind of kinds){const count=bucket.counts[kind]||0;if(!count)continue;const size=count/max*(h-10);y-=size;parts.push(`<rect x="${axis+i*step}" y="${y}" width="${Math.max(.4,step-.5)}" height="${size}" fill="${colors[kind]}"/>`)}
   if(!bucket.covered)parts.push(`<rect x="${axis+i*step}" y="${top+2}" width="${Math.max(.4,step-.5)}" height="${h-2}" fill="none" stroke="#a9b5b0" stroke-width=".5" stroke-dasharray="2 2"/>`);
   else if(!bucket.total)parts.push(`<rect x="${axis+i*step}" y="${h+top-1}" width="${Math.max(.4,step-.5)}" height="1" fill="#839a8f"/>`);
   return `<g data-event-bucket="${i}"><title>${esc(title)}</title>${parts.join('')}</g>`;
  }).join('');
  return `<div class="event-legend">${kinds.map(k=>`<span><i class="event-kind-${k}"></i>${esc(k)} · ${buckets.reduce((n,b)=>n+(b.counts[k]||0),0)}</span>`).join('')}<span><i class="uncovered"></i>Uncovered</span></div><div class="event-chart-scroll"><svg class="event-chart" viewBox="0 0 ${width} ${h+24}" preserveAspectRatio="none" role="img" aria-label="Events in the complete filtered window">${Array.from({length:5},(_,i)=>`<line x1="${axis}" x2="${width}" y1="${top+h-i*h/4}" y2="${top+h-i*h/4}" stroke="#e7ebe8"/><text x="${axis-12}" y="${top+h-i*h/4+4}" text-anchor="end" fill="#717674" font-size="10">${i*max/4}</text>`).join('')}${bars}</svg></div><div class="event-chart-axis">${Array.from({length:7},(_,i)=>{const at=new Date(Date.parse(data.query.from)+(Date.parse(data.query.until)-Date.parse(data.query.from))*i/6).toISOString();return `<span>${at.slice(0,10)}<small>${at.slice(11,16)}</small></span>`}).join('')}</div>`;
 }
 function html(projection){
  const s=ensure();if(!s)return '';
  const values=draft(),custom=!!(values.from||values.until),field=(name,label,placeholder='',attrs='')=>`<input aria-label="${label}" name="${name}" value="${esc(values[name]||'')}" placeholder="${esc(placeholder)}" ${attrs}>`;
  const objectLink=v=>v.kind==='conflict'?['/ssot?section=configuration','Inspect current conflict →']:v.object_kind==='device'?['/devices/'+encodeURIComponent(v.subject),'Open current device →']:v.object_kind==='invite'?['/devices/invites/'+encodeURIComponent(v.subject),'Open current invitation →']:v.object_kind==='service'?['/services?service='+encodeURIComponent(v.subject),'Open current service →']:v.object_kind==='policy'?['/policies?policy='+encodeURIComponent(v.subject),'Open current policy →']:['/ssot?section=configuration','Open current configuration →'];
  const sources=new Map((projection.members||[]).map(v=>[v.control_id,v.control_id]));for(const d of projection.devices||[])sources.set(d.id,d.name||d.id);for(const v of s.rows)sources.set(v.source,v.source);
  const objects=new Map((projection.targets||[]).map(v=>[v.target_id,v.target_kind+' · '+v.target_id]));for(const v of s.rows)objects.set(v.subject,v.subject);
  const options=values=>[...values].sort(([a],[b])=>a<b?-1:a>b?1:0).map(([id,name])=>`<option value="${esc(id)}">${esc(name)}</option>`).join('');
  const receipt=v=>v.kind==='runtime'?{text:v.to||'Runtime received',detail:'Signed state at receipt',status:v.to==='running'?'ok':v.to==='error'?'bad':'unknown'}:v.kind==='conflict'?{text:'Conflict recorded',detail:'Inspect the current object independently',status:'unknown'}:{text:v.kind==='membership'?'Certificate received':v.kind==='revocation'?'Withdrawal received':'Signed change received',detail:'Current effect and peer receipt are separate',status:''};
  const rows=s.rows.map(v=>{const result=receipt(v),at=new Date(v.at).toISOString();return `<div class="event-record event-kind-${esc(v.kind)}" data-event-id="${esc(v.id)}"><details><summary class="event-row"><span class="event-received"><time class="mono" datetime="${esc(v.at)}" title="${esc(stamp(v.at))}">${at.slice(11,19)}</time><small>${at.slice(0,10)}</small></span><span class="event-description"><i class="event-kind-${esc(v.kind)}"></i><span>${esc(v.subject)} · ${esc(v.detail)}<small>${esc(v.kind)} · ${esc(v.source)}</small></span></span><span class="event-at-receipt ${esc(result.status)}">${esc(result.text)}<small>${esc(result.detail)}</small></span></summary><div class="event-details"><h3>What was received at ${at.slice(11,19)} UTC</h3><p>${esc(v.detail)}</p>${v.from||v.to?`<p>${esc(v.from||'Baseline')} → ${esc(v.to||'—')}</p>`:''}<p class="tiny dim">This is the historical receipt. It does not establish current authorization, reachability or health.</p><p class="mono tiny">${esc(v.id)}</p><p><a href="${esc(objectLink(v)[0])}" data-nav>${esc(objectLink(v)[1])}</a></p></div></details></div>`}).join('');
  const local=projection.devices?.find(d=>d.id===projection.local_node_id)?.name||projection.local_node_id||'this control';
  return `<div class="heading network-heading"><div><span class="eyebrow">OPERATIONS / HISTORY</span><h1>Events</h1><p>Explore event activity and open a record to inspect its impact and current state.</p></div><button type="button" data-export-events ${s.data?'':'disabled'}>Export filtered</button></div><div class="events-reception"><span>History received by ${esc(local)}</span><span class="dim">${s.data?'As of '+esc(stamp(s.data.query.until)):'Reading the query cutoff…'} <button type="button" data-refresh-events class="tiny">Refresh</button></span></div><form id="events-filter" class="events-filter" data-events-filter data-events-key="${s.token}"><label class="events-search">${icon('search')}${field('q','Search events','Search events, devices or objects')}</label><select name="kind" aria-label="Event type"><option value="">All event types</option>${kinds.map(v=>`<option ${values.kind===v?'selected':''}>${v}</option>`).join('')}</select><label class="events-combo">${field('source','Source','All sources','list="event-sources"')}<span class="events-select-arrow" aria-hidden="true"></span></label><datalist id="event-sources">${options(sources)}</datalist><label class="events-combo">${field('object','Object','All objects','list="event-objects"')}<span class="events-select-arrow" aria-hidden="true"></span></label><datalist id="event-objects">${options(objects)}</datalist><select data-events-window aria-label="Time window"><option value="72" ${custom?'':'selected'}>Last 72 hours</option><option value="custom" ${custom?'selected':''}>Custom UTC range</option></select><select name="interval" aria-label="Bucket interval">${[10,30,60].map(v=>`<option value="${v}" ${Number(values.interval||10)===v?'selected':''}>${v} min buckets</option>`).join('')}</select><button type="submit" class="primary">Apply filters</button><a class="button" href="/events" data-events-clear>Clear</a><details class="events-range" ${custom?'open':''}><summary>Explicit UTC range</summary><label>From UTC${field('from','From UTC','Canonical UTC timestamp')}</label><label>Until UTC${field('until','Until UTC','Canonical UTC timestamp')}</label><small>Fixed range · positive window up to 30 days</small></details></form><section class="event-history"><div class="sectionhead"><h2>Events over time</h2><span data-events-total class="tiny dim">${s.data?`${s.data.total} events · ${s.data.buckets.length} intervals`:'Reading the complete query…'}</span></div>${chart(s.data)}<p class="tiny dim">UTC · ${s.data?.coverage_from?`Reception coverage starts ${esc(stamp(s.data.coverage_from))}.`:'Reception coverage is unknown.'} Earlier or partial intervals stay uncovered. Hover a bar for counts.</p></section><section class="card events-table"><div class="panel-heading"><h2>Local history</h2><span class="tiny dim">Newest receipt first · no global order</span></div><div class="event-table-head"><span>RECEIVED UTC</span><span>EVENT / SOURCE</span><span>RESULT AT RECEIPT</span></div>${rows||'<p class="empty">'+(s.loading?'Loading events…':s.error?'Event query unavailable.':'No events loaded in this window.')+'</p>'}<p class="event-history-note tiny dim">History records verified changes and authenticated reports. An earlier result does not establish current device or service state.</p><div class="event-load-status" data-events-bottom><span data-events-loaded>${s.rows.length} loaded${s.data?` of ${s.data.total}`:''}</span><span role="status">${s.loading?'Loading earlier records…':s.error?esc(s.error):s.data&&!s.data.next_cursor?'All events loaded':''}</span>${s.error?'<button type="button" data-events-retry>Retry</button>':''}</div></section>`;
 }

 function observe(){
  const s=ensure();observer?.disconnect();if(!s)return;
  const range=document.querySelector('[data-events-window]');if(range)range.onchange=()=>{const form=range.form,custom=range.value==='custom';form.querySelector('.events-range').open=custom;for(const name of ['from','until'])form.elements[name].value=custom?(form.elements[name].value||s.data?.query[name]||''):''};
  if(!s.data&&!s.loading&&!s.error){queueMicrotask(load);return}
  if(s.data?.next_cursor&&!s.loading&&!s.error){observer=new IntersectionObserver(entries=>{if(entries.some(v=>v.isIntersecting))load()},{rootMargin:'250px'});const bottom=document.querySelector('[data-events-bottom]');if(bottom)observer.observe(bottom)}
 }
 function submit(form){
  const params=new URLSearchParams(new FormData(form));if(state?.data&&!params.get('from')?.trim()&&!params.get('until')?.trim()){params.set('from',state.params.get('from'));params.set('until',state.params.get('until'))}for(const [key,value]of [...params])if(!value.trim())params.delete(key);else params.set(key,value.trim());
  // UTC inputs are explicit strings. Let the formal decoder reject ambiguity.
  history.pushState({},'','/events'+(params.size?'?'+params:''));form.remove();reset();redraw();scrollTo(0,0);
 }
 function refresh(){const values=state?draft():null,params=new URLSearchParams(location.search);if(state?.data&&new Date(state.data.query.until)-new Date(state.data.query.from)===72*3600000){params.delete('from');params.delete('until');history.replaceState({},'','/events'+(params.size?'?'+params:''))}reset();const s=ensure();if(s&&values)s.draft=values;redraw()}
 function clear(){history.pushState({},'','/events');document.querySelector('#events-filter')?.remove();reset();redraw();scrollTo(0,0)}
 function exportCSV(){if(!state?.data)return;const params=new URLSearchParams(state.params);params.set('format','csv');const link=document.createElement('a');link.href='/api/control/ui/events?'+params;link.download='loom-events.csv';link.click()}
 return {html,observe,submit,refresh,clear,exportCSV,retry:load};
}
