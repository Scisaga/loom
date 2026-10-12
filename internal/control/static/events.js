const kinds=['authority','membership','enrollment','revocation','conflict','runtime'];
const colors={authority:'#7085bf',membership:'#986db5',enrollment:'#4f9e96',revocation:'#cb765b',conflict:'#c45c7a',runtime:'#a28c54'};
const esc=value=>String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const stamp=value=>value?new Date(value).toLocaleString():'Unknown';

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
  const buckets=data.buckets,max=Math.max(1,...buckets.map(v=>v.total)),width=1200,h=150,step=width/buckets.length;
  const bars=buckets.map((bucket,i)=>{
   const title=`${stamp(bucket.from)} – ${stamp(bucket.until)}\n${bucket.covered?'Complete local reception coverage':'Uncovered reception interval'}\n${kinds.map(k=>`${k}: ${bucket.counts[k]||0}`).join('\n')}\nObserved total: ${bucket.total}`;
   let y=h;const parts=[];
   for(const kind of kinds){const count=bucket.counts[kind]||0;if(!count)continue;const size=count/max*(h-10);y-=size;parts.push(`<rect x="${i*step}" y="${y}" width="${Math.max(.4,step-.5)}" height="${size}" fill="${colors[kind]}"/>`)}
   if(!bucket.covered)parts.push(`<rect x="${i*step}" y="2" width="${Math.max(.4,step-.5)}" height="${h-2}" fill="none" stroke="#a9b5b0" stroke-width=".5" stroke-dasharray="2 2"/>`);
   else if(!bucket.total)parts.push(`<rect x="${i*step}" y="${h-1}" width="${Math.max(.4,step-.5)}" height="1" fill="#839a8f"/>`);
   return `<g data-event-bucket="${i}"><title>${esc(title)}</title>${parts.join('')}</g>`;
  }).join('');
  return `<div class="event-chart-scroll"><svg class="event-chart" viewBox="0 0 ${width} ${h}" role="img" aria-label="Events in the complete filtered window">${bars}</svg></div><div class="event-chart-axis"><span>${esc(stamp(data.query.from))}</span><span>${esc(stamp(data.query.until))}</span></div><div class="event-legend">${kinds.map(k=>`<span><i style="background:${colors[k]}"></i>${k}</span>`).join('')}<span><i class="uncovered"></i>Uncovered</span></div>`;
 }
 function html(projection){
  const s=ensure();if(!s)return '';
  const values=draft(),field=(name,label,placeholder='')=>`<label>${label}<input name="${name}" value="${esc(values[name]||'')}" placeholder="${esc(placeholder)}"></label>`;
  const objectLink=v=>v.kind==='conflict'?['/ssot?section=configuration','Open current Configuration state']:v.object_kind==='device'?['/devices/'+encodeURIComponent(v.subject),'Open current device']:v.object_kind==='invite'?['/devices/invites/'+encodeURIComponent(v.subject),'Open current invitation']:v.object_kind==='service'?['/services?service='+encodeURIComponent(v.subject),'Open current service']:v.object_kind==='policy'?['/policies?policy='+encodeURIComponent(v.subject),'Open current policy']:['/ssot?section=configuration','Open current configuration'];
  const rows=s.rows.map(v=>`<tr data-event-id="${esc(v.id)}"><td><time>${esc(stamp(v.at))}</time><small>Received here</small></td><td><span class="event-type"><i style="background:${colors[v.kind]||'#839a8f'}"></i>${esc(v.kind)}</span></td><td>${esc(v.source)}</td><td><details><summary>${esc(v.subject)}</summary><p>${esc(v.detail)}</p>${v.from||v.to?`<p>${esc(v.from||'Baseline')} → ${esc(v.to||'—')}</p>`:''}<p class="mono tiny">${esc(v.id)}</p><p><a href="${esc(objectLink(v)[0])}" data-nav>${esc(objectLink(v)[1])}</a></p></details></td></tr>`).join('');
  return `<div class="heading network-heading"><div><span class="eyebrow">OPERATIONS / HISTORY</span><h1>Events</h1><p>Local reception history of signed facts and runtime changes</p></div><div class="actions"><button type="button" data-refresh-events>Refresh</button><button type="button" data-export-events ${s.data?'':'disabled'}>Export CSV</button></div></div><form id="events-filter" class="card filter-bar" data-events-filter data-events-key="${s.token}">${field('q','Search','Search events…')}<label>Type<select name="kind"><option value="">All types</option>${kinds.map(v=>`<option ${values.kind===v?'selected':''}>${v}</option>`).join('')}</select></label>${field('source','Source','Exact control or device ID')}${field('object','Object','Exact object ID')}${field('from','From UTC','Default: 72 hours before cutoff')}${field('until','Until UTC','Default: query start')}<label>Bucket<select name="interval">${[10,30,60].map(v=>`<option value="${v}" ${Number(values.interval||10)===v?'selected':''}>${v} minutes</option>`).join('')}</select></label><button type="submit">Apply</button><a class="button" href="/events" data-events-clear>Clear</a></form><section class="card event-history"><div class="sectionhead"><h2>Filtered history</h2><span data-events-total>${s.data?`${s.data.total} events · ${s.data.buckets.length} intervals`:'Reading query…'}</span></div>${chart(s.data)}<p class="tiny dim">${s.data?.coverage_from?`Reception coverage starts ${esc(stamp(s.data.coverage_from))}.`:'Reception coverage is unknown.'} Earlier or partial intervals stay uncovered. Historical records do not establish current authorization or health.</p></section><section class="card events-table">${'<div class="sectionhead"><h2>Event records</h2><span class="tiny dim">Newest reception first</span></div>'}<div class="table-wrap"><table><thead><tr><th>TIME</th><th>TYPE</th><th>SOURCE</th><th>OBJECT / DETAILS</th></tr></thead><tbody>${rows||'<tr><td colspan="4" class="empty">'+(s.loading?'Loading events…':s.error?'Event query unavailable.':'No events loaded in this window.')+'</td></tr>'}</tbody></table></div><div class="event-load-status" data-events-bottom><span data-events-loaded>${s.rows.length} loaded${s.data?` of ${s.data.total}`:''}</span><span role="status">${s.loading?'Loading earlier records…':s.error?esc(s.error):s.data&&!s.data.next_cursor?'All events loaded':''}</span>${s.error?'<button type="button" data-events-retry>Retry</button>':''}</div></section>`;
 }
 function observe(){
  const s=ensure();observer?.disconnect();if(!s)return;
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
