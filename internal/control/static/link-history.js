import{esc,list}from'./model.js';

export function linkHistoryKey(projection,link){
 const from=list(projection.devices).find(v=>v.id===link.from),to=list(projection.devices).find(v=>v.id===link.to);
 return JSON.stringify([projection.network_id,projection.control_config_id,link.id,link.from,link.to,link.transport,link.resource_id,link.spec_digest,from?.authorized,to?.authorized,list(from?.dependencies),list(to?.dependencies),from?.last_report_at]);
}

export function linkHistoryHTML(projection,link,history){
 const item=history?.key===linkHistoryKey(projection,link)?history:null;
 let contents='<small>Loading Link samples…</small>';
 if(item?.error)contents=`<small>Link history could not be read.</small><button type="button" class="tiny" data-link-history-retry="${esc(link.id)}">Retry</button>`;
 else if(item?.data){
  const data=item.data,slots=list(data.buckets).map(bucket=>{
   const sample=bucket.observation,state=bucket.ambiguous?'ambiguous':sample?.result||'missing',hour=new Date(bucket.hour).toISOString().slice(0,16)+' UTC';
   const title=bucket.ambiguous?`${hour} · Conflicting samples at the same time`:sample?`${hour} · sampled ${new Date(sample.observed_at).toISOString()} · ${state}\n${data.from_node_id} → ${data.to_node_id}\nLink: ${data.link_id}\nSpec: ${sample.spec_digest}\nNetwork generation: ${sample.network_generation}\nAction: ${sample.action}`:`${hour} · No valid Link sample`;
   return `<span class="link-hour ${esc(state)}" data-link-hour="${bucket.hour}" tabindex="0" title="${esc(title)}" aria-label="${esc(title)}"></span>`;
  }).join('');
  contents=`<div class="link-hours" aria-label="24 hourly Link samples; not continuous uptime">${slots}</div><small title="As of ${esc(new Date(data.until).toISOString())}">24 hourly samples · not uptime <button type="button" class="tiny" data-link-history-retry="${esc(link.id)}">Refresh</button></small>`;
 }
 return `<div data-link-history="${esc(link.id)}">${contents}</div>`;
}
