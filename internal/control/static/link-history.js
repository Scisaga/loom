import{esc,list}from'./model.js';

export function linkHistoryKey(projection,link){
 const from=list(projection.devices).find(v=>v.id===link.from),to=list(projection.devices).find(v=>v.id===link.to);
 return JSON.stringify([projection.network_id,projection.control_config_id,link.id,link.from,link.to,link.transport,link.resource_id,link.spec_digest,from?.authorized,to?.authorized,list(from?.dependencies),list(to?.dependencies)]);
}
export const linkHistoryVersion=(projection,link)=>{const device=list(projection.devices).find(v=>v.id===link.from);return JSON.stringify([device?.last_report_at,device?.evidence?.report_sequence,device?.evidence?.network_generation])};

export function linkRoundTripText(link,now){
 const measured=link?.availability==='available'&&link.current_until>now&&Number.isSafeInteger(link.round_trip_ms)&&link.round_trip_ms>=0;
 return `WG DNS RTT: ${measured?link.round_trip_ms+' ms':'Unknown'}`;
}

export function linkRoundTripMetrics(projection,link,history,now){
 const device=list(projection.devices).find(v=>v.id===link.from),value=history?.key===linkHistoryKey(projection,link)?history.data?.round_trips:null;
 const current=value&&value.report_sequence===device?.evidence?.report_sequence&&value.network_generation===device?.evidence?.network_generation&&value.current_until>now&&link.current_until>now&&link.availability==='available';
 const known=current&&value.samples>=2&&Number.isSafeInteger(value.spread_ms)&&value.spread_ms>=0;
 const details=current?`${value.samples} distinct successful samples · P50 ${value.p50_ms??'Unknown'} ms · P95 ${value.p95_ms??'Unknown'} ms · ${new Date(value.from).toISOString()} — ${new Date(value.until).toISOString()}`:'No current matching RTT distribution';
 return [{text:linkRoundTripText(link,now),title:'WG DNS request/response after connection establishment, including endpoint processing. Sender: '+link.from+' · sampled '+(link.observed_at?new Date(link.observed_at).toISOString():'Unknown')},{text:`15m Δ P95−P50: ${known?value.spread_ms+' ms':'Unknown'}`,title:details}];
}

export function linkRoundTripsHTML(projection,link,history,now){
 return linkRoundTripMetrics(projection,link,history,now).map((v,i)=>`<small ${i?'data-link-spread':'data-link-rtt'}="${esc(link.id)}" title="${esc(v.title)}">${esc(v.text)}</small>`).join('');
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
